"""NBFC-side witness: pulls signed checkpoints from an LSP and checks the log only ever grows.

Runs at the NBFC, outside the LSP's control:

    python -m src.egress.witness --lsp-url https://vict.lsp.example.in --lsp-id lsp-demo \\
        --public-key lsp-checkpoint.pub.pem --state witness-state.json --interval 10

Pull rather than push: the NBFC sets the pace, and an LSP that stops answering
is itself a signal. Each poll fetches only the record digests since the last
accepted checkpoint, so no borrower data reaches the NBFC.

An alarm is sticky. Once the LSP's log fails a check, the witness keeps
reporting it until someone investigates and clears the state file.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from src.egress.audit import GENESIS, fold
from src.egress.checkpoint import CheckpointError, load_public_key, verify_signed

MAX_DIGESTS_PER_FETCH = 10_000


@dataclass(frozen=True)
class WitnessStatus:
    ok: bool
    reason: str
    seq: int
    head: str
    checked_at: str
    alarm: dict[str, Any] | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


class Witness:
    def __init__(
        self,
        *,
        lsp_id: str,
        public_key,
        fetch_checkpoint: Callable[[], dict[str, Any]],
        fetch_digests: Callable[[int, int], list[str]],
        state_path: str | Path | None = None,
    ) -> None:
        self._lsp_id = lsp_id
        self._public_key = public_key
        self._fetch_checkpoint = fetch_checkpoint
        self._fetch_digests = fetch_digests
        self._state_path = Path(state_path) if state_path else None
        self._accepted: dict[str, Any] | None = None
        self._alarm: dict[str, Any] | None = None
        self._lock = threading.Lock()
        self._load()
        self.status = self._status(True, "not-polled-yet")

    def _load(self) -> None:
        if self._state_path and self._state_path.exists():
            state = json.loads(self._state_path.read_text(encoding="utf-8"))
            self._accepted, self._alarm = state.get("accepted"), state.get("alarm")

    def _save(self, accepted_now: dict[str, Any] | None = None) -> None:
        if not self._state_path:
            return
        self._state_path.write_text(json.dumps({"accepted": self._accepted, "alarm": self._alarm}, indent=2), encoding="utf-8")
        if accepted_now:
            with self._state_path.with_suffix(".history.jsonl").open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(accepted_now, sort_keys=True) + "\n")

    @property
    def accepted(self) -> dict[str, Any] | None:
        return self._accepted

    def _status(self, ok: bool, reason: str) -> WitnessStatus:
        last = self._accepted or {"seq": 0, "head": GENESIS}
        return WitnessStatus(ok, reason, int(last["seq"]), str(last["head"]), _now(), self._alarm)

    def _raise_alarm(self, reason: str, checkpoint: dict[str, Any] | None = None) -> WitnessStatus:
        self._alarm = {"reason": reason, "at": _now(), "checkpoint": checkpoint}
        self._save()
        self.status = self._status(False, reason)
        return self.status

    def poll(self) -> WitnessStatus:
        with self._lock:
            return self._poll()

    def _poll(self) -> WitnessStatus:
        if self._alarm:
            self.status = self._status(False, self._alarm["reason"])
            return self.status

        try:
            signed = self._fetch_checkpoint()
        except Exception:  # noqa: BLE001 - any failure to answer is the same signal
            self.status = self._status(False, "lsp-unreachable")
            return self.status

        try:
            checkpoint = verify_signed(self._public_key, signed, self._lsp_id)
        except CheckpointError as exc:
            return self._raise_alarm(exc.reason, signed if isinstance(signed, dict) else None)

        last = self._accepted or {"seq": 0, "head": GENESIS, "ts": ""}
        seq, last_seq = int(checkpoint["seq"]), int(last["seq"])
        if seq < last_seq:
            return self._raise_alarm("rollback", checkpoint)
        if str(checkpoint["ts"]) < str(last["ts"]):
            return self._raise_alarm("time-went-backwards", checkpoint)
        if seq == last_seq:
            if checkpoint["head"] != last["head"]:
                return self._raise_alarm("fork", checkpoint)
            self.status = self._status(True, "no-new-entries")
            return self.status

        try:
            digests: list[str] = []
            cursor = last_seq
            while cursor < seq:
                upto = min(seq, cursor + MAX_DIGESTS_PER_FETCH)
                digests.extend(self._fetch_digests(cursor, upto))
                cursor = upto
        except Exception:  # noqa: BLE001
            self.status = self._status(False, "lsp-unreachable")
            return self.status

        if len(digests) != seq - last_seq:
            return self._raise_alarm("digest-count-mismatch", checkpoint)
        if fold(last["head"], digests) != checkpoint["head"]:
            return self._raise_alarm("does-not-extend-witnessed-head", checkpoint)

        self._accepted = checkpoint
        self._save(accepted_now=checkpoint)
        self.status = self._status(True, "verified")
        return self.status


def http_fetchers(lsp_url: str, timeout: float = 10.0):
    import requests

    base = lsp_url.rstrip("/")

    def fetch_checkpoint() -> dict[str, Any]:
        response = requests.get(f"{base}/egress/witness/checkpoint", timeout=timeout)
        response.raise_for_status()
        return response.json()

    def fetch_digests(after: int, upto: int) -> list[str]:
        response = requests.get(f"{base}/egress/witness/digests", params={"after": after, "upto": upto}, timeout=timeout)
        response.raise_for_status()
        return response.json()["digests"]

    return fetch_checkpoint, fetch_digests


def main() -> None:
    parser = argparse.ArgumentParser(description="NBFC witness for a VICT LSP audit log")
    parser.add_argument("--lsp-url", required=True)
    parser.add_argument("--lsp-id", required=True)
    parser.add_argument("--public-key", required=True, type=Path, help="LSP checkpoint public key (PEM)")
    parser.add_argument("--state", required=True, type=Path)
    parser.add_argument("--interval", type=float, default=10.0)
    args = parser.parse_args()

    fetch_checkpoint, fetch_digests = http_fetchers(args.lsp_url)
    witness = Witness(
        lsp_id=args.lsp_id,
        public_key=load_public_key(args.public_key.read_text(encoding="ascii")),
        fetch_checkpoint=fetch_checkpoint,
        fetch_digests=fetch_digests,
        state_path=args.state,
    )
    while True:
        print(json.dumps(asdict(witness.poll())), flush=True)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
