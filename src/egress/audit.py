"""Hash-chained audit log with checkpoints for external witnessing.

A hash chain on its own only proves the log is self-consistent: whoever holds
the file can rewrite an entry and rehash everything after it. It becomes
evidence once checkpoints (sequence number + head hash) are handed to a party
the LSP does not control, such as its NBFC partner, who can later check that
the log still contains the head they were given.
"""

from __future__ import annotations

import hashlib
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return hashlib.sha256(_canonical(body)).hexdigest()


@dataclass(frozen=True)
class ChainCheck:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    reason: str = ""


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._seq, self._head = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        if not self._path.exists():
            return 0, GENESIS
        last = None
        with self._path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if last is None:
            return 0, GENESIS
        record = json.loads(last)
        return int(record["seq"]), str(record["hash"])

    @property
    def path(self) -> Path:
        return self._path

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            record: dict[str, Any] = {
                **fields,
                "seq": self._seq + 1,
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "prev": self._head,
            }
            record["hash"] = _digest(record)
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(record).decode("utf-8") + "\n")
            self._seq, self._head = record["seq"], record["hash"]
            return record

    def checkpoint(self) -> dict[str, Any]:
        """The value to push to an external witness."""
        with self._lock:
            return {"seq": self._seq, "head": self._head, "ts": datetime.now(timezone.utc).isoformat()}


def read_records(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open(encoding="utf-8") as fh:
        return [json.loads(line) for line in fh if line.strip()]


def verify_chain(path: str | Path) -> ChainCheck:
    prev = GENESIS
    records = read_records(path)
    for expected_seq, record in enumerate(records, start=1):
        if record.get("seq") != expected_seq:
            return ChainCheck(False, len(records), record.get("seq"), "sequence-gap")
        if record.get("prev") != prev:
            return ChainCheck(False, len(records), expected_seq, "prev-mismatch")
        if record.get("hash") != _digest(record):
            return ChainCheck(False, len(records), expected_seq, "hash-mismatch")
        prev = record["hash"]
    return ChainCheck(True, len(records))


def verify_checkpoint(path: str | Path, checkpoint: dict[str, Any]) -> ChainCheck:
    """Witness-side check: the chain is intact and still holds the witnessed head."""
    chain = verify_chain(path)
    if not chain.ok:
        return chain
    seq = int(checkpoint["seq"])
    if seq == 0:
        return chain
    records = read_records(path)
    if seq > len(records):
        return ChainCheck(False, len(records), seq, "log-truncated")
    if records[seq - 1]["hash"] != checkpoint["head"]:
        return ChainCheck(False, len(records), seq, "history-rewritten")
    return chain
