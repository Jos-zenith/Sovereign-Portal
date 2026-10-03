"""Hash-chained audit log with checkpoints for external witnessing.

A hash chain on its own only proves the log is self-consistent: whoever holds
the file can rewrite an entry and rehash everything after it. It becomes
evidence once checkpoints (sequence number + head hash) are held by a party
the LSP does not control, such as its NBFC partner.

Each link is sha256(previous head || record digest). A witness can therefore
check that a new head extends the one it already holds from the record
digests alone, without seeing any record contents.

A record counts only once its line, newline included, is on disk. A failed
write is rolled back, and a fragment left by a crash is moved aside on open
and the recovery logged, so the chain never continues from half a record.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

GENESIS = "0" * 64


def _canonical(record: dict[str, Any]) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_digest(record: dict[str, Any]) -> str:
    body = {k: v for k, v in record.items() if k not in ("hash", "prev")}
    return hashlib.sha256(_canonical(body)).hexdigest()


def link(prev: str, digest: str) -> str:
    return hashlib.sha256(bytes.fromhex(prev) + bytes.fromhex(digest)).hexdigest()


def fold(head: str, digests: Iterable[str]) -> str:
    for digest in digests:
        head = link(head, digest)
    return head


@dataclass(frozen=True)
class ChainCheck:
    ok: bool
    records: int
    first_bad_seq: int | None = None
    reason: str = ""


def _write_all(fh, data: bytes) -> None:
    view = memoryview(data)
    while view:
        view = view[fh.write(view):]


class AuditLog:
    def __init__(self, path: str | Path) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        self._seq, self._head = self._load_tail()

    def _load_tail(self) -> tuple[int, str]:
        fragment = _quarantine_fragment(self._path)
        last = _last_line(self._path)
        seq, head = 0, GENESIS
        if last is not None:
            record = json.loads(last)
            seq, head = int(record["seq"]), str(record["hash"])
        if fragment is not None:
            self._seq, self._head = seq, head
            record = self._append_unlocked("audit-recovered", reason="incomplete-record-quarantined", **fragment)
            seq, head = record["seq"], record["hash"]
        return seq, head

    @property
    def path(self) -> Path:
        return self._path

    def reload(self) -> None:
        """Re-read the head from disk after the file was rewritten outside this object."""
        with self._lock:
            self._seq, self._head = self._load_tail()

    def append(self, event: str, **fields: Any) -> dict[str, Any]:
        # The lock covers numbering, hashing and the write, so the chain stays
        # strictly sequential whichever thread runs the append.
        with self._lock:
            return self._append_unlocked(event, **fields)

    def _append_unlocked(self, event: str, **fields: Any) -> dict[str, Any]:
        record: dict[str, Any] = {
            **fields,
            "seq": self._seq + 1,
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "prev": self._head,
        }
        record["hash"] = link(self._head, content_digest(record))
        with self._path.open("ab", buffering=0) as fh:
            start = fh.seek(0, os.SEEK_END)
            try:
                _write_all(fh, _canonical(record) + b"\n")
            except BaseException:
                # Disk full or similar: take back any partial line so the next
                # record starts on a clean line. The caller sees the error.
                try:
                    fh.truncate(start)
                except OSError:
                    pass
                raise
        self._seq, self._head = record["seq"], record["hash"]
        return record

    def checkpoint(self) -> dict[str, Any]:
        """The current head, to be signed and handed to an external witness."""
        with self._lock:
            return {"seq": self._seq, "head": self._head, "ts": datetime.now(timezone.utc).isoformat()}


def _complete_lines(fh):
    """Lines that end in a newline. A trailing line without one is a record still being written."""
    for line in fh:
        if not line.endswith(b"\n"):
            return
        if line.strip():
            yield line


def read_records(path: str | Path) -> list[dict[str, Any]]:
    path = Path(path)
    if not path.exists():
        return []
    with path.open("rb") as fh:
        return [json.loads(line) for line in _complete_lines(fh)]


def _quarantine_fragment(path: Path) -> dict[str, Any] | None:
    """Move a trailing fragment with no newline (a crash mid-write) into <log>.quarantine.

    Such a record was never acknowledged: the append that wrote it did not
    return, so no tunnel opened on it. Its bytes are kept, not discarded.
    """
    if not path.exists():
        return None
    with path.open("rb+") as fh:
        end = fh.seek(0, os.SEEK_END)
        if end == 0:
            return None
        fh.seek(end - 1)
        if fh.read(1) == b"\n":
            return None
        pos = end
        while pos > 0:
            step = min(4096, pos)
            pos -= step
            fh.seek(pos)
            newline = fh.read(step).rfind(b"\n")
            if newline != -1:
                pos += newline + 1
                break
        fh.seek(pos)
        fragment = fh.read()
        with path.with_name(path.name + ".quarantine").open("ab") as quarantine:
            quarantine.write(fragment + b"\n")
        fh.truncate(pos)
    return {"fragment_bytes": len(fragment), "fragment_sha256": hashlib.sha256(fragment).hexdigest()}


def rechain(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Renumber and rehash records into a self-consistent chain."""
    head = GENESIS
    for seq, record in enumerate(records, start=1):
        record["seq"] = seq
        record["prev"] = head
        record["hash"] = head = link(head, content_digest(record))
    return records


def _last_line(path: Path, block: int = 4096) -> bytes | None:
    """The last non-blank line, read backwards from the end of the file."""
    if not path.exists():
        return None
    with path.open("rb") as fh:
        pos = fh.seek(0, os.SEEK_END)
        tail = b""
        while pos > 0:
            step = min(block, pos)
            pos -= step
            fh.seek(pos)
            tail = fh.read(step) + tail
            stripped = tail.rstrip()
            if b"\n" in stripped:
                return stripped.rsplit(b"\n", 1)[1]
        return tail.strip() or None


def _seek_seq(fh, target_seq: int, size: int) -> None:
    """Position fh at the first record with seq >= target_seq, by bisecting byte offsets.

    Relies on seq rising through the file. A log where it doesn't is already
    tampered with, and the witness catches it: wrong digests cannot fold to a
    signed head.
    """
    lo, hi = 0, size
    while lo < hi:
        mid = (lo + hi) // 2
        fh.seek(max(0, mid - 1))
        if mid:
            fh.readline()
        start = fh.tell()
        line = fh.readline()
        if line.endswith(b"\n") and (not line.strip() or json.loads(line)["seq"] < target_seq):
            lo = start + len(line)
        else:
            hi = mid
    fh.seek(lo)


def digest_range(path: str | Path, after_seq: int, upto_seq: int) -> list[str]:
    """Record digests for seq in (after_seq, upto_seq]: what a witness needs, and nothing else.

    Seeks to after_seq instead of reading from the start, so a poll costs the
    same on a log of millions of records as on a fresh one.
    """
    path = Path(path)
    if upto_seq <= after_seq or not path.exists():
        return []
    digests = []
    with path.open("rb") as fh:
        _seek_seq(fh, after_seq + 1, fh.seek(0, os.SEEK_END))
        for line in _complete_lines(fh):
            record = json.loads(line)
            if record["seq"] > after_seq:
                digests.append(content_digest(record))
            if record["seq"] >= upto_seq:
                break
    return digests


def verify_chain(path: str | Path) -> ChainCheck:
    prev = GENESIS
    records = read_records(path)
    for expected_seq, record in enumerate(records, start=1):
        if record.get("seq") != expected_seq:
            return ChainCheck(False, len(records), record.get("seq"), "sequence-gap")
        if record.get("prev") != prev:
            return ChainCheck(False, len(records), expected_seq, "prev-mismatch")
        if record.get("hash") != link(prev, content_digest(record)):
            return ChainCheck(False, len(records), expected_seq, "hash-mismatch")
        prev = record["hash"]
    return ChainCheck(True, len(records))


def verify_checkpoint(path: str | Path, checkpoint: dict[str, Any]) -> ChainCheck:
    """Audit-time check: the chain is intact and still holds the witnessed head."""
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
