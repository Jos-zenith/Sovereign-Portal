"""Consent store and token authority for the egress spike.

Consent is keyed on (LSP, principal, purpose) so one fintech's consent can
never authorise another's calls. Reason strings match the consent gateway.

Each grant gets its own grant_id, and tokens carry it. Withdrawal is one-way:
granting again creates a new grant, so tokens minted under the old one stay dead.
"""

from __future__ import annotations

import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable, Iterator

from src.egress import tokens
from src.egress.audit import AuditLog

SCHEMA = """
CREATE TABLE IF NOT EXISTS egress_consent (
  lsp_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  purpose TEXT NOT NULL,
  granted_at TEXT NOT NULL,
  expires_at TEXT,
  revoked_at TEXT,
  grant_id TEXT,
  PRIMARY KEY (lsp_id, principal_id, purpose)
);
"""


@dataclass(frozen=True)
class ConsentCheck:
    valid: bool
    reason: str
    grant_id: str | None = None
    expires_at: float | None = None  # epoch seconds, when the consent itself ends


class ConsentDenied(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


def _now() -> datetime:
    return datetime.now(timezone.utc)


RevokeListener = Callable[[str, str, str], None]


class ConsentStore:
    def __init__(self, path: str | Path) -> None:
        self._path = str(path)
        self._revoke_listeners: list[RevokeListener] = []
        with self._db() as conn:
            conn.executescript(SCHEMA)
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(egress_consent)")}
            if "grant_id" not in columns:
                conn.execute("ALTER TABLE egress_consent ADD COLUMN grant_id TEXT")
                conn.execute("UPDATE egress_consent SET grant_id = lower(hex(randomblob(8))) WHERE grant_id IS NULL")

    def on_revoke(self, listener: RevokeListener) -> None:
        """Call listener(lsp_id, principal_id, purpose) after each revocation is committed."""
        self._revoke_listeners.append(listener)

    @contextmanager
    def _db(self) -> Iterator[sqlite3.Connection]:
        # sqlite3's own context manager commits but never closes, which leaks a
        # handle per call and keeps the file locked on Windows.
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def grant(self, lsp_id: str, principal_id: str, purpose: str, expires_at: datetime | None = None) -> str:
        """Record a new grant and return its grant_id. Any earlier grant for the same purpose is superseded."""
        grant_id = secrets.token_hex(8)
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO egress_consent
                (lsp_id, principal_id, purpose, granted_at, expires_at, revoked_at, grant_id)
                VALUES (?, ?, ?, ?, ?, NULL, ?)
                """,
                (lsp_id, principal_id, purpose, _now().isoformat(), expires_at.isoformat() if expires_at else None, grant_id),
            )
        return grant_id

    def revoke(self, lsp_id: str, principal_id: str, purpose: str) -> dict[str, str | None]:
        """Withdraw the current grant. Returns the grant_id withdrawn and when it was committed."""
        revoked_at = _now().isoformat()
        with self._db() as conn:
            row = conn.execute(
                "SELECT grant_id FROM egress_consent WHERE lsp_id = ? AND principal_id = ? AND purpose = ? AND revoked_at IS NULL",
                (lsp_id, principal_id, purpose),
            ).fetchone()
            conn.execute(
                """
                UPDATE egress_consent SET revoked_at = ?
                WHERE lsp_id = ? AND principal_id = ? AND purpose = ? AND revoked_at IS NULL
                """,
                (revoked_at, lsp_id, principal_id, purpose),
            )
        for listener in self._revoke_listeners:
            listener(lsp_id, principal_id, purpose)
        return {"grant_id": row["grant_id"] if row else None, "revoked_at": revoked_at}

    def entries(self, lsp_id: str) -> list[dict[str, str | None]]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT principal_id, purpose, grant_id, granted_at, expires_at, revoked_at FROM egress_consent
                WHERE lsp_id = ? ORDER BY principal_id, purpose
                """,
                (lsp_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def check(self, lsp_id: str, principal_id: str, purpose: str) -> ConsentCheck:
        with self._db() as conn:
            row = conn.execute(
                """
                SELECT grant_id, expires_at, revoked_at FROM egress_consent
                WHERE lsp_id = ? AND principal_id = ? AND purpose = ?
                """,
                (lsp_id, principal_id, purpose),
            ).fetchone()

        if row is None:
            return ConsentCheck(False, "consent-record-not-found")
        grant_id = row["grant_id"]
        if row["revoked_at"]:
            return ConsentCheck(False, "consent-withdrawn", grant_id)
        expires = datetime.fromisoformat(row["expires_at"]) if row["expires_at"] else None
        if expires and expires <= _now():
            return ConsentCheck(False, "consent-expired", grant_id)
        return ConsentCheck(True, "consent-valid", grant_id, expires.timestamp() if expires else None)


class ConsentAuthority:
    """Issues a token only when consent is valid at the moment of the call.

    Grants and withdrawals made through it are written to the ledger with their
    grant_id, so every later call can be traced to the grant it ran under.
    """

    def __init__(self, store: ConsentStore, key: bytes, audit: AuditLog, ttl_seconds: float = 60) -> None:
        self._store = store
        self._key = key
        self._audit = audit
        self._ttl = ttl_seconds

    def grant(self, lsp_id: str, principal_id: str, purpose: str, expires_at: datetime | None = None) -> str:
        grant_id = self._store.grant(lsp_id, principal_id, purpose, expires_at)
        self._audit.append(
            "consent-granted",
            lsp_id=lsp_id,
            principal_id=principal_id,
            purpose=purpose,
            grant_id=grant_id,
            expires_at=expires_at.isoformat() if expires_at else None,
            reason="consent-granted",
        )
        return grant_id

    def withdraw(self, lsp_id: str, principal_id: str, purpose: str) -> dict[str, str | None]:
        """Withdraw consent. Open tunnels under it are cut; the ledger records the commit time."""
        withdrawn = self._store.revoke(lsp_id, principal_id, purpose)
        self._audit.append(
            "consent-withdrawn",
            lsp_id=lsp_id,
            principal_id=principal_id,
            purpose=purpose,
            grant_id=withdrawn["grant_id"],
            revoked_at=withdrawn["revoked_at"],
            reason="consent-withdrawn",
        )
        return withdrawn

    def issue(self, lsp_id: str, principal_id: str, purpose: str, hosts: Iterable[str]) -> str:
        hosts = sorted({h.lower() for h in hosts})
        try:
            check = self._store.check(lsp_id, principal_id, purpose)
        except Exception:  # noqa: BLE001 - an unreachable store refuses, on the record
            check = ConsentCheck(False, "consent-unavailable")
        self._audit.append(
            "token-issued" if check.valid else "token-denied",
            lsp_id=lsp_id,
            principal_id=principal_id,
            purpose=purpose,
            hosts=hosts,
            grant_id=check.grant_id,
            reason=check.reason,
        )
        if not check.valid:
            raise ConsentDenied(check.reason)
        return tokens.mint(
            self._key,
            lsp_id=lsp_id,
            principal_id=principal_id,
            purpose=purpose,
            hosts=hosts,
            ttl_seconds=self._ttl,
            grant_id=check.grant_id or "",
        )
