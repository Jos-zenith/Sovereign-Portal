"""Consent store and token authority for the egress spike.

Consent is keyed on (LSP, principal, purpose) so one fintech's consent can
never authorise another's calls. Reason strings match the consent gateway.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Iterable

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
  PRIMARY KEY (lsp_id, principal_id, purpose)
);
"""


@dataclass(frozen=True)
class ConsentCheck:
    valid: bool
    reason: str


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

    def on_revoke(self, listener: RevokeListener) -> None:
        """Call listener(lsp_id, principal_id, purpose) after each revocation is committed."""
        self._revoke_listeners.append(listener)

    def _db(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path)
        conn.row_factory = sqlite3.Row
        return conn

    def grant(self, lsp_id: str, principal_id: str, purpose: str, expires_at: datetime | None = None) -> None:
        with self._db() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO egress_consent
                (lsp_id, principal_id, purpose, granted_at, expires_at, revoked_at)
                VALUES (?, ?, ?, ?, ?, NULL)
                """,
                (lsp_id, principal_id, purpose, _now().isoformat(), expires_at.isoformat() if expires_at else None),
            )

    def revoke(self, lsp_id: str, principal_id: str, purpose: str) -> None:
        with self._db() as conn:
            conn.execute(
                """
                UPDATE egress_consent SET revoked_at = ?
                WHERE lsp_id = ? AND principal_id = ? AND purpose = ?
                """,
                (_now().isoformat(), lsp_id, principal_id, purpose),
            )
        for listener in self._revoke_listeners:
            listener(lsp_id, principal_id, purpose)

    def entries(self, lsp_id: str) -> list[dict[str, str | None]]:
        with self._db() as conn:
            rows = conn.execute(
                """
                SELECT principal_id, purpose, granted_at, expires_at, revoked_at FROM egress_consent
                WHERE lsp_id = ? ORDER BY principal_id, purpose
                """,
                (lsp_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def check(self, lsp_id: str, principal_id: str, purpose: str) -> ConsentCheck:
        with self._db() as conn:
            row = conn.execute(
                """
                SELECT expires_at, revoked_at FROM egress_consent
                WHERE lsp_id = ? AND principal_id = ? AND purpose = ?
                """,
                (lsp_id, principal_id, purpose),
            ).fetchone()

        if row is None:
            return ConsentCheck(False, "consent-record-not-found")
        if row["revoked_at"]:
            return ConsentCheck(False, "consent-withdrawn")
        if row["expires_at"] and datetime.fromisoformat(row["expires_at"]) <= _now():
            return ConsentCheck(False, "consent-expired")
        return ConsentCheck(True, "consent-valid")


class ConsentAuthority:
    """Issues a token only when consent is valid at the moment of the call."""

    def __init__(self, store: ConsentStore, key: bytes, audit: AuditLog, ttl_seconds: float = 60) -> None:
        self._store = store
        self._key = key
        self._audit = audit
        self._ttl = ttl_seconds

    def issue(self, lsp_id: str, principal_id: str, purpose: str, hosts: Iterable[str]) -> str:
        hosts = sorted({h.lower() for h in hosts})
        check = self._store.check(lsp_id, principal_id, purpose)
        self._audit.append(
            "token-issued" if check.valid else "token-denied",
            lsp_id=lsp_id,
            principal_id=principal_id,
            purpose=purpose,
            hosts=hosts,
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
        )
