"""Thin client SDK: one consented session per borrower, purpose and call.

Each session gets its own token and its own connection pool, and is closed on
exit, so a pooled tunnel can never carry a different borrower's request.
"""

from __future__ import annotations

import re
from contextlib import contextmanager
from typing import Any, Iterable, Iterator, Protocol
from urllib.parse import quote, urlsplit, urlunsplit

import requests

_REASON = re.compile(r"Blocked: ([a-z0-9-]+)")


class TokenIssuer(Protocol):
    def issue(self, lsp_id: str, principal_id: str, purpose: str, hosts: Iterable[str]) -> str: ...


class EgressBlocked(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ConsentedSession(requests.Session):
    """A requests session whose proxy refusals surface as EgressBlocked."""

    def request(self, *args: Any, **kwargs: Any) -> requests.Response:
        try:
            return super().request(*args, **kwargs)
        except requests.exceptions.ProxyError as exc:
            match = _REASON.search(str(exc))
            raise EgressBlocked(match.group(1) if match else "proxy-error") from exc


def _proxy_with_token(proxy_url: str, token: str) -> str:
    parts = urlsplit(proxy_url)
    netloc = f"vict:{quote(token, safe='')}@{parts.hostname}:{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


class VictEgress:
    def __init__(self, *, issuer: TokenIssuer, proxy_url: str, lsp_id: str) -> None:
        self._issuer = issuer
        self._proxy_url = proxy_url
        self._lsp_id = lsp_id

    @contextmanager
    def session(self, *, principal_id: str, purpose: str, hosts: Iterable[str]) -> Iterator[ConsentedSession]:
        """Raises ConsentDenied before any network call if consent is not valid."""
        token = self._issuer.issue(self._lsp_id, principal_id, purpose, hosts)
        proxy = _proxy_with_token(self._proxy_url, token)
        session = ConsentedSession()
        session.trust_env = False
        session.proxies = {"https": proxy, "http": proxy}
        try:
            yield session
        finally:
            session.close()
