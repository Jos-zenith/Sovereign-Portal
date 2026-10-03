"""VICT egress proxy: a CONNECT-only forward proxy gated by consent tokens.

Every tunnel needs a fresh, single-use consent token naming the destination
host. The proxy never terminates TLS, so client certificates and signed
payloads pass through untouched and it cannot read what is sent.

The token is checked once, when the tunnel opens; after that the proxy sees
only encrypted bytes. Short-lived tokens, a small cap on tunnels per token,
and closing each tunnel when its token expires keep a pooled connection from
carrying another borrower's traffic under an old consent. The cap is not 1
because upstreams that close the connection after each response need a new
tunnel per request; each new tunnel re-checks consent.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import time
from typing import Callable

from src.egress import tokens
from src.egress.audit import AuditLog
from src.egress.consent import ConsentStore

MAX_HEADER_BYTES = 8192
HEADER_TIMEOUT_SECONDS = 10

Resolver = Callable[[str, int], tuple[str, int]]


class _Rejected(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason


def _parse_target(target: str) -> tuple[str, int]:
    host, sep, port = target.rpartition(":")
    if not sep or not port.isdigit():
        raise _Rejected(400, "bad-target")
    host = host.strip("[]").lower()
    if not host:
        raise _Rejected(400, "bad-target")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return host, int(port)
    raise _Rejected(403, "raw-ip-target")


def _extract_token(headers: dict[str, str]) -> str:
    value = headers.get("proxy-authorization", "")
    scheme, _, credentials = value.partition(" ")
    if scheme.lower() == "bearer" and credentials:
        return credentials.strip()
    if scheme.lower() == "basic" and credentials:
        try:
            decoded = base64.b64decode(credentials.strip()).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            raise _Rejected(407, "token-malformed") from None
        _, _, password = decoded.partition(":")
        if password:
            return password
    raise _Rejected(407, "token-missing")


class EgressProxy:
    def __init__(
        self,
        *,
        key: bytes,
        store: ConsentStore,
        policy,
        audit: AuditLog,
        resolver: Resolver | None = None,
        connect_timeout: float = 5.0,
        max_tunnels_per_token: int = 4,
    ) -> None:
        self._key = key
        self._store = store
        self._policy = policy
        self._audit = audit
        self._resolve = resolver or (lambda host, port: (host, port))
        self._connect_timeout = connect_timeout
        self._max_tunnels = max_tunnels_per_token
        self._token_uses: dict[str, tuple[int, float]] = {}
        self._server: asyncio.base_events.Server | None = None

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        self._server = await asyncio.start_server(self._handle, host, port, limit=MAX_HEADER_BYTES)
        bound = self._server.sockets[0].getsockname()
        return bound[0], bound[1]

    async def stop(self, grace_seconds: float = 2.0) -> None:
        if self._server is not None:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), grace_seconds)
            except asyncio.TimeoutError:
                pass

    def _claim_token(self, token: tokens.ConsentToken) -> None:
        now = time.time()
        self._token_uses = {jti: use for jti, use in self._token_uses.items() if use[1] > now}
        uses, _ = self._token_uses.get(token.token_id, (0, token.expires_at))
        if uses >= self._max_tunnels:
            raise _Rejected(403, "token-tunnel-limit")
        self._token_uses[token.token_id] = (uses + 1, token.expires_at)

    async def _read_request(self, reader: asyncio.StreamReader) -> tuple[str, str, dict[str, str]]:
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), HEADER_TIMEOUT_SECONDS)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            raise _Rejected(400, "bad-request") from None
        lines = raw.decode("latin-1").split("\r\n")
        parts = lines[0].split()
        if len(parts) != 3:
            raise _Rejected(400, "bad-request")
        headers = {}
        for line in lines[1:]:
            name, sep, value = line.partition(":")
            if sep:
                headers[name.strip().lower()] = value.strip()
        return parts[0].upper(), parts[1], headers

    async def _authorise(self, method: str, target: str, headers: dict[str, str]) -> tuple[tokens.ConsentToken, str, int]:
        if method != "CONNECT":
            raise _Rejected(405, "method-not-allowed")
        host, port = _parse_target(target)
        raw_token = _extract_token(headers)
        try:
            token = tokens.verify(self._key, raw_token)
        except tokens.TokenError as exc:
            raise _Rejected(403, exc.reason) from None
        self._claim_token(token)

        consent = await asyncio.to_thread(self._store.check, token.lsp_id, token.principal_id, token.purpose)
        request = {
            "host": host,
            "port": port,
            "token": {"lsp": token.lsp_id, "purpose": token.purpose, "hosts": list(token.hosts)},
            "consent": {"valid": consent.valid, "reason": consent.reason},
        }
        decision = await asyncio.to_thread(self._policy.decide, request)
        if not decision.allowed:
            raise _Rejected(403, decision.reason)
        return token, host, port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        target = ""
        token = None
        try:
            method, target, headers = await self._read_request(reader)
            token, host, port = await self._authorise(method, target, headers)
            upstream_host, upstream_port = self._resolve(host, port)
            try:
                up_reader, up_writer = await asyncio.wait_for(
                    asyncio.open_connection(upstream_host, upstream_port), self._connect_timeout
                )
            except (OSError, asyncio.TimeoutError):
                raise _Rejected(502, "upstream-unreachable") from None
        except Exception as exc:
            rejected = exc if isinstance(exc, _Rejected) else _Rejected(500, "proxy-error")
            self._audit.append(
                "egress-blocked",
                target=target,
                reason=rejected.reason,
                status=rejected.status,
                **_token_fields(token),
            )
            await _respond(writer, rejected.status, rejected.reason)
            return

        peer = up_writer.get_extra_info("peername") or ("", 0)
        self._audit.append(
            "egress-allowed", target=target, resolved_ip=peer[0], reason="allowed", **_token_fields(token)
        )
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        await self._relay(reader, writer, up_reader, up_writer, token, target)

    async def _relay(self, reader, writer, up_reader, up_writer, token: tokens.ConsentToken, target: str) -> None:
        counts = {"sent": 0, "received": 0}

        async def pump(src: asyncio.StreamReader, dst: asyncio.StreamWriter, field: str) -> None:
            try:
                while chunk := await src.read(65536):
                    dst.write(chunk)
                    await dst.drain()
                    counts[field] += len(chunk)
            except (ConnectionError, OSError):
                pass
            finally:
                try:
                    if dst.can_write_eof():
                        dst.write_eof()
                except (OSError, RuntimeError):
                    pass

        tasks = [
            asyncio.create_task(pump(reader, up_writer, "sent")),
            asyncio.create_task(pump(up_reader, writer, "received")),
        ]
        _, pending = await asyncio.wait(tasks, timeout=max(0.0, token.expires_at - time.time()))
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (up_writer, writer):
            stream.close()
        self._audit.append(
            "tunnel-closed",
            target=target,
            reason="token-expired" if pending else "closed",
            bytes_sent=counts["sent"],
            bytes_received=counts["received"],
            **_token_fields(token),
        )


def _token_fields(token: tokens.ConsentToken | None) -> dict[str, str]:
    if token is None:
        return {}
    return {"lsp_id": token.lsp_id, "principal_id": token.principal_id, "purpose": token.purpose}


async def _respond(writer: asyncio.StreamWriter, status: int, reason: str) -> None:
    # Clients surface the status line but drop headers of a failed CONNECT,
    # so the reason rides in the reason phrase as well.
    lines = [f"HTTP/1.1 {status} Blocked: {reason}", f"X-Vict-Reason: {reason}", "Content-Length: 0", "Connection: close"]
    if status == 407:
        lines.append('Proxy-Authenticate: Basic realm="vict"')
    try:
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()
