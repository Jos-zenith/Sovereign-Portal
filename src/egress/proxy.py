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

Withdrawing consent also closes the tunnels already open under it, so a
revocation takes effect at once rather than when the token expires. A tunnel
also closes when its consent's own expiry arrives, if that is before the
token's. Any close the proxy forces is logged as tunnel-cut.
"""

from __future__ import annotations

import asyncio
import base64
import ipaddress
import time
from dataclasses import dataclass, field
from typing import Callable

from src.egress import tokens
from src.egress.audit import AuditLog
from src.egress.consent import ConsentStore

MAX_HEADER_BYTES = 8192
HEADER_TIMEOUT_SECONDS = 10

Resolver = Callable[[str, int], tuple[str, int]]
TunnelKey = tuple[str, str, str]


class _Rejected(Exception):
    def __init__(self, status: int, reason: str) -> None:
        super().__init__(reason)
        self.status = status
        self.reason = reason
        self.token: tokens.ConsentToken | None = None


@dataclass(eq=False)
class _Tunnel:
    key: TunnelKey
    tasks: list[asyncio.Task] = field(default_factory=list)
    closed_by: str | None = None
    deadline: float = 0.0
    deadline_reason: str = "token-expired"

    def close(self, reason: str) -> None:
        self.closed_by = self.closed_by or reason
        for task in self.tasks:
            task.cancel()


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
        self._tunnels: dict[TunnelKey, set[_Tunnel]] = {}
        self._handlers: set[asyncio.Task] = set()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._server: asyncio.base_events.Server | None = None
        store.on_revoke(self._consent_revoked)

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> tuple[str, int]:
        self._loop = asyncio.get_running_loop()
        self._server = await asyncio.start_server(self._handle, host, port, limit=MAX_HEADER_BYTES)
        bound = self._server.sockets[0].getsockname()
        return bound[0], bound[1]

    async def stop(self, grace_seconds: float = 2.0) -> None:
        deadline = time.monotonic() + grace_seconds
        if self._server is not None:
            self._server.close()
            try:
                await asyncio.wait_for(self._server.wait_closed(), grace_seconds)
            except asyncio.TimeoutError:
                pass
        if self._handlers:
            # Let handlers whose sockets are closed finish writing their last audit record.
            await asyncio.wait(self._handlers, timeout=max(0.0, deadline - time.monotonic()))
        self._loop = None

    def _consent_revoked(self, lsp_id: str, principal_id: str, purpose: str) -> None:
        """Called from whichever thread revoked; the tunnels belong to the proxy's loop."""
        loop = self._loop
        if loop is None:
            return
        try:
            loop.call_soon_threadsafe(self._close_tunnels, (lsp_id, principal_id, purpose), "consent-withdrawn")
        except RuntimeError:  # loop already closed, so no tunnels are left
            pass

    def _close_tunnels(self, key: TunnelKey, reason: str) -> None:
        for tunnel in self._tunnels.get(key, ()):
            tunnel.close(reason)

    def _register(self, token: tokens.ConsentToken) -> _Tunnel:
        tunnel = _Tunnel((token.lsp_id, token.principal_id, token.purpose))
        self._tunnels.setdefault(tunnel.key, set()).add(tunnel)
        return tunnel

    def _forget(self, tunnel: _Tunnel) -> None:
        open_now = self._tunnels.get(tunnel.key, set())
        open_now.discard(tunnel)
        if not open_now:
            self._tunnels.pop(tunnel.key, None)

    async def _log(self, event: str, **fields) -> None:
        # The append writes to disk; keep that off the event loop.
        await asyncio.to_thread(self._audit.append, event, **fields)

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

    async def _authorise(
        self, method: str, target: str, headers: dict[str, str]
    ) -> tuple[tokens.ConsentToken, _Tunnel, str, int]:
        if method != "CONNECT":
            raise _Rejected(405, "method-not-allowed")
        host, port = _parse_target(target)
        raw_token = _extract_token(headers)
        try:
            token = tokens.verify(self._key, raw_token)
        except tokens.TokenError as exc:
            raise _Rejected(403, exc.reason) from None
        # Registered before the consent check, so a revocation that lands
        # between the check and the relay still finds this tunnel.
        tunnel = self._register(token)
        try:
            self._claim_token(token)
            try:
                consent = await asyncio.to_thread(self._store.check, token.lsp_id, token.principal_id, token.purpose)
            except Exception:  # noqa: BLE001 - no answer about consent means no tunnel
                raise _Rejected(503, "consent-unavailable") from None
            if consent.valid and token.grant_id != consent.grant_id:
                # Minted under an earlier grant that was withdrawn; a re-grant doesn't revive it.
                consent = type(consent)(False, "consent-superseded", consent.grant_id)
            tunnel.deadline = token.expires_at
            if consent.expires_at is not None and consent.expires_at < token.expires_at:
                tunnel.deadline, tunnel.deadline_reason = consent.expires_at, "consent-expired"
            request = {
                "host": host,
                "port": port,
                "token": {"lsp": token.lsp_id, "purpose": token.purpose, "hosts": list(token.hosts)},
                "consent": {"valid": consent.valid, "reason": consent.reason},
            }
            decision = await asyncio.to_thread(self._policy.decide, request)
            if not decision.allowed:
                raise _Rejected(403, decision.reason)
        except BaseException as exc:
            self._forget(tunnel)
            if isinstance(exc, _Rejected):
                exc.token = token
            raise
        return token, tunnel, host, port

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        target = ""
        token = None
        tunnel = None
        up_writer = None
        handler = asyncio.current_task()
        self._handlers.add(handler)
        try:
            try:
                method, target, headers = await self._read_request(reader)
                token, tunnel, host, port = await self._authorise(method, target, headers)
                upstream_host, upstream_port = self._resolve(host, port)
                try:
                    up_reader, up_writer = await asyncio.wait_for(
                        asyncio.open_connection(upstream_host, upstream_port), self._connect_timeout
                    )
                except (OSError, asyncio.TimeoutError):
                    raise _Rejected(502, "upstream-unreachable") from None
                if tunnel.closed_by:
                    raise _Rejected(403, tunnel.closed_by)
                peer = up_writer.get_extra_info("peername") or ("", 0)
                # No tunnel opens unless its record is on disk first.
                await self._log(
                    "egress-allowed", target=target, resolved_ip=peer[0], reason="allowed", **_token_fields(token)
                )
            except Exception as exc:
                rejected = exc if isinstance(exc, _Rejected) else _Rejected(500, "proxy-error")
                try:
                    await self._log(
                        "egress-blocked",
                        target=target,
                        reason=rejected.reason,
                        status=rejected.status,
                        **_token_fields(token or rejected.token),
                    )
                finally:
                    await _respond(writer, rejected.status, rejected.reason)
                return

            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()
            await self._relay(reader, writer, up_reader, up_writer, token, tunnel, target)
        finally:
            # Whatever failed, including an audit write, neither socket stays open.
            if tunnel is not None:
                self._forget(tunnel)
            for stream in (up_writer, writer):
                if stream is not None:
                    stream.close()
            self._handlers.discard(handler)

    async def _relay(
        self, reader, writer, up_reader, up_writer, token: tokens.ConsentToken, tunnel: _Tunnel, target: str
    ) -> None:
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
        tunnel.tasks = tasks
        if tunnel.closed_by:  # withdrawn while the 200 was on its way
            tunnel.close(tunnel.closed_by)
        _, pending = await asyncio.wait(tasks, timeout=max(0.0, tunnel.deadline - time.time()))
        for task in pending:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for stream in (up_writer, writer):
            stream.close()
        cut_by = tunnel.closed_by or (tunnel.deadline_reason if pending else None)
        await self._log(
            "tunnel-cut" if cut_by else "tunnel-closed",
            target=target,
            reason=cut_by or "closed",
            bytes_sent=counts["sent"],
            bytes_received=counts["received"],
            **_token_fields(token),
        )


def _token_fields(token: tokens.ConsentToken | None) -> dict[str, str]:
    if token is None:
        return {}
    return {"lsp_id": token.lsp_id, "principal_id": token.principal_id, "purpose": token.purpose, "grant_id": token.grant_id}


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
