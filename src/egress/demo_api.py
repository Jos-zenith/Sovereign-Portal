"""Browser-facing demo of the egress gate, mounted on the consent gateway.

Everything it reports comes from the real components: the consent authority,
the CONNECT proxy and the hash-chained audit log. Only the upstreams are
stand-ins: every allow-listed host is answered by a local echo server, so no
traffic leaves the machine.
"""

from __future__ import annotations

import asyncio
import json
import os
import secrets
import tempfile
import time
from collections import Counter
from dataclasses import asdict
from datetime import datetime
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from src.egress.audit import AuditLog, digest_range, read_records, rechain, verify_chain
from src.egress.checkpoint import CheckpointSigner, load_public_key
from src.egress.consent import ConsentAuthority, ConsentDenied, ConsentStore
from src.egress.policy import LocalPolicy
from src.egress.proxy import EgressProxy
from src.egress.witness import MAX_DIGESTS_PER_FETCH, Witness

LSP_ID = "lsp-demo"
ALLOWED_HOSTS = ("bureau.example.in", "aa.example.in", "kyc.example.in")
PURPOSES = ("loan-eligibility", "marketing")
BORROWERS = ("borrower-001", "borrower-002")
CALL_TIMEOUT_SECONDS = 5
WITNESS_INTERVAL_SECONDS = 3
STREAM_HOST = "aa.example.in"
STREAM_PURPOSE = "loan-eligibility"
STREAM_SECONDS = 20
STREAM_PAGE_BYTES = 2048
STREAM_PAGE_INTERVAL = 0.3
MAX_STREAMS = 20

router = APIRouter(prefix="/egress", tags=["egress-demo"])


class ConsentChange(BaseModel):
    principal_id: str = Field(..., min_length=3, max_length=64)
    purpose: str = Field(..., min_length=3, max_length=64)


class StreamRequest(BaseModel):
    principal_id: str = Field(..., min_length=3, max_length=64)


class CallRequest(BaseModel):
    principal_id: str = Field(..., min_length=3, max_length=64)
    purpose: str = Field(..., min_length=3, max_length=64)
    token_host: str = Field(..., min_length=3, max_length=253, description="Host the app asks consent for")
    target_host: str = Field(..., min_length=3, max_length=253, description="Host the code actually connects to")
    target_port: int = Field(default=443, ge=1, le=65535)


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while chunk := await reader.read(4096):
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


class DemoEnvironment:
    def __init__(self) -> None:
        base = os.getenv("VICT_EGRESS_DEMO_DIR")
        self.workdir = Path(tempfile.mkdtemp(prefix="vict-egress-demo-", dir=base))
        self.audit = AuditLog(self.workdir / "egress-audit.jsonl")
        self.store = ConsentStore(self.workdir / "egress-consent.db")
        self.key = secrets.token_bytes(32)
        self.authority = ConsentAuthority(self.store, self.key, self.audit, ttl_seconds=60)
        self.authority.grant(LSP_ID, "borrower-001", "loan-eligibility")
        self.signer = CheckpointSigner.generate(LSP_ID)
        self.witness = Witness(
            lsp_id=LSP_ID,
            public_key=load_public_key(self.signer.public_key_pem()),
            fetch_checkpoint=self.signed_checkpoint,
            fetch_digests=lambda after, upto: digest_range(self.audit.path, after, upto),
        )
        self._witness_task: asyncio.Task | None = None
        self.proxy: EgressProxy | None = None
        self.proxy_port = 0
        self._upstream: asyncio.base_events.Server | None = None
        self.streams: dict[str, dict[str, Any]] = {}
        self._stream_tasks: set[asyncio.Task] = set()

    async def start(self) -> None:
        self._upstream = await asyncio.start_server(_echo, "127.0.0.1", 0)
        upstream_port = self._upstream.sockets[0].getsockname()[1]
        self.proxy = EgressProxy(
            key=self.key,
            store=self.store,
            policy=LocalPolicy(ALLOWED_HOSTS),
            audit=self.audit,
            resolver=lambda host, port: ("127.0.0.1", upstream_port),
        )
        _, self.proxy_port = await self.proxy.start()
        self._witness_task = asyncio.create_task(self._run_witness())

    def signed_checkpoint(self) -> dict[str, Any]:
        return self.signer.sign(self.audit.checkpoint())

    async def _run_witness(self) -> None:
        """Stands in for the NBFC's witness, which in production runs on the NBFC's side."""
        while True:
            await asyncio.to_thread(self.witness.poll)
            await asyncio.sleep(WITNESS_INTERVAL_SECONDS)

    def start_stream(self, principal_id: str, token: str) -> str:
        stream_id = secrets.token_hex(6)
        if len(self.streams) >= MAX_STREAMS:
            self.streams.pop(next(iter(self.streams)))
        self.streams[stream_id] = {
            "id": stream_id,
            "principal_id": principal_id,
            "purpose": STREAM_PURPOSE,
            "host": STREAM_HOST,
            "state": "opening",
            "reason": "",
            "pages": 0,
            "started_at": time.time(),
            "ended_at": None,
        }
        task = asyncio.create_task(self._stream(stream_id, token))
        self._stream_tasks.add(task)
        task.add_done_callback(self._stream_tasks.discard)
        return stream_id

    async def _stream(self, stream_id: str, token: str) -> None:
        """Stands in for an AA fetch: pages of a bank statement, echoed back by the stand-in host."""
        stream = self.streams[stream_id]
        writer = None
        try:
            reader, writer = await asyncio.open_connection("127.0.0.1", self.proxy_port)
            target = f"{STREAM_HOST}:443"
            writer.write(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n".encode())
            await writer.drain()
            head = (await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), CALL_TIMEOUT_SECONDS)).decode("latin-1")
            status = int(head.split()[1])
            if status != 200:
                stream.update(state="blocked", reason=head.split("Blocked: ", 1)[-1].split("\r\n", 1)[0])
                return
            stream["state"] = "open"
            deadline = time.monotonic() + STREAM_SECONDS
            while time.monotonic() < deadline:
                writer.write(b"p" * STREAM_PAGE_BYTES)
                await writer.drain()
                received = 0
                while received < STREAM_PAGE_BYTES:
                    chunk = await asyncio.wait_for(reader.read(STREAM_PAGE_BYTES), CALL_TIMEOUT_SECONDS)
                    if not chunk:
                        raise ConnectionResetError
                    received += len(chunk)
                stream["pages"] += 1
                await asyncio.sleep(STREAM_PAGE_INTERVAL)
            stream.update(state="finished", reason="done")
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError, IndexError):
            check = await asyncio.to_thread(self.store.check, LSP_ID, stream["principal_id"], STREAM_PURPOSE)
            stream.update(state="cut", reason=check.reason if not check.valid else "connection-closed")
        finally:
            stream["ended_at"] = time.time()
            if writer is not None:
                writer.close()

    async def stop(self) -> None:
        for task in list(self._stream_tasks):
            task.cancel()
        if self._witness_task is not None:
            self._witness_task.cancel()
        if self.proxy is not None:
            await self.proxy.stop(grace_seconds=0.5)
        if self._upstream is not None:
            self._upstream.close()


_env: DemoEnvironment | None = None
_env_lock = asyncio.Lock()


async def _environment() -> DemoEnvironment:
    global _env
    async with _env_lock:
        if _env is None:
            env = DemoEnvironment()
            await env.start()
            _env = env
        return _env


async def _through_proxy(env: DemoEnvironment, token: str, target: str) -> tuple[int, str]:
    reader, writer = await asyncio.open_connection("127.0.0.1", env.proxy_port)
    try:
        writer.write(
            f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Bearer {token}\r\n\r\n".encode()
        )
        await writer.drain()
        head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
        status = int(head[0].split()[1])
        reason = next((line.split(":", 1)[1].strip() for line in head[1:] if line.lower().startswith("x-vict-reason")), "")
        if status == 200:
            writer.write(b"eligibility-request")
            await writer.drain()
            await reader.read(64)
            reason = "allowed"
        return status, reason
    finally:
        writer.close()


@router.post("/call")
async def call(req: CallRequest) -> dict[str, Any]:
    env = await _environment()
    try:
        token = await asyncio.to_thread(
            env.authority.issue, LSP_ID, req.principal_id, req.purpose, [req.token_host]
        )
    except ConsentDenied as denied:
        return {"allowed": False, "stage": "consent-authority", "reason": denied.reason, "network_call": False}

    target = f"{req.target_host.lower()}:{req.target_port}"
    try:
        status, reason = await asyncio.wait_for(_through_proxy(env, token, target), CALL_TIMEOUT_SECONDS)
    except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, ValueError, IndexError):
        raise HTTPException(status_code=502, detail="egress proxy did not answer") from None
    return {
        "allowed": status == 200,
        "stage": "egress-proxy",
        "status": status,
        "reason": reason,
        "network_call": status == 200,
    }


@router.post("/consent/grant")
async def grant(req: ConsentChange) -> dict[str, str]:
    env = await _environment()
    grant_id = await asyncio.to_thread(env.authority.grant, LSP_ID, req.principal_id, req.purpose)
    return {"status": "granted", "grant_id": grant_id}


@router.post("/consent/revoke")
async def revoke(req: ConsentChange) -> dict[str, Any]:
    env = await _environment()
    withdrawn = await asyncio.to_thread(env.authority.withdraw, LSP_ID, req.principal_id, req.purpose)
    revoked_at = datetime.fromisoformat(withdrawn["revoked_at"]).timestamp()
    return {"status": "revoked", "grant_id": withdrawn["grant_id"], "revoked_at": revoked_at}


@router.post("/stream")
async def start_stream(req: StreamRequest) -> dict[str, Any]:
    """Open a long-lived tunnel, as an AA statement fetch would, so a withdrawal can be seen cutting it."""
    env = await _environment()
    try:
        token = await asyncio.to_thread(env.authority.issue, LSP_ID, req.principal_id, STREAM_PURPOSE, [STREAM_HOST])
    except ConsentDenied as denied:
        return {"id": None, "state": "blocked", "stage": "consent-authority", "reason": denied.reason}
    return {"id": env.start_stream(req.principal_id, token), "state": "opening", "stage": "egress-proxy", "reason": ""}


@router.get("/stream/{stream_id}")
async def stream_status(stream_id: str) -> dict[str, Any]:
    env = await _environment()
    stream = env.streams.get(stream_id)
    if stream is None:
        raise HTTPException(status_code=404, detail="No such stream. The demo may have been reset.")
    return {**stream, "now": time.time()}


def _records(env: DemoEnvironment) -> list[dict[str, Any]]:
    return read_records(env.audit.path) if env.audit.path.exists() else []


@router.get("/state")
async def state() -> dict[str, Any]:
    env = await _environment()
    records = _records(env)
    chain = verify_chain(env.audit.path) if records else None
    events = Counter(r["event"] for r in records)
    blocked = Counter(r["reason"] for r in records if r["event"] in ("egress-blocked", "token-denied"))
    return {
        "lsp_id": LSP_ID,
        "allowed_hosts": list(ALLOWED_HOSTS),
        "borrowers": list(BORROWERS),
        "purposes": list(PURPOSES),
        "consents": await asyncio.to_thread(env.store.entries, LSP_ID),
        "counts": {
            "tokens_issued": events["token-issued"],
            "tunnels_allowed": events["egress-allowed"],
            "blocked_before_network": events["token-denied"],
            "blocked_at_proxy": events["egress-blocked"],
            "blocked_by_reason": dict(blocked.most_common()),
        },
        "chain": asdict(chain) if chain else {"ok": True, "records": 0, "first_bad_seq": None, "reason": ""},
        "head": env.audit.checkpoint(),
        "witness": {**asdict(env.witness.status), "interval_seconds": WITNESS_INTERVAL_SECONDS},
        "checkpoint_public_key": env.signer.public_key_pem(),
    }


@router.get("/audit")
async def audit_log(limit: int = 30) -> dict[str, Any]:
    env = await _environment()
    records = _records(env)
    return {"records": list(reversed(records[-max(1, min(200, limit)):]))}


@router.get("/witness/checkpoint")
async def witness_checkpoint() -> dict[str, Any]:
    """Signed head of the audit log, pulled by the NBFC's witness."""
    env = await _environment()
    return env.signed_checkpoint()


@router.get("/witness/digests")
async def witness_digests(after: int, upto: int) -> dict[str, Any]:
    """Record digests for seq in (after, upto]. No record contents leave the LSP."""
    if after < 0 or upto < after or upto - after > MAX_DIGESTS_PER_FETCH:
        raise HTTPException(status_code=400, detail=f"need 0 <= after <= upto and at most {MAX_DIGESTS_PER_FETCH} digests")
    env = await _environment()
    return {"after": after, "upto": upto, "digests": await asyncio.to_thread(digest_range, env.audit.path, after, upto)}


@router.post("/simulate/rewrite-history")
async def rewrite_history() -> dict[str, Any]:
    """Act as a dishonest LSP: delete the latest blocked call and rebuild the chain."""
    env = await _environment()
    records = _records(env)
    blocked = [i for i, r in enumerate(records) if r["event"] == "egress-blocked"]
    if not blocked:
        raise HTTPException(status_code=409, detail="No blocked call to hide yet. Make one first.")
    removed = records.pop(blocked[-1])
    rechain(records)
    env.audit.path.write_text("".join(json.dumps(r, sort_keys=True, separators=(",", ":")) + "\n" for r in records))
    env.audit.reload()
    return {"removed": removed, "chain_still_verifies": verify_chain(env.audit.path).ok}


@router.post("/reset")
async def reset() -> dict[str, str]:
    global _env
    async with _env_lock:
        if _env is not None:
            try:
                await _env.stop()
            except Exception:  # noqa: BLE001 - a half-dead demo must still reset
                pass
        _env = DemoEnvironment()
        await _env.start()
    return {"status": "reset"}
