"""Measure how fast a consent withdrawal stops data flowing, including when parts fail.

Runs the real consent store, authority and egress proxy in one process, with a local
echo server standing in for the vendor. Each trial opens a tunnel, streams data through
it, withdraws consent at a random moment and times how long until the client's
connection dies. Latency runs from the moment the withdrawal is stamped, before the
database commit, to the moment the client sees the connection close.

    python -m demo.revocation_latency            # 50 trials of the normal path
    python -m demo.revocation_latency --json out.json

Scenarios:
  push         withdrawal reaches the proxy through the store's listener
  push-lost    the proxy never hears about it (as across services without a push
               channel); open tunnels end at token expiry, new ones are refused at once
  store-down   the consent store stops answering; new tunnels fail closed, open ones
               end at token expiry, and the withdrawal itself cannot be recorded
"""

from __future__ import annotations

import argparse
import asyncio
import json
import platform
import random
import secrets
import sqlite3
import statistics
import tempfile
import time
from datetime import datetime
from pathlib import Path

from src.egress.audit import AuditLog
from src.egress.consent import ConsentAuthority, ConsentDenied, ConsentStore
from src.egress.policy import LocalPolicy
from src.egress.proxy import EgressProxy

LSP, PURPOSE, HOST = "lsp-demo", "loan-eligibility", "aa.example.in"


async def _echo(reader, writer):
    try:
        while chunk := await reader.read(65536):
            writer.write(chunk)
            await writer.drain()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


class _Switchable(ConsentStore):
    """A consent store that can be made to stop answering."""

    down = False

    def check(self, *args):
        if self.down:
            raise sqlite3.OperationalError("consent store unreachable")
        return super().check(*args)

    def revoke(self, *args):
        if self.down:
            raise sqlite3.OperationalError("consent store unreachable")
        return super().revoke(*args)


class Rig:
    def __init__(self, work: Path, ttl: float, push: bool) -> None:
        self.key = secrets.token_bytes(32)
        self.audit = AuditLog(work / "audit.jsonl")
        self.store = _Switchable(work / "consent.db")
        # Without push, the proxy reads the same database through its own store object,
        # so it never receives the authority's withdrawal callback.
        proxy_store = self.store if push else _Switchable(work / "consent.db")
        self.authority = ConsentAuthority(self.store, self.key, self.audit, ttl_seconds=ttl)
        self.proxy = EgressProxy(key=self.key, store=proxy_store, policy=LocalPolicy([HOST]), audit=self.audit,
                                 resolver=lambda host, port: ("127.0.0.1", self.upstream_port))
        self.proxy_store = proxy_store

    async def start(self) -> None:
        self.upstream = await asyncio.start_server(_echo, "127.0.0.1", 0)
        self.upstream_port = self.upstream.sockets[0].getsockname()[1]
        _, self.port = await self.proxy.start()

    async def stop(self) -> None:
        await self.proxy.stop(0.5)
        self.upstream.close()

    async def connect(self, token: str):
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        writer.write(f"CONNECT {HOST}:443 HTTP/1.1\r\nHost: {HOST}:443\r\nProxy-Authorization: Bearer {token}\r\n\r\n".encode())
        await writer.drain()
        head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1")
        return int(head.split()[1]), head.split("Blocked: ", 1)[-1].split("\r\n", 1)[0], reader, writer


async def _stream_until_closed(reader, writer) -> float:
    try:
        while True:
            writer.write(b"x" * 2048)
            await writer.drain()
            if not await reader.read(65536):
                return time.time()
            await asyncio.sleep(0.005)
    except (ConnectionError, OSError):
        return time.time()


def _epoch(iso: str) -> float:
    return datetime.fromisoformat(iso).timestamp()


async def push(trials: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        rig = Rig(Path(tmp), ttl=60, push=True)
        await rig.start()
        latencies = []
        for i in range(trials):
            borrower = f"borrower-{i:03d}"
            rig.authority.grant(LSP, borrower, PURPOSE)
            token = rig.authority.issue(LSP, borrower, PURPOSE, [HOST])
            status, _, reader, writer = await rig.connect(token)
            assert status == 200, status
            pumping = asyncio.create_task(_stream_until_closed(reader, writer))
            await asyncio.sleep(random.uniform(0.05, 0.3))
            withdrawn = await asyncio.to_thread(rig.authority.withdraw, LSP, borrower, PURPOSE)
            closed_at = await asyncio.wait_for(pumping, 10)
            latencies.append((closed_at - _epoch(withdrawn["revoked_at"])) * 1000)
            writer.close()
        await rig.stop()
    ordered = sorted(latencies)
    return {
        "scenario": "push",
        "trials": trials,
        "p50_ms": round(statistics.median(ordered), 1),
        "p95_ms": round(ordered[max(0, int(len(ordered) * 0.95) - 1)], 1),
        "max_ms": round(ordered[-1], 1),
    }


async def push_lost(trials: int, ttl: float) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        rig = Rig(Path(tmp), ttl=ttl, push=False)
        await rig.start()
        cut_after, refused = [], []
        for i in range(trials):
            borrower = f"borrower-{i:03d}"
            rig.authority.grant(LSP, borrower, PURPOSE)
            token = rig.authority.issue(LSP, borrower, PURPOSE, [HOST])
            issued = time.time()
            status, _, reader, writer = await rig.connect(token)
            assert status == 200, status
            pumping = asyncio.create_task(_stream_until_closed(reader, writer))
            await asyncio.sleep(0.2)
            withdrawn = await asyncio.to_thread(rig.authority.withdraw, LSP, borrower, PURPOSE)
            # A second tunnel with the same, still-unexpired token must be refused at once.
            second, reason, _, w2 = await rig.connect(token)
            refused.append(second == 403 and reason == "consent-withdrawn")
            w2.close()
            closed_at = await asyncio.wait_for(pumping, ttl + 10)
            cut_after.append(closed_at - _epoch(withdrawn["revoked_at"]))
            assert closed_at - issued <= ttl + 1.0
            writer.close()
        await rig.stop()
    return {
        "scenario": "push-lost",
        "trials": trials,
        "token_ttl_s": ttl,
        "open_tunnel_cut_after_s_max": round(max(cut_after), 2),
        "bounded_by_token_ttl": max(cut_after) <= ttl + 1.0,
        "new_tunnels_refused_immediately": all(refused),
    }


async def store_down(ttl: float) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        rig = Rig(Path(tmp), ttl=ttl, push=True)
        await rig.start()
        rig.authority.grant(LSP, "borrower-001", PURPOSE)
        token = rig.authority.issue(LSP, "borrower-001", PURPOSE, [HOST])
        status, _, reader, writer = await rig.connect(token)
        assert status == 200
        issued = time.time()
        pumping = asyncio.create_task(_stream_until_closed(reader, writer))
        await asyncio.sleep(0.2)
        rig.store.down = True

        new_status, new_reason, _, w2 = await rig.connect(token)
        w2.close()
        try:
            rig.authority.issue(LSP, "borrower-001", PURPOSE, [HOST])
            token_refused = False
        except ConsentDenied as denied:
            token_refused = denied.reason == "consent-unavailable"
        try:
            rig.authority.withdraw(LSP, "borrower-001", PURPOSE)
            withdrawal_recorded = True
        except sqlite3.OperationalError:
            withdrawal_recorded = False

        closed_at = await asyncio.wait_for(pumping, ttl + 10)
        writer.close()
        await rig.stop()
    return {
        "scenario": "store-down",
        "token_ttl_s": ttl,
        "new_tunnel": f"{new_status} {new_reason}",
        "new_token_refused": token_refused,
        "withdrawal_recorded": withdrawal_recorded,
        "open_tunnel_lasted_s": round(closed_at - issued, 2),
    }


async def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--trials", type=int, default=50)
    parser.add_argument("--ttl", type=float, default=3.0, help="token lifetime for the failure scenarios")
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    results = {
        "measured_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "machine": f"{platform.system()} {platform.release()}, Python {platform.python_version()}",
        "scenarios": [await push(args.trials), await push_lost(5, args.ttl), await store_down(args.ttl)],
    }
    print(json.dumps(results, indent=2))
    if args.json:
        args.json.write_text(json.dumps(results, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    asyncio.run(main())
