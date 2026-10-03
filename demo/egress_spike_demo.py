"""Walk through the egress spike end to end and measure proxy overhead.

    python demo/egress_spike_demo.py

Runs entirely on this machine: a fake bureau (TCP echo), the consent
authority, the proxy and the audit log, all in a temporary folder.
"""

from __future__ import annotations

import asyncio
import socket
import socketserver
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.egress.audit import AuditLog, verify_chain, verify_checkpoint  # noqa: E402
from src.egress.consent import ConsentAuthority, ConsentDenied, ConsentStore  # noqa: E402
from src.egress.policy import LocalPolicy  # noqa: E402
from src.egress.proxy import EgressProxy  # noqa: E402

KEY = b"demo-key-held-by-authority-and-proxy-only"
LSP, PURPOSE = "lsp-demo", "loan-eligibility"


class Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while data := self.request.recv(4096):
            self.request.sendall(data)


def tunnel(port: int, target: str, token: str | None) -> tuple[int, str, socket.socket]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    auth = f"Proxy-Authorization: Bearer {token}\r\n" if token else ""
    sock.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n".encode())
    head = b""
    while b"\r\n\r\n" not in head:
        head += sock.recv(4096)
    status_line = head.split(b"\r\n", 1)[0].decode()
    return int(status_line.split()[1]), status_line, sock


def main() -> None:
    workdir = Path(tempfile.mkdtemp(prefix="vict-egress-"))
    audit = AuditLog(workdir / "audit.jsonl")
    store = ConsentStore(workdir / "consent.db")
    store.grant(LSP, "borrower-001", PURPOSE)
    authority = ConsentAuthority(store, KEY, audit, ttl_seconds=60)

    bureau = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
    bureau.daemon_threads = True
    threading.Thread(target=bureau.serve_forever, daemon=True).start()

    proxy = EgressProxy(
        key=KEY,
        store=store,
        policy=LocalPolicy({"bureau.test"}),
        audit=audit,
        resolver=lambda host, port: ("127.0.0.1", bureau.server_address[1]),
        max_tunnels_per_token=1000,
    )
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    _, port = asyncio.run_coroutine_threadsafe(proxy.start(), loop).result(5)

    print(f"Working folder: {workdir}\n")
    print("1. Calls through the proxy")
    token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    for label, target, tok in [
        ("borrower-001 -> bureau.test", "bureau.test:443", token),
        ("no token", "bureau.test:443", None),
        ("token for bureau, sent to US host", "us-analytics.example:443", token),
    ]:
        _, status_line, sock = tunnel(port, target, tok)
        sock.close()
        print(f"   {label:38} {status_line}")

    try:
        authority.issue(LSP, "borrower-404", PURPOSE, ["bureau.test"])
    except ConsentDenied as denied:
        print(f"   {'borrower-404 (never consented)':38} refused before any network call: {denied.reason}")

    store.revoke(LSP, "borrower-001", PURPOSE)
    _, status_line, sock = tunnel(port, "bureau.test:443", token)
    sock.close()
    print(f"   {'borrower-001 after revoking consent':38} {status_line}")
    store.grant(LSP, "borrower-001", PURPOSE)

    print("\n2. Proxy overhead on this machine (100 round trips each)")
    reused_token = authority.issue(LSP, "borrower-001", PURPOSE, ["bureau.test"])
    _, _, kept = tunnel(port, "bureau.test:443", reused_token)
    reused = []
    for _ in range(100):
        start = time.perf_counter()
        kept.sendall(b"x" * 64)
        kept.recv(64)
        reused.append((time.perf_counter() - start) * 1000)
    kept.close()

    fresh = []
    for _ in range(100):
        start = time.perf_counter()
        _, _, sock = tunnel(port, "bureau.test:443", reused_token)
        sock.sendall(b"x" * 64)
        sock.recv(64)
        fresh.append((time.perf_counter() - start) * 1000)
        sock.close()
    print(f"   reused tunnel:            median {statistics.median(reused):.2f} ms")
    print(f"   new tunnel for each call: median {statistics.median(fresh):.2f} ms")
    print("   In production add one TCP + TLS handshake to the bureau per new tunnel.")

    asyncio.run_coroutine_threadsafe(proxy.stop(), loop).result(10)
    loop.call_soon_threadsafe(loop.stop)
    bureau.shutdown()

    print("\n3. Audit evidence")
    checkpoint = audit.checkpoint()
    chain = verify_chain(audit.path)
    print(f"   {chain.records} records, chain intact: {chain.ok}")
    print(f"   checkpoint to send the NBFC: seq={checkpoint['seq']} head={checkpoint['head'][:16]}...")
    print(f"   checkpoint still matches log: {verify_checkpoint(audit.path, checkpoint).ok}")


if __name__ == "__main__":
    main()
