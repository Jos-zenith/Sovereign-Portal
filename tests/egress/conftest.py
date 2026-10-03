from __future__ import annotations

import asyncio
import datetime as dt
import json
import socket
import socketserver
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

from src.egress.audit import AuditLog, read_records
from src.egress.consent import ConsentAuthority, ConsentStore
from src.egress.policy import LocalPolicy
from src.egress.proxy import EgressProxy

KEY = b"spike-shared-key-authority-and-proxy"
LSP = "lsp-demo"
PURPOSE = "loan-eligibility"
ALLOWED = {"bureau.test", "aa.test"}


class ProxyThread:
    """Runs the asyncio proxy on its own loop so blocking clients can call it."""

    def __init__(self, proxy: EgressProxy) -> None:
        self.proxy = proxy
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self.loop.run_forever, daemon=True)

    def __enter__(self) -> "ProxyThread":
        self.thread.start()
        _, self.port = asyncio.run_coroutine_threadsafe(self.proxy.start(), self.loop).result(5)
        self.url = f"http://127.0.0.1:{self.port}"
        return self

    def __exit__(self, *exc) -> None:
        asyncio.run_coroutine_threadsafe(self.proxy.stop(), self.loop).result(10)
        self.loop.call_soon_threadsafe(self.loop.stop)
        self.thread.join(5)


class _Echo(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        while data := self.request.recv(4096):
            self.request.sendall(data)


@pytest.fixture
def echo_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Echo)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def audit(tmp_path: Path) -> AuditLog:
    return AuditLog(tmp_path / "egress-audit.jsonl")


@pytest.fixture
def store(tmp_path: Path) -> ConsentStore:
    store = ConsentStore(tmp_path / "consent.db")
    store.grant(LSP, "borrower-001", PURPOSE)
    store.grant(LSP, "borrower-002", PURPOSE)
    return store


@pytest.fixture
def authority(store, audit) -> ConsentAuthority:
    return ConsentAuthority(store, KEY, audit, ttl_seconds=60)


def make_proxy(store, audit, upstream_port: int) -> EgressProxy:
    return EgressProxy(
        key=KEY,
        store=store,
        policy=LocalPolicy(ALLOWED),
        audit=audit,
        resolver=lambda host, port: ("127.0.0.1", upstream_port),
    )


@pytest.fixture
def proxy(store, audit, echo_server):
    with ProxyThread(make_proxy(store, audit, echo_server)) as running:
        yield running


def open_tunnel(port: int, target: str, auth: str | None = None, method: str = "CONNECT"):
    """Returns (status, vict reason, socket) for a raw proxy request."""
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    request = f"{method} {target} HTTP/1.1\r\nHost: {target}\r\n"
    if auth:
        request += f"Proxy-Authorization: {auth}\r\n"
    sock.sendall((request + "\r\n").encode())
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    head = data.split(b"\r\n\r\n", 1)[0].decode("latin-1").split("\r\n")
    status = int(head[0].split()[1])
    reason = next((line.split(":", 1)[1].strip() for line in head[1:] if line.lower().startswith("x-vict-reason")), None)
    return status, reason, sock


def wait_for_event(audit: AuditLog, event: str, timeout: float = 3.0) -> dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        matches = [r for r in read_records(audit.path) if r["event"] == event]
        if matches:
            return matches[-1]
        time.sleep(0.05)
    raise AssertionError(f"no {event} event in audit log")


def events(audit: AuditLog, event: str) -> list[dict]:
    return [r for r in read_records(audit.path) if r["event"] == event]


@pytest.fixture
def pki(tmp_path: Path) -> dict[str, Path]:
    """A throwaway CA, a server cert for bureau.test and a client cert, for mTLS tests."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    now = dt.datetime.now(dt.timezone.utc)

    def name(cn: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])

    def write(path: Path, cert, key) -> tuple[Path, Path]:
        cert_path, key_path = path.with_suffix(".crt"), path.with_suffix(".key")
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
            )
        )
        return cert_path, key_path

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(name("vict-test-ca"))
        .issuer_name(name("vict-test-ca"))
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_key, hashes.SHA256())
    )

    def leaf(cn: str, server: bool):
        key = ec.generate_private_key(ec.SECP256R1())
        builder = (
            x509.CertificateBuilder()
            .subject_name(name(cn))
            .issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(minutes=5))
            .not_valid_after(now + dt.timedelta(days=1))
        )
        if server:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(cn)]), critical=False)
        return builder.sign(ca_key, hashes.SHA256()), key

    ca_path = tmp_path / "ca.crt"
    ca_path.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    server_crt, server_key = write(tmp_path / "server", *leaf("bureau.test", True))
    client_crt, client_key = write(tmp_path / "client", *leaf(LSP, False))
    return {
        "ca": ca_path,
        "server_crt": server_crt,
        "server_key": server_key,
        "client_crt": client_crt,
        "client_key": client_key,
    }


class _Bureau(BaseHTTPRequestHandler):
    def do_GET(self) -> None:
        cert = self.connection.getpeercert() or {}
        subject = dict(item[0] for item in cert.get("subject", ()))
        body = json.dumps({"path": self.path, "client_cn": subject.get("commonName")}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args) -> None:
        pass


class _KeepAliveBureau(_Bureau):
    protocol_version = "HTTP/1.1"


def _serve_bureau(pki, handler):
    """An HTTPS server that refuses clients without a certificate from the test CA."""
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(pki["server_crt"], pki["server_key"])
    context.load_verify_locations(pki["ca"])
    context.verify_mode = ssl.CERT_REQUIRED
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server.daemon_threads = True
    server.socket = context.wrap_socket(server.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.fixture(params=["closes-each-response", "keep-alive"])
def mtls_bureau(request, pki):
    server = _serve_bureau(pki, _KeepAliveBureau if request.param == "keep-alive" else _Bureau)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture
def keepalive_bureau(pki):
    server = _serve_bureau(pki, _KeepAliveBureau)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()
