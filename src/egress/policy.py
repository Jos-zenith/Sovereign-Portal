"""Egress policy decisions.

LocalPolicy is the default and needs nothing installed. OpaPolicy asks an OPA
server running compliance/egress_policy.rego; both return the same reasons,
picking the alphabetically first one when several rules fail.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


class LocalPolicy:
    def __init__(self, allowed_hosts: Iterable[str], allowed_ports: Iterable[int] = (443,)) -> None:
        self._hosts = {h.lower() for h in allowed_hosts}
        self._ports = set(allowed_ports)

    def decide(self, request: dict[str, Any]) -> Decision:
        reasons = set()
        if request["host"] not in self._hosts:
            reasons.add("host-not-allow-listed")
        if request["port"] not in self._ports:
            reasons.add("port-not-allowed")
        if request["host"] not in request["token"]["hosts"]:
            reasons.add("host-not-in-token")
        if not request["consent"]["valid"]:
            reasons.add(request["consent"]["reason"])
        if reasons:
            return Decision(False, min(reasons))
        return Decision(True, "allowed")


class OpaPolicy:
    def __init__(self, url: str = "http://127.0.0.1:8181/v1/data/vict/egress/decision", timeout: float = 2.0) -> None:
        self._url = url
        self._timeout = timeout

    def decide(self, request: dict[str, Any]) -> Decision:
        payload = json.dumps({"input": request}).encode("utf-8")
        http_request = urllib.request.Request(
            self._url, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(http_request, timeout=self._timeout) as response:
                result = json.load(response).get("result") or {}
        except (urllib.error.URLError, OSError, ValueError):
            return Decision(False, "policy-unavailable")
        return Decision(bool(result.get("allow", False)), str(result.get("reason", "policy-default-deny")))
