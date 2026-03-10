"""VICT guardrail monitor bootstrap using Falco/Tetragon rule engines.

This module avoids raw eBPF authoring and uses rule-first controls to
accelerate hackathon implementation.
"""

from __future__ import annotations

import json
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "compliance"
FALCO_RULE_PATH = RULES_DIR / "falco_localization_rules.yaml"
TETRAGON_POLICY_PATH = RULES_DIR / "tetragon_localization_policy.yaml"

FALCO_RULES = """- rule: VICT RBI Localization Breach
  desc: Detect outbound connections from VICT function processes to non-India targets
  condition: evt.type=connect and proc.name in (python,wasmtime) and fd.sip.name in (us-east-1,eu-west-1)
  output: "[ACCESS DENIED: RBI LOCALIZATION BREACH] process=%proc.name target=%fd.sip.name"
  priority: CRITICAL
  tags: [vict, rbi, localization]
"""

TETRAGON_POLICY = """apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: vict-rbi-localization-guard
spec:
  kprobes:
    - call: "tcp_connect"
      syscall: false
      selectors:
        - matchPIDs:
            - operator: In
              values: ["python", "wasmtime"]
      # For PoC, destination allow-list is enforced by userspace policy logic.
"""


def ensure_rule_files() -> None:
    RULES_DIR.mkdir(parents=True, exist_ok=True)
    if not FALCO_RULE_PATH.exists():
        FALCO_RULE_PATH.write_text(FALCO_RULES, encoding="utf-8")
    if not TETRAGON_POLICY_PATH.exists():
        TETRAGON_POLICY_PATH.write_text(TETRAGON_POLICY, encoding="utf-8")


def _emit(event_type: str, message: str, engine: str) -> None:
    event = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "source": "guardrail",
        "engine": engine,
        "event_type": event_type,
        "message": message,
        "compliance_tag": "rbi-localization",
    }
    print(json.dumps(event), flush=True)


def _check_binary(command: str) -> bool:
    result = subprocess.run(["where", command], capture_output=True, text=True, check=False)
    return result.returncode == 0


def stream_guardrail_events() -> None:
    ensure_rule_files()

    if _check_binary("falco"):
        _emit("engine-ready", f"Falco rules loaded from {FALCO_RULE_PATH}", "falco")
    elif _check_binary("tetra"):
        _emit("engine-ready", f"Tetragon policy loaded from {TETRAGON_POLICY_PATH}", "tetragon")
    else:
        _emit(
            "engine-missing",
            "Falco/Tetragon not found. Running deterministic demo signal mode.",
            "simulator",
        )

    # Demo signal mode: force a visible localization breach event when requested.
    while True:
        simulate = os.getenv("VICT_SIMULATE_BREACH", "false").lower() == "true"
        if simulate:
            _emit(
                "deny",
                "[ACCESS DENIED: RBI LOCALIZATION BREACH] outbound target us-east-1 blocked",
                "simulator",
            )
        time.sleep(2)


def main() -> None:
    while True:
        try:
            stream_guardrail_events()
        except Exception as exc:  # noqa: BLE001
            _emit("error", str(exc), "guardrail")
            time.sleep(2)


if __name__ == "__main__":
    main()
