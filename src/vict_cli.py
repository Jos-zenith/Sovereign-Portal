"""VICT CLI: sovereign guardrail commands for developers.

Commands:
- scan: detect non-sovereign PII transfer patterns.
- wrap: build Wasm artifact (or deterministic stub fallback).
- deploy: generate least-privilege policy and region-locked deploy plan.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
from pathlib import Path

ALLOWED_REGION_PREFIXES = ("ap-south-1", "ap-south-2")
NON_INDIA_HOST_HINTS = ("us-", "eu-", "ap-northeast", "global", "west", "east")
PII_HINTS = ("aadhaar", "pan", "phone", "upi", "account", "dob", "address", "email")


def _read(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def scan_file(path: Path) -> int:
    lines = _read(path)
    findings = []
    pii_lines = []
    non_india_endpoint_lines = []

    for idx, line in enumerate(lines, start=1):
        low = line.lower()

        has_http = "http://" in low or "https://" in low
        has_non_india_hint = any(h in low for h in NON_INDIA_HOST_HINTS)
        has_pii_signal = any(p in low for p in PII_HINTS)

        if has_pii_signal:
            pii_lines.append(idx)

        if has_http and has_non_india_hint:
            non_india_endpoint_lines.append(idx)

        if has_http and has_non_india_hint and has_pii_signal:
            findings.append((idx, "PII may be sent to non-India endpoint"))

        if re.search(r"s3:\*|\*\"\s*:\s*\*", line):
            findings.append((idx, "Wildcard IAM access pattern detected"))

    if pii_lines and non_india_endpoint_lines:
        line_hint = non_india_endpoint_lines[0]
        findings.append((line_hint, "PII context combined with non-India endpoint in file"))

    if not findings:
        print(f"[OK] {path}: no sovereignty violations found")
        return 0

    print(f"[WARN] {path}: {len(findings)} issue(s) found")
    for ln, msg in findings:
        print(f"  - Line {ln}: {msg}")
    return 1


def wrap_source(path: Path, out_dir: Path) -> int:
    out_dir.mkdir(parents=True, exist_ok=True)
    out_file = out_dir / f"{path.stem}.wasm"

    if path.suffix == ".go" and shutil.which("tinygo"):
        cmd = ["tinygo", "build", "-o", str(out_file), "-target", "wasi", str(path)]
        subprocess.run(cmd, check=True)
        print(f"[OK] Built Wasm module: {out_file}")
        return 0

    # Python and generic fallback: create deterministic stub for demo workflow.
    stub = {
        "source": str(path),
        "runtime": "wasi",
        "note": "Stub artifact. Replace with real toolchain for production.",
    }
    out_file = out_dir / f"{path.stem}.wasm.stub"
    out_file.write_text(json.dumps(stub, indent=2), encoding="utf-8")
    print(f"[OK] Wrapped as Wasm package stub: {out_file}")
    return 0


def deploy(region: str, workspace: Path) -> int:
    if not region.startswith(ALLOWED_REGION_PREFIXES):
        print("[FAIL] Deployment blocked: region must be ap-south-1 or ap-south-2")
        return 2

    autopilot = workspace / "compliance" / "iam_autopilot.py"
    if autopilot.exists():
        subprocess.run(["python", str(autopilot)], check=False)

    plan = {
        "region": region,
        "policy": "compliance/generated_iam_policy.json",
        "runtime": "wasm",
        "sovereignty": "india-only",
    }
    plan_path = workspace / "dist" / "deploy-plan.json"
    plan_path.parent.mkdir(parents=True, exist_ok=True)
    plan_path.write_text(json.dumps(plan, indent=2), encoding="utf-8")
    print(f"[OK] Deployment plan generated: {plan_path}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vict", description="VICT Sovereign Security CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    scan_p = sub.add_parser("scan", help="Scan source for sovereignty violations")
    scan_p.add_argument("source", type=Path)

    wrap_p = sub.add_parser("wrap", help="Wrap function as Wasm artifact")
    wrap_p.add_argument("source", type=Path)
    wrap_p.add_argument("--out", type=Path, default=Path("dist"))

    dep_p = sub.add_parser("deploy", help="Generate policy-backed sovereign deploy plan")
    dep_p.add_argument("--region", required=True)
    dep_p.add_argument("--workspace", type=Path, default=Path.cwd())

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.cmd == "scan":
        return scan_file(args.source)
    if args.cmd == "wrap":
        return wrap_source(args.source, args.out)
    if args.cmd == "deploy":
        return deploy(args.region, args.workspace)

    parser.print_help()
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
