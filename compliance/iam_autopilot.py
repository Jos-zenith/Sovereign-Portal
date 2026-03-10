"""Deterministic least-privilege policy generator scaffold.

Reads a simple service access manifest and emits resource-scoped IAM policy JSON.
"""

from __future__ import annotations

import json
from pathlib import Path

MANIFEST_PATH = Path("compliance/service_access_manifest.json")
OUTPUT_PATH = Path("compliance/generated_iam_policy.json")

ACTION_MAP = {
    "s3.read": ["s3:GetObject"],
    "s3.write": ["s3:PutObject"],
    "dynamodb.read": ["dynamodb:GetItem", "dynamodb:Query"],
    "dynamodb.write": ["dynamodb:PutItem", "dynamodb:UpdateItem"],
    "kms.decrypt": ["kms:Decrypt"],
}


def generate_policy() -> dict:
    data = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    statements = []

    for rule in data.get("access", []):
        actions = []
        for capability in rule.get("capabilities", []):
            actions.extend(ACTION_MAP.get(capability, []))

        if not actions:
            continue

        statements.append(
            {
                "Sid": f"Allow{rule['name'].replace('-', '').title()}",
                "Effect": "Allow",
                "Action": sorted(set(actions)),
                "Resource": rule.get("resources", []),
            }
        )

    return {"Version": "2012-10-17", "Statement": statements}


def main() -> None:
    policy = generate_policy()
    OUTPUT_PATH.write_text(json.dumps(policy, indent=2), encoding="utf-8")
    print(f"Generated {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
