"""Capability-oriented Wasm runner for VICT.

The runner defaults to no network and minimal WASI preopens.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any


@dataclass
class WasmExecResult:
    stdout: str
    stderr: str
    returncode: int


class WasmRunner:
    def execute(
        self,
        wasm_path: str,
        payload: dict[str, Any],
        allow_network: bool,
        wasi_preopens: list[str] | None = None,
    ) -> dict[str, Any]:
        wasm_file = Path(wasm_path)
        if not wasm_file.exists():
            raise FileNotFoundError(f"Wasm module not found: {wasm_path}")

        preopens = wasi_preopens or []
        with NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".json") as temp:
            json.dump(payload, temp)
            payload_file = temp.name

        cmd = ["wasmtime", "run"]
        for directory in preopens:
            cmd.extend(["--dir", directory])

        # Keep deterministic isolation: network is denied unless explicitly requested.
        if not allow_network:
            cmd.extend(["--env", "VICT_NETWORK=deny"])

        cmd.extend([str(wasm_file), payload_file])

        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        parsed = self._parse_output(result)

        if result.returncode != 0:
            raise RuntimeError(
                f"Wasm execution failed (exit={result.returncode}): {result.stderr.strip()}"
            )

        return parsed

    @staticmethod
    def _parse_output(result: WasmExecResult | subprocess.CompletedProcess[str]) -> dict[str, Any]:
        raw = (result.stdout or "").strip()
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"raw": raw}
