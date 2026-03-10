"""VICT eBPF forensic streaming bootstrap.

Runs lightweight syscall/network probes and forwards events to stdout in JSON,
ready for OTEL/SigNoz ingestion.
"""

from __future__ import annotations

import json
import subprocess
import time
from datetime import datetime, timezone

BPFTRACE_PROGRAM = r'''
tracepoint:syscalls:sys_enter_openat
{
  printf("openat pid=%d comm=%s file=%s\n", pid, comm, str(args->filename));
}

tracepoint:syscalls:sys_enter_connect
{
  printf("connect pid=%d comm=%s\n", pid, comm);
}
'''


def stream_forensic_events() -> None:
    proc = subprocess.Popen(
        ["bpftrace", "-e", BPFTRACE_PROGRAM],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    assert proc.stdout is not None
    for line in proc.stdout:
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source": "ebpf",
            "event": line.strip(),
            "compliance_tag": "dpdp-72h-forensics",
        }
        print(json.dumps(event), flush=True)


def main() -> None:
    while True:
        try:
            stream_forensic_events()
        except Exception as exc:  # noqa: BLE001
            # Keep monitor alive for long-running hosts.
            print(json.dumps({"source": "ebpf", "error": str(exc)}), flush=True)
            time.sleep(2)


if __name__ == "__main__":
    main()
