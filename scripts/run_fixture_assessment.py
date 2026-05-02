#!/usr/bin/env python3
"""Run the bundled demo fixture scenario."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    cmd = [
        sys.executable,
        str(ROOT / "agent.py"),
        "assess",
        "--provider",
        "fixture",
        "--scenario",
        "scenario_public_admin_vuln_event",
    ]
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
