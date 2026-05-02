#!/usr/bin/env python3
"""Run assessment against an AWS evidence export directory (fixture-compatible layout)."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    p = argparse.ArgumentParser(description="Assess AWS-exported evidence directory")
    p.add_argument("--evidence-dir", required=True, help="Path with declared_inventory.csv, cloud_events.json, …")
    p.add_argument("--output-dir", default=None, help="Output directory (default ./output)")
    args = p.parse_args()
    cmd = [
        sys.executable,
        str(ROOT / "agent.py"),
        "assess",
        "--provider",
        "aws",
        "--evidence-dir",
        args.evidence_dir,
    ]
    if args.output_dir:
        cmd.extend(["--output-dir", args.output_dir])
    return subprocess.call(cmd, cwd=str(ROOT))


if __name__ == "__main__":
    raise SystemExit(main())
