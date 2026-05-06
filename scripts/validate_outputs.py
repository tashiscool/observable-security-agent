#!/usr/bin/env python3
"""
Fail fast if the build does not produce the complete evidence package.

Checks required artifacts, eval_results.json eval coverage, instrumentation
plan platform coverage, auditor control references, and evidence graph shape.
Demo mode also requires at least one FAIL and generated POA&M row; live mode
allows clean environments.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.output_validation import validate_evidence_package  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description="Validate assessment output directory.")
    p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory containing evidence_graph.json, eval_results.json, etc. (default: output)",
    )
    p.add_argument(
        "--mode",
        choices=["demo", "live"],
        default="demo",
        help="Validation profile: demo preserves fixture expectations; live allows clean environments.",
    )
    args = p.parse_args()
    od: Path = args.output_dir.resolve()
    errors = validate_evidence_package(od, mode=args.mode)
    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        return 1
    print("VALIDATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
