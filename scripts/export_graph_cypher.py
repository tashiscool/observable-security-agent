#!/usr/bin/env python3
"""Read ``output/evidence_graph.json`` (v3 flat ``nodes`` / ``edges``) and write Cypher MERGE fragments."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from core.evidence_graph import evidence_graph_dict_to_cypher  # noqa: E402


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument(
        "--input",
        type=Path,
        default=_ROOT / "output" / "evidence_graph.json",
        help="Evidence graph JSON (EvidenceGraph.to_dict v3 shape).",
    )
    p.add_argument("--output", type=Path, help="Write Cypher here (default: stdout).")
    args = p.parse_args()
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    cy = evidence_graph_dict_to_cypher(data)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(cy, encoding="utf-8")
    else:
        sys.stdout.write(cy)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
