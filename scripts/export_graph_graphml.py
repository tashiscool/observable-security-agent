#!/usr/bin/env python3
"""Export ``evidence_graph.json`` (v3 flat nodes/edges) to GraphML for Gephi/yEd."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]


def _safe_id(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]+", "_", s)[:128] or "n"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--input", type=Path, default=_ROOT / "output" / "evidence_graph.json")
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    data = json.loads(Path(args.input).read_text(encoding="utf-8"))
    nodes = data.get("nodes") or []
    edges = data.get("edges") or []

    ns = "http://graphml.graphdrawing.org/xmlns"
    ET.register_namespace("", ns)
    root = ET.Element(f"{{{ns}}}graphml")
    doc = ET.ElementTree(root)

    key_label = ET.SubElement(root, f"{{{ns}}}key")
    key_label.set("id", "label")
    key_label.set("for", "node")
    key_label.set("attr.name", "label")
    key_label.set("attr.type", "string")

    key_ntype = ET.SubElement(root, f"{{{ns}}}key")
    key_ntype.set("id", "node_type")
    key_ntype.set("for", "node")
    key_ntype.set("attr.name", "node_type")
    key_ntype.set("attr.type", "string")

    key_rel = ET.SubElement(root, f"{{{ns}}}key")
    key_rel.set("id", "rel")
    key_rel.set("for", "edge")
    key_rel.set("attr.name", "relationship")
    key_rel.set("attr.type", "string")

    graph_el = ET.SubElement(root, f"{{{ns}}}graph")
    graph_el.set("edgedefault", "directed")

    gk_to_xml: dict[str, str] = {}
    for i, n in enumerate(nodes):
        if not isinstance(n, dict):
            continue
        ntype = str(n.get("type") or "unknown")
        nid = str(n.get("id") or f"_{i}")
        gk = f"{ntype}::{nid}"
        xml_id = f"n{i}"
        gk_to_xml[gk] = xml_id
        node_el = ET.SubElement(graph_el, f"{{{ns}}}node")
        node_el.set("id", xml_id)
        d0 = ET.SubElement(node_el, f"{{{ns}}}data")
        d0.set("key", "label")
        d0.text = gk
        d1 = ET.SubElement(node_el, f"{{{ns}}}data")
        d1.set("key", "node_type")
        d1.text = ntype

    ei = 0
    for e in edges:
        if not isinstance(e, dict):
            continue
        fr = str(e.get("from") or "")
        to = str(e.get("to") or "")
        if fr not in gk_to_xml or to not in gk_to_xml:
            continue
        edge_el = ET.SubElement(graph_el, f"{{{ns}}}edge")
        edge_el.set("id", f"e{ei}")
        edge_el.set("source", gk_to_xml[fr])
        edge_el.set("target", gk_to_xml[to])
        dr = ET.SubElement(edge_el, f"{{{ns}}}data")
        dr.set("key", "rel")
        dr.text = str(e.get("relationship") or "")
        ei += 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    doc.write(args.output, encoding="utf-8", xml_declaration=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
