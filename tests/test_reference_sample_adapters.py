"""Prove reference samples inform adapters, policy, graph vocabulary, and FedRAMP 20x docs."""

from __future__ import annotations

import json
import re
from pathlib import Path
import yaml

from core import evidence_graph
from providers.cloudsploit import iter_cloudsploit_records
from providers.ocsf import import_ocsf
from providers.prowler import iter_prowler_records

ROOT = Path(__file__).resolve().parents[1]
RS = ROOT / "reference_samples"
MANIFEST = RS / "manifest.json"
PUBLIC_EXPOSURE_POLICY = ROOT / "config" / "public-exposure-policy.yaml"
ELECTRIC_EYE_CHECKS = RS / "electriceye" / "checks" / "electriceye_secgroup_auditor_config.json"
FEDRAMP_LESSONS = ROOT / "docs" / "fedramp20x_reference_lessons.md"
CARTOGRAPHY_README_EXCERPT = RS / "cartography" / "docs" / "README_excerpt.md"


def test_prowler_reference_scan_sample_parses() -> None:
    path = RS / "prowler" / "outputs" / "scan_result_sample.json"
    assert path.is_file()
    rows = iter_prowler_records(path)
    assert len(rows) >= 1


def test_cloudsploit_reference_scan_sample_parses() -> None:
    path = RS / "cloudsploit" / "outputs" / "scan_result_sample.json"
    assert path.is_file()
    rows = iter_cloudsploit_records(path)
    assert len(rows) >= 1


def test_ocsf_reference_samples_are_json_and_import_adapter_accepts_base_event() -> None:
    for rel in (
        "ocsf/examples/base_event.json",
        "ocsf/schemas/cloud.json",
        "ocsf/schemas/finding.json",
    ):
        p = RS / rel
        assert p.is_file(), rel
        json.loads(p.read_text(encoding="utf-8"))
    base = RS / "ocsf" / "examples" / "base_event.json"
    findings, events = import_ocsf(base)
    assert findings and events


def test_graph_reference_cartography_cypher_rel_traced_to_canonical_rel_constants() -> None:
    """Cartography excerpt uses ``-[:RESOURCE]->``; we model containment/account grouping explicitly."""
    text = CARTOGRAPHY_README_EXCERPT.read_text(encoding="utf-8")
    m = re.search(r"-\[:(\w+)\]->", text)
    assert m, "expected a Cypher relationship in cartography README excerpt"
    rel = m.group(1)
    assert rel == "RESOURCE", rel
    eg = Path(evidence_graph.__file__).read_text(encoding="utf-8")
    for token in ("INVENTORY_DESCRIBES_ASSET", "BELONGS_TO_ACCOUNT"):
        assert token in eg, f"{token} missing from evidence_graph (traceability for {rel} pattern)"


def test_public_exposure_reference_samples_reflected_in_policy() -> None:
    policy_text = PUBLIC_EXPOSURE_POLICY.read_text(encoding="utf-8")
    assert "reference_samples/electriceye/checks/electriceye_secgroup_auditor_config.json" in policy_text
    cfg = json.loads(ELECTRIC_EYE_CHECKS.read_text(encoding="utf-8"))
    assert isinstance(cfg, list) and cfg
    ports = set()
    for row in cfg:
        for key in ("ToPort", "FromPort"):
            v = row.get(key)
            if isinstance(v, int):
                ports.add(v)
            elif isinstance(v, str) and v.isdigit():
                ports.add(int(v))
    covered = {p for p in ports if str(p) in policy_text}
    ratio = len(covered) / max(len(ports), 1)
    assert ratio >= 0.72, (
        "public-exposure-policy should cover most ElectricEye reference rule ports "
        f"({len(covered)}/{len(ports)} = {ratio:.2f}; missing sample {sorted(ports - covered)[:20]})"
    )
    for baseline in (22, 23, 3389, 445):
        assert str(baseline) in policy_text, f"baseline exposure port {baseline} missing from policy YAML"

    data = json.loads(MANIFEST.read_text(encoding="utf-8"))
    aurelian_hits = [
        e for e in data["files"] if e.get("source_project") == "aurelian" and "public" in (e.get("copied_path") or "")
    ]
    assert aurelian_hits, "manifest should list aurelian public-resources recon excerpt"
    excerpt_path = ROOT / aurelian_hits[0]["copied_path"]
    excerpt = excerpt_path.read_text(encoding="utf-8").lower()
    assert "public" in excerpt
    loaded = yaml.safe_load(policy_text)
    services = loaded.get("services") or []
    sem = " ".join(str(s.get("semantic_type", "")) for s in services)
    assert "network.public" in sem


def test_fedramp20x_mcp_and_knox_samples_reflected_in_docs_and_ksi_catalog() -> None:
    doc = FEDRAMP_LESSONS.read_text(encoding="utf-8")
    for frag in (
        "reference_samples/fedramp20xmcp",
        "reference_samples/knox_20x_pilot",
        "ksi_patterns.yaml",
        "ksi-validation-results.json",
        "fedramp20x-package",
        "ksi-catalog.yaml",
    ):
        assert frag in doc, f"expected {frag!r} in fedramp20x_reference_lessons.md"

    ksi = (ROOT / "config" / "ksi-catalog.yaml").read_text(encoding="utf-8")
    assert "ksi_id:" in ksi

    knox_sample = RS / "knox_20x_pilot" / "package_examples" / "ksi-validation-results.json"
    assert knox_sample.is_file()
    sample = json.loads(knox_sample.read_text(encoding="utf-8"))
    assert "summary" in sample or "evidence" in sample
