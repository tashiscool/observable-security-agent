"""Competition-facing auditability inventory stays tied to implemented assets."""

from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOC = ROOT / "docs" / "competition_auditability_feature_inventory.md"


def _doc_text() -> str:
    assert DOC.is_file()
    return DOC.read_text(encoding="utf-8").lower()


def test_auditability_inventory_mentions_all_reference_projects() -> None:
    text = _doc_text()
    for project in (
        "prowler",
        "cloudsploit",
        "electriceye",
        "aurelian",
        "cloudgraph-cli",
        "fixinventory",
        "cartography",
        "ocsf-schema",
        "nisify",
        "fedramp20xmcp",
        "knox-fedramp-20x-pilot",
        "auditkit",
    ):
        assert project.lower() in text


def test_auditability_inventory_links_reference_and_policy_anchors() -> None:
    text = _doc_text()
    for anchor in (
        "reference_samples/manifest.json",
        "tests/test_reference_samples.py",
        "docs/reference_gap_matrix.md",
        "config/ksi-catalog.yaml",
        "config/3pao-sufficiency-rules.yaml",
        "config/conmon-catalog.yaml",
        "fixtures/assessment_tracker/3pao_spirit_manifest.yaml",
        "fixtures/assessment_tracker/3pao_spirit_batch_*.csv",
    ):
        assert anchor.lower() in text


def test_auditability_inventory_covers_core_competition_capabilities() -> None:
    text = _doc_text()
    for capability in (
        "live and fixture aws evidence ingestion",
        "multi-region aws collection",
        "csv and assessment tracker import",
        "3pao spirit tracker corpus",
        "evidence gap taxonomy",
        "3pao reasonable-test artifact sufficiency",
        "ai reasoning with deterministic fallback",
        "conmon reasonableness catalog",
        "inventory reconciliation",
        "scanner scope coverage",
        "vulnerability scanner imports",
        "exploitation review",
        "centralized log coverage",
        "local-to-central log correlation",
        "alert rule instrumentation",
        "incident and response ticket linkage",
        "change management chain",
        "poa&m and deviation handling",
        "fedramp 20x ksi package generation",
        "human/machine reconciliation",
        "assessor, ao, executive, and web reports",
        "evidence graph and cypher export",
        "bounded autonomous workflow",
        "secret and live artifact guards",
        "buildlab demo/readiness harness",
    ):
        assert capability in text


def test_auditability_inventory_states_reference_samples_are_not_runtime_dependencies() -> None:
    text = _doc_text()
    assert "not runtime dependencies" in text
    assert "runtime code stays independent" in text
    assert "3pao-style reasonableness test" in text
