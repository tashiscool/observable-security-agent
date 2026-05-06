from __future__ import annotations

from pathlib import Path

from core.evidence_graph import evidence_graph_from_assessment_bundle
from core.models import Asset, AssessmentBundle, DeclaredInventoryRecord, ScannerTarget
from core.pipeline_models import PipelineSemanticEvent as SemanticEvent
from core.utils import build_asset_evidence, load_evidence_bundle_from_directory
from evals.scanner_scope import eval_ra5_scanner_scope_coverage, eval_scanner_scope


def _bundle(tmp_path: Path) -> None:
    (tmp_path / "declared_inventory.csv").write_text("asset_id\nx\n", encoding="utf-8")
    (tmp_path / "discovered_assets.json").write_text('{"assets":[{"asset_id":"x"}]}', encoding="utf-8")
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"e","provider":"aws","asset_id":"x","timestamp":"2026-01-01T00:00:00Z","raw_event_ref":"r"}]',
        encoding="utf-8",
    )
    (tmp_path / "scanner_findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (tmp_path / "scanner_targets.csv").write_text("asset_id,scanner\nother,nessus\n", encoding="utf-8")
    (tmp_path / "central_log_sources.json").write_text('{"sources":[]}', encoding="utf-8")
    (tmp_path / "alert_rules.json").write_text('{"rules":[]}', encoding="utf-8")
    (tmp_path / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")


def _decl(**kw: object) -> DeclaredInventoryRecord:
    b = dict(
        inventory_id="inv-1",
        name="n1",
        asset_type="compute",
        in_boundary=True,
        scanner_required=True,
        log_required=True,
    )
    b.update(kw)
    return DeclaredInventoryRecord(**b)  # type: ignore[arg-type]


def _asset(**kw: object) -> Asset:
    b = dict(
        asset_id="a1",
        provider="aws",
        asset_type="compute",
        name="a1",
        criticality="high",
        environment="prod",
    )
    b.update(kw)
    return Asset(**b)  # type: ignore[arg-type]


def test_ra5_fail_prod_api_missing_scanner_target() -> None:
    inv = _decl(inventory_id="inv-papi", name="prod-api-01", asset_id="prod-api-01")
    ast = _asset(asset_id="prod-api-01", name="prod-api-01", environment="prod")
    st = ScannerTarget(
        scanner_name="nessus",
        target_id="other-host",
        target_type="host",
        asset_id="other",
        credentialed=True,
    )
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[ast], scanner_targets=[st])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_ra5_scanner_scope_coverage(bundle, graph)
    assert r.result == "FAIL"
    assert any("prod-api-01" in g and "scanner_required=true" in g for g in r.gaps)


def test_ra5_pass_all_required_covered() -> None:
    inv = _decl(inventory_id="inv-papi", name="prod-api-01", asset_id="prod-api-01")
    ast = _asset(asset_id="prod-api-01", name="prod-api-01", environment="prod")
    st = ScannerTarget(
        scanner_name="nessus",
        target_id="prod-api-01",
        target_type="host",
        asset_id="prod-api-01",
        credentialed=True,
    )
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[ast], scanner_targets=[st])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_ra5_scanner_scope_coverage(bundle, graph)
    assert r.result == "PASS"


def test_ra5_partial_stale_scanner_target() -> None:
    st = ScannerTarget(
        scanner_name="nessus",
        target_id="old-api-99",
        target_type="host",
        hostname="ghost.example",
        credentialed=False,
    )
    bundle = AssessmentBundle(scanner_targets=[st], assets=[])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_ra5_scanner_scope_coverage(bundle, graph)
    assert r.result == "PARTIAL"
    assert any("old-api-99" in g and "no matching" in g for g in r.gaps)


def test_ra5_live_assets_without_scanner_export_are_partial() -> None:
    ast = _asset(asset_id="i-live", name="i-live", environment="unknown")
    bundle = AssessmentBundle(assets=[ast], scanner_targets=[], scanner_findings=[])
    graph = evidence_graph_from_assessment_bundle(bundle)

    r = eval_ra5_scanner_scope_coverage(bundle, graph)

    assert r.result == "PARTIAL"
    assert any("scanner target export" in g for g in r.gaps)


def test_scanner_scope_fail_when_asset_not_in_targets(tmp_path: Path) -> None:
    _bundle(tmp_path)
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="t",
        provider="aws",
        asset_id="x",
        timestamp="",
        raw_event_ref="r",
    )
    ae = build_asset_evidence(b, "x")
    r = eval_scanner_scope(b, sem, ae)
    assert r.result.value == "FAIL"
