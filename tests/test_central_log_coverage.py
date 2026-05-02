from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.evidence_graph import evidence_graph_from_assessment_bundle
from core.models import Asset, AssessmentBundle, DeclaredInventoryRecord, LogSource
from core.pipeline_models import PipelineSemanticEvent as SemanticEvent
from core.utils import build_asset_evidence, load_evidence_bundle_from_directory
from evals.central_log_coverage import eval_au6_au12_central_log_coverage, eval_central_log_coverage


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
        criticality="moderate",
        environment="prod",
    )
    b.update(kw)
    return Asset(**b)  # type: ignore[arg-type]


def _ls(**kw: object) -> LogSource:
    b = dict(
        log_source_id="ls-1",
        asset_id=None,
        source_type="os_auth",
        local_source="/var/log/syslog",
        central_destination="splunk",
        last_seen=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
        status="active",
    )
    b.update(kw)
    return LogSource(**b)  # type: ignore[arg-type]


def test_au6_fail_missing_prod_api_log_source() -> None:
    now = datetime(2026, 5, 1, 15, 0, tzinfo=timezone.utc)
    inv = _decl(inventory_id="inv-papi", name="prod-api-01", asset_id="prod-api-01")
    ast = _asset(asset_id="prod-api-01", name="prod-api-01")
    cp = _ls(
        log_source_id="ls-cp",
        asset_id="org-wide-aws",
        source_type="cloud_control_plane",
        local_source="trail",
        last_seen=now - timedelta(hours=1),
    )
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[ast], log_sources=[cp])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_au6_au12_central_log_coverage(bundle, graph, now=now, hours_threshold=24.0)
    assert r.result == "FAIL"
    assert any("prod-api-01 requires logging" in g for g in r.gaps)


def test_au6_partial_stale_central_log() -> None:
    now = datetime(2026, 5, 1, 15, 0, tzinfo=timezone.utc)
    inv = _decl(inventory_id="inv-a", name="side", asset_id="side", log_required=False)
    ast = _asset(asset_id="side", name="side", criticality="moderate")
    cp = _ls(
        log_source_id="ls-cp",
        asset_id="org-wide-aws",
        source_type="cloud_control_plane",
        last_seen=now - timedelta(hours=1),
    )
    stale = _ls(
        log_source_id="ls-old",
        asset_id="side",
        source_type="network_flow",
        central_destination="splunk",
        last_seen=datetime(2020, 1, 1, tzinfo=timezone.utc),
        status="active",
    )
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[ast], log_sources=[cp, stale])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_au6_au12_central_log_coverage(bundle, graph, now=now, hours_threshold=24.0)
    assert r.result == "PARTIAL"
    assert any("stale" in g.lower() for g in r.gaps)


def test_au6_pass_active_logs() -> None:
    now = datetime(2026, 5, 1, 15, 0, tzinfo=timezone.utc)
    inv = _decl(inventory_id="inv-papi", name="prod-api-01", asset_id="prod-api-01")
    ast = _asset(asset_id="prod-api-01", name="prod-api-01", criticality="moderate")
    cp = _ls(
        log_source_id="ls-cp",
        asset_id="org-wide-aws",
        source_type="cloud_control_plane",
        last_seen=now - timedelta(hours=1),
    )
    asset_ls = _ls(
        log_source_id="ls-api",
        asset_id="prod-api-01",
        source_type="os_auth",
        last_seen=now - timedelta(hours=2),
    )
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[ast], log_sources=[cp, asset_ls])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_au6_au12_central_log_coverage(bundle, graph, now=now, hours_threshold=24.0)
    assert r.result == "PASS"
    assert any("Cloud control plane log source is active." in e for e in r.evidence)


def _write_layout(tmp_path: Path) -> None:
    (tmp_path / "declared_inventory.csv").write_text("asset_id,log_required\na,false\n", encoding="utf-8")
    (tmp_path / "discovered_assets.json").write_text('{"assets":[{"asset_id":"a"}]}', encoding="utf-8")
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"e","provider":"aws","asset_id":"a","timestamp":"2026-01-01T00:00:00Z","raw_event_ref":"r"}]',
        encoding="utf-8",
    )
    (tmp_path / "scanner_findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (tmp_path / "scanner_targets.csv").write_text("asset_id\na\n", encoding="utf-8")
    (tmp_path / "central_log_sources.json").write_text(
        '{"sources":['
        '{"name":"cp","log_source_id":"cp1","asset_id":"org-wide-aws","source_type":"cloud_control_plane",'
        '"central_destination":"splunk","seen_last_24h":true,"local_only":false},'
        '{"name":"lg","log_source_id":"lg1","asset_id":"a","central_destination":"splunk",'
        '"seen_last_24h":true,"local_only":false,"status":"active","sample_local_event_ref":"local://1"}'
        "]}",
        encoding="utf-8",
    )
    (tmp_path / "alert_rules.json").write_text('{"rules":[]}', encoding="utf-8")
    (tmp_path / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")


def test_central_log_partial_sample_local_without_central(tmp_path: Path) -> None:
    _write_layout(tmp_path)
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="e",
        provider="aws",
        asset_id="a",
        timestamp="2026-01-01T00:00:00Z",
        raw_event_ref="r",
    )
    ae = build_asset_evidence(b, "a")
    r = eval_central_log_coverage(b, sem, ae)
    assert r.result.value == "PARTIAL"
