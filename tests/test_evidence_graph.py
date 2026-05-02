"""Tests for :class:`core.evidence_graph.EvidenceGraph` and bundle builder."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.evidence_graph import (
    REL_COVERED_BY_ALERT,
    REL_EVENT_TARGETS_ASSET,
    REL_HAS_FINDING,
    REL_INVENTORY_DESCRIBES_ASSET,
    REL_LINKED_TO_TICKET,
    EvidenceGraph,
    evidence_graph_from_assessment_bundle,
)
from core.models import (
    AlertRule,
    AssessmentBundle,
    Asset,
    DeclaredInventoryRecord,
    EvalResult,
    ScannerFinding,
    ScannerTarget,
    SecurityEvent,
    Ticket,
)


def _asset(**kw: object) -> Asset:
    defaults = dict(
        asset_id="a1",
        provider="aws",
        asset_type="compute",
        name="prod-api",
        criticality="high",
        environment="prod",
    )
    defaults.update(kw)
    return Asset(**defaults)  # type: ignore[arg-type]


def test_inventory_links_to_asset_by_asset_id() -> None:
    inv = DeclaredInventoryRecord(
        inventory_id="inv-1",
        asset_id="prod-api",
        name="ignored-name",
        asset_type="compute",
        in_boundary=True,
        scanner_required=True,
        log_required=True,
    )
    bundle = AssessmentBundle(
        assets=[_asset(asset_id="prod-api", name="prod-api")],
        declared_inventory=[inv],
    )
    g = evidence_graph_from_assessment_bundle(bundle)
    edges = g.find_edges(relationship=REL_INVENTORY_DESCRIBES_ASSET)
    assert len(edges) == 1
    assert edges[0]["data"].get("match") == "asset_id"


def test_inventory_links_by_name_when_asset_id_absent() -> None:
    inv = DeclaredInventoryRecord(
        inventory_id="inv-2",
        asset_id=None,
        name="prod-api",
        asset_type="compute",
        in_boundary=True,
        scanner_required=True,
        log_required=True,
    )
    bundle = AssessmentBundle(
        assets=[_asset(asset_id="x1", name="prod-api")],
        declared_inventory=[inv],
    )
    g = evidence_graph_from_assessment_bundle(bundle)
    assert len(g.find_edges(relationship=REL_INVENTORY_DESCRIBES_ASSET)) == 1
    assert g.find_edges(relationship=REL_INVENTORY_DESCRIBES_ASSET)[0]["data"]["match"] == "name"


def test_scanner_target_no_match_produces_no_edge() -> None:
    st = ScannerTarget(
        scanner_name="nessus",
        target_id="t-orphan",
        target_type="host",
        hostname="nonexistent.example",
        ip=None,
        asset_id=None,
        credentialed=False,
    )
    bundle = AssessmentBundle(assets=[_asset()], scanner_targets=[st])
    g = evidence_graph_from_assessment_bundle(bundle)
    assert g.find_edges(relationship="COVERED_BY_SCANNER_TARGET") == []


def test_event_links_to_asset() -> None:
    ev = SecurityEvent(
        event_id="evt-1",
        provider="aws",
        semantic_type="network.public_admin_port_opened",
        timestamp=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
        asset_id="prod-api",
    )
    bundle = AssessmentBundle(assets=[_asset(asset_id="prod-api", name="prod-api")], events=[ev])
    g = evidence_graph_from_assessment_bundle(bundle)
    e = g.find_edges(relationship=REL_EVENT_TARGETS_ASSET)
    assert len(e) == 1
    assert e[0]["data"].get("match") == "event.asset_id"


def test_alert_rule_covers_semantic_event_type() -> None:
    rule = AlertRule(
        rule_id="r1",
        platform="splunk",
        name="Admin port",
        enabled=True,
        mapped_semantic_types=["network.public_admin_port_opened"],
    )
    bundle = AssessmentBundle(alert_rules=[rule])
    g = evidence_graph_from_assessment_bundle(bundle)
    e = g.find_edges(relationship=REL_COVERED_BY_ALERT)
    assert len(e) == 1
    assert e[0]["to"].endswith("::network.public_admin_port_opened")


def test_ticket_links_finding() -> None:
    f = ScannerFinding(
        finding_id="fid-9",
        scanner_name="nessus",
        asset_id="a1",
        severity="high",
        title="Open port",
        status="open",
        evidence="see scan",
    )
    t = Ticket(
        ticket_id="JIRA-1",
        system="jira",
        title="fix vuln",
        status="open",
        linked_finding_ids=["fid-9"],
        has_security_impact_analysis=True,
        has_testing_evidence=False,
        has_approval=True,
        has_deployment_evidence=False,
        has_verification_evidence=False,
    )
    bundle = AssessmentBundle(scanner_findings=[f], tickets=[t])
    g = evidence_graph_from_assessment_bundle(bundle)
    e = g.find_edges(relationship=REL_LINKED_TO_TICKET)
    assert len(e) == 1


def test_eval_maps_control_and_write_json(tmp_path: Path) -> None:
    evr = EvalResult(
        eval_id="CM8-001",
        name="Inventory",
        result="PASS",
        controls=["CM-8"],
        severity="low",
        summary="ok",
    )
    g = evidence_graph_from_assessment_bundle(AssessmentBundle(), eval_results=[evr])
    path = tmp_path / "evidence_graph.json"
    g.write_json(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["version"] == "3.0"
    assert any(n["id"] == "CM8-001" and n["type"] == "evaluation" for n in data["nodes"])
    assert any(e["relationship"] == "MAPS_TO_CONTROL" for e in data["edges"])


def test_neighbors_filtered() -> None:
    g = EvidenceGraph()
    g.add_node("asset", "a", {})
    g.add_node("asset", "b", {})
    g.add_edge("asset::a", "asset::b", "peer", {})
    g.add_edge("asset::a", "asset::b", "other", {})
    assert set(g.neighbors("asset::a", relationship="peer")) == {"asset::b"}


def test_asset_has_finding_edge_direction() -> None:
    f = ScannerFinding(
        finding_id="f1",
        scanner_name="nessus",
        asset_id="prod-api",
        severity="high",
        title="x",
        status="open",
        evidence="e",
    )
    bundle = AssessmentBundle(assets=[_asset(asset_id="prod-api")], scanner_findings=[f])
    g = evidence_graph_from_assessment_bundle(bundle)
    edges = g.find_edges(relationship=REL_HAS_FINDING)
    assert len(edges) == 1
    assert edges[0]["from"].startswith("asset::")

