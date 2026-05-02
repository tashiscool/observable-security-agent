from __future__ import annotations

import json
from pathlib import Path

from core.pipeline_models import PipelineSemanticEvent as SemanticEvent
from core.utils import build_asset_evidence, load_evidence_bundle_from_directory
from evals.change_ticket_linkage import eval_change_ticket_linkage


def _base(tmp_path: Path) -> None:
    (tmp_path / "declared_inventory.csv").write_text("asset_id,name\na,prod-api-01\n", encoding="utf-8")
    (tmp_path / "discovered_assets.json").write_text(
        '{"assets":[{"asset_id":"a","name":"prod-api-01"}]}',
        encoding="utf-8",
    )
    (tmp_path / "scanner_findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (tmp_path / "scanner_targets.csv").write_text("asset_id\na\n", encoding="utf-8")
    (tmp_path / "central_log_sources.json").write_text('{"sources":[]}', encoding="utf-8")
    (tmp_path / "alert_rules.json").write_text('{"rules":[]}', encoding="utf-8")
    (tmp_path / "poam.csv").write_text("", encoding="utf-8")


def test_fail_no_ticket_public_admin(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"network.public_admin_port_opened","provider":"aws","asset_id":"a",'
        '"timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"evt-001"}]',
        encoding="utf-8",
    )
    (tmp_path / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-001",
    )
    r = eval_change_ticket_linkage(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "FAIL"
    assert any("evt-001" in e and "network.public_admin_port_opened" in e for e in r.evidence)


def test_partial_ticket_missing_sia_and_test(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"network.public_admin_port_opened","provider":"aws","asset_id":"a",'
        '"timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"evt-001"}]',
        encoding="utf-8",
    )
    (tmp_path / "tickets.json").write_text(
        json.dumps(
            {
                "tickets": [
                    {
                        "id": "SEC-123",
                        "title": "SG change",
                        "status": "open",
                        "links_event_ref": "evt-001",
                        "security_impact_analysis": False,
                        "test_evidence": False,
                        "approval_recorded": True,
                        "has_deployment_evidence": True,
                        "has_verification_evidence": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-001",
    )
    r = eval_change_ticket_linkage(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "PARTIAL"
    assert any("SEC-123" in e and "SIA" in e for e in r.evidence)


def test_pass_complete_ticket(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"network.public_admin_port_opened","provider":"aws","asset_id":"a",'
        '"timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"evt-001"}]',
        encoding="utf-8",
    )
    (tmp_path / "tickets.json").write_text(
        json.dumps(
            {
                "tickets": [
                    {
                        "id": "SEC-999",
                        "title": "SG change",
                        "status": "closed",
                        "links_event_ref": "evt-001",
                        "security_impact_analysis": True,
                        "test_evidence": True,
                        "approval_recorded": True,
                        "has_deployment_evidence": True,
                        "has_verification_evidence": True,
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-001",
    )
    r = eval_change_ticket_linkage(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "PASS"
    assert any("SEC-999" in e for e in r.evidence)


def test_pass_no_risky_semantics_or_high_findings(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"e","provider":"aws","asset_id":"a","timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"r"}]',
        encoding="utf-8",
    )
    (tmp_path / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="e",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r",
    )
    r = eval_change_ticket_linkage(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "PASS"
