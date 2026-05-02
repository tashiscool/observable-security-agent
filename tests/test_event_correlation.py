from __future__ import annotations

import json
from pathlib import Path

from core.pipeline_models import PipelineSemanticEvent as SemanticEvent
from core.utils import build_asset_evidence, load_evidence_bundle_from_directory
from evals.event_correlation import eval_event_correlation


def _base(tmp_path: Path) -> None:
    (tmp_path / "declared_inventory.csv").write_text(
        "asset_id,name,scanner_required,log_required\na,node-a,true,true\n",
        encoding="utf-8",
    )
    (tmp_path / "discovered_assets.json").write_text('{"assets":[{"asset_id":"a"}]}', encoding="utf-8")
    (tmp_path / "scanner_findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (tmp_path / "scanner_targets.csv").write_text("asset_id\na\n", encoding="utf-8")
    (tmp_path / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")
    (tmp_path / "poam.csv").write_text("", encoding="utf-8")


def test_event_correlation_pass_no_risky_semantics(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"unknown.custom","provider":"aws","asset_id":"a","timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"r"}]',
        encoding="utf-8",
    )
    (tmp_path / "central_log_sources.json").write_text(
        '{"sources":[{"asset_id":"a","seen_last_24h":true,"local_only":false}]}',
        encoding="utf-8",
    )
    (tmp_path / "alert_rules.json").write_text(
        '{"platform":"splunk","rules":[{"rule_id":"r1","name":"x","enabled":true,"mapped_semantic_types":["unknown.custom"],"recipients":["soc@example.com"]}]}',
        encoding="utf-8",
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="unknown.custom",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r",
    )
    ae = build_asset_evidence(b, "a")
    r = eval_event_correlation(b, sem, ae)
    assert r.result.value == "PASS"
    out = tmp_path / "output" / "correlations.json"
    assert out.is_file()
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["eval_id"] == "CROSS_DOMAIN_EVENT_CORRELATION"
    assert data["correlations"] == []


def test_fail_public_admin_missing_ticket_log_alert(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"network.public_admin_port_opened","provider":"aws","asset_id":"a","timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"evt-pub"}]',
        encoding="utf-8",
    )
    (tmp_path / "central_log_sources.json").write_text(
        '{"sources":[{"asset_id":"a","seen_last_24h":false,"local_only":true}]}',
        encoding="utf-8",
    )
    (tmp_path / "alert_rules.json").write_text('{"platform":"splunk","rules":[]}', encoding="utf-8")
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-pub",
    )
    r = eval_event_correlation(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "FAIL"
    assert any("linked_ticket=false" in e for e in r.evidence)
    data = json.loads((tmp_path / "output" / "correlations.json").read_text(encoding="utf-8"))
    row = data["correlations"][0]
    assert row["alert_rule_enabled"] is False
    assert row["central_logging_active"] is False
    assert row["linked_ticket_id"] is None


def test_partial_identity_admin_alert_no_ticket(tmp_path: Path) -> None:
    _base(tmp_path)
    (tmp_path / "cloud_events.json").write_text(
        '[{"event_type":"identity.admin_role_granted","provider":"aws","asset_id":"a","actor":"alice","timestamp":"2026-05-01T12:00:00Z","raw_event_ref":"evt-iam"}]',
        encoding="utf-8",
    )
    (tmp_path / "central_log_sources.json").write_text(
        '{"sources":[{"asset_id":"a","seen_last_24h":true,"local_only":false}]}',
        encoding="utf-8",
    )
    (tmp_path / "alert_rules.json").write_text(
        json.dumps(
            {
                "platform": "splunk",
                "rules": [
                    {
                        "rule_id": "iam-1",
                        "name": "Admin attach",
                        "enabled": True,
                        "mapped_semantic_types": ["identity.admin_role_granted"],
                        "recipients": ["soc@example.com"],
                        "sample_alert_ref": "splunk://saved/alert/iam",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="identity.admin_role_granted",
        provider="aws",
        asset_id="a",
        actor="alice",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="evt-iam",
    )
    r = eval_event_correlation(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "PARTIAL"
    assert "ticket" in (r.gap or "").lower()
