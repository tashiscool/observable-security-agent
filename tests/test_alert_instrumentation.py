from __future__ import annotations

import json

from core.pipeline_models import PipelineSemanticEvent as SemanticEvent
from core.utils import build_asset_evidence, load_evidence_bundle_from_directory
from evals.alert_instrumentation import eval_alert_instrumentation


def _base_files(tmp_path: Path) -> None:
    (tmp_path / "declared_inventory.csv").write_text("asset_id\na\n", encoding="utf-8")
    (tmp_path / "discovered_assets.json").write_text('{"assets":[{"asset_id":"a"}]}', encoding="utf-8")
    (tmp_path / "scanner_findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (tmp_path / "scanner_targets.csv").write_text("asset_id\na\n", encoding="utf-8")
    (tmp_path / "central_log_sources.json").write_text('{"sources":[]}', encoding="utf-8")
    (tmp_path / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")


def _write_cloud_events(tmp_path: Path, events: list[dict]) -> None:
    (tmp_path / "cloud_events.json").write_text(json.dumps(events), encoding="utf-8")


def _write_alert_rules(tmp_path: Path, rules: list[dict]) -> None:
    (tmp_path / "alert_rules.json").write_text(
        json.dumps({"platform": "splunk", "rules": rules}),
        encoding="utf-8",
    )


def test_alert_fail_when_rule_disabled(tmp_path: Path) -> None:
    _base_files(tmp_path)
    _write_cloud_events(
        tmp_path,
        [
            {
                "event_type": "network.public_admin_port_opened",
                "provider": "aws",
                "asset_id": "a",
                "timestamp": "2026-05-01T12:00:00Z",
                "raw_event_ref": "r1",
            }
        ],
    )
    _write_alert_rules(
        tmp_path,
        [
            {
                "rule_id": "r-pub",
                "name": "Public admin (disabled)",
                "enabled": False,
                "matches_event_type": "network.public_admin_port_opened",
                "recipients": ["soc@example.com"],
            }
        ],
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r1",
    )
    ae = build_asset_evidence(b, "a")
    r = eval_alert_instrumentation(b, sem, ae)
    assert r.result.value == "FAIL"


def test_fail_missing_enabled_rule_for_public_admin_port(tmp_path: Path) -> None:
    """Mandatory instrumentation: no enabled rule covering public admin → FAIL."""
    _base_files(tmp_path)
    _write_cloud_events(
        tmp_path,
        [
            {
                "event_type": "network.public_admin_port_opened",
                "provider": "aws",
                "asset_id": "a",
                "timestamp": "2026-05-01T12:00:00Z",
                "raw_event_ref": "r-pub",
            }
        ],
    )
    _write_alert_rules(
        tmp_path,
        [
            {
                "rule_id": "r-audit",
                "name": "Audit disabled",
                "enabled": True,
                "mapped_semantic_types": ["logging.audit_disabled"],
                "recipients": ["soc@example.com"],
                "sample_alert_ref": "splunk://saved/alert/audit",
            }
        ],
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r-pub",
    )
    r = eval_alert_instrumentation(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "FAIL"
    assert any("public_admin_port_opened" in (e or "") for e in r.evidence)


def test_fail_or_partial_high_vulnerability_only_disabled_rule(tmp_path: Path) -> None:
    """High/critical vuln semantic with only a disabled mapped rule → FAIL (no enabled coverage)."""
    _base_files(tmp_path)
    _write_cloud_events(
        tmp_path,
        [
            {
                "event_type": "scanner.high_vulnerability_detected",
                "provider": "aws",
                "asset_id": "a",
                "timestamp": "2026-05-01T12:00:00Z",
                "raw_event_ref": "r-v",
            },
            {
                "event_type": "logging.audit_disabled",
                "provider": "aws",
                "asset_id": "a",
                "timestamp": "2026-05-01T12:01:00Z",
                "raw_event_ref": "r-a",
            },
        ],
    )
    _write_alert_rules(
        tmp_path,
        [
            {
                "rule_id": "r-vuln",
                "name": "High vuln (disabled)",
                "enabled": False,
                "mapped_semantic_types": ["scanner.high_vulnerability_detected"],
                "recipients": ["vuln@example.com"],
            },
            {
                "rule_id": "r-audit",
                "name": "Audit disabled",
                "enabled": True,
                "mapped_semantic_types": ["logging.audit_disabled"],
                "recipients": ["soc@example.com"],
                "sample_alert_ref": "splunk://saved/alert/audit",
            },
            {
                "rule_id": "r-pub",
                "name": "Public admin",
                "enabled": True,
                "mapped_semantic_types": ["network.public_admin_port_opened"],
                "recipients": ["soc@example.com"],
                "sample_alert_ref": "splunk://saved/alert/pub",
            },
        ],
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="scanner.high_vulnerability_detected",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r-v",
    )
    r = eval_alert_instrumentation(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value in ("FAIL", "PARTIAL")


def test_pass_enabled_alert_with_recipients_for_observed_semantic(tmp_path: Path) -> None:
    """Enabled rules with recipients for mandatory + observed semantics; sample ref where events overlap → PASS."""
    _base_files(tmp_path)
    _write_cloud_events(
        tmp_path,
        [
            {
                "event_type": "identity.admin_role_granted",
                "provider": "aws",
                "asset_id": "a",
                "timestamp": "2026-05-01T12:00:00Z",
                "raw_event_ref": "r-adm",
            }
        ],
    )
    _write_alert_rules(
        tmp_path,
        [
            {
                "rule_id": "r-pub",
                "name": "Public admin",
                "enabled": True,
                "mapped_semantic_types": ["network.public_admin_port_opened"],
                "recipients": ["soc@example.com"],
                "sample_alert_ref": "splunk://saved/alert/pub",
            },
            {
                "rule_id": "r-audit",
                "name": "Audit disabled",
                "enabled": True,
                "mapped_semantic_types": ["logging.audit_disabled"],
                "recipients": ["soc@example.com"],
                "sample_alert_ref": "splunk://saved/alert/audit",
            },
            {
                "rule_id": "r-iam",
                "name": "Identity Admin Grant",
                "enabled": True,
                "mapped_semantic_types": ["identity.admin_role_granted"],
                "recipients": ["security@example.com"],
                "sample_alert_ref": "splunk://saved/alert/iam_admin_attach",
            },
        ],
    )
    b = load_evidence_bundle_from_directory(tmp_path)
    sem = SemanticEvent(
        event_type="identity.admin_role_granted",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r-adm",
    )
    r = eval_alert_instrumentation(b, sem, build_asset_evidence(b, "a"))
    assert r.result.value == "PASS"
    assert any("Identity Admin Grant" in e and "identity.admin_role_granted" in e for e in r.evidence)
