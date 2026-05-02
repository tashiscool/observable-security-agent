"""Tests for canonical `core.models` (provider-neutral schema)."""

from __future__ import annotations

from datetime import date, datetime, timezone

import pytest
from pydantic import ValidationError

from core.models import (
    AlertRule,
    Asset,
    AssessmentBundle,
    DeclaredInventoryRecord,
    EvalResult,
    LogSource,
    PoamItem,
    ScannerFinding,
    ScannerTarget,
    SecurityEvent,
    Ticket,
    assessment_bundle_from_json,
    assessment_bundle_to_json,
    model_from_json,
    model_to_json,
    model_to_python_dict,
)


def test_asset_strict_required_fields() -> None:
    with pytest.raises(ValidationError):
        Asset(provider="aws")  # type: ignore[call-arg]


def test_asset_forbids_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Asset(
            asset_id="a1",
            provider="aws",
            asset_type="compute",
            name="vm",
            criticality="high",
            environment="prod",
            extra_field="no",
        )  # type: ignore[call-arg]


def test_asset_valid_minimal() -> None:
    a = Asset(
        asset_id="a1",
        provider="aws",
        asset_type="compute",
        name="prod-api",
        criticality="high",
        environment="prod",
    )
    assert a.private_ips == []
    assert a.tags == {}


def test_declared_inventory_record() -> None:
    r = DeclaredInventoryRecord(
        inventory_id="inv-1",
        name="auth svc",
        asset_type="compute",
        in_boundary=True,
        scanner_required=True,
        log_required=True,
    )
    assert r.asset_id is None


def test_security_event_semantic_type_literal() -> None:
    ev = SecurityEvent(
        event_id="e1",
        provider="aws",
        semantic_type="network.public_admin_port_opened",
        timestamp=datetime(2026, 5, 1, 12, 0, tzinfo=timezone.utc),
    )
    assert ev.metadata == {}


def test_security_event_rejects_bad_semantic_type() -> None:
    with pytest.raises(ValidationError):
        SecurityEvent(
            event_id="e1",
            provider="aws",
            semantic_type="not.a.valid.type",  # type: ignore[arg-type]
            timestamp=datetime.now(timezone.utc),
        )


def test_scanner_target_credentialed_required() -> None:
    ScannerTarget(
        scanner_name="nessus",
        target_id="t1",
        target_type="host",
        credentialed=True,
    )


def test_scanner_finding() -> None:
    ScannerFinding(
        finding_id="f1",
        scanner_name="nessus",
        severity="high",
        title="Open port",
        status="open",
        evidence="See scan export",
    )


def test_log_source() -> None:
    LogSource(
        log_source_id="ls1",
        source_type="cloud_control_plane",
        status="active",
        central_destination="splunk",
    )


def test_alert_rule() -> None:
    AlertRule(
        rule_id="ar1",
        platform="splunk",
        name="Admin port",
        enabled=True,
        mapped_semantic_types=["network.public_admin_port_opened"],
        recipients=["soc@example.com"],
        controls=["SI-4"],
    )


def test_ticket_change_controls() -> None:
    Ticket(
        ticket_id="JIRA-1",
        system="jira",
        title="Change",
        status="Closed",
        has_security_impact_analysis=True,
        has_testing_evidence=True,
        has_approval=True,
        has_deployment_evidence=True,
        has_verification_evidence=False,
    )


def test_poam_item_date() -> None:
    p = PoamItem(
        poam_id="p1",
        weakness_name="Gap",
        weakness_description="Details",
        asset_identifier="a1",
        raw_severity="high",
        adjusted_risk_rating="high",
        status="open",
        planned_remediation="Fix",
        milestone_due_date=date(2026, 12, 31),
        controls=["CM-8"],
    )
    assert p.milestone_due_date.year == 2026


def test_eval_result_outcomes() -> None:
    er = EvalResult(
        eval_id="CM8-1",
        name="Inventory coverage",
        result="PASS",
        severity="low",
        summary="Aligned",
        evidence=["row a"],
        gaps=[],
        affected_assets=["a1"],
        recommended_actions=["none"],
        generated_artifacts=["eval_results.json"],
        controls=["CM-8"],
    )
    assert er.result == "PASS"


def test_eval_result_invalid_outcome() -> None:
    with pytest.raises(ValidationError):
        EvalResult(
            eval_id="x",
            name="n",
            result="MAYBE",  # type: ignore[arg-type]
            severity="low",
            summary="s",
        )


def test_model_to_json_round_trip_asset() -> None:
    a = Asset(
        asset_id="x",
        provider="gcp",
        asset_type="compute",
        name="n",
        criticality="moderate",
        environment="stage",
    )
    s = model_to_json(a)
    b = model_from_json(Asset, s)
    assert b.asset_id == "x"


def test_assessment_bundle_json_helpers() -> None:
    bundle = AssessmentBundle(
        assets=[
            Asset(
                asset_id="a",
                provider="aws",
                asset_type="unknown",
                name="?",
                criticality="low",
                environment="unknown",
            )
        ],
        events=[
            SecurityEvent(
                event_id="ev",
                provider="aws",
                semantic_type="unknown",
                timestamp=datetime(2026, 1, 1, tzinfo=timezone.utc),
            )
        ],
    )
    js = assessment_bundle_to_json(bundle)
    back = assessment_bundle_from_json(js)
    assert len(back.assets) == 1
    assert len(back.events) == 1


def test_model_to_python_dict_datetime() -> None:
    ev = SecurityEvent(
        event_id="e",
        provider="azure",
        semantic_type="identity.user_created",
        timestamp=datetime(2026, 6, 15, 8, 30, tzinfo=timezone.utc),
    )
    d = model_to_python_dict(ev)
    assert isinstance(d["timestamp"], str)
    assert "2026" in d["timestamp"]
