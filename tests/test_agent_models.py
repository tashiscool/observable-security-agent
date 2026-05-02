"""Tests for ``core.agent_models`` (AI agent behavior telemetry)."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.agent_models import (
    AgentAssessmentBundle,
    AgentIdentity,
    AgentMemoryEvent,
    AgentPolicyViolation,
    AgentToolCall,
    agent_assessment_bundle_from_json,
    agent_assessment_bundle_to_json,
)


def _identity(agent_id: str = "agent-001") -> AgentIdentity:
    return AgentIdentity(
        agent_id=agent_id,
        name="BuildLab Agent",
        owner="security-team@example.com",
        environment="prod",
        purpose="Correlate cloud evidence with policy checks",
        allowed_tools=["read_object", "run_eval"],
        allowed_data_scopes=["s3://evidence-bucket/read"],
        allowed_actions=["read", "assess"],
        human_approval_required_for=["mutate_security_group"],
        credentials_ref="vault://kv/buildlab/agent-001",
        created_at=datetime(2026, 5, 1, 10, 0, 0, tzinfo=timezone.utc),
        last_reviewed_at=datetime(2026, 5, 15, 9, 0, 0, tzinfo=timezone.utc),
    )


def test_agent_identity_validation() -> None:
    with pytest.raises(ValidationError):
        AgentIdentity(
            agent_id="a",
            name="n",
            owner="o",
            environment="e",
            purpose="p",
            created_at=datetime.now(tz=timezone.utc),
            extra_field="x",  # type: ignore[call-arg]
        )


def test_tool_call_approval_required_missing_is_detectable() -> None:
    tc = AgentToolCall(
        call_id="call-1",
        agent_id="agent-001",
        timestamp=datetime(2026, 5, 1, 11, 0, 0, tzinfo=timezone.utc),
        tool_name="run_shell",
        action="execute",
        target_resource="arn:aws:ec2:us-east-1:123456789012:instance/i-abc",
        input_summary="user prompt: rotate keys",
        output_summary="exit 0",
        risk_level="high",
        approved_by=None,
        approval_required=True,
        approval_status="missing",
        policy_decision="allowed",
    )
    assert tc.approval_gap_detectable is True


def test_pii_memory_write_represented() -> None:
    ev = AgentMemoryEvent(
        memory_event_id="mem-1",
        agent_id="agent-001",
        timestamp=datetime(2026, 5, 1, 11, 5, 0, tzinfo=timezone.utc),
        memory_type="vector",
        action="write",
        sensitivity="pii",
        source="rag-store:/collections/customer-notes",
        policy_decision="warned",
    )
    assert ev.sensitivity == "pii"
    assert ev.action == "write"


def test_unauthorized_tool_use_violation_represented() -> None:
    v = AgentPolicyViolation(
        violation_id="vio-1",
        agent_id="agent-001",
        timestamp=datetime(2026, 5, 1, 11, 10, 0, tzinfo=timezone.utc),
        violation_type="unauthorized_tool_use",
        severity="high",
        evidence="Tool `delete_bucket` not in allow list; invoked anyway.",
        affected_resource="s3://prod-data",
        recommended_action="Revoke session; rotate credentials; add guardrail deny rule.",
        linked_ticket_id="SEC-4421",
    )
    assert v.violation_type == "unauthorized_tool_use"


def test_agent_assessment_bundle_rejects_unknown_agent_when_identities_present() -> None:
    with pytest.raises(ValidationError) as ei:
        AgentAssessmentBundle(
            agent_identities=[_identity()],
            tool_calls=[
                AgentToolCall(
                    call_id="c1",
                    agent_id="unknown-agent",
                    timestamp=datetime(2026, 5, 1, 12, 0, 0, tzinfo=timezone.utc),
                    tool_name="t",
                    action="a",
                    input_summary="in",
                    output_summary="out",
                    risk_level="low",
                    approval_required=False,
                    approval_status="not_required",
                    policy_decision="unknown",
                )
            ],
        )
    assert "unknown agent_id" in str(ei.value).lower()


def test_agent_assessment_bundle_json_round_trip() -> None:
    bundle = AgentAssessmentBundle(
        agent_identities=[_identity()],
        tool_calls=[
            AgentToolCall(
                call_id="call-rt",
                agent_id="agent-001",
                timestamp=datetime(2026, 5, 1, 13, 0, 0, tzinfo=timezone.utc),
                tool_name="fetch_logs",
                action="read",
                target_resource=None,
                input_summary="query last 1h",
                output_summary="42 rows",
                risk_level="low",
                approved_by="alice",
                approval_required=False,
                approval_status="not_required",
                policy_decision="allowed",
            )
        ],
        memory_events=[],
        policy_violations=[],
    )
    js = agent_assessment_bundle_to_json(bundle)
    back = agent_assessment_bundle_from_json(js)
    assert back.agent_identities[0].agent_id == "agent-001"
    assert back.tool_calls[0].call_id == "call-rt"


def test_invalid_violation_type_rejected() -> None:
    with pytest.raises(ValidationError):
        AgentPolicyViolation(
            violation_id="v",
            agent_id="agent-001",
            timestamp=datetime(2026, 5, 1, 0, 0, 0, tzinfo=timezone.utc),
            violation_type="not_a_real_type",  # type: ignore[arg-type]
            severity="high",
            evidence="e",
            recommended_action="r",
        )
