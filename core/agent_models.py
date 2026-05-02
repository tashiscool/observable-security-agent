"""
Canonical models for AI agent behavior telemetry (identity, tool calls, memory, violations).

Composed with :class:`core.models.AssessmentBundle` for joint cloud + agent posture reviews.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from core.models import AssessmentBundle

AgentApprovalStatus = Literal["approved", "denied", "not_required", "missing"]
AgentPolicyDecision = Literal["allowed", "blocked", "warned", "unknown"]
AgentMemoryType = Literal["short_term", "long_term", "vector", "file", "external_context"]
AgentMemoryAction = Literal["read", "write", "delete", "retrieve"]
AgentMemorySensitivity = Literal["public", "internal", "confidential", "pii", "secret", "unknown"]
AgentToolRiskLevel = Literal["low", "medium", "high", "critical", "unknown"]
AgentViolationType = Literal[
    "prompt_injection_suspected",
    "unauthorized_tool_use",
    "unauthorized_data_access",
    "credential_misuse",
    "privilege_escalation_attempt",
    "approval_bypass",
    "pii_exposure",
    "secret_exposure",
    "out_of_scope_action",
    "unknown",
]
ViolationSeverity = Literal["critical", "high", "medium", "low", "info"]


class AgentIdentity(BaseModel):
    """Registered agent / bot definition for governance and audit."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    agent_id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    owner: str = Field(..., min_length=1)
    environment: str = Field(..., min_length=1)
    purpose: str = Field(..., min_length=1)
    allowed_tools: list[str] = Field(default_factory=list)
    allowed_data_scopes: list[str] = Field(default_factory=list)
    allowed_actions: list[str] = Field(default_factory=list)
    human_approval_required_for: list[str] = Field(default_factory=list)
    credentials_ref: str | None = None
    created_at: datetime
    last_reviewed_at: datetime | None = None


class AgentToolCall(BaseModel):
    """Single tool invocation attributed to an agent."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    call_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    timestamp: datetime
    tool_name: str = Field(..., min_length=1)
    action: str = Field(..., min_length=1)
    target_resource: str | None = None
    input_summary: str = Field(..., min_length=1)
    output_summary: str = Field(..., min_length=1)
    risk_level: AgentToolRiskLevel
    approved_by: str | None = None
    approval_required: bool
    approval_status: AgentApprovalStatus
    policy_decision: AgentPolicyDecision
    raw_ref: str | None = None

    @property
    def approval_gap_detectable(self) -> bool:
        """True when governance expects human approval but none is recorded (review signal)."""
        return self.approval_required and self.approval_status == "missing"


class AgentMemoryEvent(BaseModel):
    """Memory store interaction (RAG, buffer, file context, etc.)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    memory_event_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    timestamp: datetime
    memory_type: AgentMemoryType
    action: AgentMemoryAction
    sensitivity: AgentMemorySensitivity
    source: str = Field(..., min_length=1)
    policy_decision: AgentPolicyDecision


class AgentPolicyViolation(BaseModel):
    """Policy or guardrail breach attributed to an agent."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    violation_id: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)
    timestamp: datetime
    violation_type: AgentViolationType
    severity: ViolationSeverity
    evidence: str = Field(..., min_length=1)
    affected_resource: str | None = None
    recommended_action: str = Field(..., min_length=1)
    linked_ticket_id: str | None = None


class AgentAssessmentBundle(BaseModel):
    """Agent telemetry plus existing cloud evidence bundle."""

    model_config = ConfigDict(extra="forbid")

    agent_identities: list[AgentIdentity] = Field(default_factory=list)
    tool_calls: list[AgentToolCall] = Field(default_factory=list)
    memory_events: list[AgentMemoryEvent] = Field(default_factory=list)
    policy_violations: list[AgentPolicyViolation] = Field(default_factory=list)
    assessment_bundle: AssessmentBundle = Field(default_factory=AssessmentBundle)

    @model_validator(mode="after")
    def _agent_ids_referenced_exist(self) -> AgentAssessmentBundle:
        known = {a.agent_id for a in self.agent_identities}
        if not known:
            return self
        for tc in self.tool_calls:
            if tc.agent_id not in known:
                raise ValueError(f"tool_calls reference unknown agent_id: {tc.agent_id!r}")
        for me in self.memory_events:
            if me.agent_id not in known:
                raise ValueError(f"memory_events reference unknown agent_id: {me.agent_id!r}")
        for pv in self.policy_violations:
            if pv.agent_id not in known:
                raise ValueError(f"policy_violations reference unknown agent_id: {pv.agent_id!r}")
        return self


# --- JSON serialization ---


def agent_assessment_bundle_to_json(bundle: AgentAssessmentBundle, *, indent: int | None = 2) -> str:
    """Serialize :class:`AgentAssessmentBundle` to JSON (ISO datetimes)."""
    return bundle.model_dump_json(indent=indent)


def agent_assessment_bundle_from_json(data: str | bytes) -> AgentAssessmentBundle:
    """Parse JSON into :class:`AgentAssessmentBundle`."""
    if isinstance(data, bytes):
        text = data.decode("utf-8")
    else:
        text = data
    return AgentAssessmentBundle.model_validate_json(text)


def agent_bundle_to_python_dict(bundle: AgentAssessmentBundle) -> dict[str, Any]:
    """JSON-compatible dict (ISO datetimes)."""
    return json.loads(bundle.model_dump_json())


__all__ = [
    "AgentApprovalStatus",
    "AgentAssessmentBundle",
    "AgentIdentity",
    "AgentMemoryAction",
    "AgentMemoryEvent",
    "AgentMemorySensitivity",
    "AgentMemoryType",
    "AgentPolicyDecision",
    "AgentPolicyViolation",
    "AgentToolCall",
    "AgentToolRiskLevel",
    "AgentViolationType",
    "ViolationSeverity",
    "agent_assessment_bundle_from_json",
    "agent_assessment_bundle_to_json",
    "agent_bundle_to_python_dict",
]
