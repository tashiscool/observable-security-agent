"""Structured Pydantic outputs for every LLM-backed reasoner in :mod:`ai`.

These models are the *only* return shape downstream callers ever see — whether
the answer came from an LLM or from the deterministic fallback. The
``source`` field on every model records which path was taken so reviewers can
trace any given output back to its origin.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from core.models import GapSeverity, GapType


__all__ = [
    "AuditorResponseDraft",
    "EvidenceCitation",
    "ExplanationAudience",
    "ExplanationResponse",
    "LlmBackendStatus",
    "ReasoningSource",
    "RemediationTicketDraft",
    "RowClassificationReasoning",
    "ArtifactSufficiencyFinding",
    "ThreePaoRemediationEvaluation",
    "TicketSeverity",
]


class ReasoningSource(str, Enum):
    """Provenance of the structured reasoning output."""

    LLM = "llm"
    DETERMINISTIC_FALLBACK = "deterministic_fallback"


ExplanationAudience = Literal["assessor", "executive", "ao", "derivation_trace"]
TicketSeverity = Literal["low", "moderate", "high", "critical", "informational"]
ConfidenceBand = Literal["low", "moderate", "high"]


class EvidenceCitation(BaseModel):
    """A single citation back to a named artifact + (optionally) a field within it."""

    model_config = ConfigDict(extra="forbid")

    artifact: str = Field(..., min_length=1, description="Artifact filename, e.g. eval_results.json")
    field: str | None = Field(
        default=None,
        description="Optional dotted/array path inside the artifact, e.g. evaluations[3].gap.",
    )
    note: str | None = Field(
        default=None,
        description="Optional human-readable note about why this field was cited.",
    )


# ---------------------------------------------------------------------------
# Use case 1: classifying ambiguous tracker rows
# ---------------------------------------------------------------------------


class RowClassificationReasoning(BaseModel):
    """LLM- or fallback-derived classification for an ambiguous tracker row.

    Only invoked when the deterministic phrase classifier in
    :mod:`classification.classify_tracker_gap` returns ``gap_type='unknown'``.
    The returned ``gap_type`` is constrained to the same canonical
    :class:`core.models.GapType` literal — the LLM cannot invent new types.
    """

    model_config = ConfigDict(extra="forbid")

    source: ReasoningSource
    source_item_id: str = Field(..., min_length=1)

    gap_type: GapType
    severity: GapSeverity
    confidence: ConfidenceBand

    rationale: str = Field(
        ...,
        min_length=1,
        description="Why this row maps to gap_type — must reference cited phrases only.",
    )
    cited_phrases: list[str] = Field(
        default_factory=list,
        description="Substrings copied from request_text / assessor_comment that drove the choice.",
    )
    recommended_artifact: str | None = None
    recommended_validation: str | None = None
    poam_required: bool = False

    citations: list[EvidenceCitation] = Field(default_factory=list)
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Field names from the input that were absent / null and could not be used.",
    )
    warnings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Use cases 2–5: assessor / executive / AO / derivation-trace explanations
# ---------------------------------------------------------------------------


class ExplanationResponse(BaseModel):
    """Generic audience-targeted explanation produced from supplied artifacts only."""

    model_config = ConfigDict(extra="forbid")

    source: ReasoningSource
    audience: ExplanationAudience

    headline: str = Field(..., min_length=1)
    body: str = Field(..., min_length=1, description="Markdown body grounded in citations.")

    citations: list[EvidenceCitation] = Field(default_factory=list)
    missing_evidence: list[str] = Field(
        default_factory=list,
        description="Fields/artifacts the input did NOT supply; explanation must remain silent on them.",
    )
    warnings: list[str] = Field(default_factory=list)

    # Set when the explanation describes a specific eval / KSI / finding so
    # downstream reports can deep-link.
    referenced_eval_id: str | None = None
    referenced_ksi_id: str | None = None
    referenced_finding_id: str | None = None


class LlmBackendStatus(BaseModel):
    """Runtime posture for the OpenAI-compatible LLM transport.

    ``backend`` is informational; all non-deterministic calls use the same
    bounded JSON contract and transport. Bedrock is normally reached through
    LiteLLM or another OpenAI-compatible proxy, while Ollama can be reached via
    its local OpenAI-compatible endpoint.
    """

    model_config = ConfigDict(extra="forbid")

    configured: bool
    backend: str
    endpoint: str
    model: str
    requires_api_key: bool
    reasoners: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Use case 6: remediation-ticket draft
# ---------------------------------------------------------------------------


class RemediationTicketDraft(BaseModel):
    """Local draft of a remediation ticket. NEVER submitted to external systems."""

    model_config = ConfigDict(extra="forbid")

    source: ReasoningSource
    draft_ticket_id: str = Field(..., min_length=1)

    title: str = Field(..., min_length=1)
    description_md: str = Field(..., min_length=1)
    severity: TicketSeverity
    controls: list[str] = Field(default_factory=list)

    affected_artifacts: list[str] = Field(
        default_factory=list,
        description="Artifact filenames whose evidence drives this ticket.",
    )
    acceptance_criteria: list[str] = Field(
        default_factory=list,
        description="Bullet-list of conditions reviewers can verify deterministically.",
    )

    citations: list[EvidenceCitation] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    submitted_externally: Literal[False] = False
    note: str = Field(
        default="Draft only — not submitted to any external ticket system.",
        description="Stable string downstream code can grep for to confirm draft-only status.",
    )


# ---------------------------------------------------------------------------
# Use case 7: auditor-response draft
# ---------------------------------------------------------------------------


class AuditorResponseDraft(BaseModel):
    """Local draft text answering an auditor question. NEVER sent to the auditor."""

    model_config = ConfigDict(extra="forbid")

    source: ReasoningSource
    question: str = Field(..., min_length=1)

    response_md: str = Field(..., min_length=1)
    cited_artifacts: list[str] = Field(default_factory=list)
    cited_fields: list[str] = Field(default_factory=list)

    citations: list[EvidenceCitation] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    confidence: ConfidenceBand = "moderate"

    submitted_externally: Literal[False] = False
    note: str = Field(
        default="Draft only — for human review before any communication is sent.",
    )


# ---------------------------------------------------------------------------
# Use case 8: 3PAO Remediation Evaluation
# ---------------------------------------------------------------------------


class ArtifactSufficiencyFinding(BaseModel):
    """One 3PAO reasonableness check against supplied artifacts."""

    model_config = ConfigDict(extra="forbid")

    requirement: str = Field(..., min_length=1)
    status: Literal["pass", "fail", "unknown"]
    evidence: str = Field(..., min_length=1)
    remediation: str | None = None


class ThreePaoRemediationEvaluation(BaseModel):
    """Virtual 3PAO recommendation and remediation plan for an evidence gap."""

    model_config = ConfigDict(extra="forbid")

    source: ReasoningSource
    gap_id: str = Field(..., min_length=1)

    recommendation: str = Field(
        ...,
        min_length=1,
        description="The 3PAO-style recommendation on how the CSP should satisfy the assessor.",
    )
    remediation_plan_md: str = Field(
        ...,
        min_length=1,
        description="Markdown formatted step-by-step remediation plan.",
    )
    reasonable_test_passed: bool = Field(
        ...,
        description="Whether the CSP's current stance meets the 'reasonable test' for compliance.",
    )

    citations: list[EvidenceCitation] = Field(default_factory=list)
    artifact_sufficiency: list[ArtifactSufficiencyFinding] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
