"""Core domain models for agentic compliance operations.

These schemas are intentionally separate from the legacy assessment pipeline
models in :mod:`core.models`. They define the stable platform vocabulary for
evidence artifacts, normalized findings, control requirements, assessment
results, recommendations, human review, assurance manifests, and agent run logs.
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Literal, TypeVar

from jsonschema import Draft202012Validator
from pydantic import BaseModel, ConfigDict, Field, model_validator

T = TypeVar("T", bound=BaseModel)


ComplianceStatus = Literal[
    "COMPLIANT",
    "NON_COMPLIANT",
    "PARTIALLY_COMPLIANT",
    "NOT_APPLICABLE",
    "INSUFFICIENT_EVIDENCE",
    "NEEDS_HUMAN_REVIEW",
    "COLLECTOR_FAILED",
    "SCAN_STALE",
    "EVIDENCE_UNAVAILABLE",
    "SOURCE_UNREACHABLE",
    "CONTROL_NOT_ASSESSED",
]

TrustLevel = Literal["authoritative", "corroborated", "self_reported", "derived", "unknown"]
FreshnessStatus = Literal["current", "stale", "expired", "unknown"]
FindingSeverity = Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL", "UNKNOWN"]
FindingStatus = Literal["OPEN", "FIXED", "SUPPRESSED", "FALSE_POSITIVE", "RISK_ACCEPTED", "UNKNOWN"]
Responsibility = Literal["provider", "customer", "shared", "inherited", "unknown"]
MappingConfidence = Literal["EXACT_SOURCE_CONTROL", "STATIC_RULE", "HEURISTIC", "NEEDS_REVIEW"]
RecommendationType = Literal[
    "collect_evidence",
    "remediate",
    "open_poam",
    "accept_risk",
    "update_control",
    "investigate",
    "human_review",
    "CREATE_POAM",
    "UPDATE_POAM",
    "REQUEST_RESCAN",
    "REQUEST_EVIDENCE",
    "ESCALATE_TO_REVIEWER",
    "ACCEPT_COMPENSATING_CONTROL_REVIEW",
    "MARK_INSUFFICIENT_EVIDENCE",
    "DRAFT_ASSESSMENT_NARRATIVE",
    "NO_ACTION_REQUIRED",
]
ReviewDecision = Literal[
    "ACCEPTED",
    "ACCEPTED_WITH_EDITS",
    "REJECTED",
    "NEEDS_MORE_EVIDENCE",
    "FALSE_POSITIVE",
    "RISK_ACCEPTED",
    "COMPENSATING_CONTROL_ACCEPTED",
    "ESCALATED_TO_AO",
    "ESCALATED_TO_3PAO",
    # Backward-compatible legacy vocabulary used by earlier tests/artifacts.
    "approved",
    "rejected",
    "needs_changes",
    "deferred",
]
RunDecision = Literal["completed", "failed", "blocked", "needs_human_review"]
RunStatus = Literal["SUCCESS", "FAILED", "PARTIAL", "COLLECTOR_FAILED"]
GuardrailStatus = Literal["PASS", "FAIL", "WARN"]


class DomainModel(BaseModel):
    """Base config for JSON-facing domain models.

    Python code uses snake_case attributes; serialized API/schema fields use the
    requested camelCase aliases.
    """

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
    )


class EvidenceArtifact(DomainModel):
    evidence_id: str = Field(..., alias="evidenceId", min_length=1)
    source_system: str = Field(..., alias="sourceSystem", min_length=1)
    source_type: str = Field(..., alias="sourceType", min_length=1)
    collected_at: datetime = Field(..., alias="collectedAt")
    observed_at: datetime | None = Field(..., alias="observedAt")
    account_id: str | None = Field(..., alias="accountId")
    region: str | None = Field(..., alias="region")
    resource_id: str | None = Field(..., alias="resourceId")
    resource_arn: str | None = Field(..., alias="resourceArn")
    resource_type: str | None = Field(..., alias="resourceType")
    scanner: str | None = Field(..., alias="scanner")
    finding_id: str | None = Field(..., alias="findingId")
    vulnerability_id: str | None = Field(..., alias="vulnerabilityId")
    package_name: str | None = Field(..., alias="packageName")
    package_version: str | None = Field(..., alias="packageVersion")
    image_digest: str | None = Field(..., alias="imageDigest")
    control_ids: list[str] = Field(..., alias="controlIds")
    raw_ref: str = Field(..., alias="rawRef", min_length=1)
    normalized_summary: str = Field(..., alias="normalizedSummary", min_length=1)
    trust_level: TrustLevel = Field(..., alias="trustLevel")
    freshness_status: FreshnessStatus = Field(..., alias="freshnessStatus")


class NormalizedFinding(DomainModel):
    finding_id: str = Field(..., alias="findingId", min_length=1)
    source_system: str = Field(..., alias="sourceSystem", min_length=1)
    scanner: str | None = Field(..., alias="scanner")
    title: str = Field(..., alias="title", min_length=1)
    description: str = Field(..., alias="description", min_length=1)
    severity: FindingSeverity = Field(..., alias="severity")
    status: FindingStatus = Field(..., alias="status")
    vulnerability_id: str | None = Field(..., alias="vulnerabilityId")
    package_name: str | None = Field(..., alias="packageName")
    package_version: str | None = Field(..., alias="packageVersion")
    fixed_version: str | None = Field(..., alias="fixedVersion")
    account_id: str | None = Field(..., alias="accountId")
    region: str | None = Field(..., alias="region")
    resource_id: str | None = Field(..., alias="resourceId")
    image_digest: str | None = Field(..., alias="imageDigest")
    first_observed_at: datetime | None = Field(..., alias="firstObservedAt")
    last_observed_at: datetime | None = Field(..., alias="lastObservedAt")
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    control_ids: list[str] = Field(..., alias="controlIds")


class CloudAsset(DomainModel):
    asset_id: str = Field(..., alias="assetId", min_length=1)
    provider: str = Field(..., alias="provider", min_length=1)
    account_id: str | None = Field(..., alias="accountId")
    region: str | None = Field(..., alias="region")
    resource_id: str = Field(..., alias="resourceId", min_length=1)
    resource_arn: str | None = Field(..., alias="resourceArn")
    resource_type: str = Field(..., alias="resourceType", min_length=1)
    name: str | None = Field(..., alias="name")
    tags: dict[str, str] = Field(..., alias="tags")
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    control_ids: list[str] = Field(..., alias="controlIds")


class ControlRequirement(DomainModel):
    control_id: str = Field(..., alias="controlId", min_length=1)
    family: str = Field(..., alias="family", min_length=1)
    title: str = Field(..., alias="title", min_length=1)
    requirement_text: str = Field(..., alias="requirementText", min_length=1)
    parameters: dict[str, Any] = Field(..., alias="parameters")
    framework: str = Field(..., alias="framework", min_length=1)
    baseline: str | None = Field(..., alias="baseline")
    responsibility: Responsibility = Field(..., alias="responsibility")
    source_ref: str = Field(..., alias="sourceRef", min_length=1)


class ControlMapping(DomainModel):
    mapping_id: str = Field(..., alias="mappingId", min_length=1)
    source_control_id: str = Field(..., alias="sourceControlId", min_length=1)
    target_control_id: str = Field(..., alias="targetControlId", min_length=1)
    source_framework: str = Field(..., alias="sourceFramework", min_length=1)
    target_framework: str = Field(..., alias="targetFramework", min_length=1)
    relationship: str = Field(..., alias="relationship", min_length=1)
    rationale: str = Field(..., alias="rationale", min_length=1)
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    mapping_confidence: MappingConfidence = Field(default="NEEDS_REVIEW", alias="mappingConfidence")
    source_ref: str = Field(..., alias="sourceRef", min_length=1)


class AssessmentResult(DomainModel):
    assessment_id: str = Field(..., alias="assessmentId", min_length=1)
    control_id: str = Field(..., alias="controlId", min_length=1)
    status: ComplianceStatus = Field(..., alias="status")
    summary: str = Field(..., alias="summary", min_length=1)
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    finding_ids: list[str] = Field(..., alias="findingIds")
    gaps: list[str] = Field(..., alias="gaps")
    recommendations: list[str] = Field(..., alias="recommendations")
    review_decision_ids: list[str] = Field(default_factory=list, alias="reviewDecisionIds")
    confidence: float = Field(..., alias="confidence", ge=0.0, le=1.0)
    human_review_required: bool = Field(..., alias="humanReviewRequired")
    created_at: datetime = Field(..., alias="createdAt")


class AgentRecommendation(DomainModel):
    recommendation_id: str = Field(..., alias="recommendationId", min_length=1)
    control_id: str = Field(..., alias="controlId", min_length=1)
    finding_ids: list[str] = Field(..., alias="findingIds")
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    recommendation_type: RecommendationType = Field(..., alias="recommendationType")
    summary: str = Field(..., alias="summary", min_length=1)
    rationale: str = Field(..., alias="rationale", min_length=1)
    confidence: float = Field(..., alias="confidence", ge=0.0, le=1.0)
    blocked_unsupported_claims: bool = Field(..., alias="blockedUnsupportedClaims")
    human_review_required: bool = Field(..., alias="humanReviewRequired")


class HumanReviewDecision(DomainModel):
    review_decision_id: str = Field(..., alias="reviewDecisionId", min_length=1)
    recommendation_id: str = Field(..., alias="recommendationId", min_length=1)
    control_id: str | None = Field(default=None, alias="controlId")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    reviewer: str = Field(..., alias="reviewer", min_length=1)
    decision: ReviewDecision = Field(..., alias="decision")
    justification: str = Field(..., alias="justification")
    timestamp: datetime = Field(..., alias="timestamp")

    @model_validator(mode="after")
    def _validate_review_decision(self) -> "HumanReviewDecision":
        justification = (self.justification or "").strip()
        if not justification:
            raise ValueError("HumanReviewDecision requires justification")
        requires_justification = {
            "RISK_ACCEPTED",
            "FALSE_POSITIVE",
            "COMPENSATING_CONTROL_ACCEPTED",
        }
        if self.decision in requires_justification and not justification:
            raise ValueError(f"{self.decision} requires justification")
        if self.decision == "COMPENSATING_CONTROL_ACCEPTED" and not self.evidence_ids:
            raise ValueError("COMPENSATING_CONTROL_ACCEPTED requires evidenceIds")
        return self


class AssurancePackageManifest(DomainModel):
    manifest_id: str = Field(..., alias="manifestId", min_length=1)
    package_id: str = Field(..., alias="packageId", min_length=1)
    generated_at: datetime = Field(..., alias="generatedAt")
    framework: str = Field(..., alias="framework", min_length=1)
    baseline: str | None = Field(..., alias="baseline")
    assessment_result_ids: list[str] = Field(..., alias="assessmentResultIds")
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    finding_ids: list[str] = Field(..., alias="findingIds")
    control_ids: list[str] = Field(..., alias="controlIds")
    artifact_refs: list[str] = Field(..., alias="artifactRefs")
    schema_version: str = Field(..., alias="schemaVersion", min_length=1)


class AgentRunLog(DomainModel):
    agent_run_id: str = Field(..., alias="agentRunId", min_length=1)
    workflow: str = Field(..., alias="workflow", min_length=1)
    input_hash: str = Field(..., alias="inputHash", min_length=1)
    model_name: str | None = Field(default=None, alias="modelName")
    started_at: datetime = Field(..., alias="startedAt")
    completed_at: datetime | None = Field(..., alias="completedAt")
    duration_ms: int = Field(default=0, alias="durationMs", ge=0)
    evidence_ids: list[str] = Field(..., alias="evidenceIds")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    control_ids: list[str] = Field(..., alias="controlIds")
    status: RunStatus = Field(default="SUCCESS", alias="status")
    decision: RunDecision = Field(..., alias="decision")
    confidence: float = Field(..., alias="confidence", ge=0.0, le=1.0)
    schema_valid: bool = Field(..., alias="schemaValid")
    unsupported_claims_blocked: bool = Field(..., alias="unsupportedClaimsBlocked")
    human_review_required: bool = Field(..., alias="humanReviewRequired")
    errors: list[str] = Field(..., alias="errors")
    warnings: list[str] = Field(default_factory=list, alias="warnings")


class GuardrailPolicy(DomainModel):
    policy_id: str = Field(default="default-guardrail-policy", alias="policyId", min_length=1)
    allowed_account_ids: list[str] = Field(default_factory=list, alias="allowedAccountIds")
    allowed_regions: list[str] = Field(default_factory=list, alias="allowedRegions")
    allowed_resource_ids: list[str] = Field(default_factory=list, alias="allowedResourceIds")
    allowed_tenant_ids: list[str] = Field(default_factory=list, alias="allowedTenantIds")
    allow_stale_evidence: bool = Field(default=False, alias="allowStaleEvidence")
    require_human_review_for_compliance: bool = Field(default=True, alias="requireHumanReviewForCompliance")
    block_certification_language: bool = Field(default=True, alias="blockCertificationLanguage")
    block_destructive_operations: bool = Field(default=True, alias="blockDestructiveOperations")
    validate_structured_outputs: bool = Field(default=True, alias="validateStructuredOutputs")
    detect_prompt_injection: bool = Field(default=True, alias="detectPromptInjection")
    prompt_injection_patterns: list[str] = Field(
        default_factory=lambda: [
            "ignore previous instructions",
            "ignore all instructions",
            "disregard the system prompt",
            "reveal the system prompt",
            "developer message",
            "disable guardrails",
            "jailbreak",
            "exfiltrate",
        ],
        alias="promptInjectionPatterns",
    )


class GuardrailResult(DomainModel):
    guardrail_id: str = Field(..., alias="guardrailId", min_length=1)
    status: GuardrailStatus = Field(..., alias="status")
    message: str = Field(..., alias="message", min_length=1)
    blocked_action: str | None = Field(default=None, alias="blockedAction")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    recommendation_id: str | None = Field(default=None, alias="recommendationId")
    timestamp: datetime = Field(..., alias="timestamp")


class DomainValidationReport(DomainModel):
    valid: bool = Field(..., alias="valid")
    errors: list[str] = Field(..., alias="errors")
    model_name: str = Field(..., alias="modelName")


def model_to_json(model: DomainModel, *, indent: int | None = 2) -> str:
    """Serialize a domain model with canonical camelCase field names."""
    return model.model_dump_json(indent=indent, by_alias=True)


def model_from_json(cls: type[T], data: str | bytes) -> T:
    """Deserialize JSON into a strict domain model."""
    text = data.decode("utf-8") if isinstance(data, bytes) else data
    return cls.model_validate_json(text)


def model_to_python_dict(model: DomainModel) -> dict[str, Any]:
    """Return a JSON-compatible dict using canonical camelCase field names."""
    return json.loads(model_to_json(model))


def validate_model_schema(model: DomainModel) -> DomainValidationReport:
    """Validate a model's serialized JSON against its generated JSON Schema.

    Pydantic performs field validation at construction time; this helper uses
    the repository's existing ``jsonschema`` dependency to verify the emitted
    wire shape as well.
    """
    schema = model.__class__.model_json_schema(by_alias=True)
    instance = model_to_python_dict(model)
    validator = Draft202012Validator(schema)
    errors = [
        f"{'/'.join(str(p) for p in err.absolute_path) or '$'}: {err.message}"
        for err in sorted(validator.iter_errors(instance), key=lambda e: (list(e.absolute_path), e.message))
    ]
    return DomainValidationReport(
        valid=not errors,
        errors=errors,
        modelName=model.__class__.__name__,
    )


__all__ = [
    "AgentRecommendation",
    "AgentRunLog",
    "AssessmentResult",
    "AssurancePackageManifest",
    "CloudAsset",
    "ComplianceStatus",
    "ControlMapping",
    "ControlRequirement",
    "DomainValidationReport",
    "EvidenceArtifact",
    "GuardrailPolicy",
    "GuardrailResult",
    "GuardrailStatus",
    "HumanReviewDecision",
    "MappingConfidence",
    "NormalizedFinding",
    "model_from_json",
    "model_to_json",
    "model_to_python_dict",
    "validate_model_schema",
]
