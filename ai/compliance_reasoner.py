"""Optional compliance reasoning adapters.

This module defines a narrow interface for future LLM-backed workflows while
keeping tests and offline evaluations deterministic. Reasoners receive only
bounded RAG context bundles or assurance package dictionaries, emit strict
typed JSON-compatible objects, and pass guardrail validation before callers can
use the output.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any, Callable, Mapping, Sequence

from pydantic import Field

from core.domain_models import (
    ComplianceStatus,
    DomainModel,
    GuardrailPolicy,
    validate_model_schema,
)
from core.guardrails import (
    detect_prompt_injection,
    enforce_guardrails,
    evaluate_certification_language,
    evaluate_destructive_action,
    evaluate_unsupported_claim,
)
from core.rag_context_builder import RAGContextBundle


ReasonerTransport = Callable[[str, Mapping[str, Any]], str | Mapping[str, Any]]


class StructuredClaim(DomainModel):
    claim_id: str = Field(..., alias="claimId", min_length=1)
    text: str = Field(..., alias="text", min_length=1)
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")


class StructuredNarrative(DomainModel):
    status: ComplianceStatus = Field(..., alias="status")
    control_id: str | None = Field(default=None, alias="controlId")
    summary: str = Field(..., alias="summary", min_length=1)
    observations: list[StructuredClaim] = Field(default_factory=list, alias="observations")
    recommendations: list[str] = Field(default_factory=list, alias="recommendations")
    missing_evidence: list[str] = Field(default_factory=list, alias="missingEvidence")
    unsupported_claims_blocked: int = Field(default=0, alias="unsupportedClaimsBlocked", ge=0)
    human_review_required: bool = Field(default=True, alias="humanReviewRequired")
    schema_valid: bool = Field(default=True, alias="schemaValid")


class StructuredExecutiveSummary(DomainModel):
    status: ComplianceStatus = Field(..., alias="status")
    system: str = Field(..., alias="system", min_length=1)
    summary: str = Field(..., alias="summary", min_length=1)
    top_risks: list[StructuredClaim] = Field(default_factory=list, alias="topRisks")
    controls_with_insufficient_evidence: list[str] = Field(default_factory=list, alias="controlsWithInsufficientEvidence")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    unsupported_claims_blocked: int = Field(default=0, alias="unsupportedClaimsBlocked", ge=0)
    human_review_required: bool = Field(default=True, alias="humanReviewRequired")
    schema_valid: bool = Field(default=True, alias="schemaValid")


class StructuredPoamDraft(DomainModel):
    status: ComplianceStatus = Field(..., alias="status")
    control_id: str | None = Field(default=None, alias="controlId")
    title: str = Field(..., alias="title", min_length=1)
    description: str = Field(..., alias="description", min_length=1)
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    recommended_milestones: list[str] = Field(default_factory=list, alias="recommendedMilestones")
    missing_evidence: list[str] = Field(default_factory=list, alias="missingEvidence")
    unsupported_claims_blocked: int = Field(default=0, alias="unsupportedClaimsBlocked", ge=0)
    human_review_required: bool = Field(default=True, alias="humanReviewRequired")
    schema_valid: bool = Field(default=True, alias="schemaValid")
    submitted_externally: bool = Field(default=False, alias="submittedExternally")


class ComplianceReasoner(ABC):
    """Clean interface for deterministic, fake, or injected-LLM reasoners."""

    @abstractmethod
    def generateAssessmentNarrative(self, bundle: RAGContextBundle) -> StructuredNarrative:
        """Generate a bounded assessment narrative from supplied context only."""

    @abstractmethod
    def generateExecutiveSummary(self, assurance_package: Mapping[str, Any]) -> StructuredExecutiveSummary:
        """Generate an executive summary from an assurance package dictionary only."""

    @abstractmethod
    def draftPoamRecommendation(self, bundle: RAGContextBundle) -> StructuredPoamDraft:
        """Draft local POA&M recommendation text from supplied context only."""


def _all_evidence_ids(bundle: RAGContextBundle) -> list[str]:
    return sorted({evidence.evidence_id for evidence in bundle.selected_evidence})


def _all_finding_ids(bundle: RAGContextBundle) -> list[str]:
    return sorted({finding.finding_id for finding in bundle.selected_findings})


def _scope_control_id(bundle: RAGContextBundle) -> str | None:
    if bundle.parsed_scope.control_ids:
        return bundle.parsed_scope.control_ids[0]
    if bundle.selected_controls:
        return bundle.selected_controls[0].control_id
    return None


def _bundle_has_insufficient_evidence(bundle: RAGContextBundle) -> bool:
    return bool(bundle.missing_evidence_summary) or not bundle.selected_evidence


def _enforce_bundle_insufficiency(
    output: StructuredNarrative | StructuredPoamDraft,
    bundle: RAGContextBundle,
) -> None:
    if not _bundle_has_insufficient_evidence(bundle):
        return
    if output.status != "INSUFFICIENT_EVIDENCE":
        raise ValueError("reasoner output must use INSUFFICIENT_EVIDENCE when the RAG bundle has missing evidence")
    if not output.missing_evidence:
        raise ValueError("reasoner output must carry missingEvidence from an insufficient RAG bundle")


def _manifest_insufficient_controls(assurance_package: Mapping[str, Any]) -> list[str]:
    manifest = assurance_package.get("manifest") or {}
    return [str(item) for item in manifest.get("controlsWithInsufficientEvidence") or [] if str(item).strip()]


def _truncate(text: str, limit: int = 220) -> str:
    clean = " ".join(str(text or "").split())
    return clean if len(clean) <= limit else clean[: limit - 3].rstrip() + "..."


def _model_text(output: DomainModel) -> str:
    data = output.model_dump(mode="json", by_alias=True)
    chunks: list[str] = []

    def walk(value: Any) -> None:
        if isinstance(value, str):
            chunks.append(value)
        elif isinstance(value, Mapping):
            for child in value.values():
                walk(child)
        elif isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
            for child in value:
                walk(child)

    walk(data)
    return "\n".join(chunks)


def _claim_guardrails(
    claims: Sequence[StructuredClaim],
    *,
    policy: GuardrailPolicy,
) -> list[Any]:
    results: list[Any] = []
    for claim in claims:
        results.append(
            evaluate_unsupported_claim(
                conclusion=claim.text,
                evidence_ids=claim.evidence_ids,
            )
        )
    return results


def validate_reasoner_output(
    output: StructuredNarrative | StructuredExecutiveSummary | StructuredPoamDraft,
    *,
    policy: GuardrailPolicy | None = None,
) -> StructuredNarrative | StructuredExecutiveSummary | StructuredPoamDraft:
    """Validate schema and guardrails for reasoner output.

    Raises ``ValueError`` when an output would make unsupported claims, use
    certification language without review support, recommend a blocked action,
    omit required review gates, or fail its generated schema.
    """

    policy = policy or GuardrailPolicy()
    schema_report = validate_model_schema(output)
    if not schema_report.valid:
        raise ValueError("reasoner output schema invalid: " + "; ".join(schema_report.errors))

    if output.status == "COMPLIANT":
        raise ValueError("reasoner output cannot emit final COMPLIANT status")
    if not output.human_review_required:
        raise ValueError("reasoner output must require human review")

    results = [
        evaluate_certification_language(text=_model_text(output), policy=policy),
        evaluate_destructive_action(action_text=_model_text(output), policy=policy),
    ]
    if isinstance(output, StructuredNarrative):
        results.extend(_claim_guardrails(output.observations, policy=policy))
        if output.status == "INSUFFICIENT_EVIDENCE" and not output.missing_evidence:
            raise ValueError("INSUFFICIENT_EVIDENCE narrative must include missingEvidence")
    elif isinstance(output, StructuredExecutiveSummary):
        results.extend(_claim_guardrails(output.top_risks, policy=policy))
    elif isinstance(output, StructuredPoamDraft):
        if output.status == "INSUFFICIENT_EVIDENCE" and not output.missing_evidence:
            raise ValueError("INSUFFICIENT_EVIDENCE POA&M draft must include missingEvidence")
        if output.status != "INSUFFICIENT_EVIDENCE" and not output.evidence_ids:
            results.append(
                evaluate_unsupported_claim(
                    conclusion=output.description,
                    evidence_ids=output.evidence_ids,
                )
            )
        if output.submitted_externally:
            raise ValueError("POA&M drafts must never be submitted externally by the reasoner")

    results.extend(detect_prompt_injection([_model_text(output)], policy=policy))
    enforce_guardrails(results)
    return output


class FakeComplianceReasoner(ComplianceReasoner):
    """Offline deterministic reasoner for tests and eval harnesses."""

    def __init__(self, *, policy: GuardrailPolicy | None = None) -> None:
        self.policy = policy or GuardrailPolicy()

    def generateAssessmentNarrative(self, bundle: RAGContextBundle) -> StructuredNarrative:
        control_id = _scope_control_id(bundle)
        missing = list(bundle.missing_evidence_summary)
        if missing or not bundle.selected_evidence:
            output = StructuredNarrative(
                status="INSUFFICIENT_EVIDENCE",
                controlId=control_id,
                summary="INSUFFICIENT_EVIDENCE: selected context does not contain enough fresh in-scope evidence.",
                observations=[],
                recommendations=["Request fresh in-scope evidence and route the result for human review."],
                missingEvidence=missing or ["No selected evidence is available for the scoped request."],
                unsupportedClaimsBlocked=0,
                humanReviewRequired=True,
                schemaValid=True,
            )
            return validate_reasoner_output(output, policy=self.policy)  # type: ignore[return-value]

        observations = [
            StructuredClaim(
                claimId=f"claim-{idx:03d}",
                text=_truncate(evidence.normalized_summary),
                evidenceIds=[evidence.evidence_id],
            )
            for idx, evidence in enumerate(bundle.selected_evidence, start=1)
        ]
        output = StructuredNarrative(
            status="NEEDS_HUMAN_REVIEW",
            controlId=control_id,
            summary="Evidence-backed observations are ready for reviewer evaluation.",
            observations=observations,
            recommendations=["Reviewer should compare cited evidence against the control requirement before any assessment decision."],
            missingEvidence=[],
            unsupportedClaimsBlocked=0,
            humanReviewRequired=True,
            schemaValid=True,
        )
        return validate_reasoner_output(output, policy=self.policy)  # type: ignore[return-value]

    def generateExecutiveSummary(self, assurance_package: Mapping[str, Any]) -> StructuredExecutiveSummary:
        manifest = assurance_package.get("manifest") or {}
        system = str(manifest.get("system") or assurance_package.get("system") or "Unknown System")
        evidence = list(assurance_package.get("evidence") or [])
        findings = list(assurance_package.get("findings") or [])
        evidence_ids = sorted({str(row.get("evidenceId")) for row in evidence if row.get("evidenceId")})
        top_risks: list[StructuredClaim] = []
        for idx, finding in enumerate(findings, start=1):
            if str(finding.get("status") or "").upper() != "OPEN":
                continue
            if str(finding.get("severity") or "").upper() not in {"CRITICAL", "HIGH"}:
                continue
            claim_evidence_ids = [str(eid) for eid in finding.get("evidenceIds") or [] if str(eid).strip()]
            if not claim_evidence_ids:
                continue
            title = str(finding.get("title") or finding.get("findingId") or "Open high-risk finding")
            top_risks.append(
                StructuredClaim(
                    claimId=f"risk-{idx:03d}",
                    text=_truncate(title),
                    evidenceIds=claim_evidence_ids,
                )
            )

        insufficient = [str(item) for item in manifest.get("controlsWithInsufficientEvidence") or []]
        output = StructuredExecutiveSummary(
            status="NEEDS_HUMAN_REVIEW",
            system=system,
            summary="Assurance package is summarized for reviewer evaluation only.",
            topRisks=top_risks,
            controlsWithInsufficientEvidence=insufficient,
            evidenceIds=evidence_ids,
            unsupportedClaimsBlocked=0,
            humanReviewRequired=True,
            schemaValid=True,
        )
        return validate_reasoner_output(output, policy=self.policy)  # type: ignore[return-value]

    def draftPoamRecommendation(self, bundle: RAGContextBundle) -> StructuredPoamDraft:
        control_id = _scope_control_id(bundle)
        missing = list(bundle.missing_evidence_summary)
        if missing or not bundle.selected_evidence:
            output = StructuredPoamDraft(
                status="INSUFFICIENT_EVIDENCE",
                controlId=control_id,
                title="Evidence request for reviewer triage",
                description="INSUFFICIENT_EVIDENCE: fresh in-scope evidence is required before drafting remediation details.",
                findingIds=_all_finding_ids(bundle),
                evidenceIds=[],
                recommendedMilestones=["Collect or refresh scoped evidence.", "Run deterministic validators.", "Route recommendation to a human reviewer."],
                missingEvidence=missing or ["No selected evidence is available for the scoped request."],
                unsupportedClaimsBlocked=0,
                humanReviewRequired=True,
                schemaValid=True,
                submittedExternally=False,
            )
            return validate_reasoner_output(output, policy=self.policy)  # type: ignore[return-value]

        findings = bundle.selected_findings
        title = "Reviewer triage for cited security findings" if findings else "Reviewer triage for cited control evidence"
        output = StructuredPoamDraft(
            status="NEEDS_HUMAN_REVIEW",
            controlId=control_id,
            title=title,
            description="Draft only: reviewer should evaluate cited evidence and determine whether POA&M action is appropriate.",
            findingIds=_all_finding_ids(bundle),
            evidenceIds=_all_evidence_ids(bundle),
            recommendedMilestones=["Review cited evidence.", "Confirm remediation ownership and target dates.", "Record the human decision before package publication."],
            missingEvidence=[],
            unsupportedClaimsBlocked=0,
            humanReviewRequired=True,
            schemaValid=True,
            submittedExternally=False,
        )
        return validate_reasoner_output(output, policy=self.policy)  # type: ignore[return-value]


class InjectedLLMComplianceReasoner(ComplianceReasoner):
    """LLM-compatible adapter using caller-supplied JSON transport.

    The transport is injected so this class never owns network configuration and
    unit tests can use pure mocks. The transport receives a task name and a
    bounded JSON payload, then returns either a JSON string or mapping matching
    the expected structured output model.
    """

    def __init__(self, transport: ReasonerTransport, *, policy: GuardrailPolicy | None = None) -> None:
        self.transport = transport
        self.policy = policy or GuardrailPolicy()

    def _invoke(
        self,
        task: str,
        payload: Mapping[str, Any],
        output_cls: type[StructuredNarrative] | type[StructuredExecutiveSummary] | type[StructuredPoamDraft],
    ) -> StructuredNarrative | StructuredExecutiveSummary | StructuredPoamDraft:
        raw = self.transport(task, payload)
        data = json.loads(raw) if isinstance(raw, str) else dict(raw)
        output = output_cls.model_validate(data)
        return validate_reasoner_output(output, policy=self.policy)

    def generateAssessmentNarrative(self, bundle: RAGContextBundle) -> StructuredNarrative:
        payload = {
            "instructions": bundle.instructions_for_llm,
            "ragContextBundle": bundle.model_dump(mode="json", by_alias=True),
            "outputSchema": StructuredNarrative.model_json_schema(by_alias=True),
        }
        output = self._invoke("generateAssessmentNarrative", payload, StructuredNarrative)
        _enforce_bundle_insufficiency(output, bundle)
        return output  # type: ignore[return-value]

    def generateExecutiveSummary(self, assurance_package: Mapping[str, Any]) -> StructuredExecutiveSummary:
        payload = {
            "assurancePackage": dict(assurance_package),
            "outputSchema": StructuredExecutiveSummary.model_json_schema(by_alias=True),
            "rules": [
                "Use only supplied assurancePackage fields.",
                "Every factual risk must include evidenceIds.",
                "Do not certify compliance or approve the package.",
                "Require human review for conclusions.",
            ],
        }
        output = self._invoke("generateExecutiveSummary", payload, StructuredExecutiveSummary)
        expected_insufficient = set(_manifest_insufficient_controls(assurance_package))
        if expected_insufficient and not expected_insufficient <= set(output.controls_with_insufficient_evidence):
            raise ValueError("executive summary must preserve controlsWithInsufficientEvidence from the assurance package")
        return output  # type: ignore[return-value]

    def draftPoamRecommendation(self, bundle: RAGContextBundle) -> StructuredPoamDraft:
        payload = {
            "instructions": bundle.instructions_for_llm,
            "ragContextBundle": bundle.model_dump(mode="json", by_alias=True),
            "outputSchema": StructuredPoamDraft.model_json_schema(by_alias=True),
            "rules": [
                "Draft only; do not submit externally.",
                "Every factual remediation statement must cite evidenceIds or explicit missingEvidence.",
                "Do not close, suppress, waive, or approve findings or POA&Ms.",
            ],
        }
        output = self._invoke("draftPoamRecommendation", payload, StructuredPoamDraft)
        _enforce_bundle_insufficiency(output, bundle)
        return output  # type: ignore[return-value]


__all__ = [
    "ComplianceReasoner",
    "FakeComplianceReasoner",
    "InjectedLLMComplianceReasoner",
    "ReasonerTransport",
    "StructuredClaim",
    "StructuredExecutiveSummary",
    "StructuredNarrative",
    "StructuredPoamDraft",
    "validate_reasoner_output",
]
