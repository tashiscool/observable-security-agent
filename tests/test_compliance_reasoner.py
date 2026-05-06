"""Tests for optional compliance reasoner adapters."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

import pytest

from ai.compliance_reasoner import (
    FakeComplianceReasoner,
    InjectedLLMComplianceReasoner,
    StructuredClaim,
    StructuredNarrative,
    validate_reasoner_output,
)
from core.domain_models import ControlRequirement, EvidenceArtifact, NormalizedFinding
from core.rag_context_builder import RAGContextBundle, build_rag_context


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def _control(control_id: str = "RA-5") -> ControlRequirement:
    return ControlRequirement(
        controlId=control_id,
        family=control_id.split("-")[0],
        title=f"{control_id} control",
        requirementText=f"{control_id} requirement text.",
        parameters={},
        framework="NIST SP 800-53",
        baseline="moderate",
        responsibility="shared",
        sourceRef=f"controls#{control_id}",
    )


def _evidence(evidence_id: str = "ev-001", *, control_ids: list[str] | None = None) -> EvidenceArtifact:
    return EvidenceArtifact(
        evidenceId=evidence_id,
        sourceSystem="nessus",
        sourceType="vulnerability_scan_json",
        collectedAt=NOW,
        observedAt=NOW,
        accountId="123456789012",
        region="us-east-1",
        resourceId="i-001",
        resourceArn="arn:aws:ec2:us-east-1:123456789012:instance/i-001",
        resourceType="ec2.instance",
        scanner="nessus",
        findingId=None,
        vulnerabilityId=None,
        packageName=None,
        packageVersion=None,
        imageDigest=None,
        controlIds=control_ids or ["RA-5"],
        rawRef=f"raw/nessus.json#{evidence_id}",
        normalizedSummary="Credentialed vulnerability scan evidence was collected.",
        trustLevel="authoritative",
        freshnessStatus="current",
    )


def _finding() -> NormalizedFinding:
    return NormalizedFinding(
        findingId="nf-001",
        sourceSystem="nessus",
        scanner="nessus",
        title="Open high vulnerability",
        description="Package patch required.",
        severity="HIGH",
        status="OPEN",
        vulnerabilityId="CVE-2026-0001",
        packageName="openssl",
        packageVersion="1.0",
        fixedVersion="1.1",
        accountId="123456789012",
        region="us-east-1",
        resourceId="i-001",
        imageDigest=None,
        firstObservedAt=NOW,
        lastObservedAt=NOW,
        evidenceIds=["ev-001"],
        controlIds=["RA-5"],
    )


def _bundle(*, include_evidence: bool = True, control_id: str = "RA-5") -> RAGContextBundle:
    return build_rag_context(
        user_request=f"Assess {control_id}.",
        control_ids=[control_id],
        evidence_artifacts=[_evidence()] if include_evidence else [],
        findings=[_finding()] if include_evidence else [],
        controls=[_control(control_id)],
    )


def _package() -> dict[str, Any]:
    return {
        "manifest": {
            "system": "Fixture System",
            "controlsWithInsufficientEvidence": ["AC-2"],
        },
        "evidence": [_evidence().model_dump(mode="json", by_alias=True)],
        "findings": [_finding().model_dump(mode="json", by_alias=True)],
    }


def test_valid_structured_output_accepted() -> None:
    output = StructuredNarrative(
        status="NEEDS_HUMAN_REVIEW",
        controlId="RA-5",
        summary="Evidence-backed observations are ready for reviewer evaluation.",
        observations=[
            StructuredClaim(
                claimId="claim-001",
                text="Credentialed scan evidence was collected.",
                evidenceIds=["ev-001"],
            )
        ],
        recommendations=["Reviewer should evaluate cited evidence before recording a decision."],
        missingEvidence=[],
        unsupportedClaimsBlocked=0,
        humanReviewRequired=True,
        schemaValid=True,
    )

    assert validate_reasoner_output(output) == output


def test_missing_evidence_ids_rejected() -> None:
    output = StructuredNarrative(
        status="NEEDS_HUMAN_REVIEW",
        controlId="RA-5",
        summary="Evidence-backed observations are ready for reviewer evaluation.",
        observations=[
            StructuredClaim(
                claimId="claim-001",
                text="Credentialed scan evidence was collected.",
                evidenceIds=[],
            )
        ],
        recommendations=[],
        missingEvidence=[],
        unsupportedClaimsBlocked=0,
        humanReviewRequired=True,
        schemaValid=True,
    )

    with pytest.raises(ValueError, match="unsupported_compliance_claim"):
        validate_reasoner_output(output)


def test_unsupported_compliance_claim_rejected_by_guardrail() -> None:
    output = StructuredNarrative(
        status="NEEDS_HUMAN_REVIEW",
        controlId="RA-5",
        summary="The control is compliant.",
        observations=[
            StructuredClaim(
                claimId="claim-001",
                text="Credentialed scan evidence was collected.",
                evidenceIds=["ev-001"],
            )
        ],
        recommendations=[],
        missingEvidence=[],
        unsupportedClaimsBlocked=0,
        humanReviewRequired=True,
        schemaValid=True,
    )

    with pytest.raises(ValueError, match="certification_language"):
        validate_reasoner_output(output)


def test_insufficient_evidence_produces_insufficient_status() -> None:
    reasoner = FakeComplianceReasoner()
    output = reasoner.generateAssessmentNarrative(_bundle(include_evidence=False, control_id="AU-6"))

    assert output.status == "INSUFFICIENT_EVIDENCE"
    assert output.missing_evidence
    assert output.human_review_required


def test_fake_reasoner_allows_offline_evals() -> None:
    reasoner = FakeComplianceReasoner()
    bundle = _bundle()

    narrative = reasoner.generateAssessmentNarrative(bundle)
    executive = reasoner.generateExecutiveSummary(_package())
    poam = reasoner.draftPoamRecommendation(bundle)

    assert narrative.observations[0].evidence_ids == ["ev-001"]
    assert executive.top_risks[0].evidence_ids == ["ev-001"]
    assert poam.evidence_ids == ["ev-001"]
    assert not poam.submitted_externally


def test_injected_reasoner_uses_dependency_injected_transport() -> None:
    seen_payloads: list[tuple[str, Mapping[str, Any]]] = []

    def transport(task: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        seen_payloads.append((task, payload))
        return {
            "status": "NEEDS_HUMAN_REVIEW",
            "controlId": "RA-5",
            "summary": "Evidence-backed observations are ready for reviewer evaluation.",
            "observations": [
                {
                    "claimId": "claim-001",
                    "text": "Credentialed scan evidence was collected.",
                    "evidenceIds": ["ev-001"],
                }
            ],
            "recommendations": ["Reviewer should evaluate cited evidence before recording a decision."],
            "missingEvidence": [],
            "unsupportedClaimsBlocked": 0,
            "humanReviewRequired": True,
            "schemaValid": True,
        }

    reasoner = InjectedLLMComplianceReasoner(transport)
    output = reasoner.generateAssessmentNarrative(_bundle())

    assert output.observations[0].evidence_ids == ["ev-001"]
    assert seen_payloads[0][0] == "generateAssessmentNarrative"
    assert "ragContextBundle" in seen_payloads[0][1]


def test_injected_reasoner_cannot_ignore_missing_bundle_evidence() -> None:
    def transport(_: str, __: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status": "NEEDS_HUMAN_REVIEW",
            "controlId": "AU-6",
            "summary": "Evidence-backed observations are ready for reviewer evaluation.",
            "observations": [],
            "recommendations": [],
            "missingEvidence": [],
            "unsupportedClaimsBlocked": 0,
            "humanReviewRequired": True,
            "schemaValid": True,
        }

    reasoner = InjectedLLMComplianceReasoner(transport)

    with pytest.raises(ValueError, match="INSUFFICIENT_EVIDENCE"):
        reasoner.generateAssessmentNarrative(_bundle(include_evidence=False, control_id="AU-6"))


def test_injected_executive_summary_preserves_insufficient_controls() -> None:
    def transport(_: str, __: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "status": "NEEDS_HUMAN_REVIEW",
            "system": "Fixture System",
            "summary": "Assurance package is summarized for reviewer evaluation only.",
            "topRisks": [],
            "controlsWithInsufficientEvidence": [],
            "evidenceIds": ["ev-001"],
            "unsupportedClaimsBlocked": 0,
            "humanReviewRequired": True,
            "schemaValid": True,
        }

    reasoner = InjectedLLMComplianceReasoner(transport)

    with pytest.raises(ValueError, match="controlsWithInsufficientEvidence"):
        reasoner.generateExecutiveSummary(_package())
