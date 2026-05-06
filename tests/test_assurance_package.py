"""Tests for machine-readable assurance package generation."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.assurance_package import (
    build_and_write_assurance_package,
    build_assurance_package,
    validate_assurance_package_document,
    write_assurance_package,
)
from core.control_mapping_engine import map_controls
from core.deterministic_validators import (
    aggregate_assessment_result,
    validate_required_control_evidence,
    validate_unresolved_vulnerabilities,
)
from core.domain_models import AgentRecommendation, ControlRequirement, EvidenceArtifact, HumanReviewDecision, NormalizedFinding
from core.human_review import attach_review_decisions_to_assessment
from core.rag_context_builder import build_rag_context
from core.recommendation_generator import generate_agent_recommendations


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def _control(control_id: str) -> ControlRequirement:
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


def _controls() -> list[ControlRequirement]:
    return [_control("AC-2"), _control("RA-5"), _control("SI-2")]


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
        normalizedSummary="Credentialed vulnerability scan evidence.",
        trustLevel="authoritative",
        freshnessStatus="current",
    )


def _finding() -> NormalizedFinding:
    return NormalizedFinding(
        findingId="nf-001",
        sourceSystem="nessus",
        scanner="nessus",
        title="Open vulnerability",
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


def _fixture_package_inputs(*, with_human_review: bool = True):
    controls = _controls()
    evidence = [_evidence()]
    findings = [_finding()]
    mappings = map_controls(evidence, findings, controls)
    validations = [
        validate_required_control_evidence(_control("RA-5"), evidence, timestamp=NOW),
        validate_required_control_evidence(_control("AC-2"), evidence, timestamp=NOW),
        validate_unresolved_vulnerabilities(findings, timestamp=NOW),
    ]
    assessment = aggregate_assessment_result(
        assessment_id="assess-ra5",
        control=_control("RA-5"),
        validator_results=[validations[0], validations[2]],
        created_at=NOW,
    )
    missing_assessment = aggregate_assessment_result(
        assessment_id="assess-ac2",
        control=_control("AC-2"),
        validator_results=[validations[1]],
        created_at=NOW,
    )
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=evidence,
        findings=findings,
        controls=controls,
        control_mappings=mappings,
        validation_results=validations,
    )
    recommendations = generate_agent_recommendations(bundle, validations, mappings)
    review_decisions: list[HumanReviewDecision] = []
    assessments = [assessment, missing_assessment]
    if with_human_review:
        reviewed = next((rec for rec in recommendations if rec.evidence_ids), recommendations[0])
        decision = HumanReviewDecision(
            reviewDecisionId="hrd-001",
            recommendationId=reviewed.recommendation_id,
            controlId=reviewed.control_id,
            findingIds=reviewed.finding_ids,
            evidenceIds=reviewed.evidence_ids,
            reviewer="ISSO",
            decision="ACCEPTED",
            justification="Recommendation is appropriate for package review.",
            timestamp=NOW,
        )
        review_decisions.append(decision)
        assessments = [attach_review_decisions_to_assessment(a, review_decisions) for a in assessments]
    return {
        "controls": controls,
        "evidence": evidence,
        "findings": findings,
        "control_mappings": mappings,
        "validation_results": validations,
        "agent_recommendations": recommendations,
        "human_review_decisions": review_decisions,
        "assessment_results": assessments,
    }


def _build_package(**overrides):
    kwargs = {
        "package_id": "pkg-001",
        "system": "Fixture System",
        "assessment_period_start": NOW,
        "assessment_period_end": NOW,
        "framework": "NIST SP 800-53",
        "baseline": "moderate",
        "generated_at": NOW,
        "package_status": "READY_FOR_REVIEW",
        **_fixture_package_inputs(),
    }
    kwargs.update(overrides)
    return build_assurance_package(**kwargs)


def test_package_generated_from_fixture_data(tmp_path: Path) -> None:
    package = _build_package()
    path = write_assurance_package(tmp_path, package=package)
    data = json.loads(path.read_text(encoding="utf-8"))

    assert path.name == "assurance-package.json"
    assert data["manifest"]["packageId"] == "pkg-001"
    assert data["manifest"]["evidenceCount"] == 1
    assert data["manifest"]["findingCount"] == 1
    assert data["evidence"][0]["evidenceId"] == "ev-001"
    assert data["controls"][0]["evidenceIds"] == []
    assert data["controls"][1]["evidenceIds"] == ["ev-001"]


def test_schema_validation_passes() -> None:
    package = _build_package()
    report = validate_assurance_package_document(package)

    assert report["valid"], report["errors"]
    assert package["manifest"]["schemaValidation"] == "PASS"


def test_missing_evidence_appears_in_controls_with_insufficient_evidence() -> None:
    package = _build_package()

    assert "AC-2" in package["manifest"]["controlsWithInsufficientEvidence"]


def test_package_cannot_be_approved_without_human_review() -> None:
    with pytest.raises(ValueError, match="cannot be APPROVED"):
        _build_package(
            package_status="APPROVED",
            **_fixture_package_inputs(with_human_review=False),
        )


def test_approved_package_requires_human_review_data() -> None:
    package = _build_package(package_status="APPROVED")

    assert package["manifest"]["packageStatus"] == "APPROVED"
    assert package["manifest"]["humanReviewedRecommendations"] == 1


def test_stable_json_output_snapshot(tmp_path: Path) -> None:
    package = _build_package()
    first = build_and_write_assurance_package(
        tmp_path,
        package_id="pkg-001",
        system="Fixture System",
        assessment_period_start=NOW,
        assessment_period_end=NOW,
        framework="NIST SP 800-53",
        baseline="moderate",
        generated_at=NOW,
        package_status="READY_FOR_REVIEW",
        **_fixture_package_inputs(),
    )
    first_text = first.read_text(encoding="utf-8")
    second = write_assurance_package(tmp_path, package=package)
    second_text = second.read_text(encoding="utf-8")

    assert first_text == second_text
    snapshot = json.loads(first_text)
    assert list(snapshot.keys()) == [
        "agentRecommendations",
        "assessmentResults",
        "audit",
        "controlMappings",
        "controls",
        "evidence",
        "findings",
        "humanReviewDecisions",
        "manifest",
        "validationResults",
    ]
    assert snapshot["manifest"]["unsupportedClaimsBlockedCount"] >= 1


def test_invalid_package_schema_fails_before_write(tmp_path: Path) -> None:
    package = _build_package()
    del package["manifest"]["packageId"]

    with pytest.raises(ValueError, match="schema validation failed"):
        write_assurance_package(tmp_path, package=package)
