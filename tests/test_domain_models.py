"""Tests for core agentic compliance operations domain models."""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from core.domain_models import (
    AgentRecommendation,
    AgentRunLog,
    AssessmentResult,
    AssurancePackageManifest,
    CloudAsset,
    ControlMapping,
    ControlRequirement,
    EvidenceArtifact,
    HumanReviewDecision,
    NormalizedFinding,
    model_from_json,
    model_to_json,
    model_to_python_dict,
    validate_model_schema,
)


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def evidence_artifact_payload() -> dict:
    return {
        "evidenceId": "ev-001",
        "sourceSystem": "aws",
        "sourceType": "cloudtrail",
        "collectedAt": NOW.isoformat(),
        "observedAt": NOW.isoformat(),
        "accountId": "123456789012",
        "region": "us-east-1",
        "resourceId": "i-001",
        "resourceArn": "arn:aws:ec2:us-east-1:123456789012:instance/i-001",
        "resourceType": "ec2.instance",
        "scanner": None,
        "findingId": None,
        "vulnerabilityId": None,
        "packageName": None,
        "packageVersion": None,
        "imageDigest": None,
        "controlIds": ["CM-8", "AU-6"],
        "rawRef": "raw/aws/123456789012/us-east-1/cloudtrail/events.json#0",
        "normalizedSummary": "CloudTrail management event for instance i-001.",
        "trustLevel": "authoritative",
        "freshnessStatus": "current",
    }


def test_evidence_artifact_valid_round_trip_and_schema_validation() -> None:
    artifact = EvidenceArtifact.model_validate(evidence_artifact_payload())

    assert artifact.evidence_id == "ev-001"
    serialized = model_to_json(artifact)
    assert '"evidenceId"' in serialized
    assert '"evidence_id"' not in serialized
    assert model_from_json(EvidenceArtifact, serialized) == artifact

    report = validate_model_schema(artifact)
    assert report.valid, report.errors


def test_evidence_artifact_missing_required_field_fails() -> None:
    payload = evidence_artifact_payload()
    del payload["evidenceId"]

    with pytest.raises(ValidationError) as exc:
        EvidenceArtifact.model_validate(payload)

    assert "evidenceId" in str(exc.value)


def test_evidence_artifact_invalid_trust_level_fails() -> None:
    payload = evidence_artifact_payload()
    payload["trustLevel"] = "just_trust_me"

    with pytest.raises(ValidationError):
        EvidenceArtifact.model_validate(payload)


def test_normalized_finding_valid_and_rejects_invalid_status() -> None:
    finding = NormalizedFinding.model_validate(
        {
            "findingId": "nf-001",
            "sourceSystem": "nessus",
            "scanner": "nessus",
            "title": "Outdated package",
            "description": "Package requires remediation.",
            "severity": "HIGH",
            "status": "OPEN",
            "vulnerabilityId": "CVE-2026-0001",
            "packageName": "openssl",
            "packageVersion": "1.0",
            "fixedVersion": "1.1",
            "accountId": "123456789012",
            "region": "us-east-1",
            "resourceId": "i-001",
            "imageDigest": None,
            "firstObservedAt": NOW.isoformat(),
            "lastObservedAt": NOW.isoformat(),
            "evidenceIds": ["ev-001"],
            "controlIds": ["RA-5"],
        }
    )
    assert finding.finding_id == "nf-001"

    bad = json.loads(model_to_json(finding))
    bad["status"] = "COMPLIANT"
    with pytest.raises(ValidationError):
        NormalizedFinding.model_validate(bad)


def test_cloud_asset_valid_object() -> None:
    asset = CloudAsset(
        assetId="asset-001",
        provider="aws",
        accountId="123456789012",
        region="us-east-1",
        resourceId="i-001",
        resourceArn="arn:aws:ec2:us-east-1:123456789012:instance/i-001",
        resourceType="ec2.instance",
        name="prod-api",
        tags={"Environment": "prod"},
        evidenceIds=["ev-001"],
        controlIds=["CM-8"],
    )
    assert model_to_python_dict(asset)["resourceId"] == "i-001"


def test_control_requirement_and_mapping_round_trip() -> None:
    req = ControlRequirement(
        controlId="CM-8",
        family="CM",
        title="System Component Inventory",
        requirementText="Maintain an accurate inventory.",
        parameters={"frequency": "monthly"},
        framework="NIST SP 800-53",
        baseline="moderate",
        responsibility="shared",
        sourceRef="config/control-crosswalk.yaml#CM-8",
    )
    mapping = ControlMapping(
        mappingId="map-001",
        sourceControlId="CM-8",
        targetControlId="KSI-CM-8",
        sourceFramework="NIST SP 800-53",
        targetFramework="FedRAMP 20x",
        relationship="supports",
        rationale="Inventory evidence supports KSI inventory assertions.",
        evidenceIds=["ev-001"],
        sourceRef="mappings/rev5-to-20x-ksi-crosswalk.csv#CM-8",
    )

    assert model_from_json(ControlRequirement, model_to_json(req)) == req
    assert model_from_json(ControlMapping, model_to_json(mapping)) == mapping


def test_assessment_result_uses_required_status_vocabulary() -> None:
    result = AssessmentResult(
        assessmentId="assess-001",
        controlId="CM-8",
        status="INSUFFICIENT_EVIDENCE",
        summary="Inventory evidence is incomplete.",
        evidenceIds=["ev-001"],
        findingIds=["nf-001"],
        gaps=["Missing authoritative inventory export."],
        recommendations=["Collect inventory export and re-run validation."],
        confidence=0.76,
        humanReviewRequired=True,
        createdAt=NOW,
    )
    assert result.status == "INSUFFICIENT_EVIDENCE"

    payload = model_to_python_dict(result)
    payload["status"] = "PASS"
    with pytest.raises(ValidationError):
        AssessmentResult.model_validate(payload)


def test_agent_recommendation_valid_and_invalid_confidence() -> None:
    rec = AgentRecommendation(
        recommendationId="rec-001",
        controlId="RA-5",
        findingIds=["nf-001"],
        evidenceIds=["ev-001"],
        recommendationType="collect_evidence",
        summary="Collect credentialed scan evidence.",
        rationale="The finding lacks credentialed scanner proof.",
        confidence=0.8,
        blockedUnsupportedClaims=True,
        humanReviewRequired=True,
    )
    assert rec.blocked_unsupported_claims is True

    data = model_to_python_dict(rec)
    data["confidence"] = 2.0
    with pytest.raises(ValidationError):
        AgentRecommendation.model_validate(data)


def test_human_review_decision_valid_and_invalid_decision() -> None:
    decision = HumanReviewDecision(
        reviewDecisionId="hrd-001",
        recommendationId="rec-001",
        reviewer="ISSO",
        decision="needs_changes",
        justification="Evidence reference needs to point to the raw scanner export.",
        timestamp=NOW,
    )
    assert decision.reviewer == "ISSO"

    data = model_to_python_dict(decision)
    data["decision"] = "auto_approved"
    with pytest.raises(ValidationError):
        HumanReviewDecision.model_validate(data)


def test_assurance_package_manifest_valid() -> None:
    manifest = AssurancePackageManifest(
        manifestId="manifest-001",
        packageId="pkg-001",
        generatedAt=NOW,
        framework="FedRAMP 20x-style",
        baseline="moderate",
        assessmentResultIds=["assess-001"],
        evidenceIds=["ev-001"],
        findingIds=["nf-001"],
        controlIds=["CM-8"],
        artifactRefs=["fedramp20x-package.json", "assessor-summary.md"],
        schemaVersion="1.0",
    )
    assert validate_model_schema(manifest).valid


def test_agent_run_log_valid_model_name_optional_and_round_trip() -> None:
    run = AgentRunLog(
        agentRunId="run-001",
        workflow="assess",
        inputHash="sha256:abc123",
        startedAt=NOW,
        completedAt=NOW,
        evidenceIds=["ev-001"],
        controlIds=["CM-8"],
        decision="needs_human_review",
        confidence=0.67,
        schemaValid=True,
        unsupportedClaimsBlocked=True,
        humanReviewRequired=True,
        errors=[],
    )

    payload = model_to_python_dict(run)
    assert payload["modelName"] is None
    assert model_from_json(AgentRunLog, model_to_json(run)) == run


def test_agent_run_log_invalid_decision_fails() -> None:
    payload = model_to_python_dict(
        AgentRunLog(
            agentRunId="run-001",
            workflow="assess",
            inputHash="sha256:abc123",
            startedAt=NOW,
            completedAt=None,
            evidenceIds=["ev-001"],
            controlIds=["CM-8"],
            decision="blocked",
            confidence=0.67,
            schemaValid=True,
            unsupportedClaimsBlocked=True,
            humanReviewRequired=True,
            errors=[],
        )
    )
    payload["decision"] = "approved_control"

    with pytest.raises(ValidationError):
        AgentRunLog.model_validate(payload)
