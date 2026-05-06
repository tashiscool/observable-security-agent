"""Tests for deterministic AgentRecommendation generation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.control_mapping_engine import map_controls
from core.deterministic_validators import (
    validate_evidence_freshness,
    validate_required_control_evidence,
    validate_unresolved_vulnerabilities,
)
from core.domain_models import ControlMapping, ControlRequirement, EvidenceArtifact, NormalizedFinding, model_from_json, model_to_json
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
    return [_control("AC-2"), _control("CA-5"), _control("RA-5"), _control("SI-2")]


def _evidence(
    evidence_id: str = "ev-001",
    *,
    control_ids: list[str] | None = None,
    observed_at: datetime = NOW,
    freshness_status: str = "current",
    summary: str = "Credentialed vulnerability scan evidence.",
) -> EvidenceArtifact:
    return EvidenceArtifact(
        evidenceId=evidence_id,
        sourceSystem="nessus",
        sourceType="vulnerability_scan_json",
        collectedAt=observed_at,
        observedAt=observed_at,
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
        normalizedSummary=summary,
        trustLevel="authoritative",
        freshnessStatus=freshness_status,
    )


def _finding(
    finding_id: str = "nf-001",
    *,
    severity: str = "HIGH",
    status: str = "OPEN",
    evidence_ids: list[str] | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        findingId=finding_id,
        sourceSystem="nessus",
        scanner="nessus",
        title="Open vulnerability",
        description="Package patch required.",
        severity=severity,
        status=status,
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
        evidenceIds=evidence_ids or ["ev-001"],
        controlIds=["RA-5"],
    )


def _types(recs) -> set[str]:
    return {rec.recommendation_type for rec in recs}


def test_create_poam_for_open_high_vulnerability_without_existing_poam_signal() -> None:
    evidence = _evidence()
    finding = _finding()
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        findings=[finding],
        controls=_controls(),
    )

    recs = generate_agent_recommendations(bundle, [validate_unresolved_vulnerabilities([finding], timestamp=NOW)], [])

    assert "CREATE_POAM" in _types(recs)
    rec = next(r for r in recs if r.recommendation_type == "CREATE_POAM")
    assert rec.finding_ids == ["nf-001"]
    assert "ev-001" in rec.evidence_ids
    assert rec.human_review_required is True


def test_update_poam_when_existing_poam_signal_exists() -> None:
    evidence = _evidence()
    finding = _finding()
    poam_validator = validate_required_control_evidence(_control("CA-5"), [_evidence("ev-poam", control_ids=["CA-5"])], timestamp=NOW)
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        findings=[finding],
        controls=_controls(),
    )

    recs = generate_agent_recommendations(bundle, [poam_validator], [])

    assert "UPDATE_POAM" in _types(recs)


def test_request_rescan_for_stale_scan_evidence() -> None:
    stale = _evidence("ev-stale", observed_at=NOW - timedelta(days=60), freshness_status="stale")
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[stale],
        controls=_controls(),
    )

    recs = generate_agent_recommendations(bundle, [validate_evidence_freshness([stale], timestamp=NOW)], [])

    rec = next(r for r in recs if r.recommendation_type == "REQUEST_RESCAN")
    assert rec.evidence_ids == ["ev-stale"]


def test_request_evidence_and_mark_insufficient_when_required_evidence_missing() -> None:
    bundle = build_rag_context(
        user_request="Assess AC-2.",
        control_ids=["AC-2"],
        evidence_artifacts=[_evidence("ev-ra5", control_ids=["RA-5"])],
        controls=_controls(),
    )
    missing_validator = validate_required_control_evidence(_control("AC-2"), [], timestamp=NOW)

    recs = generate_agent_recommendations(bundle, [missing_validator], [])

    assert "MARK_INSUFFICIENT_EVIDENCE" in _types(recs)
    assert "REQUEST_EVIDENCE" in _types(recs)
    for rec in recs:
        if rec.recommendation_type in {"MARK_INSUFFICIENT_EVIDENCE", "REQUEST_EVIDENCE"}:
            assert "missingEvidence:" in f"{rec.summary} {rec.rationale}"
            assert rec.human_review_required is True


def test_escalate_to_reviewer_for_needs_review_mapping() -> None:
    evidence = _evidence()
    mapping = ControlMapping(
        mappingId="map-review",
        sourceControlId="heuristic",
        targetControlId="NEEDS_REVIEW",
        sourceFramework="normalized-evidence",
        targetFramework="NIST SP 800-53",
        relationship="needs_review",
        rationale="No deterministic match.",
        evidenceIds=["ev-001"],
        findingIds=[],
        mappingConfidence="NEEDS_REVIEW",
        sourceRef="raw/nessus.json#ev-001#heuristic",
    )
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        controls=_controls(),
        control_mappings=[mapping],
    )

    recs = generate_agent_recommendations(bundle, [], [mapping])

    rec = next(r for r in recs if r.recommendation_type == "ESCALATE_TO_REVIEWER")
    assert rec.evidence_ids == ["ev-001"]


def test_accept_compensating_control_review_for_compensating_evidence() -> None:
    evidence = _evidence(summary="Compensating control evidence and risk acceptance memo for scanner limitation.")
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        controls=_controls(),
    )

    recs = generate_agent_recommendations(bundle, [], [])

    rec = next(r for r in recs if r.recommendation_type == "ACCEPT_COMPENSATING_CONTROL_REVIEW")
    assert rec.evidence_ids == ["ev-001"]
    assert rec.human_review_required is True


def test_draft_assessment_narrative_from_bounded_bundle() -> None:
    evidence = _evidence()
    bundle = build_rag_context(
        user_request="Draft RA-5 narrative.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        controls=_controls(),
    )

    recs = generate_agent_recommendations(bundle, [], [])

    rec = next(r for r in recs if r.recommendation_type == "DRAFT_ASSESSMENT_NARRATIVE")
    assert rec.evidence_ids == ["ev-001"]
    assert "avoid certification" in rec.rationale
    assert model_from_json(type(rec), model_to_json(rec)) == rec


def test_no_action_required_requires_validator_support_and_no_satisfaction_claim() -> None:
    evidence = _evidence()
    validator = validate_required_control_evidence(_control("RA-5"), [evidence], timestamp=NOW)
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        controls=_controls(),
        validation_results=[validator],
    )

    recs = generate_agent_recommendations(bundle, [validator], [])

    rec = next(r for r in recs if r.recommendation_type == "NO_ACTION_REQUIRED")
    assert rec.evidence_ids == ["ev-001"]
    assert rec.human_review_required is True
    assert "not a certification" in rec.rationale.lower()
    assert "control satisfied" not in rec.summary.lower()


def test_update_poam_can_be_inferred_from_ca5_mapping() -> None:
    evidence = _evidence()
    finding = _finding()
    mappings = map_controls([evidence], [finding], _controls())
    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[evidence],
        findings=[finding],
        controls=_controls(),
        control_mappings=mappings,
    )

    recs = generate_agent_recommendations(bundle, [], mappings)

    assert "UPDATE_POAM" in _types(recs)
