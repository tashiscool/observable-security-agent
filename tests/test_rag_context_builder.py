"""Tests for compliance RAG context selection."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from core.control_mapping_engine import map_controls
from core.deterministic_validators import validate_required_control_evidence
from core.domain_models import ControlRequirement, EvidenceArtifact, HumanReviewDecision, NormalizedFinding, model_from_json, model_to_json
from core.rag_context_builder import build_rag_context


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
    return [_control("AC-2"), _control("AU-6"), _control("RA-5"), _control("SI-2")]


def _evidence(
    evidence_id: str,
    *,
    control_ids: list[str],
    resource_id: str = "i-001",
    account_id: str = "123456789012",
    region: str = "us-east-1",
    observed_at: datetime = NOW,
    freshness_status: str = "current",
    trust_level: str = "authoritative",
    summary: str = "Credentialed vulnerability scan evidence.",
) -> EvidenceArtifact:
    return EvidenceArtifact(
        evidenceId=evidence_id,
        sourceSystem="nessus",
        sourceType="vulnerability_scan_json",
        collectedAt=observed_at,
        observedAt=observed_at,
        accountId=account_id,
        region=region,
        resourceId=resource_id,
        resourceArn=f"arn:aws:ec2:{region}:{account_id}:instance/{resource_id}",
        resourceType="ec2.instance",
        scanner="nessus",
        findingId=None,
        vulnerabilityId=None,
        packageName=None,
        packageVersion=None,
        imageDigest=None,
        controlIds=control_ids,
        rawRef=f"raw/nessus.json#{evidence_id}",
        normalizedSummary=summary,
        trustLevel=trust_level,
        freshnessStatus=freshness_status,
    )


def _finding(finding_id: str, *, evidence_ids: list[str], control_ids: list[str] | None = None, resource_id: str = "i-001") -> NormalizedFinding:
    return NormalizedFinding(
        findingId=finding_id,
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
        resourceId=resource_id,
        imageDigest=None,
        firstObservedAt=NOW,
        lastObservedAt=NOW,
        evidenceIds=evidence_ids,
        controlIds=control_ids or ["RA-5"],
    )


def test_exact_control_retrieval() -> None:
    evidence = [
        _evidence("ev-ra5", control_ids=["RA-5"]),
        _evidence("ev-ac2", control_ids=["AC-2"], summary="IAM account evidence."),
    ]

    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=evidence,
        controls=_controls(),
    )

    assert [c.control_id for c in bundle.selected_controls] == ["RA-5"]
    assert [e.evidence_id for e in bundle.selected_evidence] == ["ev-ra5"]
    assert any(x.source_id == "ev-ac2" and "WRONG_CONTROL" in x.reasons for x in bundle.excluded_sources)
    assert model_from_json(type(bundle), model_to_json(bundle)) == bundle


def test_exact_asset_retrieval() -> None:
    evidence = [
        _evidence("ev-target", control_ids=["RA-5"], resource_id="i-target"),
        _evidence("ev-other", control_ids=["RA-5"], resource_id="i-other"),
    ]

    bundle = build_rag_context(
        user_request="Assess asset i-target.",
        control_ids=["RA-5"],
        asset_ids=["i-target"],
        evidence_artifacts=evidence,
        controls=_controls(),
    )

    assert [e.resource_id for e in bundle.selected_evidence] == ["i-target"]
    assert any(x.source_id == "ev-other" and "WRONG_RESOURCE" in x.reasons for x in bundle.excluded_sources)


def test_stale_evidence_excluded_unless_requested() -> None:
    stale = _evidence(
        "ev-stale",
        control_ids=["RA-5"],
        observed_at=NOW - timedelta(days=60),
        freshness_status="stale",
    )

    bundle = build_rag_context(
        user_request="Assess RA-5.",
        control_ids=["RA-5"],
        evidence_artifacts=[stale],
        controls=_controls(),
    )
    included = build_rag_context(
        user_request="Assess RA-5 and include stale evidence.",
        control_ids=["RA-5"],
        evidence_artifacts=[stale],
        controls=_controls(),
    )

    assert not bundle.selected_evidence
    assert any(x.source_id == "ev-stale" and "STALE" in x.reasons for x in bundle.excluded_sources)
    assert [e.evidence_id for e in included.selected_evidence] == ["ev-stale"]


def test_wrong_account_excluded() -> None:
    evidence = [
        _evidence("ev-right", control_ids=["RA-5"], account_id="123456789012"),
        _evidence("ev-wrong", control_ids=["RA-5"], account_id="999999999999"),
    ]

    bundle = build_rag_context(
        user_request="Assess RA-5 in account 123456789012.",
        control_ids=["RA-5"],
        account_ids=["123456789012"],
        evidence_artifacts=evidence,
        controls=_controls(),
    )

    assert [e.evidence_id for e in bundle.selected_evidence] == ["ev-right"]
    assert any(x.source_id == "ev-wrong" and "WRONG_ACCOUNT" in x.reasons for x in bundle.excluded_sources)


def test_missing_evidence_summary_produced() -> None:
    bundle = build_rag_context(
        user_request="Assess AU-6.",
        control_ids=["AU-6"],
        evidence_artifacts=[_evidence("ev-ra5", control_ids=["RA-5"])],
        controls=_controls(),
    )

    assert not bundle.selected_evidence
    assert bundle.missing_evidence_summary == ["AU-6: no selected fresh, in-scope evidence is available."]


def test_context_bundle_contains_no_unsupported_source() -> None:
    evidence = [
        _evidence("ev-good", control_ids=["RA-5"]),
        _evidence("ev-low-trust", control_ids=["RA-5"], trust_level="self_reported"),
        _evidence("ev-wrong-region", control_ids=["RA-5"], region="us-west-2"),
        _evidence("ev-outside-window", control_ids=["RA-5"], observed_at=NOW - timedelta(days=90)),
    ]
    finding = _finding("nf-good", evidence_ids=["ev-good"])
    mappings = map_controls([evidence[0]], [finding], _controls())
    validation = validate_required_control_evidence(_control("RA-5"), [evidence[0]], timestamp=NOW)
    decision = HumanReviewDecision(
        reviewDecisionId="hrd-001",
        recommendationId="rec-RA-5",
        reviewer="ISSO",
        decision="needs_changes",
        justification="RA-5 needs refreshed scanner evidence before conclusion.",
        timestamp=NOW,
    )

    bundle = build_rag_context(
        user_request="Assess RA-5 for us-east-1.",
        control_ids=["RA-5"],
        region="us-east-1",
        time_window_start=NOW - timedelta(days=7),
        time_window_end=NOW + timedelta(days=1),
        evidence_artifacts=evidence,
        findings=[finding],
        controls=_controls(),
        control_mappings=mappings,
        validation_results=[validation],
        human_review_decisions=[decision],
    )

    assert [e.evidence_id for e in bundle.selected_evidence] == ["ev-good"]
    assert [f.finding_id for f in bundle.selected_findings] == ["nf-good"]
    assert [v.validator_id for v in bundle.selected_validation_results] == ["required_control_evidence"]
    assert [d.review_decision_id for d in bundle.selected_prior_human_decisions] == ["hrd-001"]
    excluded = {x.source_id: set(x.reasons) for x in bundle.excluded_sources}
    assert "LOW_TRUST" in excluded["ev-low-trust"]
    assert "WRONG_REGION" in excluded["ev-wrong-region"]
    assert "OUTSIDE_TIME_WINDOW" in excluded["ev-outside-window"]
    assert all(e.evidence_id.startswith("ev-good") for e in bundle.selected_evidence)


def test_instructions_include_evidence_only_rule() -> None:
    bundle = build_rag_context(user_request="Explain RA-5.", control_ids=["RA-5"], controls=_controls())

    assert "Use only supplied evidence" in bundle.instructions_for_llm
    assert "INSUFFICIENT_EVIDENCE" in bundle.instructions_for_llm
    assert "Do not certify compliance" in bundle.instructions_for_llm
    assert "Every factual claim must reference evidenceIds" in bundle.instructions_for_llm
