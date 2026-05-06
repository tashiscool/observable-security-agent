"""Offline evaluation harness for the agentic compliance platform.

The harness exercises the new platform flow end-to-end with fixture-only data:
domain model coercion, deterministic validators, control mapping, RAG context
selection, recommendation generation, guardrails, and package generation.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Mapping, Sequence

from core.assurance_package import build_assurance_package
from core.control_mapping_engine import map_controls
from core.deterministic_validators import (
    ValidatorResult,
    aggregate_assessment_result,
    validate_evidence_freshness,
    validate_required_control_evidence,
    validate_unresolved_vulnerabilities,
)
from core.domain_models import (
    AgentRecommendation,
    AssessmentResult,
    ControlMapping,
    ControlRequirement,
    EvidenceArtifact,
    GuardrailPolicy,
    GuardrailResult,
    HumanReviewDecision,
    NormalizedFinding,
)
from core.guardrails import (
    detect_prompt_injection,
    evaluate_certification_language,
    evaluate_destructive_action,
    evaluate_scope_boundaries,
    evaluate_unsupported_claim,
)
from core.rag_context_builder import build_rag_context
from core.recommendation_generator import generate_agent_recommendations


DEFAULT_EVAL_FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "eval_harness" / "builtins.json"
DEFAULT_NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


@dataclass
class EvalCaseResult:
    eval_id: str
    name: str
    passed: bool
    actual: dict[str, Any]
    expected: dict[str, Any]
    failures: list[dict[str, Any]] = field(default_factory=list)


def _dt(value: Any = None) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if value:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    return DEFAULT_NOW


def _control(row: Mapping[str, Any]) -> ControlRequirement:
    cid = str(row.get("controlId") or row.get("control_id") or "RA-5")
    return ControlRequirement(
        controlId=cid,
        family=str(row.get("family") or cid.split("-")[0]),
        title=str(row.get("title") or f"{cid} control"),
        requirementText=str(row.get("requirementText") or row.get("requirement_text") or f"{cid} requirement."),
        parameters=dict(row.get("parameters") or {}),
        framework=str(row.get("framework") or "NIST SP 800-53"),
        baseline=row.get("baseline") or "moderate",
        responsibility=str(row.get("responsibility") or "shared"),
        sourceRef=str(row.get("sourceRef") or row.get("source_ref") or f"fixture-controls#{cid}"),
    )


def _evidence(row: Mapping[str, Any], index: int) -> EvidenceArtifact:
    eid = str(row.get("evidenceId") or row.get("evidence_id") or f"ev-{index:03d}")
    observed = _dt(row.get("observedAt") or row.get("observed_at"))
    return EvidenceArtifact(
        evidenceId=eid,
        sourceSystem=str(row.get("sourceSystem") or row.get("source_system") or "fixture"),
        sourceType=str(row.get("sourceType") or row.get("source_type") or "cloud_config_json"),
        collectedAt=_dt(row.get("collectedAt") or row.get("collected_at") or observed),
        observedAt=observed,
        accountId=row.get("accountId") or row.get("account_id") or "111111111111",
        region=row.get("region") or "us-east-1",
        resourceId=row.get("resourceId") or row.get("resource_id") or "resource-1",
        resourceArn=row.get("resourceArn") or row.get("resource_arn"),
        resourceType=row.get("resourceType") or row.get("resource_type") or "ec2.instance",
        scanner=row.get("scanner"),
        findingId=row.get("findingId") or row.get("finding_id"),
        vulnerabilityId=row.get("vulnerabilityId") or row.get("vulnerability_id"),
        packageName=row.get("packageName") or row.get("package_name"),
        packageVersion=row.get("packageVersion") or row.get("package_version"),
        imageDigest=row.get("imageDigest") or row.get("image_digest"),
        controlIds=list(row.get("controlIds") or row.get("control_ids") or []),
        rawRef=str(row.get("rawRef") or row.get("raw_ref") or f"fixtures/eval_harness#{eid}"),
        normalizedSummary=str(row.get("normalizedSummary") or row.get("normalized_summary") or "Fixture evidence."),
        trustLevel=str(row.get("trustLevel") or row.get("trust_level") or "authoritative"),
        freshnessStatus=str(row.get("freshnessStatus") or row.get("freshness_status") or "current"),
    )


def _finding(row: Mapping[str, Any], index: int) -> NormalizedFinding:
    fid = str(row.get("findingId") or row.get("finding_id") or f"nf-{index:03d}")
    return NormalizedFinding(
        findingId=fid,
        sourceSystem=str(row.get("sourceSystem") or row.get("source_system") or "fixture-scanner"),
        scanner=row.get("scanner") or "fixture-scanner",
        title=str(row.get("title") or "Fixture finding"),
        description=str(row.get("description") or "Fixture finding description."),
        severity=str(row.get("severity") or "UNKNOWN"),
        status=str(row.get("status") or "UNKNOWN"),
        vulnerabilityId=row.get("vulnerabilityId") or row.get("vulnerability_id"),
        packageName=row.get("packageName") or row.get("package_name"),
        packageVersion=row.get("packageVersion") or row.get("package_version"),
        fixedVersion=row.get("fixedVersion") or row.get("fixed_version"),
        accountId=row.get("accountId") or row.get("account_id") or "111111111111",
        region=row.get("region") or "us-east-1",
        resourceId=row.get("resourceId") or row.get("resource_id") or "resource-1",
        imageDigest=row.get("imageDigest") or row.get("image_digest"),
        firstObservedAt=_dt(row.get("firstObservedAt") or row.get("first_observed_at")),
        lastObservedAt=_dt(row.get("lastObservedAt") or row.get("last_observed_at")),
        evidenceIds=list(row.get("evidenceIds") or row.get("evidence_ids") or []),
        controlIds=list(row.get("controlIds") or row.get("control_ids") or []),
    )


def _result(
    validator_id: str,
    status: str,
    message: str,
    *,
    control_id: str | None = None,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
) -> ValidatorResult:
    return ValidatorResult(
        validatorId=validator_id,
        status=status,
        controlId=control_id,
        assetId=None,
        evidenceIds=list(evidence_ids),
        findingIds=list(finding_ids),
        message=message,
        remediationHint="Collect current evidence, route for review, or update remediation tracking.",
        timestamp=DEFAULT_NOW,
    )


def _scope_policy(scope: Mapping[str, Any]) -> GuardrailPolicy:
    return GuardrailPolicy(
        allowedAccountIds=list(scope.get("accountIds") or scope.get("account_ids") or []),
        allowedRegions=list(scope.get("regions") or []),
        allowedResourceIds=list(scope.get("resourceIds") or scope.get("resource_ids") or []),
    )


def _in_scope(row: Any, scope: Mapping[str, Any]) -> bool:
    if not scope:
        return True
    account_ids = set(scope.get("accountIds") or scope.get("account_ids") or [])
    regions = set(scope.get("regions") or [])
    resource_ids = set(scope.get("resourceIds") or scope.get("resource_ids") or [])
    return not (
        (account_ids and getattr(row, "account_id", None) not in account_ids)
        or (regions and getattr(row, "region", None) not in regions)
        or (resource_ids and getattr(row, "resource_id", None) not in resource_ids and getattr(row, "image_digest", None) not in resource_ids)
    )


def _custom_validations(
    *,
    control: ControlRequirement,
    evidence: Sequence[EvidenceArtifact],
    findings: Sequence[NormalizedFinding],
) -> list[ValidatorResult]:
    out: list[ValidatorResult] = []
    mapped_evidence = [e for e in evidence if control.control_id in e.control_ids]
    mapped_findings = [f for f in findings if control.control_id in f.control_ids]
    if any(e.source_type in {"collector_failure", "scanner_failure"} or "scanner failed" in e.normalized_summary.lower() for e in mapped_evidence):
        out.append(_result("collector_failed", "FAIL", f"Collector/scanner failure evidence exists for {control.control_id}.", control_id=control.control_id, evidence_ids=[e.evidence_id for e in mapped_evidence]))
    if any(e.source_type in {"exception", "deviation"} and ("expired" in e.normalized_summary.lower() or "inactive" in e.normalized_summary.lower()) for e in mapped_evidence):
        out.append(_result("exception_active", "FAIL", f"Exception/deviation evidence for {control.control_id} is inactive or expired.", control_id=control.control_id, evidence_ids=[e.evidence_id for e in mapped_evidence]))
    if any(e.source_type == "poam" and "closed without rescan" in e.normalized_summary.lower() for e in mapped_evidence):
        out.append(_result("poam_closed_without_rescan", "FAIL", f"POA&M closure for {control.control_id} lacks rescan evidence.", control_id=control.control_id, evidence_ids=[e.evidence_id for e in mapped_evidence]))

    by_key: dict[tuple[str, str, str], set[str]] = {}
    for finding in mapped_findings:
        key = (
            str(finding.vulnerability_id or finding.finding_id),
            str(finding.resource_id or finding.image_digest or ""),
            str(finding.package_name or ""),
        )
        by_key.setdefault(key, set()).add(finding.status)
    conflicting = [key for key, statuses in by_key.items() if "OPEN" in statuses and "FIXED" in statuses]
    if conflicting:
        out.append(
            _result(
                "conflicting_scanner_results",
                "FAIL",
                f"Conflicting scanner results exist for {control.control_id}.",
                control_id=control.control_id,
                finding_ids=[f.finding_id for f in mapped_findings],
            )
        )
    return out


def _coerce_reviews(
    rows: Sequence[Mapping[str, Any]],
    recommendations: Sequence[AgentRecommendation],
) -> list[HumanReviewDecision]:
    reviews: list[HumanReviewDecision] = []
    for index, row in enumerate(rows):
        rec_id = row.get("recommendationId") or row.get("recommendation_id")
        rec_type = row.get("recommendationType") or row.get("recommendation_type")
        matched = None
        if rec_id and rec_id != "*":
            matched = next((rec for rec in recommendations if rec.recommendation_id == rec_id), None)
        if matched is None and rec_type:
            matched = next((rec for rec in recommendations if rec.recommendation_type == rec_type), None)
        if matched is None and recommendations:
            matched = recommendations[0]
        reviews.append(
            HumanReviewDecision(
                reviewDecisionId=str(row.get("reviewDecisionId") or row.get("review_decision_id") or f"hrd-{index + 1:03d}"),
                recommendationId=str((matched.recommendation_id if matched else rec_id) or f"rec-{index + 1:03d}"),
                controlId=row.get("controlId") or row.get("control_id") or (matched.control_id if matched else None),
                findingIds=list(row.get("findingIds") or row.get("finding_ids") or (matched.finding_ids if matched else [])),
                evidenceIds=list(row.get("evidenceIds") or row.get("evidence_ids") or (matched.evidence_ids if matched else [])),
                reviewer=str(row.get("reviewer") or "Fixture Reviewer"),
                decision=str(row.get("decision") or "ACCEPTED"),
                justification=str(row.get("justification") or "Fixture human review decision."),
                timestamp=_dt(row.get("timestamp")),
            )
        )
    return reviews


def _recommendation(
    *,
    eval_id: str,
    recommendation_type: str,
    control_id: str,
    summary: str,
    rationale: str,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
) -> AgentRecommendation:
    return AgentRecommendation(
        recommendationId=f"rec-{eval_id.lower()}-{recommendation_type.lower()}-{control_id.lower()}",
        controlId=control_id,
        findingIds=list(dict.fromkeys(finding_ids)),
        evidenceIds=list(dict.fromkeys(evidence_ids)),
        recommendationType=recommendation_type,
        summary=summary,
        rationale=rationale,
        confidence=0.86,
        blockedUnsupportedClaims=True,
        humanReviewRequired=True,
    )


def _custom_recommendations(eval_id: str, validations: Sequence[ValidatorResult]) -> list[AgentRecommendation]:
    out: list[AgentRecommendation] = []
    for result in validations:
        if result.validator_id == "collector_failed":
            out.append(
                _recommendation(
                    eval_id=eval_id,
                    recommendation_type="REQUEST_RESCAN",
                    control_id=result.control_id or "RA-5",
                    evidence_ids=result.evidence_ids,
                    summary="Request a rescan because scanner or collector evidence failed.",
                    rationale="Collector failure is explicit evidence that current scanner output cannot support final assurance.",
                )
            )
        if result.validator_id == "poam_closed_without_rescan":
            out.append(
                _recommendation(
                    eval_id=eval_id,
                    recommendation_type="UPDATE_POAM",
                    control_id=result.control_id or "CA-5",
                    evidence_ids=result.evidence_ids,
                    summary="Update POA&M because closure lacks rescan evidence.",
                    rationale="POA&M closure affecting vulnerability posture requires current verification evidence before closure is supportable.",
                )
            )
    return out


def _compare_expected(actual: dict[str, Any], expected: Mapping[str, Any]) -> list[dict[str, Any]]:
    failures: list[dict[str, Any]] = []
    for control_id, expected_status in (expected.get("assessmentStatuses") or {}).items():
        got = (actual.get("assessmentStatuses") or {}).get(control_id)
        if got != expected_status:
            failures.append({"field": f"assessmentStatuses.{control_id}", "expected": expected_status, "actual": got})
    for key in ("requiredRecommendations", "blockedClaims", "missingEvidenceControls", "guardrailFailures"):
        expected_items = set(expected.get(key) or [])
        actual_items = set(actual.get(key) or [])
        missing = sorted(expected_items - actual_items)
        if missing:
            failures.append({"field": key, "expected": sorted(expected_items), "actual": sorted(actual_items), "missing": missing})
    return failures


def run_eval_case(case: Mapping[str, Any]) -> EvalCaseResult:
    inputs = case.get("inputs") or {}
    expected = case.get("expected") or {}
    scope = inputs.get("scope") or {}
    policy = _scope_policy(scope)
    controls = [_control(row) for row in inputs.get("controls") or []]
    evidence_all = [_evidence(row, i + 1) for i, row in enumerate(inputs.get("evidence") or [])]
    findings_all = [_finding(row, i + 1) for i, row in enumerate(inputs.get("findings") or [])]
    evidence = [item for item in evidence_all if _in_scope(item, scope)]
    findings = [item for item in findings_all if _in_scope(item, scope)]

    mappings = map_controls(evidence, findings, controls)
    validations: list[ValidatorResult] = []
    assessments: list[AssessmentResult] = []
    for control in controls:
        control_evidence = [item for item in evidence if control.control_id in item.control_ids]
        control_findings = [item for item in findings if control.control_id in item.control_ids]
        validators = [
            validate_required_control_evidence(control, evidence, timestamp=DEFAULT_NOW),
        ]
        if control_evidence:
            validators.append(validate_evidence_freshness(control_evidence, control_id=control.control_id, timestamp=DEFAULT_NOW))
        if control_findings:
            validators.append(validate_unresolved_vulnerabilities(control_findings, control_id=control.control_id, timestamp=DEFAULT_NOW))
        validators.extend(_custom_validations(control=control, evidence=evidence, findings=findings))
        validations.extend(validators)
        assessments.append(
            aggregate_assessment_result(
                assessment_id=f"assess-{case.get('evalId')}-{control.control_id}",
                control=control,
                validator_results=validators,
                created_at=DEFAULT_NOW,
            )
        )

    recommendations: list[AgentRecommendation] = []
    for control in controls:
        bundle = build_rag_context(
            user_request=f"Evaluate {control.control_id} for {case.get('name')}.",
            control_ids=[control.control_id],
            account_ids=list(scope.get("accountIds") or scope.get("account_ids") or []),
            region=(scope.get("regions") or [None])[0] if scope.get("regions") else None,
            asset_ids=list(scope.get("resourceIds") or scope.get("resource_ids") or []),
            evidence_artifacts=evidence_all,
            findings=findings_all,
            controls=controls,
            control_mappings=mappings,
            validation_results=validations,
        )
        recommendations.extend(generate_agent_recommendations(bundle, validations, mappings))
    recommendations.extend(_custom_recommendations(str(case.get("evalId") or "eval"), validations))

    reviews = _coerce_reviews(inputs.get("humanReviews") or [], recommendations)
    guardrails: list[GuardrailResult] = []
    for claim in inputs.get("claims") or []:
        text = str(claim.get("text") or "")
        eids = list(claim.get("evidenceIds") or claim.get("evidence_ids") or [])
        guardrails.append(evaluate_unsupported_claim(conclusion=text, evidence_ids=eids))
        guardrails.append(evaluate_certification_language(text=text, human_review_decisions=reviews, evidence_ids=eids))
        guardrails.append(evaluate_destructive_action(action_text=text, evidence_ids=eids))
    guardrails.extend(detect_prompt_injection(evidence_all))
    for item in evidence_all:
        guardrails.extend(evaluate_scope_boundaries(item, policy=policy))

    package_error: str | None = None
    try:
        build_assurance_package(
            package_id=f"pkg-{case.get('evalId')}",
            system="Observable Security Agent Eval Fixture",
            assessment_period_start=DEFAULT_NOW,
            assessment_period_end=DEFAULT_NOW,
            framework="NIST SP 800-53",
            baseline="moderate",
            controls=controls,
            evidence=evidence,
            findings=findings,
            control_mappings=mappings,
            validation_results=validations,
            agent_recommendations=recommendations,
            human_review_decisions=reviews,
            assessment_results=assessments,
            package_status="READY_FOR_REVIEW",
            generated_at=DEFAULT_NOW,
        )
    except ValueError as exc:
        package_error = str(exc)

    failing_guardrails = [result.guardrail_id for result in guardrails if result.status == "FAIL"]
    actual = {
        "assessmentStatuses": {result.control_id: result.status for result in assessments},
        "requiredRecommendations": sorted({rec.recommendation_type for rec in recommendations}),
        "blockedClaims": sorted({result.guardrail_id for result in guardrails if result.status == "FAIL" and result.guardrail_id in {"unsupported_compliance_claim", "certification_language", "destructive_operation"}}),
        "missingEvidenceControls": sorted({result.control_id for result in assessments if result.status == "INSUFFICIENT_EVIDENCE"}),
        "guardrailFailures": sorted(set(failing_guardrails)),
        "guardrailWarnings": sorted({result.guardrail_id for result in guardrails if result.status == "WARN"}),
        "mappingConfidenceCounts": _mapping_confidence_counts(mappings),
        "packageGenerated": package_error is None,
        "packageError": package_error,
    }
    failures = _compare_expected(actual, expected)
    return EvalCaseResult(
        eval_id=str(case.get("evalId") or "unknown"),
        name=str(case.get("name") or case.get("evalId") or "Unnamed eval"),
        passed=not failures,
        actual=actual,
        expected=dict(expected),
        failures=failures,
    )


def _mapping_confidence_counts(mappings: Sequence[ControlMapping]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for mapping in mappings:
        counts[mapping.mapping_confidence] = counts.get(mapping.mapping_confidence, 0) + 1
    return dict(sorted(counts.items()))


def load_eval_cases(path: Path | None = None) -> list[dict[str, Any]]:
    fixture_path = path or DEFAULT_EVAL_FIXTURE
    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    if isinstance(data, dict):
        cases = data.get("evals") or data.get("cases") or []
    else:
        cases = data
    if not isinstance(cases, list):
        raise ValueError(f"Eval fixture must be a list or object containing evals[]: {fixture_path}")
    return [dict(case) for case in cases]


def _summary_markdown(results: Sequence[EvalCaseResult]) -> str:
    passed = sum(1 for result in results if result.passed)
    failed = len(results) - passed
    lines = [
        "# Observable Security Agent eval summary",
        "",
        f"- Total evals: {len(results)}",
        f"- Passed: {passed}",
        f"- Failed: {failed}",
        "",
        "| Eval | Name | Result | Failure count |",
        "| --- | --- | --- | --- |",
    ]
    for result in results:
        lines.append(f"| `{result.eval_id}` | {result.name} | {'PASS' if result.passed else 'FAIL'} | {len(result.failures)} |")
    if failed:
        lines.extend(["", "## Failures", ""])
        for result in results:
            if not result.failures:
                continue
            lines.append(f"### {result.eval_id} - {result.name}")
            lines.append("")
            for failure in result.failures:
                lines.append(
                    f"- `{failure['field']}` expected `{failure.get('expected')}` but got `{failure.get('actual')}`."
                )
            lines.append("")
    return "\n".join(lines) + "\n"


def run_eval_harness(*, fixture_path: Path | None = None, output_dir: Path) -> dict[str, Any]:
    cases = load_eval_cases(fixture_path)
    results = [run_eval_case(case) for case in cases]
    output_dir.mkdir(parents=True, exist_ok=True)
    doc = {
        "summary": {
            "total": len(results),
            "passed": sum(1 for result in results if result.passed),
            "failed": sum(1 for result in results if not result.passed),
        },
        "evals": [
            {
                "evalId": result.eval_id,
                "name": result.name,
                "passed": result.passed,
                "expected": result.expected,
                "actual": result.actual,
                "failures": result.failures,
            }
            for result in results
        ],
    }
    (output_dir / "eval_results.json").write_text(json.dumps(doc, indent=2, sort_keys=True), encoding="utf-8")
    (output_dir / "eval_summary.md").write_text(_summary_markdown(results), encoding="utf-8")
    return doc


__all__ = [
    "DEFAULT_EVAL_FIXTURE",
    "EvalCaseResult",
    "load_eval_cases",
    "run_eval_case",
    "run_eval_harness",
]
