"""End-to-end fixture workflow for the assurance package demo."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence

from core.assurance_package import (
    build_assurance_package,
    validate_assurance_package_document,
    write_assurance_package,
)
from core.assurance_reports import write_human_readable_reports
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
    AgentRunLog,
    AssessmentResult,
    ControlRequirement,
    EvidenceArtifact,
    HumanReviewDecision,
    NormalizedFinding,
)
from core.eval_harness import run_eval_harness
from core.evidence_normalization import (
    EvidenceNormalizationResult,
    FreshnessThresholds,
    normalize_cloud_config_json,
    normalize_vulnerability_scan_json,
)
from core.guardrails import enforce_guardrails, evaluate_recommendation_guardrails
from core.human_review import attach_review_decisions_to_assessment, create_review_decision
from core.observability import aggregate_observability_metrics, create_run_log, write_metrics_json
from core.rag_context_builder import RAGContextBundle, build_rag_context
from core.recommendation_generator import generate_agent_recommendations


REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_FIXTURE_DIR = REPO_ROOT / "fixtures" / "golden_path"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "build" / "assurance-package-demo"
DEMO_NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, default=str) + "\n"


def _load_controls(path: Path) -> list[ControlRequirement]:
    rows = _load_json(path)
    if not isinstance(rows, list):
        raise ValueError(f"golden path controls fixture must be a list: {path}")
    return [ControlRequirement.model_validate(row) for row in rows]


def _merge_normalization_results(results: Sequence[EvidenceNormalizationResult]) -> tuple[list[EvidenceArtifact], list[NormalizedFinding], list[str]]:
    errors = [f"{diag.raw_ref}: {diag.message}" for result in results for diag in result.errors]
    if errors:
        raise ValueError("golden path normalization failed: " + "; ".join(errors))
    evidence = [item for result in results for item in result.evidence_artifacts]
    findings_by_id: dict[str, NormalizedFinding] = {}
    for result in results:
        for finding in result.findings:
            existing = findings_by_id.get(finding.finding_id)
            if existing is None:
                findings_by_id[finding.finding_id] = finding
            else:
                findings_by_id[finding.finding_id] = existing.model_copy(
                    update={
                        "evidence_ids": sorted(set(existing.evidence_ids) | set(finding.evidence_ids)),
                        "control_ids": sorted(set(existing.control_ids) | set(finding.control_ids)),
                    }
                )
    warnings = [f"{diag.raw_ref}: {diag.message}" for result in results for diag in result.warnings]
    return evidence, sorted(findings_by_id.values(), key=lambda f: f.finding_id), warnings


def _control_evidence(control: ControlRequirement, evidence: Sequence[EvidenceArtifact]) -> list[EvidenceArtifact]:
    return [item for item in evidence if control.control_id in item.control_ids]


def _control_findings(control: ControlRequirement, findings: Sequence[NormalizedFinding]) -> list[NormalizedFinding]:
    return [finding for finding in findings if control.control_id in finding.control_ids]


def _run_validators(
    controls: Sequence[ControlRequirement],
    evidence: Sequence[EvidenceArtifact],
    findings: Sequence[NormalizedFinding],
) -> tuple[list[ValidatorResult], list[AssessmentResult]]:
    validation_results: list[ValidatorResult] = []
    assessments: list[AssessmentResult] = []
    for control in controls:
        mapped_evidence = _control_evidence(control, evidence)
        mapped_findings = _control_findings(control, findings)
        results = [
            validate_required_control_evidence(control, mapped_evidence, timestamp=DEMO_NOW),
            validate_evidence_freshness(mapped_evidence, control_id=control.control_id, timestamp=DEMO_NOW),
        ]
        if control.control_id in {"RA-5", "SI-2", "CA-5"}:
            results.append(validate_unresolved_vulnerabilities(mapped_findings, control_id=control.control_id, timestamp=DEMO_NOW))
        validation_results.extend(results)
        assessments.append(
            aggregate_assessment_result(
                assessment_id=f"assess-{control.control_id.lower().replace('-', '')}",
                control=control,
                validator_results=results,
                created_at=DEMO_NOW,
            )
        )
    return validation_results, assessments


def _review_templates(path: Path) -> dict[str, Any]:
    raw = _load_json(path)
    if not isinstance(raw, dict):
        raise ValueError(f"golden path review fixture must be an object: {path}")
    return raw


def _record_fixture_reviews(
    recommendations: Sequence[AgentRecommendation],
    *,
    review_fixture_path: Path,
) -> list[HumanReviewDecision]:
    raw = _review_templates(review_fixture_path)
    reviewer = str(raw.get("reviewer") or "Demo Reviewer")
    templates = raw.get("templates") or {}
    decisions: list[HumanReviewDecision] = []
    for index, recommendation in enumerate(sorted(recommendations, key=lambda rec: rec.recommendation_id), start=1):
        template = templates.get(str(recommendation.recommendation_type)) or {
            "decision": "ACCEPTED_WITH_EDITS",
            "justification": "Reviewer recorded a fixture decision for this recommendation.",
        }
        decisions.append(
            create_review_decision(
                recommendation=recommendation,
                reviewer=reviewer,
                decision=str(template.get("decision") or "ACCEPTED_WITH_EDITS"),
                justification=str(template.get("justification") or "Reviewer recorded a fixture decision."),
                timestamp=DEMO_NOW,
                review_decision_id=f"hrd-golden-{index:03d}",
            )
        )
    return decisions


def _stable_id(*parts: object) -> str:
    text = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _finding_evidence_ids(finding: NormalizedFinding, evidence: Sequence[EvidenceArtifact]) -> list[str]:
    known = {item.evidence_id for item in evidence}
    return sorted(eid for eid in finding.evidence_ids if eid in known)


def _disposition_recommendations(
    findings: Sequence[NormalizedFinding],
    evidence: Sequence[EvidenceArtifact],
) -> list[AgentRecommendation]:
    """Create explicit review recommendations for dispositioned scanner findings."""

    recommendations: list[AgentRecommendation] = []
    for finding in findings:
        evidence_ids = _finding_evidence_ids(finding, evidence)
        if finding.status == "FALSE_POSITIVE":
            recommendations.append(
                AgentRecommendation(
                    recommendationId=f"rec-golden-fp-{_stable_id(finding.finding_id)}",
                    controlId=(finding.control_ids[0] if finding.control_ids else "RA-5"),
                    findingIds=[finding.finding_id],
                    evidenceIds=evidence_ids,
                    recommendationType="human_review",
                    summary=f"Review false positive disposition for scanner finding {finding.finding_id}.",
                    rationale=(
                        "Normalized scanner evidence marks this finding FALSE_POSITIVE. "
                        "A human reviewer must confirm the disposition using cited evidence before it informs assurance reporting."
                    ),
                    confidence=0.86,
                    blockedUnsupportedClaims=True,
                    humanReviewRequired=True,
                )
            )
        elif finding.status == "RISK_ACCEPTED":
            recommendations.append(
                AgentRecommendation(
                    recommendationId=f"rec-golden-risk-{_stable_id(finding.finding_id)}",
                    controlId=(finding.control_ids[0] if finding.control_ids else "RA-5"),
                    findingIds=[finding.finding_id],
                    evidenceIds=evidence_ids,
                    recommendationType="accept_risk",
                    summary=f"Route risk acceptance review for scanner finding {finding.finding_id}.",
                    rationale=(
                        "Normalized scanner evidence marks this finding RISK_ACCEPTED. "
                        "A human reviewer must preserve the acceptance justification and cited evidence."
                    ),
                    confidence=0.84,
                    blockedUnsupportedClaims=True,
                    humanReviewRequired=True,
                )
            )
    return recommendations


def _bundle_for_control(
    control: ControlRequirement,
    *,
    evidence: Sequence[EvidenceArtifact],
    findings: Sequence[NormalizedFinding],
    controls: Sequence[ControlRequirement],
    control_mappings: Sequence[Any],
    validation_results: Sequence[ValidatorResult],
) -> RAGContextBundle:
    return build_rag_context(
        user_request=f"Assess {control.control_id} for the golden path assurance demo.",
        control_ids=[control.control_id],
        evidence_artifacts=evidence,
        findings=findings,
        controls=controls,
        control_mappings=control_mappings,
        validation_results=validation_results,
        account_ids=["123456789012"],
        region="us-east-1",
        time_window_start=datetime(2026, 5, 1, tzinfo=timezone.utc),
        time_window_end=datetime(2026, 5, 7, tzinfo=timezone.utc),
    )


def _log(
    workflow: str,
    *,
    input_payload: Any,
    evidence: Sequence[EvidenceArtifact] = (),
    findings: Sequence[NormalizedFinding] = (),
    controls: Sequence[ControlRequirement] = (),
    status: str = "SUCCESS",
    warnings: Sequence[str] = (),
    human_review_required: bool = False,
    schema_valid: bool = True,
) -> AgentRunLog:
    return create_run_log(
        workflow=workflow,
        input_payload=input_payload,
        started_at=DEMO_NOW,
        completed_at=DEMO_NOW,
        evidence_ids=[item.evidence_id for item in evidence],
        finding_ids=[item.finding_id for item in findings],
        control_ids=[item.control_id for item in controls],
        status=status,  # type: ignore[arg-type]
        warnings=warnings,
        human_review_required=human_review_required,
        schema_valid=schema_valid,
        unsupported_claims_blocked=True,
    )


def run_golden_path_demo(
    *,
    fixture_dir: Path | None = None,
    output_dir: Path | None = None,
) -> dict[str, Any]:
    """Run the complete offline assurance pipeline on curated fixture data."""

    fixture_root = fixture_dir or DEFAULT_FIXTURE_DIR
    out = output_dir or DEFAULT_OUTPUT_DIR
    out.mkdir(parents=True, exist_ok=True)

    raw_dir = fixture_root / "raw"
    thresholds = FreshnessThresholds(current_days=14, stale_days=30)
    vuln_result = normalize_vulnerability_scan_json(
        raw_dir / "vulnerability_scan.json",
        scanner="inspector-fixture",
        collected_at=DEMO_NOW,
        thresholds=thresholds,
    )
    config_result = normalize_cloud_config_json(
        raw_dir / "cloud_config.json",
        source_system="aws-config-fixture",
        collected_at=DEMO_NOW,
        thresholds=thresholds,
    )
    evidence, findings, normalization_warnings = _merge_normalization_results([vuln_result, config_result])
    controls = _load_controls(fixture_root / "controls.json")
    run_logs = [
        _log(
            "evidence_normalization",
            input_payload={"rawDir": str(raw_dir)},
            evidence=evidence,
            findings=findings,
            warnings=normalization_warnings,
        )
    ]

    validation_results, assessments = _run_validators(controls, evidence, findings)
    run_logs.append(
        _log(
            "deterministic_validation",
            input_payload={"controls": [c.control_id for c in controls]},
            evidence=evidence,
            findings=findings,
            controls=controls,
            human_review_required=any(result.status in {"FAIL", "WARN", "UNKNOWN"} for result in validation_results),
        )
    )

    control_mappings = map_controls(evidence, findings, controls)
    run_logs.append(
        _log(
            "control_mapping",
            input_payload={"evidence": [e.evidence_id for e in evidence], "findings": [f.finding_id for f in findings]},
            evidence=evidence,
            findings=findings,
            controls=controls,
            human_review_required=any(mapping.mapping_confidence == "NEEDS_REVIEW" for mapping in control_mappings),
        )
    )

    rag_contexts = [
        _bundle_for_control(
            control,
            evidence=evidence,
            findings=findings,
            controls=controls,
            control_mappings=control_mappings,
            validation_results=validation_results,
        )
        for control in controls
    ]
    run_logs.append(
        _log(
            "rag_context_build",
            input_payload={"contexts": [ctx.request_id for ctx in rag_contexts]},
            evidence=evidence,
            findings=findings,
            controls=controls,
            human_review_required=True,
        )
    )

    recommendations: list[AgentRecommendation] = []
    for bundle in rag_contexts:
        recommendations.extend(generate_agent_recommendations(bundle, validation_results, control_mappings))
    recommendations.extend(_disposition_recommendations(findings, evidence))
    recommendations = sorted({rec.recommendation_id: rec for rec in recommendations}.values(), key=lambda rec: rec.recommendation_id)
    enforce_guardrails(evaluate_recommendation_guardrails(recommendations))
    run_logs.append(
        _log(
            "recommendation_generation",
            input_payload={"recommendations": [rec.recommendation_id for rec in recommendations]},
            evidence=evidence,
            findings=findings,
            controls=controls,
            human_review_required=True,
        )
    )

    review_decisions = _record_fixture_reviews(recommendations, review_fixture_path=fixture_root / "human_review_decisions.json")
    assessments = [attach_review_decisions_to_assessment(assessment, review_decisions) for assessment in assessments]
    run_logs.append(
        _log(
            "human_review_recording",
            input_payload={"reviewDecisions": [decision.review_decision_id for decision in review_decisions]},
            evidence=evidence,
            findings=findings,
            controls=controls,
            human_review_required=True,
        )
    )

    package = build_assurance_package(
        package_id="golden-path-demo",
        system="Observable Security Agent Fixture System",
        assessment_period_start=datetime(2026, 5, 1, tzinfo=timezone.utc),
        assessment_period_end=datetime(2026, 5, 6, tzinfo=timezone.utc),
        framework="NIST SP 800-53",
        baseline="moderate",
        controls=controls,
        evidence=evidence,
        findings=findings,
        control_mappings=control_mappings,
        validation_results=validation_results,
        agent_recommendations=recommendations,
        human_review_decisions=review_decisions,
        assessment_results=assessments,
        audit=run_logs,
        package_status="READY_FOR_REVIEW",
        generated_at=DEMO_NOW,
    )
    schema_report = validate_assurance_package_document(package)
    run_logs.append(
        _log(
            "assurance_package_generation",
            input_payload={"packageId": package["manifest"]["packageId"]},
            evidence=evidence,
            findings=findings,
            controls=controls,
            human_review_required=True,
            schema_valid=bool(schema_report["valid"]),
        )
    )

    package["audit"] = sorted(
        [log.model_dump(mode="json", by_alias=True) for log in run_logs] + package["audit"],
        key=lambda row: str(row.get("eventId") or row.get("agentRunId") or row.get("timestamp") or ""),
    )
    package_path = write_assurance_package(out, package=package)
    report_paths = write_human_readable_reports(out, package)
    metrics = aggregate_observability_metrics(
        assurance_package=package,
        run_logs=run_logs,
        rag_contexts=[ctx.model_dump(mode="json", by_alias=True) for ctx in rag_contexts],
    )
    metrics_path = out / "metrics.json"
    write_metrics_json(metrics_path, metrics)
    eval_doc = run_eval_harness(output_dir=out)
    run_log_path = out / "agent-run-log.json"
    run_log_path.write_text(_stable_json([log.model_dump(mode="json", by_alias=True) for log in run_logs]), encoding="utf-8")

    return {
        "outputDir": str(out),
        "packagePath": str(package_path),
        "reportPaths": {name: str(path) for name, path in report_paths.items()},
        "metricsPath": str(metrics_path),
        "evalResultsPath": str(out / "eval_results.json"),
        "evalSummaryPath": str(out / "eval_summary.md"),
        "agentRunLogPath": str(run_log_path),
        "schemaValid": bool(schema_report["valid"]),
        "evalsPassed": eval_doc["summary"]["failed"] == 0,
        "package": package,
        "metrics": metrics,
    }


__all__ = [
    "DEFAULT_FIXTURE_DIR",
    "DEFAULT_OUTPUT_DIR",
    "run_golden_path_demo",
]
