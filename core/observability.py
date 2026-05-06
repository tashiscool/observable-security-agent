"""Agent run logging and observability metrics."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Literal, Sequence, TypeVar

from core.domain_models import AgentRunLog


WORKFLOWS = {
    "evidence_normalization",
    "deterministic_validation",
    "control_mapping",
    "rag_context_build",
    "recommendation_generation",
    "assurance_package_generation",
    "human_review_recording",
}

RunStatus = Literal["SUCCESS", "FAILED", "PARTIAL", "COLLECTOR_FAILED"]
T = TypeVar("T")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _hash_input(value: Any) -> str:
    payload = json.dumps(value, sort_keys=True, default=str, ensure_ascii=False)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _ids(rows: Sequence[dict[str, Any]], key: str) -> list[str]:
    return sorted({str(row.get(key)) for row in rows if row.get(key)})


def create_run_log(
    *,
    workflow: str,
    input_payload: Any,
    started_at: datetime,
    completed_at: datetime | None = None,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
    control_ids: Sequence[str] = (),
    status: RunStatus = "SUCCESS",
    errors: Sequence[str] = (),
    warnings: Sequence[str] = (),
    schema_valid: bool = True,
    unsupported_claims_blocked: bool = True,
    human_review_required: bool = False,
    confidence: float = 1.0,
) -> AgentRunLog:
    """Create an auditable run log for a workflow."""

    if workflow not in WORKFLOWS:
        raise ValueError(f"unknown observable workflow: {workflow}")
    completed = completed_at or _now()
    duration_ms = max(0, int((_aware(completed) - _aware(started_at)).total_seconds() * 1000))
    input_hash = _hash_input(input_payload)
    decision = "failed" if status in {"FAILED", "COLLECTOR_FAILED"} else "needs_human_review" if human_review_required else "completed"
    return AgentRunLog(
        agentRunId="run-" + hashlib.sha256(f"{workflow}|{input_hash}|{started_at.isoformat()}".encode("utf-8")).hexdigest()[:16],
        workflow=workflow,
        inputHash=input_hash,
        startedAt=started_at,
        completedAt=completed,
        durationMs=duration_ms,
        evidenceIds=sorted(set(evidence_ids)),
        findingIds=sorted(set(finding_ids)),
        controlIds=sorted(set(control_ids)),
        status=status,
        decision=decision,
        confidence=confidence,
        schemaValid=schema_valid,
        unsupportedClaimsBlocked=unsupported_claims_blocked,
        humanReviewRequired=human_review_required,
        errors=list(errors),
        warnings=list(warnings),
    )


def failed_run_log(
    *,
    workflow: str,
    input_payload: Any,
    started_at: datetime,
    error: BaseException | str,
    collector_failed: bool = False,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
    control_ids: Sequence[str] = (),
) -> AgentRunLog:
    """Create a failed run log for caught exceptions; use before re-raising or returning."""

    status: RunStatus = "COLLECTOR_FAILED" if collector_failed else "FAILED"
    return create_run_log(
        workflow=workflow,
        input_payload=input_payload,
        started_at=started_at,
        evidence_ids=evidence_ids,
        finding_ids=finding_ids,
        control_ids=control_ids,
        status=status,
        errors=[str(error)],
        schema_valid=False,
        unsupported_claims_blocked=True,
        human_review_required=True,
        confidence=0.0,
    )


def run_with_observability(
    *,
    workflow: str,
    input_payload: Any,
    func: Callable[[], T],
    collector: bool = False,
) -> tuple[T | None, AgentRunLog]:
    """Run a workflow and always return an AgentRunLog, including failures."""

    started = _now()
    try:
        result = func()
    except Exception as exc:  # deliberate: caught exception must produce failed log
        return None, failed_run_log(workflow=workflow, input_payload=input_payload, started_at=started, error=exc, collector_failed=collector)
    return result, create_run_log(workflow=workflow, input_payload=input_payload, started_at=started)


def write_run_log(path: Path, run_log: AgentRunLog) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(run_log.model_dump_json(by_alias=True))
        f.write("\n")


def load_run_logs(path: Path) -> list[AgentRunLog]:
    if not path.is_file():
        return []
    out: list[AgentRunLog] = []
    for line_no, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        try:
            out.append(AgentRunLog.model_validate_json(line))
        except Exception as exc:
            raise ValueError(f"{path}:{line_no}: invalid agent run log: {exc}") from exc
    return out


def aggregate_observability_metrics(
    *,
    assurance_package: dict[str, Any] | None = None,
    run_logs: Sequence[AgentRunLog] = (),
    rag_contexts: Sequence[dict[str, Any]] = (),
    assets: Sequence[dict[str, Any]] = (),
) -> dict[str, Any]:
    """Aggregate observability and compliance-operation metrics."""

    package = assurance_package or {}
    evidence = list(package.get("evidence") or [])
    findings = list(package.get("findings") or [])
    controls = list(package.get("controls") or [])
    mappings = list(package.get("controlMappings") or [])
    validations = list(package.get("validationResults") or [])
    recommendations = list(package.get("agentRecommendations") or [])
    decisions = list(package.get("humanReviewDecisions") or [])
    assessments = list(package.get("assessmentResults") or [])

    selected = sum(len(ctx.get("selectedEvidence") or []) for ctx in rag_contexts)
    excluded = sum(len(ctx.get("excludedSources") or []) for ctx in rag_contexts)
    retrieval_total = selected + excluded
    freshness_hours = []
    now = _now()
    for row in evidence:
        observed = row.get("observedAt") or row.get("collectedAt")
        if not observed:
            continue
        try:
            dt = datetime.fromisoformat(str(observed).replace("Z", "+00:00"))
        except ValueError:
            continue
        freshness_hours.append(max(0.0, (_aware(now) - _aware(dt)).total_seconds() / 3600.0))

    confidence_counts = Counter(str(row.get("mappingConfidence") or "UNKNOWN") for row in mappings)
    successful = sum(1 for log in run_logs if log.status == "SUCCESS")
    failed = sum(1 for log in run_logs if log.status in {"FAILED", "COLLECTOR_FAILED"})
    total_runs = len(run_logs)
    decided = {row.get("recommendationId"): row for row in decisions}
    accepted = sum(1 for row in decisions if row.get("decision") in {"ACCEPTED", "ACCEPTED_WITH_EDITS", "RISK_ACCEPTED", "COMPENSATING_CONTROL_ACCEPTED"})
    overrides = sum(1 for row in decisions if row.get("decision") in {"REJECTED", "ACCEPTED_WITH_EDITS", "FALSE_POSITIVE", "RISK_ACCEPTED", "COMPENSATING_CONTROL_ACCEPTED"})
    controls_without_evidence = sorted(str(row.get("controlId")) for row in controls if not row.get("evidenceIds"))
    assets_without_scan = sorted(
        str(row.get("assetId") or row.get("resourceId"))
        for row in assets
        if not row.get("scannerEvidenceIds") and not row.get("scanEvidenceIds") and not row.get("evidenceIds")
    )
    missing_evidence_count = len(set(package.get("manifest", {}).get("controlsWithInsufficientEvidence") or []))
    missing_evidence_count += sum(
        1
        for row in validations
        if str(row.get("status")) in {"FAIL", "UNKNOWN"}
        and ("missing" in str(row.get("message", "")).lower() or "no evidence" in str(row.get("message", "")).lower())
    )
    silent_failures = sum(1 for log in run_logs if log.status in {"FAILED", "COLLECTOR_FAILED"} and not log.errors)
    schema_failures = sum(1 for log in run_logs if not log.schema_valid)
    schema_failures += 1 if package.get("manifest", {}).get("schemaValidation") == "FAIL" else 0

    return {
        "retrieval_hit_rate": selected / retrieval_total if retrieval_total else 0.0,
        "evidence_freshness_age_hours": {
            "count": len(freshness_hours),
            "avg": sum(freshness_hours) / len(freshness_hours) if freshness_hours else 0.0,
            "max": max(freshness_hours) if freshness_hours else 0.0,
        },
        "stale_evidence_count": sum(1 for row in evidence if row.get("freshnessStatus") in {"stale", "expired"}),
        "missing_evidence_count": missing_evidence_count,
        "unsupported_claim_count": sum(1 for row in recommendations if row.get("blockedUnsupportedClaims")),
        "source_document_count": len(evidence),
        "control_mapping_confidence_counts": dict(sorted(confidence_counts.items())),
        "tool_call_success_rate": successful / total_runs if total_runs else 0.0,
        "tool_call_failure_rate": failed / total_runs if total_runs else 0.0,
        "silent_failure_count": silent_failures,
        "recommendation_acceptance_rate": accepted / len(recommendations) if recommendations else 0.0,
        "reviewer_override_rate": overrides / len(decisions) if decisions else 0.0,
        "schema_validation_failure_count": schema_failures,
        "controls_without_evidence": controls_without_evidence,
        "assets_without_scan": assets_without_scan,
        "high_findings_open": sum(1 for row in findings if row.get("status") == "OPEN" and row.get("severity") == "HIGH"),
        "critical_findings_open": sum(1 for row in findings if row.get("status") == "OPEN" and row.get("severity") == "CRITICAL"),
        "assessment_result_count": len(assessments),
        "run_log_count": total_runs,
    }


def write_metrics_json(path: Path, metrics: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(metrics, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8")


def metrics_markdown(metrics: dict[str, Any]) -> str:
    lines = [
        "# Observability metrics",
        "",
        "| Metric | Value |",
        "| --- | --- |",
    ]
    for key in sorted(metrics):
        lines.append(f"| `{key}` | `{json.dumps(metrics[key], sort_keys=True, default=str)}` |")
    return "\n".join(lines) + "\n"


def write_metrics_markdown(path: Path, metrics: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(metrics_markdown(metrics), encoding="utf-8")
