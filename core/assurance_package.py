"""Machine-readable assurance package generation.

The structure is OSCAL-inspired but intentionally project-local. It preserves
normalized evidence, deterministic validation, recommendations, and human
review decisions in one stable JSON artifact.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Sequence

from jsonschema import Draft202012Validator

from core.deterministic_validators import ValidatorResult
from core.domain_models import (
    AgentRecommendation,
    AgentRunLog,
    AssessmentResult,
    ControlMapping,
    ControlRequirement,
    EvidenceArtifact,
    HumanReviewDecision,
    NormalizedFinding,
    model_to_python_dict,
)
from core.guardrails import enforce_guardrails, evaluate_assurance_package_guardrails


PackageStatus = Literal["DRAFT", "READY_FOR_REVIEW", "RETURNED", "APPROVED"]
SchemaValidationStatus = Literal["PASS", "FAIL"]

DEFAULT_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "assurance-package.schema.json"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _json_model(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", by_alias=True)
    return dict(obj)


def _stable_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _sort_by_key(rows: Sequence[Any], key: str) -> list[dict[str, Any]]:
    return sorted((_json_model(row) for row in rows), key=lambda row: str(row.get(key) or ""))


def _control_evidence_ids(
    control_id: str,
    evidence: Sequence[EvidenceArtifact],
    mappings: Sequence[ControlMapping],
) -> list[str]:
    ids = {item.evidence_id for item in evidence if control_id in item.control_ids}
    for mapping in mappings:
        if mapping.target_control_id == control_id or mapping.source_control_id == control_id:
            ids.update(mapping.evidence_ids)
    return sorted(ids)


def _control_finding_ids(
    control_id: str,
    findings: Sequence[NormalizedFinding],
    mappings: Sequence[ControlMapping],
) -> list[str]:
    ids = {finding.finding_id for finding in findings if control_id in finding.control_ids}
    for mapping in mappings:
        if mapping.target_control_id == control_id or mapping.source_control_id == control_id:
            ids.update(mapping.finding_ids)
    return sorted(ids)


def _controls_payload(
    controls: Sequence[ControlRequirement],
    evidence: Sequence[EvidenceArtifact],
    findings: Sequence[NormalizedFinding],
    mappings: Sequence[ControlMapping],
) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for control in sorted(controls, key=lambda c: c.control_id):
        row = model_to_python_dict(control)
        row["evidenceIds"] = _control_evidence_ids(control.control_id, evidence, mappings)
        row["findingIds"] = _control_finding_ids(control.control_id, findings, mappings)
        rows.append(row)
    return rows


def _controls_with_insufficient_evidence(
    assessment_results: Sequence[AssessmentResult],
    validation_results: Sequence[ValidatorResult],
) -> list[str]:
    controls = {
        result.control_id
        for result in assessment_results
        if result.status == "INSUFFICIENT_EVIDENCE"
    }
    controls.update(
        result.control_id
        for result in validation_results
        if result.control_id
        and result.status in {"FAIL", "UNKNOWN"}
        and (
            result.validator_id in {"required_control_evidence", "evidence_presence"}
            or "no evidence" in result.message.lower()
            or "missing" in result.message.lower()
            or "insufficient" in result.message.lower()
        )
    )
    return sorted(c for c in controls if c)


def _reviewed_recommendation_ids(decisions: Sequence[HumanReviewDecision]) -> set[str]:
    return {decision.recommendation_id for decision in decisions}


def _audit_rows(
    *,
    generated_at: datetime,
    package_status: str,
    schema_validation: str,
    unsupported_claims_blocked_count: int,
    human_reviews: int,
) -> list[dict[str, Any]]:
    return [
        {
            "eventId": "audit-001",
            "eventType": "PACKAGE_GENERATED",
            "timestamp": generated_at.isoformat(),
            "message": "Machine-readable assurance package generated from normalized domain records.",
        },
        {
            "eventId": "audit-002",
            "eventType": "SCHEMA_VALIDATED",
            "timestamp": generated_at.isoformat(),
            "message": f"Schema validation status: {schema_validation}.",
        },
        {
            "eventId": "audit-003",
            "eventType": "UNSUPPORTED_CLAIMS_BLOCKED",
            "timestamp": generated_at.isoformat(),
            "message": f"Unsupported claims blocked count: {unsupported_claims_blocked_count}.",
        },
        {
            "eventId": "audit-004",
            "eventType": "HUMAN_REVIEW_SUMMARY",
            "timestamp": generated_at.isoformat(),
            "message": f"Human review decisions recorded: {human_reviews}; package status: {package_status}.",
        },
    ]


def build_assurance_package(
    *,
    package_id: str,
    system: str,
    assessment_period_start: datetime,
    assessment_period_end: datetime,
    framework: str,
    baseline: str,
    controls: Sequence[ControlRequirement],
    evidence: Sequence[EvidenceArtifact],
    findings: Sequence[NormalizedFinding],
    control_mappings: Sequence[ControlMapping],
    validation_results: Sequence[ValidatorResult],
    agent_recommendations: Sequence[AgentRecommendation],
    human_review_decisions: Sequence[HumanReviewDecision],
    assessment_results: Sequence[AssessmentResult],
    audit: Sequence[AgentRunLog | dict[str, Any]] = (),
    package_status: PackageStatus = "DRAFT",
    generated_at: datetime | None = None,
) -> dict[str, Any]:
    """Build and validate a stable assurance package document."""

    if package_status == "APPROVED" and not human_review_decisions:
        raise ValueError("assurance package cannot be APPROVED without human review decisions")

    generated = generated_at or _now()
    insufficient = _controls_with_insufficient_evidence(assessment_results, validation_results)
    reviewed_ids = _reviewed_recommendation_ids(human_review_decisions)
    unsupported_claims_blocked = sum(1 for rec in agent_recommendations if rec.blocked_unsupported_claims)
    audit_payload = [
        _json_model(row) if hasattr(row, "model_dump") else dict(row)
        for row in audit
    ]
    audit_payload.extend(
        _audit_rows(
            generated_at=generated,
            package_status=package_status,
            schema_validation="PASS",
            unsupported_claims_blocked_count=unsupported_claims_blocked,
            human_reviews=len(human_review_decisions),
        )
    )

    doc: dict[str, Any] = {
        "manifest": {
            "packageId": package_id,
            "system": system,
            "assessmentPeriod": {
                "start": assessment_period_start.isoformat(),
                "end": assessment_period_end.isoformat(),
            },
            "framework": framework,
            "baseline": baseline,
            "controlsAssessed": sorted({control.control_id for control in controls}),
            "evidenceCount": len(evidence),
            "findingCount": len(findings),
            "aiGeneratedRecommendations": len(agent_recommendations),
            "humanReviewedRecommendations": len(reviewed_ids),
            "controlsWithInsufficientEvidence": insufficient,
            "schemaValidation": "PASS",
            "packageStatus": package_status,
            "unsupportedClaimsBlockedCount": unsupported_claims_blocked,
            "generatedAt": generated.isoformat(),
        },
        "controls": _controls_payload(controls, evidence, findings, control_mappings),
        "evidence": _sort_by_key(evidence, "evidenceId"),
        "findings": _sort_by_key(findings, "findingId"),
        "controlMappings": _sort_by_key(control_mappings, "mappingId"),
        "validationResults": _sort_by_key(validation_results, "validatorId"),
        "agentRecommendations": _sort_by_key(agent_recommendations, "recommendationId"),
        "humanReviewDecisions": _sort_by_key(human_review_decisions, "reviewDecisionId"),
        "assessmentResults": _sort_by_key(assessment_results, "assessmentId"),
        "audit": sorted(audit_payload, key=lambda row: str(row.get("eventId") or row.get("agentRunId") or row.get("timestamp") or "")),
    }

    report = validate_assurance_package_document(doc)
    if not report["valid"]:
        doc["manifest"]["schemaValidation"] = "FAIL"
        raise ValueError("assurance package schema validation failed: " + "; ".join(report["errors"]))
    enforce_guardrails(evaluate_assurance_package_guardrails(doc, schema_path=DEFAULT_SCHEMA_PATH))
    return doc


def validate_assurance_package_document(
    document: dict[str, Any],
    *,
    schema_path: Path | None = None,
) -> dict[str, Any]:
    """Validate an in-memory assurance package against the bundled schema."""

    schema_file = schema_path or DEFAULT_SCHEMA_PATH
    schema = json.loads(schema_file.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = [
        f"{'/'.join(str(p) for p in err.absolute_path) or '$'}: {err.message}"
        for err in sorted(validator.iter_errors(document), key=lambda e: (list(e.absolute_path), e.message))
    ]
    return {
        "valid": not errors,
        "errors": errors,
        "schemaPath": str(schema_file),
    }


def write_assurance_package(
    output_dir: Path,
    *,
    package: dict[str, Any],
) -> Path:
    """Write a pre-validated assurance package as deterministic JSON."""

    report = validate_assurance_package_document(package)
    if not report["valid"]:
        package["manifest"]["schemaValidation"] = "FAIL"
        raise ValueError("assurance package schema validation failed: " + "; ".join(report["errors"]))
    enforce_guardrails(evaluate_assurance_package_guardrails(package, schema_path=DEFAULT_SCHEMA_PATH))
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / "assurance-package.json"
    path.write_text(_stable_json(package), encoding="utf-8")
    return path


def build_and_write_assurance_package(
    output_dir: Path,
    **kwargs: Any,
) -> Path:
    """Build, validate, and write ``assurance-package.json``."""

    package = build_assurance_package(**kwargs)
    return write_assurance_package(output_dir, package=package)
