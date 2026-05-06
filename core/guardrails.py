"""Guardrails for agentic compliance operations.

The guardrail layer is deliberately deterministic. It does not decide whether a
control passes; it blocks unsafe agent behavior, unsupported conclusions, stale
primary evidence, scope bleed, and malformed structured outputs before reports
or packages leave the workflow.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from jsonschema import Draft202012Validator

from core.domain_models import (
    AgentRecommendation,
    EvidenceArtifact,
    GuardrailPolicy,
    GuardrailResult,
    HumanReviewDecision,
)


_CERTIFICATION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcertified\b", re.I),
    re.compile(r"\bcertify\b", re.I),
    re.compile(r"\bato[-\s]?ready\s+approved\b", re.I),
    re.compile(r"\bcontrol\s+satisfied\b", re.I),
    re.compile(r"\bcontrols?\s+are\s+satisfied\b", re.I),
    re.compile(r"\bcompliant\b", re.I),
)

_DESTRUCTIVE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bdelete\b", re.I),
    re.compile(r"\bsuppress(?:ion|ed|es|ing)?\b", re.I),
    re.compile(r"\bclose(?:d|s|ing)?\b", re.I),
    re.compile(r"\bwaive(?:d|s|r|ing)?\b", re.I),
    re.compile(r"\bapprove(?:d|s|ing)?\s+(?:control|package|recommendation|poa&?m|poam|finding|exception|waiver)\b", re.I),
    re.compile(r"\bmodify\s+(?:a\s+)?cloud\s+resource\b", re.I),
    re.compile(r"\bchange\s+(?:a\s+)?cloud\s+resource\b", re.I),
    re.compile(r"\bclose\s+poa&?m\b", re.I),
    re.compile(r"\bclose\s+poam\b", re.I),
)

_COMPLIANCE_IMPACTING_TYPES = {
    "CREATE_POAM",
    "UPDATE_POAM",
    "ACCEPT_COMPENSATING_CONTROL_REVIEW",
    "MARK_INSUFFICIENT_EVIDENCE",
    "DRAFT_ASSESSMENT_NARRATIVE",
    "NO_ACTION_REQUIRED",
}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _result(
    guardrail_id: str,
    status: str,
    message: str,
    *,
    blocked_action: str | None = None,
    evidence_ids: Sequence[str] = (),
    recommendation_id: str | None = None,
) -> GuardrailResult:
    return GuardrailResult(
        guardrailId=guardrail_id,
        status=status,
        message=message,
        blockedAction=blocked_action,
        evidenceIds=list(dict.fromkeys(str(eid) for eid in evidence_ids if str(eid).strip())),
        recommendationId=recommendation_id,
        timestamp=_now(),
    )


def _as_mapping(obj: Any) -> Mapping[str, Any]:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", by_alias=True)
    if isinstance(obj, Mapping):
        return obj
    return {}


def _text_fields(obj: Any, fields: Sequence[str]) -> str:
    row = _as_mapping(obj)
    return " ".join(str(row.get(field) or "") for field in fields)


def _human_review_supports(
    recommendation_id: str | None,
    human_review_decisions: Sequence[HumanReviewDecision | Mapping[str, Any]],
) -> bool:
    if not recommendation_id:
        return bool(human_review_decisions)
    for decision in human_review_decisions:
        row = _as_mapping(decision)
        if row.get("recommendationId") == recommendation_id and str(row.get("decision") or "").strip():
            return True
    return False


def _certification_phrase(text: str) -> str | None:
    for pattern in _CERTIFICATION_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return match.group(0)
    return None


def _destructive_phrase(text: str) -> str | None:
    for pattern in _DESTRUCTIVE_PATTERNS:
        match = pattern.search(text or "")
        if match:
            return match.group(0)
    return None


def _explicit_missing_evidence(text: str) -> bool:
    lowered = (text or "").lower()
    return "missingevidence:" in lowered or "insufficient_evidence" in lowered or "missing evidence" in lowered


def evaluate_unsupported_claim(
    *,
    conclusion: str,
    evidence_ids: Sequence[str],
    recommendation_id: str | None = None,
) -> GuardrailResult:
    """Fail conclusions that cite no evidence and are not explicit missing-evidence statements."""

    if evidence_ids or _explicit_missing_evidence(conclusion):
        return _result(
            "unsupported_compliance_claim",
            "PASS",
            "Conclusion has evidence references or explicitly states missing evidence.",
            evidence_ids=evidence_ids,
            recommendation_id=recommendation_id,
        )
    return _result(
        "unsupported_compliance_claim",
        "FAIL",
        "Conclusion has no evidenceIds; unsupported compliance claims are blocked.",
        blocked_action="emit_unsupported_conclusion",
        evidence_ids=evidence_ids,
        recommendation_id=recommendation_id,
    )


def evaluate_certification_language(
    *,
    text: str,
    human_review_decisions: Sequence[HumanReviewDecision | Mapping[str, Any]] = (),
    recommendation_id: str | None = None,
    evidence_ids: Sequence[str] = (),
    policy: GuardrailPolicy | None = None,
) -> GuardrailResult:
    policy = policy or GuardrailPolicy()
    if not policy.block_certification_language:
        return _result("certification_language", "PASS", "Certification language blocking disabled.")
    phrase = _certification_phrase(text)
    if not phrase:
        return _result("certification_language", "PASS", "No certification language detected.", evidence_ids=evidence_ids, recommendation_id=recommendation_id)
    if _human_review_supports(recommendation_id, human_review_decisions):
        return _result("certification_language", "PASS", "Certification-like language has related human review support.", evidence_ids=evidence_ids, recommendation_id=recommendation_id)
    return _result(
        "certification_language",
        "FAIL",
        f"Certification-like language `{phrase}` requires human review support.",
        blocked_action="emit_certification_language",
        evidence_ids=evidence_ids,
        recommendation_id=recommendation_id,
    )


def evaluate_destructive_action(
    *,
    action_text: str,
    recommendation_id: str | None = None,
    evidence_ids: Sequence[str] = (),
    policy: GuardrailPolicy | None = None,
) -> GuardrailResult:
    policy = policy or GuardrailPolicy()
    if not policy.block_destructive_operations:
        return _result("destructive_operation", "PASS", "Destructive operation blocking disabled.")
    phrase = _destructive_phrase(action_text)
    if not phrase:
        return _result("destructive_operation", "PASS", "No destructive operation detected.", evidence_ids=evidence_ids, recommendation_id=recommendation_id)
    return _result(
        "destructive_operation",
        "FAIL",
        f"Agent workflow attempted or recommended blocked operation `{phrase}`.",
        blocked_action=phrase,
        evidence_ids=evidence_ids,
        recommendation_id=recommendation_id,
    )


def evaluate_scope_boundaries(
    record: Any,
    *,
    policy: GuardrailPolicy | None = None,
    recommendation_id: str | None = None,
) -> list[GuardrailResult]:
    policy = policy or GuardrailPolicy()
    row = _as_mapping(record)
    checks = [
        ("account_boundary", "accountId", policy.allowed_account_ids),
        ("region_boundary", "region", policy.allowed_regions),
        ("resource_boundary", "resourceId", policy.allowed_resource_ids),
        ("tenant_boundary", "tenantId", policy.allowed_tenant_ids),
    ]
    out: list[GuardrailResult] = []
    for guardrail_id, key, allowed in checks:
        value = row.get(key)
        if not allowed or value in (None, ""):
            out.append(_result(guardrail_id, "PASS", f"No {key} boundary restriction applied.", recommendation_id=recommendation_id))
        elif str(value) not in set(allowed):
            out.append(
                _result(
                    guardrail_id,
                    "FAIL",
                    f"Record {key} `{value}` is outside the allowed guardrail scope.",
                    blocked_action="use_out_of_scope_record",
                    evidence_ids=[str(row.get("evidenceId"))] if row.get("evidenceId") else [],
                    recommendation_id=recommendation_id,
                )
            )
        else:
            out.append(_result(guardrail_id, "PASS", f"Record {key} is within allowed scope.", recommendation_id=recommendation_id))
    return out


def evaluate_evidence_freshness(
    evidence: EvidenceArtifact | Mapping[str, Any],
    *,
    policy: GuardrailPolicy | None = None,
) -> GuardrailResult:
    policy = policy or GuardrailPolicy()
    row = _as_mapping(evidence)
    evidence_id = str(row.get("evidenceId") or "")
    freshness = str(row.get("freshnessStatus") or "unknown").lower()
    if freshness == "current":
        return _result("evidence_freshness", "PASS", "Evidence is current.", evidence_ids=[evidence_id])
    if freshness == "expired":
        return _result(
            "evidence_freshness",
            "FAIL",
            "Expired evidence cannot be used as primary compliance support.",
            blocked_action="use_expired_evidence",
            evidence_ids=[evidence_id],
        )
    if freshness == "stale" and not policy.allow_stale_evidence:
        return _result(
            "evidence_freshness",
            "WARN",
            "Stale evidence should not be used as primary support without review or refresh.",
            blocked_action="use_stale_evidence_as_primary_support",
            evidence_ids=[evidence_id],
        )
    return _result("evidence_freshness", "PASS", f"Evidence freshness `{freshness}` accepted by policy.", evidence_ids=[evidence_id])


def evaluate_human_review_requirement(
    recommendation: AgentRecommendation | Mapping[str, Any],
    *,
    policy: GuardrailPolicy | None = None,
) -> GuardrailResult:
    policy = policy or GuardrailPolicy()
    row = _as_mapping(recommendation)
    rec_id = str(row.get("recommendationId") or "")
    rec_type = str(row.get("recommendationType") or "")
    if not policy.require_human_review_for_compliance or rec_type not in _COMPLIANCE_IMPACTING_TYPES:
        return _result("human_review_required", "PASS", "Recommendation does not require the compliance-impact review guardrail.", recommendation_id=rec_id)
    if bool(row.get("humanReviewRequired")):
        return _result("human_review_required", "PASS", "Compliance-impacting recommendation requires human review.", recommendation_id=rec_id)
    return _result(
        "human_review_required",
        "FAIL",
        "Compliance-impacting recommendations must require human review.",
        blocked_action="emit_compliance_impacting_recommendation_without_review_gate",
        evidence_ids=row.get("evidenceIds") or [],
        recommendation_id=rec_id,
    )


def validate_structured_output(
    document: Mapping[str, Any],
    *,
    schema_path: Path,
    policy: GuardrailPolicy | None = None,
) -> GuardrailResult:
    policy = policy or GuardrailPolicy()
    if not policy.validate_structured_outputs:
        return _result("structured_output_schema", "PASS", "Structured output schema validation disabled.")
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = [
        f"{'/'.join(str(p) for p in err.absolute_path) or '$'}: {err.message}"
        for err in sorted(validator.iter_errors(document), key=lambda e: (list(e.absolute_path), e.message))
    ]
    if errors:
        return _result(
            "structured_output_schema",
            "FAIL",
            "Structured output failed schema validation: " + "; ".join(errors[:5]),
            blocked_action="emit_invalid_structured_output",
        )
    return _result("structured_output_schema", "PASS", "Structured output passed schema validation.")


def detect_prompt_injection(
    sources: Iterable[EvidenceArtifact | Mapping[str, Any] | str],
    *,
    policy: GuardrailPolicy | None = None,
) -> list[GuardrailResult]:
    policy = policy or GuardrailPolicy()
    if not policy.detect_prompt_injection:
        return [_result("prompt_injection", "PASS", "Prompt injection detection disabled.")]
    patterns = [re.compile(re.escape(pattern), re.I) for pattern in policy.prompt_injection_patterns]
    out: list[GuardrailResult] = []
    for source in sources:
        if isinstance(source, str):
            text = source
            evidence_ids: list[str] = []
            source_label = "text"
        else:
            row = _as_mapping(source)
            text = " ".join(
                str(row.get(key) or "")
                for key in ("normalizedSummary", "rawRef", "description", "title", "comment", "content", "text")
            )
            evidence_ids = [str(row.get("evidenceId"))] if row.get("evidenceId") else []
            source_label = str(row.get("sourceSystem") or row.get("sourceType") or "source")
        matched = next((pattern.pattern for pattern in patterns if pattern.search(text)), None)
        if matched:
            out.append(
                _result(
                    "prompt_injection",
                    "WARN",
                    f"Potential prompt injection pattern detected in {source_label}.",
                    blocked_action="use_untrusted_text_without_review",
                    evidence_ids=evidence_ids,
                )
            )
    if not out:
        out.append(_result("prompt_injection", "PASS", "No prompt injection patterns detected."))
    return out


def evaluate_recommendation_guardrails(
    recommendations: Sequence[AgentRecommendation | Mapping[str, Any]],
    *,
    policy: GuardrailPolicy | None = None,
    human_review_decisions: Sequence[HumanReviewDecision | Mapping[str, Any]] = (),
) -> list[GuardrailResult]:
    policy = policy or GuardrailPolicy()
    results: list[GuardrailResult] = []
    for recommendation in recommendations:
        row = _as_mapping(recommendation)
        rec_id = str(row.get("recommendationId") or "")
        evidence_ids = row.get("evidenceIds") or []
        text = _text_fields(row, ("summary", "rationale", "recommendationType"))
        results.append(evaluate_unsupported_claim(conclusion=text, evidence_ids=evidence_ids, recommendation_id=rec_id))
        results.append(
            evaluate_certification_language(
                text=text,
                human_review_decisions=human_review_decisions,
                recommendation_id=rec_id,
                evidence_ids=evidence_ids,
                policy=policy,
            )
        )
        results.append(evaluate_destructive_action(action_text=text, recommendation_id=rec_id, evidence_ids=evidence_ids, policy=policy))
        results.append(evaluate_human_review_requirement(row, policy=policy))
    return results


def evaluate_assurance_package_guardrails(
    package: Mapping[str, Any],
    *,
    schema_path: Path,
    policy: GuardrailPolicy | None = None,
) -> list[GuardrailResult]:
    policy = policy or GuardrailPolicy()
    decisions = package.get("humanReviewDecisions") or []
    results = [validate_structured_output(package, schema_path=schema_path, policy=policy)]
    for evidence in package.get("evidence") or []:
        results.append(evaluate_evidence_freshness(evidence, policy=policy))
        results.extend(evaluate_scope_boundaries(evidence, policy=policy))
    results.extend(evaluate_recommendation_guardrails(package.get("agentRecommendations") or [], policy=policy, human_review_decisions=decisions))
    for assessment in package.get("assessmentResults") or []:
        text = _text_fields(assessment, ("status", "summary"))
        recommendation_ids = assessment.get("recommendations") or []
        recommendation_id = str(recommendation_ids[0]) if recommendation_ids else None
        results.append(
            evaluate_certification_language(
                text=text,
                human_review_decisions=decisions,
                recommendation_id=recommendation_id,
                evidence_ids=assessment.get("evidenceIds") or [],
                policy=policy,
            )
        )
    results.extend(detect_prompt_injection(package.get("evidence") or [], policy=policy))
    return results


def evaluate_report_guardrails(
    report_text: str,
    *,
    package: Mapping[str, Any],
    policy: GuardrailPolicy | None = None,
) -> list[GuardrailResult]:
    policy = policy or GuardrailPolicy()
    decisions = package.get("humanReviewDecisions") or []
    results = [
        evaluate_certification_language(text=report_text, human_review_decisions=decisions, policy=policy),
        evaluate_destructive_action(action_text=report_text, policy=policy),
    ]
    results.extend(detect_prompt_injection([report_text], policy=policy))
    return results


def enforce_guardrails(results: Sequence[GuardrailResult]) -> None:
    failures = [result for result in results if result.status == "FAIL"]
    if failures:
        details = "; ".join(f"{result.guardrail_id}: {result.message}" for result in failures)
        raise ValueError("guardrail validation failed: " + details)


__all__ = [
    "detect_prompt_injection",
    "enforce_guardrails",
    "evaluate_assurance_package_guardrails",
    "evaluate_certification_language",
    "evaluate_destructive_action",
    "evaluate_evidence_freshness",
    "evaluate_human_review_requirement",
    "evaluate_recommendation_guardrails",
    "evaluate_report_guardrails",
    "evaluate_scope_boundaries",
    "evaluate_unsupported_claim",
    "validate_structured_output",
]
