"""Deterministic baseline recommendation generator.

This module turns validated, bounded context bundles into structured
``AgentRecommendation`` objects without calling an LLM. It deliberately avoids
certifying compliance; even positive/no-action outputs require human review.
"""

from __future__ import annotations

import hashlib
from typing import Literal, Sequence

from core.deterministic_validators import ValidatorResult
from core.domain_models import AgentRecommendation, ControlMapping
from core.guardrails import enforce_guardrails, evaluate_recommendation_guardrails
from core.rag_context_builder import RAGContextBundle


RecommendationType = Literal[
    "CREATE_POAM",
    "UPDATE_POAM",
    "REQUEST_RESCAN",
    "REQUEST_EVIDENCE",
    "ESCALATE_TO_REVIEWER",
    "ACCEPT_COMPENSATING_CONTROL_REVIEW",
    "MARK_INSUFFICIENT_EVIDENCE",
    "DRAFT_ASSESSMENT_NARRATIVE",
    "NO_ACTION_REQUIRED",
]


def _stable_id(*parts: object) -> str:
    text = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _scope_control(bundle: RAGContextBundle, fallback: str = "GENERAL") -> str:
    if bundle.parsed_scope.control_ids:
        return bundle.parsed_scope.control_ids[0]
    if bundle.selected_controls:
        return bundle.selected_controls[0].control_id
    return fallback


def _bundle_validation_results(
    bundle: RAGContextBundle,
    validation_results: Sequence[ValidatorResult],
) -> list[ValidatorResult]:
    seen: set[str] = set()
    out: list[ValidatorResult] = []
    for result in list(bundle.selected_validation_results) + list(validation_results):
        key = "|".join(
            [
                result.validator_id,
                result.control_id or "",
                result.asset_id or "",
                result.status,
                ",".join(result.evidence_ids),
                ",".join(result.finding_ids),
            ]
        )
        if key not in seen:
            seen.add(key)
            out.append(result)
    return out


def _rec(
    *,
    bundle: RAGContextBundle,
    recommendation_type: RecommendationType,
    control_id: str,
    summary: str,
    rationale: str,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
    confidence: float = 0.82,
    human_review_required: bool = True,
) -> AgentRecommendation:
    return AgentRecommendation(
        recommendationId="rec-" + _stable_id(bundle.request_id, recommendation_type, control_id, summary, rationale),
        controlId=control_id,
        findingIds=_dedupe(finding_ids),
        evidenceIds=_dedupe(evidence_ids),
        recommendationType=recommendation_type,
        summary=summary,
        rationale=rationale,
        confidence=confidence,
        blockedUnsupportedClaims=True,
        humanReviewRequired=human_review_required,
    )


def _selected_control_ids(bundle: RAGContextBundle) -> list[str]:
    return _dedupe(
        list(bundle.parsed_scope.control_ids)
        + [control.control_id for control in bundle.selected_controls]
        + [control_id for evidence in bundle.selected_evidence for control_id in evidence.control_ids]
        + [control_id for finding in bundle.selected_findings for control_id in finding.control_ids]
    )


def _missing_ref_text(bundle: RAGContextBundle) -> str:
    if bundle.missing_evidence_summary:
        return "missingEvidence: " + " | ".join(bundle.missing_evidence_summary)
    return "missingEvidence: validator reported insufficient evidence."


def _has_existing_poam_signal(validation_results: Sequence[ValidatorResult], mappings: Sequence[ControlMapping]) -> bool:
    if any(result.validator_id.startswith("poam") or "poa&m" in result.message.lower() or "poam" in result.message.lower() for result in validation_results):
        return True
    if any(result.control_id == "CA-5" for result in validation_results):
        return True
    return any(mapping.target_control_id == "CA-5" for mapping in mappings)


def generate_agent_recommendations(
    bundle: RAGContextBundle,
    validation_results: Sequence[ValidatorResult] = (),
    control_mappings: Sequence[ControlMapping] = (),
) -> list[AgentRecommendation]:
    """Generate deterministic baseline recommendations from validated context."""

    all_validation = _bundle_validation_results(bundle, validation_results)
    selected_evidence_ids = [e.evidence_id for e in bundle.selected_evidence]
    control_id = _scope_control(bundle)
    recommendations: list[AgentRecommendation] = []

    insufficient_validators = [
        result
        for result in all_validation
        if result.status in {"FAIL", "UNKNOWN"}
        and (
            result.validator_id in {"required_control_evidence", "evidence_presence", "evidence_freshness"}
            or "insufficient" in result.message.lower()
            or "no evidence" in result.message.lower()
            or "missing" in result.message.lower()
        )
    ]
    if bundle.missing_evidence_summary or insufficient_validators:
        missing_ref = _missing_ref_text(bundle)
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="MARK_INSUFFICIENT_EVIDENCE",
                control_id=control_id,
                evidence_ids=[eid for result in insufficient_validators for eid in result.evidence_ids],
                finding_ids=[fid for result in insufficient_validators for fid in result.finding_ids],
                summary=f"Mark assessment context as INSUFFICIENT_EVIDENCE for {control_id}; {missing_ref}",
                rationale=(
                    "Deterministic validators or context selection found missing support. "
                    f"{missing_ref}. Do not infer compliance from absent evidence."
                ),
                confidence=0.95,
            )
        )
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="REQUEST_EVIDENCE",
                control_id=control_id,
                summary=f"Request missing evidence for {control_id}; {missing_ref}",
                rationale=(
                    "Required evidence is absent from the selected bundle. "
                    f"{missing_ref}. The request should cite source systems, account, region, resource, and time window."
                ),
                confidence=0.9,
            )
        )

    stale_ids = sorted(
        {
            source.source_id
            for source in bundle.excluded_sources
            if source.source_type == "evidence" and "STALE" in source.reasons
        }
    )
    if stale_ids:
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="REQUEST_RESCAN",
                control_id=control_id,
                evidence_ids=stale_ids,
                summary=f"Request a rescan or evidence refresh for stale evidence: {', '.join(stale_ids)}.",
                rationale="Context builder excluded stale evidence as primary support, so fresh scanner or telemetry evidence is required before reasoning.",
                confidence=0.9,
            )
        )

    open_high = [
        finding
        for finding in bundle.selected_findings
        if finding.status == "OPEN" and finding.severity in {"CRITICAL", "HIGH"}
    ]
    if open_high:
        vuln_evidence_ids = _dedupe([eid for finding in open_high for eid in finding.evidence_ids] + selected_evidence_ids)
        vuln_finding_ids = [finding.finding_id for finding in open_high]
        rec_type: RecommendationType = "UPDATE_POAM" if _has_existing_poam_signal(all_validation, control_mappings) else "CREATE_POAM"
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type=rec_type,
                control_id="CA-5" if "CA-5" in _selected_control_ids(bundle) else control_id,
                evidence_ids=vuln_evidence_ids,
                finding_ids=vuln_finding_ids,
                summary=f"{rec_type} for open critical/high vulnerability findings: {', '.join(vuln_finding_ids)}.",
                rationale="Deterministic finding data shows unresolved critical/high vulnerabilities; track remediation with POA&M evidence and human review.",
                confidence=0.92,
            )
        )

    needs_review_mappings = [m for m in control_mappings if m.mapping_confidence == "NEEDS_REVIEW"]
    if needs_review_mappings:
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="ESCALATE_TO_REVIEWER",
                control_id=control_id,
                evidence_ids=[eid for mapping in needs_review_mappings for eid in mapping.evidence_ids],
                finding_ids=[fid for mapping in needs_review_mappings for fid in mapping.finding_ids],
                summary="Escalate uncertain control mappings to a human reviewer.",
                rationale="At least one control mapping has mappingConfidence NEEDS_REVIEW, so deterministic mapping is not sufficient for final reasoning.",
                confidence=0.88,
            )
        )

    compensating = [
        evidence
        for evidence in bundle.selected_evidence
        if any(keyword in evidence.normalized_summary.lower() for keyword in ("compensating", "manual exception", "risk acceptance", "risk accepted"))
    ]
    if compensating:
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="ACCEPT_COMPENSATING_CONTROL_REVIEW",
                control_id=control_id,
                evidence_ids=[e.evidence_id for e in compensating],
                summary="Route compensating control evidence for human review.",
                rationale="Compensating control or risk acceptance evidence can inform assessor judgment, but deterministic logic must not accept it without review.",
                confidence=0.8,
            )
        )

    if bundle.selected_evidence or bundle.selected_findings:
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="DRAFT_ASSESSMENT_NARRATIVE",
                control_id=control_id,
                evidence_ids=selected_evidence_ids,
                finding_ids=[finding.finding_id for finding in bundle.selected_findings],
                summary="Draft an assessment narrative from supplied evidence for human review.",
                rationale="A bounded evidence bundle exists. Narrative generation may summarize observations and recommendations but must cite evidenceIds and avoid certification.",
                confidence=0.78,
            )
        )

    actionable_types = {
        "CREATE_POAM",
        "UPDATE_POAM",
        "REQUEST_RESCAN",
        "REQUEST_EVIDENCE",
        "ESCALATE_TO_REVIEWER",
        "ACCEPT_COMPENSATING_CONTROL_REVIEW",
        "MARK_INSUFFICIENT_EVIDENCE",
    }
    if not any(rec.recommendation_type in actionable_types for rec in recommendations):
        supported = bool(all_validation) and all(result.status == "PASS" for result in all_validation)
        recommendations.append(
            _rec(
                bundle=bundle,
                recommendation_type="NO_ACTION_REQUIRED",
                control_id=control_id,
                evidence_ids=selected_evidence_ids,
                finding_ids=[finding.finding_id for finding in bundle.selected_findings],
                summary="No deterministic remediation action identified; human reviewer must confirm before any compliance conclusion.",
                rationale=(
                    "Deterministic validators did not identify missing evidence, stale evidence, open high/critical findings, "
                    "or uncertain mappings. This is not a certification of control satisfaction."
                ),
                confidence=0.84 if supported else 0.55,
                human_review_required=True,
            )
        )

    enforce_guardrails(evaluate_recommendation_guardrails(recommendations))
    return recommendations
