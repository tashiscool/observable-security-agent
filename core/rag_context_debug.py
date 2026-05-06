"""Deterministic debug views for RAG context bundles."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Sequence

from core.domain_models import ControlRequirement, EvidenceArtifact, HumanReviewDecision, NormalizedFinding
from core.rag_context_builder import RAGContextBundle, build_rag_context


def _json_model(obj: Any) -> dict[str, Any]:
    if hasattr(obj, "model_dump"):
        return obj.model_dump(mode="json", by_alias=True)
    return dict(obj)


def _selected_evidence_reason(evidence: EvidenceArtifact, bundle: RAGContextBundle) -> dict[str, Any]:
    scope = bundle.parsed_scope
    relevance: list[str] = []
    if scope.control_ids and set(evidence.control_ids) & set(scope.control_ids):
        relevance.append("MATCHED_CONTROL")
    if scope.asset_ids and (evidence.resource_id in scope.asset_ids or evidence.resource_arn in scope.asset_ids):
        relevance.append("MATCHED_RESOURCE")
    if scope.account_ids and evidence.account_id in scope.account_ids:
        relevance.append("MATCHED_ACCOUNT")
    if scope.region and evidence.region == scope.region:
        relevance.append("MATCHED_REGION")
    if not relevance:
        relevance.append("SELECTED_BY_UNFILTERED_SCOPE")
    return {
        "evidenceId": evidence.evidence_id,
        "sourceSystem": evidence.source_system,
        "sourceType": evidence.source_type,
        "accountId": evidence.account_id,
        "region": evidence.region,
        "resourceId": evidence.resource_id,
        "controlIds": sorted(evidence.control_ids),
        "relevanceReasons": sorted(relevance),
        "freshnessReason": f"freshnessStatus={evidence.freshness_status}",
        "trustReason": f"trustLevel={evidence.trust_level}",
        "rawRef": evidence.raw_ref,
        "normalizedSummary": evidence.normalized_summary,
    }


def _selected_finding_reason(finding: NormalizedFinding, bundle: RAGContextBundle) -> dict[str, Any]:
    scope = bundle.parsed_scope
    relevance: list[str] = []
    if scope.control_ids and set(finding.control_ids) & set(scope.control_ids):
        relevance.append("MATCHED_CONTROL")
    if scope.asset_ids and (finding.resource_id in scope.asset_ids or finding.image_digest in scope.asset_ids):
        relevance.append("MATCHED_RESOURCE")
    if scope.account_ids and finding.account_id in scope.account_ids:
        relevance.append("MATCHED_ACCOUNT")
    if scope.region and finding.region == scope.region:
        relevance.append("MATCHED_REGION")
    if not relevance:
        relevance.append("SELECTED_BY_UNFILTERED_SCOPE")
    return {
        "findingId": finding.finding_id,
        "scanner": finding.scanner,
        "severity": finding.severity,
        "status": finding.status,
        "resourceId": finding.resource_id,
        "controlIds": sorted(finding.control_ids),
        "evidenceIds": sorted(finding.evidence_ids),
        "relevanceReasons": sorted(relevance),
        "title": finding.title,
    }


def rag_context_debug_document(bundle: RAGContextBundle) -> dict[str, Any]:
    """Return a deterministic, reviewer-friendly explanation of a RAG bundle."""

    return {
        "requestId": bundle.request_id,
        "originalRequest": bundle.parsed_scope.user_request,
        "parsedScope": _json_model(bundle.parsed_scope),
        "selectedControls": sorted(
            (
                {
                    "controlId": control.control_id,
                    "family": control.family,
                    "title": control.title,
                    "responsibility": control.responsibility,
                    "sourceRef": control.source_ref,
                }
                for control in bundle.selected_controls
            ),
            key=lambda row: row["controlId"],
        ),
        "selectedEvidence": sorted(
            (_selected_evidence_reason(evidence, bundle) for evidence in bundle.selected_evidence),
            key=lambda row: row["evidenceId"],
        ),
        "selectedFindings": sorted(
            (_selected_finding_reason(finding, bundle) for finding in bundle.selected_findings),
            key=lambda row: row["findingId"],
        ),
        "excludedSources": sorted(
            (
                {
                    "sourceId": source.source_id,
                    "sourceType": source.source_type,
                    "reasons": sorted(source.reasons),
                    "message": source.message,
                }
                for source in bundle.excluded_sources
            ),
            key=lambda row: (row["sourceType"], row["sourceId"]),
        ),
        "missingEvidenceSummary": sorted(bundle.missing_evidence_summary),
        "freshnessSummary": _json_model(bundle.freshness_summary),
        "finalInstructions": bundle.instructions_for_llm,
    }


def build_rag_context_debug_document(
    *,
    user_request: str,
    control_ids: Sequence[str] = (),
    asset_ids: Sequence[str] = (),
    account_ids: Sequence[str] = (),
    region: str | None = None,
    time_window_start: datetime | None = None,
    time_window_end: datetime | None = None,
    evidence_artifacts: Sequence[EvidenceArtifact] = (),
    findings: Sequence[NormalizedFinding] = (),
    controls: Sequence[ControlRequirement] = (),
    human_review_decisions: Sequence[HumanReviewDecision] = (),
) -> dict[str, Any]:
    bundle = build_rag_context(
        user_request=user_request,
        control_ids=control_ids,
        asset_ids=asset_ids,
        account_ids=account_ids,
        region=region,
        time_window_start=time_window_start,
        time_window_end=time_window_end,
        evidence_artifacts=evidence_artifacts,
        findings=findings,
        controls=controls,
        human_review_decisions=human_review_decisions,
    )
    return rag_context_debug_document(bundle)


def write_rag_context_debug_document(path: Path, document: dict[str, Any]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False) + "\n", encoding="utf-8")
    return path


__all__ = [
    "build_rag_context_debug_document",
    "rag_context_debug_document",
    "write_rag_context_debug_document",
]
