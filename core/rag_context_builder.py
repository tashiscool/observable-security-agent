"""Build bounded, source-linked context bundles for compliance reasoning."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Literal, Sequence

from pydantic import Field

from core.deterministic_validators import ValidatorResult
from core.domain_models import (
    ControlMapping,
    ControlRequirement,
    DomainModel,
    EvidenceArtifact,
    HumanReviewDecision,
    NormalizedFinding,
)


ExcludedReason = Literal[
    "STALE",
    "WRONG_ACCOUNT",
    "WRONG_REGION",
    "WRONG_RESOURCE",
    "WRONG_CONTROL",
    "SUPERSEDED",
    "LOW_TRUST",
    "OUTSIDE_TIME_WINDOW",
]


class ParsedScope(DomainModel):
    user_request: str = Field(..., alias="userRequest")
    control_ids: list[str] = Field(default_factory=list, alias="controlIds")
    asset_ids: list[str] = Field(default_factory=list, alias="assetIds")
    account_ids: list[str] = Field(default_factory=list, alias="accountIds")
    region: str | None = Field(default=None, alias="region")
    time_window_start: datetime | None = Field(default=None, alias="timeWindowStart")
    time_window_end: datetime | None = Field(default=None, alias="timeWindowEnd")
    include_stale_evidence: bool = Field(default=False, alias="includeStaleEvidence")


class ExcludedSource(DomainModel):
    source_id: str = Field(..., alias="sourceId", min_length=1)
    source_type: str = Field(..., alias="sourceType", min_length=1)
    reasons: list[ExcludedReason] = Field(..., alias="reasons")
    message: str = Field(..., alias="message", min_length=1)


class FreshnessSummary(DomainModel):
    current: int = Field(..., alias="current")
    stale: int = Field(..., alias="stale")
    expired: int = Field(..., alias="expired")
    unknown: int = Field(..., alias="unknown")


class RAGContextBundle(DomainModel):
    request_id: str = Field(..., alias="requestId", min_length=1)
    parsed_scope: ParsedScope = Field(..., alias="parsedScope")
    selected_controls: list[ControlRequirement] = Field(default_factory=list, alias="selectedControls")
    selected_evidence: list[EvidenceArtifact] = Field(default_factory=list, alias="selectedEvidence")
    selected_findings: list[NormalizedFinding] = Field(default_factory=list, alias="selectedFindings")
    selected_validation_results: list[ValidatorResult] = Field(default_factory=list, alias="selectedValidationResults")
    selected_prior_human_decisions: list[HumanReviewDecision] = Field(default_factory=list, alias="selectedPriorHumanDecisions")
    excluded_sources: list[ExcludedSource] = Field(default_factory=list, alias="excludedSources")
    freshness_summary: FreshnessSummary = Field(..., alias="freshnessSummary")
    missing_evidence_summary: list[str] = Field(default_factory=list, alias="missingEvidenceSummary")
    instructions_for_llm: str = Field(..., alias="instructionsForLLM", min_length=1)


def _stable_id(*parts: object) -> str:
    text = "|".join(str(part or "") for part in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:20]


def _dedupe(items: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def _aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _subject_time(evidence: EvidenceArtifact) -> datetime:
    return evidence.observed_at or evidence.collected_at


def _inside_window(dt: datetime, start: datetime | None, end: datetime | None) -> bool:
    ref = _aware(dt)
    if start and ref < _aware(start):
        return False
    if end and ref > _aware(end):
        return False
    return True


def _source_message(reasons: Sequence[str]) -> str:
    return "Excluded because " + ", ".join(reasons).lower().replace("_", " ") + "."


def _mapping_control_index(mappings: Sequence[ControlMapping]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for mapping in mappings:
        for evidence_id in mapping.evidence_ids:
            out.setdefault(evidence_id, set()).add(mapping.target_control_id)
        for finding_id in mapping.finding_ids:
            out.setdefault(finding_id, set()).add(mapping.target_control_id)
    return out


def _mapping_finding_evidence_index(mappings: Sequence[ControlMapping]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for mapping in mappings:
        for finding_id in mapping.finding_ids:
            out.setdefault(finding_id, set()).update(mapping.evidence_ids)
    return out


def _matches_resource(resource_id: str | None, resource_arn: str | None, asset_ids: set[str]) -> bool:
    if not asset_ids:
        return True
    values = {str(resource_id or ""), str(resource_arn or "")}
    return bool(values & asset_ids)


def _evidence_control_ids(evidence: EvidenceArtifact, mapping_controls: dict[str, set[str]]) -> set[str]:
    return set(evidence.control_ids) | mapping_controls.get(evidence.evidence_id, set())


def _finding_control_ids(finding: NormalizedFinding, mapping_controls: dict[str, set[str]]) -> set[str]:
    return set(finding.control_ids) | mapping_controls.get(finding.finding_id, set())


def _exclude_evidence_reasons(
    evidence: EvidenceArtifact,
    *,
    scope: ParsedScope,
    control_ids: set[str],
    asset_ids: set[str],
    account_ids: set[str],
    mapping_controls: dict[str, set[str]],
) -> list[ExcludedReason]:
    reasons: list[ExcludedReason] = []
    evidence_controls = _evidence_control_ids(evidence, mapping_controls)
    if account_ids and evidence.account_id not in account_ids:
        reasons.append("WRONG_ACCOUNT")
    if scope.region and evidence.region != scope.region:
        reasons.append("WRONG_REGION")
    if not _matches_resource(evidence.resource_id, evidence.resource_arn, asset_ids):
        reasons.append("WRONG_RESOURCE")
    if control_ids and not (evidence_controls & control_ids):
        reasons.append("WRONG_CONTROL")
    if evidence.freshness_status in {"stale", "expired"} and not scope.include_stale_evidence:
        reasons.append("STALE")
    if evidence.trust_level in {"self_reported", "unknown"}:
        reasons.append("LOW_TRUST")
    if not _inside_window(_subject_time(evidence), scope.time_window_start, scope.time_window_end):
        reasons.append("OUTSIDE_TIME_WINDOW")
    return reasons


def _exclude_finding_reasons(
    finding: NormalizedFinding,
    *,
    scope: ParsedScope,
    control_ids: set[str],
    asset_ids: set[str],
    account_ids: set[str],
    mapping_controls: dict[str, set[str]],
) -> list[ExcludedReason]:
    reasons: list[ExcludedReason] = []
    finding_controls = _finding_control_ids(finding, mapping_controls)
    if account_ids and finding.account_id not in account_ids:
        reasons.append("WRONG_ACCOUNT")
    if scope.region and finding.region != scope.region:
        reasons.append("WRONG_REGION")
    if asset_ids and finding.resource_id not in asset_ids and finding.image_digest not in asset_ids:
        reasons.append("WRONG_RESOURCE")
    if control_ids and not (finding_controls & control_ids):
        reasons.append("WRONG_CONTROL")
    if finding.last_observed_at and not _inside_window(finding.last_observed_at, scope.time_window_start, scope.time_window_end):
        reasons.append("OUTSIDE_TIME_WINDOW")
    return reasons


def _superseded_evidence_ids(evidence: Sequence[EvidenceArtifact]) -> set[str]:
    latest_by_subject: dict[tuple[str | None, str | None, str | None, tuple[str, ...]], EvidenceArtifact] = {}
    for item in evidence:
        key = (
            item.account_id,
            item.region,
            item.resource_id,
            item.resource_arn,
            item.source_type,
            tuple(sorted(item.control_ids)),
        )
        current = latest_by_subject.get(key)
        if current is None or _subject_time(item) > _subject_time(current):
            latest_by_subject[key] = item
    latest_ids = {item.evidence_id for item in latest_by_subject.values()}
    return {item.evidence_id for item in evidence if item.evidence_id not in latest_ids}


def _freshness_summary(evidence: Sequence[EvidenceArtifact]) -> FreshnessSummary:
    counts = {"current": 0, "stale": 0, "expired": 0, "unknown": 0}
    for item in evidence:
        counts[item.freshness_status] = counts.get(item.freshness_status, 0) + 1
    return FreshnessSummary(**counts)


def _instructions_for_llm() -> str:
    return "\n".join(
        [
            "Use only supplied evidence in this RAGContextBundle.",
            "If evidence is insufficient, say INSUFFICIENT_EVIDENCE.",
            "Do not certify compliance or state that a control is approved.",
            "Every factual claim must reference evidenceIds from selectedEvidence.",
            "Separate observations from recommendations.",
            "Require human review for compliance conclusions.",
        ]
    )


def _select_human_decisions(
    decisions: Sequence[HumanReviewDecision],
    *,
    control_ids: set[str],
    request_text: str,
) -> list[HumanReviewDecision]:
    if not control_ids:
        return list(decisions)
    selected: list[HumanReviewDecision] = []
    for decision in decisions:
        text = f"{decision.recommendation_id} {decision.justification} {request_text}".lower()
        if any(control_id.lower() in text for control_id in control_ids):
            selected.append(decision)
    return selected


def build_rag_context(
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
    control_mappings: Sequence[ControlMapping] = (),
    validation_results: Sequence[ValidatorResult] = (),
    human_review_decisions: Sequence[HumanReviewDecision] = (),
    include_stale_evidence: bool | None = None,
) -> RAGContextBundle:
    """Build an evidence-only context bundle for compliance reasoning."""

    include_stale = include_stale_evidence
    if include_stale is None:
        include_stale = "include stale" in user_request.lower() or "use stale" in user_request.lower()
    scope = ParsedScope(
        userRequest=user_request,
        controlIds=_dedupe(control_ids),
        assetIds=_dedupe(asset_ids),
        accountIds=_dedupe(account_ids),
        region=region,
        timeWindowStart=time_window_start,
        timeWindowEnd=time_window_end,
        includeStaleEvidence=include_stale,
    )
    scope_controls = set(scope.control_ids)
    scope_assets = set(scope.asset_ids)
    scope_accounts = set(scope.account_ids)
    mapping_controls = _mapping_control_index(control_mappings)

    selected_controls = [
        control for control in controls if not scope_controls or control.control_id in scope_controls
    ]

    excluded: list[ExcludedSource] = []
    selected_evidence: list[EvidenceArtifact] = []
    superseded = _superseded_evidence_ids(evidence_artifacts)
    for item in evidence_artifacts:
        reasons = _exclude_evidence_reasons(
            item,
            scope=scope,
            control_ids=scope_controls,
            asset_ids=scope_assets,
            account_ids=scope_accounts,
            mapping_controls=mapping_controls,
        )
        if item.evidence_id in superseded:
            reasons.append("SUPERSEDED")
        if reasons:
            excluded.append(
                ExcludedSource(
                    sourceId=item.evidence_id,
                    sourceType="evidence",
                    reasons=_dedupe(reasons),
                    message=_source_message(_dedupe(reasons)),
                )
            )
            continue
        selected_evidence.append(item)

    selected_evidence_ids = {item.evidence_id for item in selected_evidence}
    finding_evidence_index = _mapping_finding_evidence_index(control_mappings)
    selected_findings: list[NormalizedFinding] = []
    for finding in findings:
        reasons = _exclude_finding_reasons(
            finding,
            scope=scope,
            control_ids=scope_controls,
            asset_ids=scope_assets,
            account_ids=scope_accounts,
            mapping_controls=mapping_controls,
        )
        linked_evidence_ids = set(finding.evidence_ids) | finding_evidence_index.get(finding.finding_id, set())
        if linked_evidence_ids and not (linked_evidence_ids & selected_evidence_ids):
            reasons.append("WRONG_RESOURCE" if scope_assets else "WRONG_CONTROL")
        if reasons:
            excluded.append(
                ExcludedSource(
                    sourceId=finding.finding_id,
                    sourceType="finding",
                    reasons=_dedupe(reasons),
                    message=_source_message(_dedupe(reasons)),
                )
            )
            continue
        selected_findings.append(finding)

    selected_finding_ids = {finding.finding_id for finding in selected_findings}
    selected_validation_results = [
        result
        for result in validation_results
        if (
            (not scope_controls or result.control_id in scope_controls)
            and (not scope_assets or result.asset_id in scope_assets or set(result.evidence_ids) & selected_evidence_ids)
            and (not result.evidence_ids or set(result.evidence_ids) <= selected_evidence_ids)
            and (not result.finding_ids or set(result.finding_ids) <= selected_finding_ids)
        )
    ]
    selected_prior_decisions = _select_human_decisions(
        human_review_decisions,
        control_ids=scope_controls,
        request_text=user_request,
    )

    missing: list[str] = []
    selected_control_ids = {control.control_id for control in selected_controls}
    evidence_controls = {
        control_id
        for item in selected_evidence
        for control_id in _evidence_control_ids(item, mapping_controls)
    }
    for control_id in sorted(scope_controls or selected_control_ids):
        if control_id not in evidence_controls:
            missing.append(f"{control_id}: no selected fresh, in-scope evidence is available.")
    if scope_assets and not selected_evidence:
        missing.append("Requested asset scope has no selected fresh, in-scope evidence.")

    request_id = "rag-" + _stable_id(
        user_request,
        ",".join(scope.control_ids),
        ",".join(scope.asset_ids),
        ",".join(scope.account_ids),
        region,
        time_window_start,
        time_window_end,
    )
    return RAGContextBundle(
        requestId=request_id,
        parsedScope=scope,
        selectedControls=selected_controls,
        selectedEvidence=selected_evidence,
        selectedFindings=selected_findings,
        selectedValidationResults=selected_validation_results,
        selectedPriorHumanDecisions=selected_prior_decisions,
        excludedSources=excluded,
        freshnessSummary=_freshness_summary(selected_evidence),
        missingEvidenceSummary=missing,
        instructionsForLLM=_instructions_for_llm(),
    )
