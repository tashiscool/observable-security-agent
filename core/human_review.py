"""Human-in-the-loop review lifecycle support.

The agent recommends; humans decide. This module stores decisions as append-only
JSONL records so history is preserved even without a database.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Sequence

from core.domain_models import AgentRecommendation, AssessmentResult, HumanReviewDecision


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _dedupe(items: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        text = str(item or "").strip()
        if text and text not in seen:
            seen.add(text)
            out.append(text)
    return out


def load_recommendations(path: Path) -> list[AgentRecommendation]:
    """Load recommendations from a JSON file containing a list or wrapper object."""

    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        rows = raw.get("recommendations") or raw.get("agentRecommendations") or raw.get("items") or []
    else:
        rows = raw
    if not isinstance(rows, list):
        raise ValueError(f"Recommendations file must contain a list: {path}")
    return [AgentRecommendation.model_validate(row) for row in rows]


def load_review_history(path: Path) -> list[HumanReviewDecision]:
    """Load append-only review history from JSONL or JSON array."""

    if not path.is_file():
        return []
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return []
    if text.startswith("["):
        raw = json.loads(text)
        if not isinstance(raw, list):
            raise ValueError(f"Review history JSON must be a list: {path}")
        return [HumanReviewDecision.model_validate(row) for row in raw]
    decisions: list[HumanReviewDecision] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError(f"{path}:{line_no}: invalid JSONL review decision: {exc}") from exc
        decisions.append(HumanReviewDecision.model_validate(raw))
    return decisions


def list_pending_recommendations(
    recommendations: Sequence[AgentRecommendation],
    review_history: Sequence[HumanReviewDecision],
) -> list[AgentRecommendation]:
    """Return recommendations with no recorded human decision."""

    decided = {decision.recommendation_id for decision in review_history}
    return [rec for rec in recommendations if rec.recommendation_id not in decided]


def _recommendation_by_id(
    recommendations: Sequence[AgentRecommendation],
    recommendation_id: str,
) -> AgentRecommendation:
    for recommendation in recommendations:
        if recommendation.recommendation_id == recommendation_id:
            return recommendation
    raise ValueError(f"HumanReviewDecision must reference an existing AgentRecommendation: {recommendation_id}")


def create_review_decision(
    *,
    recommendation: AgentRecommendation,
    reviewer: str,
    decision: str,
    justification: str,
    timestamp: datetime | None = None,
    review_decision_id: str | None = None,
    evidence_ids: Sequence[str] | None = None,
    finding_ids: Sequence[str] | None = None,
    control_id: str | None = None,
) -> HumanReviewDecision:
    """Create a validated decision referencing an AgentRecommendation."""

    ts = timestamp or _now()
    rid = review_decision_id or f"hrd-{recommendation.recommendation_id}-{ts.isoformat()}"
    return HumanReviewDecision(
        reviewDecisionId=rid,
        recommendationId=recommendation.recommendation_id,
        controlId=control_id or recommendation.control_id,
        findingIds=_dedupe(list(finding_ids or []) + recommendation.finding_ids),
        evidenceIds=_dedupe(list(evidence_ids or []) + recommendation.evidence_ids),
        reviewer=reviewer,
        decision=decision,
        justification=justification,
        timestamp=ts,
    )


def append_review_decision(path: Path, decision: HumanReviewDecision) -> None:
    """Append one immutable JSONL decision record."""

    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as f:
        f.write(decision.model_dump_json(by_alias=True))
        f.write("\n")


def record_review_decision(
    *,
    history_path: Path,
    recommendations: Sequence[AgentRecommendation],
    recommendation_id: str,
    reviewer: str,
    decision: str,
    justification: str,
    timestamp: datetime | None = None,
    evidence_ids: Sequence[str] | None = None,
    finding_ids: Sequence[str] | None = None,
    control_id: str | None = None,
) -> HumanReviewDecision:
    """Validate and append a review decision for an existing recommendation."""

    recommendation = _recommendation_by_id(recommendations, recommendation_id)
    review = create_review_decision(
        recommendation=recommendation,
        reviewer=reviewer,
        decision=decision,
        justification=justification,
        timestamp=timestamp,
        evidence_ids=evidence_ids,
        finding_ids=finding_ids,
        control_id=control_id,
    )
    append_review_decision(history_path, review)
    return review


def filter_review_history(
    decisions: Sequence[HumanReviewDecision],
    *,
    control_id: str | None = None,
    finding_id: str | None = None,
    recommendation_id: str | None = None,
) -> list[HumanReviewDecision]:
    """Filter review history for CLI/API display."""

    out: list[HumanReviewDecision] = []
    for decision in decisions:
        if control_id and decision.control_id != control_id:
            continue
        if finding_id and finding_id not in decision.finding_ids:
            continue
        if recommendation_id and decision.recommendation_id != recommendation_id:
            continue
        out.append(decision)
    return out


def attach_review_decisions_to_assessment(
    assessment: AssessmentResult,
    decisions: Sequence[HumanReviewDecision],
) -> AssessmentResult:
    """Return an assessment result with related review decision IDs recorded.

    This records human decisions for auditability only; it does not change the
    assessment status or close/satisfy controls automatically.
    """

    related = [
        decision.review_decision_id
        for decision in decisions
        if decision.control_id == assessment.control_id
        or bool(set(decision.finding_ids) & set(assessment.finding_ids))
        or bool(set(decision.evidence_ids) & set(assessment.evidence_ids))
    ]
    return assessment.model_copy(
        update={"review_decision_ids": _dedupe(list(assessment.review_decision_ids) + related)}
    )
