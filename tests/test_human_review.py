"""Tests for human-in-the-loop review lifecycle."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from core.domain_models import AgentRecommendation, AssessmentResult, HumanReviewDecision, model_from_json, model_to_json
from core.human_review import (
    attach_review_decisions_to_assessment,
    filter_review_history,
    list_pending_recommendations,
    load_review_history,
    record_review_decision,
)


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def _recommendation(
    recommendation_id: str = "rec-001",
    *,
    recommendation_type: str = "REQUEST_EVIDENCE",
    evidence_ids: list[str] | None = None,
    finding_ids: list[str] | None = None,
) -> AgentRecommendation:
    return AgentRecommendation(
        recommendationId=recommendation_id,
        controlId="RA-5",
        findingIds=finding_ids or ["nf-001"],
        evidenceIds=evidence_ids or ["ev-001"],
        recommendationType=recommendation_type,
        summary="Request evidence.",
        rationale="Evidence is required before assessment.",
        confidence=0.8,
        blockedUnsupportedClaims=True,
        humanReviewRequired=True,
    )


def _write_recommendations(path: Path, recommendations: list[AgentRecommendation]) -> None:
    path.write_text(
        json.dumps([rec.model_dump(mode="json", by_alias=True) for rec in recommendations]),
        encoding="utf-8",
    )


def _assessment() -> AssessmentResult:
    return AssessmentResult(
        assessmentId="assess-001",
        controlId="RA-5",
        status="INSUFFICIENT_EVIDENCE",
        summary="RA-5 needs evidence.",
        evidenceIds=["ev-001"],
        findingIds=["nf-001"],
        gaps=["Missing scan evidence."],
        recommendations=["Request scanner evidence."],
        confidence=0.7,
        humanReviewRequired=True,
        createdAt=NOW,
    )


def test_accepted_recommendation_recorded_and_removed_from_pending(tmp_path: Path) -> None:
    rec = _recommendation()
    history = tmp_path / "review-history.jsonl"

    decision = record_review_decision(
        history_path=history,
        recommendations=[rec],
        recommendation_id="rec-001",
        reviewer="ISSO",
        decision="ACCEPTED",
        justification="Evidence request is appropriate.",
        timestamp=NOW,
    )
    loaded = load_review_history(history)

    assert decision.decision == "ACCEPTED"
    assert loaded == [decision]
    assert list_pending_recommendations([rec], loaded) == []
    assert model_from_json(type(decision), model_to_json(decision)) == decision


def test_rejected_recommendation_recorded(tmp_path: Path) -> None:
    rec = _recommendation()
    history = tmp_path / "review-history.jsonl"

    decision = record_review_decision(
        history_path=history,
        recommendations=[rec],
        recommendation_id="rec-001",
        reviewer="3PAO",
        decision="REJECTED",
        justification="Recommendation references the wrong evidence source.",
        timestamp=NOW,
    )

    assert decision.decision == "REJECTED"
    assert filter_review_history(load_review_history(history), recommendation_id="rec-001") == [decision]


def test_risk_accepted_without_justification_fails() -> None:
    rec = _recommendation(recommendation_type="ACCEPT_COMPENSATING_CONTROL_REVIEW")

    with pytest.raises(ValidationError):
        HumanReviewDecision(
            reviewDecisionId="hrd-001",
            recommendationId=rec.recommendation_id,
            controlId=rec.control_id,
            findingIds=rec.finding_ids,
            evidenceIds=rec.evidence_ids,
            reviewer="AO",
            decision="RISK_ACCEPTED",
            justification="",
            timestamp=NOW,
        )


def test_false_positive_without_justification_fails() -> None:
    rec = _recommendation(recommendation_type="ESCALATE_TO_REVIEWER")

    with pytest.raises(ValidationError):
        HumanReviewDecision(
            reviewDecisionId="hrd-002",
            recommendationId=rec.recommendation_id,
            controlId=rec.control_id,
            findingIds=rec.finding_ids,
            evidenceIds=rec.evidence_ids,
            reviewer="3PAO",
            decision="FALSE_POSITIVE",
            justification=" ",
            timestamp=NOW,
        )


def test_compensating_control_accepted_requires_evidence_reference() -> None:
    rec = _recommendation(evidence_ids=[])

    with pytest.raises(ValidationError):
        HumanReviewDecision(
            reviewDecisionId="hrd-003",
            recommendationId=rec.recommendation_id,
            controlId=rec.control_id,
            findingIds=rec.finding_ids,
            evidenceIds=[],
            reviewer="AO",
            decision="COMPENSATING_CONTROL_ACCEPTED",
            justification="Compensating control is documented.",
            timestamp=NOW,
        )


def test_history_is_append_only(tmp_path: Path) -> None:
    rec = _recommendation()
    history = tmp_path / "review-history.jsonl"

    first = record_review_decision(
        history_path=history,
        recommendations=[rec],
        recommendation_id="rec-001",
        reviewer="ISSO",
        decision="NEEDS_MORE_EVIDENCE",
        justification="Need current scanner evidence.",
        timestamp=NOW,
    )
    second = record_review_decision(
        history_path=history,
        recommendations=[rec],
        recommendation_id="rec-001",
        reviewer="AO",
        decision="ESCALATED_TO_3PAO",
        justification="Assessment judgment should be confirmed.",
        timestamp=NOW,
    )

    lines = history.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 2
    assert load_review_history(history) == [first, second]


def test_assessment_result_includes_review_decision_references_without_status_change() -> None:
    rec = _recommendation()
    decision = HumanReviewDecision(
        reviewDecisionId="hrd-004",
        recommendationId=rec.recommendation_id,
        controlId="RA-5",
        findingIds=["nf-001"],
        evidenceIds=["ev-001"],
        reviewer="ISSO",
        decision="ACCEPTED_WITH_EDITS",
        justification="Accepted with edited wording.",
        timestamp=NOW,
    )
    assessment = _assessment()

    updated = attach_review_decisions_to_assessment(assessment, [decision])

    assert updated.review_decision_ids == ["hrd-004"]
    assert updated.status == assessment.status
    assert updated.human_review_required is True


def test_record_decision_requires_existing_recommendation(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        record_review_decision(
            history_path=tmp_path / "history.jsonl",
            recommendations=[],
            recommendation_id="rec-missing",
            reviewer="ISSO",
            decision="ACCEPTED",
            justification="Known recommendation only.",
            timestamp=NOW,
        )


def test_cli_review_lifecycle(tmp_path: Path) -> None:
    rec = _recommendation()
    recs = tmp_path / "recommendations.json"
    history = tmp_path / "history.jsonl"
    _write_recommendations(recs, [rec])

    pending = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "list-pending-recommendations",
            "--recommendations",
            str(recs),
            "--history",
            str(history),
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(pending.stdout)["count"] == 1

    recorded = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "record-review-decision",
            "--recommendations",
            str(recs),
            "--history",
            str(history),
            "--recommendation-id",
            "rec-001",
            "--reviewer",
            "ISSO",
            "--decision",
            "ACCEPTED",
            "--justification",
            "Accept recommendation for evidence collection.",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(recorded.stdout)["decision"] == "ACCEPTED"

    shown = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "show-review-history",
            "--history",
            str(history),
            "--control-id",
            "RA-5",
        ],
        check=True,
        text=True,
        capture_output=True,
    )
    assert json.loads(shown.stdout)["count"] == 1


def test_api_review_lifecycle(tmp_path: Path) -> None:
    from fastapi.testclient import TestClient

    from api.server import app

    rec = _recommendation()
    recs = tmp_path / "recommendations.json"
    history = tmp_path / "history.jsonl"
    _write_recommendations(recs, [rec])
    client = TestClient(app)

    pending = client.post(
        "/api/review/pending",
        json={"recommendationsPath": str(recs), "historyPath": str(history)},
    )
    assert pending.status_code == 200
    assert pending.json()["count"] == 1

    recorded = client.post(
        "/api/review/decision",
        json={
            "recommendationsPath": str(recs),
            "historyPath": str(history),
            "recommendationId": "rec-001",
            "reviewer": "ISSO",
            "decision": "ACCEPTED",
            "justification": "Accept recommendation for evidence collection.",
        },
    )
    assert recorded.status_code == 200
    assert recorded.json()["recommendationId"] == "rec-001"

    shown = client.post(
        "/api/review/history",
        json={"historyPath": str(history), "recommendationId": "rec-001"},
    )
    assert shown.status_code == 200
    assert shown.json()["count"] == 1
