"""FastAPI app: grounded /api/explain with deterministic fallback.

Also exposes the structured ``ai.reasoning`` reasoners under ``/api/ai/*`` so
the web explorer can invoke any of the reasoners and render the typed
:mod:`ai.models` response (including which path — LLM vs deterministic
fallback — produced the answer).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai import (
    classify_ambiguous_row,
    draft_auditor_response,
    draft_remediation_ticket,
    explain_conmon_reasonableness,
    explain_derivation_trace,
    explain_for_assessor,
    explain_for_executive,
    explain_residual_risk_for_ao,
    evaluate_3pao_remediation_for_gap,
    is_llm_configured,
    llm_backend_status,
)
from api.explain import run_explain
from core.human_review import (
    filter_review_history,
    list_pending_recommendations,
    load_recommendations,
    load_review_history,
    record_review_decision,
)

app = FastAPI(title="Observable Security Agent — Explain API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Audience = Literal["assessor", "executive", "ao", "engineer"]


class ExplainBody(BaseModel):
    """POST /api/explain — primary FedRAMP / assessment explain payload."""

    mode: str = Field(default="explain_eval")
    question: str | None = None
    audience: Audience | None = Field(default="engineer")
    selected_ksi: dict[str, Any] | None = None
    selected_eval: dict[str, Any] | None = None
    selected_finding: dict[str, Any] | None = None
    selected_poam: dict[str, Any] | list[dict[str, Any]] | None = None
    related_evidence: dict[str, Any] | None = None
    related_reconciliation: dict[str, Any] | None = None
    # Legacy fields (older web client)
    related_graph: dict[str, Any] | None = None
    related_poam: list[dict[str, Any]] | None = None
    fedramp20x_context: dict[str, Any] | None = None


@app.get("/api/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/explain")
def explain(body: ExplainBody) -> dict[str, Any]:
    return run_explain(
        mode=body.mode,
        question=body.question,
        audience=body.audience,
        selected_ksi=body.selected_ksi,
        selected_eval=body.selected_eval,
        selected_finding=body.selected_finding,
        selected_poam=body.selected_poam,
        related_evidence=body.related_evidence,
        related_reconciliation=body.related_reconciliation,
        related_graph=body.related_graph,
        related_poam=body.related_poam or [],
        fedramp20x_context=body.fedramp20x_context,
    )


# ---------------------------------------------------------------------------
# Structured AI reasoner API
#
# Each reasoner accepts a small JSON ``payload`` whose shape mirrors the
# function signature in :mod:`ai.reasoning`. The response is the Pydantic
# model serialized via ``model_dump()`` — ``source`` records LLM vs
# deterministic_fallback so callers can render provenance.
# ---------------------------------------------------------------------------


class ReasonerBody(BaseModel):
    reasoner: Literal[
        "classify_ambiguous_row",
        "explain_for_assessor",
        "explain_for_executive",
        "explain_conmon_reasonableness",
        "explain_residual_risk_for_ao",
        "explain_derivation_trace",
        "draft_remediation_ticket",
        "draft_auditor_response",
        "evaluate_3pao_remediation_for_gap",
    ]
    payload: dict[str, Any] = Field(default_factory=dict)


class ReviewFilesBody(BaseModel):
    recommendations_path: str = Field(..., alias="recommendationsPath")
    history_path: str = Field(..., alias="historyPath")


class RecordReviewBody(ReviewFilesBody):
    recommendation_id: str = Field(..., alias="recommendationId")
    reviewer: str
    decision: Literal[
        "ACCEPTED",
        "ACCEPTED_WITH_EDITS",
        "REJECTED",
        "NEEDS_MORE_EVIDENCE",
        "FALSE_POSITIVE",
        "RISK_ACCEPTED",
        "COMPENSATING_CONTROL_ACCEPTED",
        "ESCALATED_TO_AO",
        "ESCALATED_TO_3PAO",
    ]
    justification: str
    control_id: str | None = Field(default=None, alias="controlId")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")


class ReviewHistoryBody(BaseModel):
    history_path: str = Field(..., alias="historyPath")
    control_id: str | None = Field(default=None, alias="controlId")
    finding_id: str | None = Field(default=None, alias="findingId")
    recommendation_id: str | None = Field(default=None, alias="recommendationId")


_REASONER_MAP: dict[str, Any] = {
    "classify_ambiguous_row": classify_ambiguous_row,
    "explain_for_assessor": explain_for_assessor,
    "explain_for_executive": explain_for_executive,
    "explain_conmon_reasonableness": explain_conmon_reasonableness,
    "explain_residual_risk_for_ao": explain_residual_risk_for_ao,
    "explain_derivation_trace": explain_derivation_trace,
    "draft_remediation_ticket": draft_remediation_ticket,
    "draft_auditor_response": draft_auditor_response,
    "evaluate_3pao_remediation_for_gap": evaluate_3pao_remediation_for_gap,
}


@app.get("/api/ai/status")
def ai_status() -> dict[str, Any]:
    """Report the AI reasoner posture (no key → deterministic-only mode)."""
    status = llm_backend_status(reasoners=list(_REASONER_MAP.keys()))
    return {
        "llm_configured": is_llm_configured(),
        **status,
    }


@app.post("/api/ai/reasoner")
def ai_reasoner(body: ReasonerBody) -> dict[str, Any]:
    """Invoke any of the structured ``ai.reasoning`` reasoners.

    The body looks like ``{"reasoner": "<name>", "payload": {<kwargs>}}``.
    ``payload`` is forwarded as kwargs; missing fields fall through to the
    reasoner's defaults / deterministic-fallback path.
    """
    fn = _REASONER_MAP.get(body.reasoner)
    if fn is None:
        raise HTTPException(status_code=400, detail=f"unknown reasoner {body.reasoner!r}")
    try:
        result = fn(**body.payload)
    except TypeError as e:
        raise HTTPException(status_code=400, detail=f"bad payload for {body.reasoner!r}: {e}") from e
    # Every reasoner returns a Pydantic model.
    if hasattr(result, "model_dump"):
        return result.model_dump(mode="json")
    return {"result": result}


@app.post("/api/review/pending")
def review_pending(body: ReviewFilesBody) -> dict[str, Any]:
    try:
        recommendations = load_recommendations(Path(body.recommendations_path))
        history = load_review_history(Path(body.history_path))
        pending = list_pending_recommendations(recommendations, history)
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "pendingRecommendations": [rec.model_dump(mode="json", by_alias=True) for rec in pending],
        "count": len(pending),
    }


@app.post("/api/review/decision")
def review_decision(body: RecordReviewBody) -> dict[str, Any]:
    try:
        recommendations = load_recommendations(Path(body.recommendations_path))
        decision = record_review_decision(
            history_path=Path(body.history_path),
            recommendations=recommendations,
            recommendation_id=body.recommendation_id,
            reviewer=body.reviewer,
            decision=body.decision,
            justification=body.justification,
            evidence_ids=body.evidence_ids,
            finding_ids=body.finding_ids,
            control_id=body.control_id,
        )
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return decision.model_dump(mode="json", by_alias=True)


@app.post("/api/review/history")
def review_history(body: ReviewHistoryBody) -> dict[str, Any]:
    try:
        history = load_review_history(Path(body.history_path))
        filtered = filter_review_history(
            history,
            control_id=body.control_id,
            finding_id=body.finding_id,
            recommendation_id=body.recommendation_id,
        )
    except (OSError, ValueError) as e:
        raise HTTPException(status_code=400, detail=str(e)) from e
    return {
        "reviewHistory": [decision.model_dump(mode="json", by_alias=True) for decision in filtered],
        "count": len(filtered),
    }


def main() -> None:
    import uvicorn

    uvicorn.run("api.server:app", host="127.0.0.1", port=8081, reload=False)


if __name__ == "__main__":
    main()
