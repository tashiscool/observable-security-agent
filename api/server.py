"""FastAPI app: grounded /api/explain with deterministic fallback.

Also exposes the structured ``ai.reasoning`` reasoners under ``/api/ai/*`` so
the web explorer can invoke any of the seven reasoners and render the typed
:mod:`ai.models` response (including which path — LLM vs deterministic
fallback — produced the answer).
"""

from __future__ import annotations

import os
from typing import Any, Literal

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from ai import (
    classify_ambiguous_row,
    draft_auditor_response,
    draft_remediation_ticket,
    explain_derivation_trace,
    explain_for_assessor,
    explain_for_executive,
    explain_residual_risk_for_ao,
    is_llm_configured,
)
from api.explain import run_explain

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
        "explain_residual_risk_for_ao",
        "explain_derivation_trace",
        "draft_remediation_ticket",
        "draft_auditor_response",
    ]
    payload: dict[str, Any] = Field(default_factory=dict)


_REASONER_MAP: dict[str, Any] = {
    "classify_ambiguous_row": classify_ambiguous_row,
    "explain_for_assessor": explain_for_assessor,
    "explain_for_executive": explain_for_executive,
    "explain_residual_risk_for_ao": explain_residual_risk_for_ao,
    "explain_derivation_trace": explain_derivation_trace,
    "draft_remediation_ticket": draft_remediation_ticket,
    "draft_auditor_response": draft_auditor_response,
}


@app.get("/api/ai/status")
def ai_status() -> dict[str, Any]:
    """Report the AI reasoner posture (no key → deterministic-only mode)."""
    return {
        "llm_configured": is_llm_configured(),
        "endpoint": (os.environ.get("AI_API_BASE") or "https://api.openai.com/v1").rstrip("/"),
        "model": (os.environ.get("AI_MODEL") or "gpt-4o-mini").strip(),
        "reasoners": list(_REASONER_MAP.keys()),
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


def main() -> None:
    import uvicorn

    uvicorn.run("api.server:app", host="127.0.0.1", port=8081, reload=False)


if __name__ == "__main__":
    main()
