"""Bounded LLM-backed reasoning for the observable security agent.

This package wraps a small set of high-value reasoning calls behind an
*identical* deterministic-fallback path. When ``AI_API_KEY`` is not set (or the
LLM call fails for any reason), every reasoner returns a structured
deterministic answer derived solely from the provided artifacts. The structure
of every return value is a Pydantic model; downstream callers can serialize it
to JSON without further branching.

Public reasoners:

* :func:`classify_ambiguous_row` — when the deterministic phrase classifier
  returns ``unknown``, ask the LLM to pick a typed gap from the canonical list.
* :func:`explain_for_assessor` — assessor-ready explanation of an eval row.
* :func:`explain_for_executive` — executive-ready summary of a 20x package.
* :func:`explain_residual_risk_for_ao` — AO residual-risk framing of a finding.
* :func:`explain_derivation_trace` — natural-language walk of the agent_loop trace.
* :func:`draft_remediation_ticket` — local draft text for a remediation ticket
  (NEVER submitted externally).
* :func:`draft_auditor_response` — local draft text answering an auditor question.

Strict invariants:

* No LLM call is used for pass/fail computation, schema validation, evidence
  existence, dates, or artifact-path existence.
* Every prompt embeds the binding evidence contract from
  :mod:`core.evidence_contract`.
* Every output is sanitized so it cannot claim a missing alert, ticket, or log
  exists; sanitized claims are rewritten to ``**missing evidence**`` markers.
"""

from ai.models import (
    AuditorResponseDraft,
    EvidenceCitation,
    ExplanationResponse,
    ReasoningSource,
    RemediationTicketDraft,
    RowClassificationReasoning,
)
from ai.reasoning import (
    classify_ambiguous_row,
    draft_auditor_response,
    draft_remediation_ticket,
    explain_derivation_trace,
    explain_for_assessor,
    explain_for_executive,
    explain_residual_risk_for_ao,
    is_llm_configured,
)

__all__ = [
    "AuditorResponseDraft",
    "EvidenceCitation",
    "ExplanationResponse",
    "ReasoningSource",
    "RemediationTicketDraft",
    "RowClassificationReasoning",
    "classify_ambiguous_row",
    "draft_auditor_response",
    "draft_remediation_ticket",
    "explain_derivation_trace",
    "explain_for_assessor",
    "explain_for_executive",
    "explain_residual_risk_for_ao",
    "is_llm_configured",
]
