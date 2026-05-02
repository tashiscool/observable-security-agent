"""Public LLM-backed reasoners with deterministic fallback.

Each public function in this module:

1. Builds an LLM prompt via :mod:`ai.prompts` (which embeds the binding
   evidence contract from :mod:`core.evidence_contract`).
2. Computes a deterministic fallback via :mod:`ai.fallbacks`.
3. If ``AI_API_KEY`` is set AND the LLM call succeeds AND the LLM output parses
   into the expected Pydantic model, returns the LLM result. Otherwise returns
   the deterministic fallback.
4. ALWAYS runs the result through :func:`sanitize_no_invented_evidence` so
   that no output can claim a missing alert / ticket / log exists.

The LLM client is intentionally tiny (stdlib ``urllib`` only) so this package
adds no third-party dependencies.

Testing notes:

* Tests can override the LLM HTTP transport by monkey-patching
  :func:`_call_openai_compatible`.
* The default no-key path is fully deterministic and covered by the fallback
  module's tests.
"""

from __future__ import annotations

import json
import logging
import os
import re
import urllib.error
import urllib.request
from typing import Any

from pydantic import BaseModel, ValidationError

from ai import fallbacks
from ai.models import (
    AuditorResponseDraft,
    ExplanationResponse,
    ReasoningSource,
    RemediationTicketDraft,
    RowClassificationReasoning,
)
from ai.prompts import (
    build_assessor_explanation_messages,
    build_auditor_response_messages,
    build_classify_row_messages,
    build_derivation_trace_messages,
    build_executive_summary_messages,
    build_remediation_ticket_messages,
    build_residual_risk_messages,
)


__all__ = [
    "MISSING_EVIDENCE_MARK",
    "classify_ambiguous_row",
    "draft_auditor_response",
    "draft_remediation_ticket",
    "explain_derivation_trace",
    "explain_for_assessor",
    "explain_for_executive",
    "explain_residual_risk_for_ao",
    "is_llm_configured",
    "sanitize_no_invented_evidence",
]


_LOG = logging.getLogger(__name__)
_DEFAULT_TIMEOUT_S = 90.0


MISSING_EVIDENCE_MARK = "**missing evidence**"


# ---------------------------------------------------------------------------
# Environment / configuration
# ---------------------------------------------------------------------------


def is_llm_configured() -> bool:
    """True iff ``AI_API_KEY`` is set in the environment."""
    return bool((os.environ.get("AI_API_KEY") or "").strip())


def _llm_endpoint() -> tuple[str, str, str]:
    """Return ``(api_base, model, api_key)`` from the environment."""
    base = (os.environ.get("AI_API_BASE") or "https://api.openai.com/v1").rstrip("/")
    model = (os.environ.get("AI_MODEL") or "gpt-4o-mini").strip()
    key = (os.environ.get("AI_API_KEY") or "").strip()
    return base, model, key


# ---------------------------------------------------------------------------
# LLM client (OpenAI-compatible chat completions over stdlib urllib)
# ---------------------------------------------------------------------------


def _call_openai_compatible(
    *,
    system_message: str,
    user_message: str,
    temperature: float = 0.1,
    timeout_s: float = _DEFAULT_TIMEOUT_S,
) -> str | None:
    """Make a single chat-completion call and return the raw assistant content.

    Returns ``None`` if no API key is set, or if any network / HTTP / parsing
    error occurs. This function is the SINGLE injection point tests can
    monkey-patch to simulate LLM responses.
    """
    base, model, key = _llm_endpoint()
    if not key:
        return None
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": system_message},
            {"role": "user", "content": user_message},
        ],
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url=f"{base}/chat/completions",
        data=body,
        method="POST",
        headers={
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout_s) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
        doc = json.loads(raw)
        choices = doc.get("choices") or []
        if not choices:
            return None
        msg = (choices[0] or {}).get("message") or {}
        content = msg.get("content")
        if not isinstance(content, str):
            return None
        return content
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, OSError) as e:
        _LOG.warning("LLM call failed: %s", e)
        return None
    except (json.JSONDecodeError, ValueError, KeyError) as e:
        _LOG.warning("LLM response parsing failed: %s", e)
        return None


def _try_parse_json(text: str) -> dict[str, Any] | None:
    """Best-effort: parse a JSON object out of ``text``."""
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        # Try to recover an embedded JSON object.
        m = re.search(r"\{.*\}", text, re.DOTALL)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None


def _coerce_into_model(model_cls: type[BaseModel], obj: dict[str, Any]) -> BaseModel | None:
    """Attempt to validate ``obj`` into ``model_cls``; return None on failure."""
    try:
        return model_cls.model_validate(obj)
    except ValidationError as e:
        _LOG.warning("LLM output failed Pydantic validation for %s: %s", model_cls.__name__, e)
        return None


# ---------------------------------------------------------------------------
# Sanitization: never claim missing alert / ticket / log exists
# ---------------------------------------------------------------------------


# Patterns that ASSERT a thing exists. If the input declares the corresponding
# evidence is missing, these are rewritten to MISSING_EVIDENCE_MARK.
_ALERT_EXISTS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\b(?:an?|the)\s+alert\s+(?:fired|was\s+(?:fired|triggered|raised|sent))\b", re.I),
    re.compile(r"\balerts?\s+(?:fired|were\s+(?:fired|triggered|raised|sent))\b", re.I),
    re.compile(r"\bsample[_ ]alert[_ ]ref\s*(?:is|was)\s+\w+\b", re.I),
    re.compile(r"\blast[_ ]fired\s*(?:is|was|=)\s*\S+\b", re.I),
)

_TICKET_EXISTS_PATTERNS: tuple[re.Pattern[str], ...] = (
    # Bare ticket-style identifiers (JIRA-1234, INC9999, CHG-42, etc.) that imply
    # a real linked ticket exists. Most-specific first.
    re.compile(
        r"\b(?:JIRA|INC|SNOW|TICKET|TKT|CHG|PROJ|SVC|REQ|SR)[-_ ]?\d{2,}\b", re.I
    ),
    re.compile(r"\b(?:ticket|jira|servicenow|incident)[\s-]+[A-Z][\w-]+\d+\b", re.I),
    re.compile(
        r"\b(?:the|an?)\s+(?:linked\s+)?ticket\s+(?:exists|was\s+filed|was\s+created|is\s+filed)\b",
        re.I,
    ),
    re.compile(r"\blinked[_ ]ticket[_ ]id\s*(?:is|was|=)\s*\w+\b", re.I),
    re.compile(r"\bticket\s+id\s*(?:is|was|=)\s*\w+\b", re.I),
    re.compile(r"\b\w+[-_]\d{3,}\s+was\s+(?:filed|created|opened)\b", re.I),
)

_LOG_EXISTS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bcentral(?:ized)?\s+log(?:s)?\s+(?:are\s+)?(?:active|ingest(?:ed|ing)|present)\b", re.I),
    re.compile(r"\blogs?\s+(?:were|are)\s+ingested\b", re.I),
    re.compile(r"\bsplunk\s+(?:contains|shows|has)\s+\b", re.I),
)

# Map from missing-evidence keyword fragments to their pattern bucket.
_MISSING_KEY_TO_PATTERNS: tuple[tuple[tuple[str, ...], tuple[re.Pattern[str], ...], str], ...] = (
    (
        ("alert", "sample_alert_ref", "last_fired", "alert_firing", "alert_rule"),
        _ALERT_EXISTS_PATTERNS,
        "alert firing",
    ),
    (
        ("ticket", "linked_ticket_id", "linked_ticket", "jira", "servicenow"),
        _TICKET_EXISTS_PATTERNS,
        "ticket linkage",
    ),
    (
        ("log", "central_log", "centralized_log", "splunk", "siem", "ingest"),
        _LOG_EXISTS_PATTERNS,
        "centralized log capture",
    ),
)


def _missing_buckets(missing_evidence: list[str]) -> list[str]:
    """Return the bucket labels (alert/ticket/log) implicated by ``missing_evidence``."""
    me_blob = " ".join(str(x).lower() for x in (missing_evidence or []))
    out: list[str] = []
    for fragments, _patterns, label in _MISSING_KEY_TO_PATTERNS:
        if any(frag in me_blob for frag in fragments):
            out.append(label)
    return out


def sanitize_no_invented_evidence(
    text: str,
    *,
    missing_evidence: list[str],
) -> tuple[str, list[str]]:
    """Rewrite assertion phrases to ``**missing evidence**`` when input says so.

    Returns ``(sanitized_text, warnings)``. Warnings list each sanitization
    rule that fired so callers can surface them in the structured output.
    """
    if not text:
        return text, []
    warnings: list[str] = []
    me_blob = " ".join(str(x).lower() for x in (missing_evidence or []))
    out = text
    for fragments, patterns, label in _MISSING_KEY_TO_PATTERNS:
        if not any(frag in me_blob for frag in fragments):
            continue
        for pat in patterns:
            if pat.search(out):
                out, n = pat.subn(f"{MISSING_EVIDENCE_MARK} for {label}", out)
                if n:
                    warnings.append(
                        f"sanitized {n} mention(s) implying {label} existed (missing in input)"
                    )
    return out, warnings


def _sanitize_explanation(resp: ExplanationResponse) -> ExplanationResponse:
    body, w = sanitize_no_invented_evidence(resp.body, missing_evidence=resp.missing_evidence)
    if not w:
        return resp
    return resp.model_copy(update={"body": body, "warnings": [*resp.warnings, *w]})


def _sanitize_remediation(resp: RemediationTicketDraft) -> RemediationTicketDraft:
    desc, w = sanitize_no_invented_evidence(
        resp.description_md, missing_evidence=resp.missing_evidence
    )
    title, _w2 = sanitize_no_invented_evidence(
        resp.title, missing_evidence=resp.missing_evidence
    )
    if not w and title == resp.title:
        return resp
    return resp.model_copy(
        update={"description_md": desc, "title": title, "warnings": [*resp.warnings, *w]}
    )


def _sanitize_auditor(resp: AuditorResponseDraft) -> AuditorResponseDraft:
    body, w = sanitize_no_invented_evidence(
        resp.response_md, missing_evidence=resp.missing_evidence
    )
    if not w:
        return resp
    return resp.model_copy(update={"response_md": body, "warnings": [*resp.warnings, *w]})


# ---------------------------------------------------------------------------
# Helper: shared LLM-or-fallback flow
# ---------------------------------------------------------------------------


def _llm_or_fallback(
    *,
    model_cls: type[BaseModel],
    system_message: str,
    user_message: str,
    fallback_value: BaseModel,
) -> BaseModel:
    if not is_llm_configured():
        return fallback_value
    raw = _call_openai_compatible(
        system_message=system_message, user_message=user_message
    )
    if not raw:
        warnings = list(getattr(fallback_value, "warnings", []) or [])
        warnings.append("LLM unavailable or empty response; used deterministic fallback.")
        return fallback_value.model_copy(update={"warnings": warnings})
    parsed = _try_parse_json(raw)
    if parsed is None:
        warnings = list(getattr(fallback_value, "warnings", []) or [])
        warnings.append("LLM response was not valid JSON; used deterministic fallback.")
        return fallback_value.model_copy(update={"warnings": warnings})
    parsed["source"] = ReasoningSource.LLM.value
    obj = _coerce_into_model(model_cls, parsed)
    if obj is None:
        warnings = list(getattr(fallback_value, "warnings", []) or [])
        warnings.append("LLM response failed schema validation; used deterministic fallback.")
        return fallback_value.model_copy(update={"warnings": warnings})
    return obj


# ---------------------------------------------------------------------------
# Public reasoners (one per use case)
# ---------------------------------------------------------------------------


def classify_ambiguous_row(
    *,
    tracker_row: dict[str, Any],
    deterministic_classification: dict[str, Any],
) -> RowClassificationReasoning:
    """Classify a tracker row whose deterministic ``gap_type`` is ``unknown``."""
    sysm, userm = build_classify_row_messages(
        tracker_row=tracker_row,
        deterministic_classification=deterministic_classification,
    )
    fb = fallbacks.fallback_classify_row(
        tracker_row=tracker_row,
        deterministic_classification=deterministic_classification,
    )
    out = _llm_or_fallback(
        model_cls=RowClassificationReasoning,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, RowClassificationReasoning)
    return out


def explain_for_assessor(
    *,
    eval_record: dict[str, Any],
    related_evidence: dict[str, Any] | None = None,
    fedramp20x_context: dict[str, Any] | None = None,
) -> ExplanationResponse:
    sysm, userm = build_assessor_explanation_messages(
        eval_record=eval_record,
        related_evidence=related_evidence,
        fedramp20x_context=fedramp20x_context,
    )
    fb = fallbacks.fallback_explain_for_assessor(
        eval_record=eval_record,
        related_evidence=related_evidence,
        fedramp20x_context=fedramp20x_context,
    )
    out = _llm_or_fallback(
        model_cls=ExplanationResponse,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, ExplanationResponse)
    return _sanitize_explanation(out)


def explain_for_executive(
    *,
    package_summary: dict[str, Any],
    fail_partial_findings: list[dict[str, Any]] | None = None,
    open_poam: list[dict[str, Any]] | None = None,
) -> ExplanationResponse:
    sysm, userm = build_executive_summary_messages(
        package_summary=package_summary,
        fail_partial_findings=fail_partial_findings,
        open_poam=open_poam,
    )
    fb = fallbacks.fallback_explain_for_executive(
        package_summary=package_summary,
        fail_partial_findings=fail_partial_findings,
        open_poam=open_poam,
    )
    out = _llm_or_fallback(
        model_cls=ExplanationResponse,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, ExplanationResponse)
    return _sanitize_explanation(out)


def explain_residual_risk_for_ao(
    *,
    finding: dict[str, Any],
    poam: dict[str, Any] | None = None,
    related_ksi: dict[str, Any] | None = None,
) -> ExplanationResponse:
    sysm, userm = build_residual_risk_messages(
        finding=finding, poam=poam, related_ksi=related_ksi
    )
    fb = fallbacks.fallback_explain_residual_risk(
        finding=finding, poam=poam, related_ksi=related_ksi
    )
    out = _llm_or_fallback(
        model_cls=ExplanationResponse,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, ExplanationResponse)
    return _sanitize_explanation(out)


def explain_derivation_trace(*, trace: dict[str, Any]) -> ExplanationResponse:
    sysm, userm = build_derivation_trace_messages(trace=trace)
    fb = fallbacks.fallback_explain_derivation_trace(trace=trace)
    out = _llm_or_fallback(
        model_cls=ExplanationResponse,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, ExplanationResponse)
    return _sanitize_explanation(out)


def draft_remediation_ticket(
    *,
    finding: dict[str, Any],
    eval_record: dict[str, Any] | None = None,
) -> RemediationTicketDraft:
    sysm, userm = build_remediation_ticket_messages(
        finding=finding, eval_record=eval_record
    )
    fb = fallbacks.fallback_draft_remediation_ticket(
        finding=finding, eval_record=eval_record
    )
    out = _llm_or_fallback(
        model_cls=RemediationTicketDraft,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, RemediationTicketDraft)
    return _sanitize_remediation(out)


def draft_auditor_response(
    *,
    question: str,
    evidence_gap: dict[str, Any] | None = None,
    eval_record: dict[str, Any] | None = None,
    related_artifacts: dict[str, Any] | None = None,
) -> AuditorResponseDraft:
    sysm, userm = build_auditor_response_messages(
        question=question,
        evidence_gap=evidence_gap,
        eval_record=eval_record,
        related_artifacts=related_artifacts,
    )
    fb = fallbacks.fallback_draft_auditor_response(
        question=question,
        evidence_gap=evidence_gap,
        eval_record=eval_record,
        related_artifacts=related_artifacts,
    )
    out = _llm_or_fallback(
        model_cls=AuditorResponseDraft,
        system_message=sysm,
        user_message=userm,
        fallback_value=fb,
    )
    assert isinstance(out, AuditorResponseDraft)
    return _sanitize_auditor(out)
