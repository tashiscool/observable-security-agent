"""Deterministic fallbacks for every reasoner in :mod:`ai.reasoning`.

Each function here returns the same Pydantic model the LLM-backed path returns
(see :mod:`ai.models`), but is constructed exclusively from the supplied input
artifacts. No LLM call is performed.

Invariants:

* The output ``source`` is always
  :attr:`ai.models.ReasoningSource.DETERMINISTIC_FALLBACK`.
* Pass/fail computation, schema validation, evidence existence, dates, and
  artifact-path checks are NEVER inferred — they are echoed from the input.
* Every fallback honors the ``missing_evidence`` invariant: if a field is not
  in the input, it is added to ``missing_evidence`` rather than fabricated.
"""

from __future__ import annotations

from typing import Any, get_args

from ai.models import (
    AuditorResponseDraft,
    EvidenceCitation,
    ExplanationResponse,
    ReasoningSource,
    RemediationTicketDraft,
    RowClassificationReasoning,
    TicketSeverity,
)
from core.models import GapSeverity, GapType


__all__ = [
    "fallback_classify_row",
    "fallback_explain_for_assessor",
    "fallback_explain_for_executive",
    "fallback_explain_residual_risk",
    "fallback_explain_derivation_trace",
    "fallback_draft_remediation_ticket",
    "fallback_draft_auditor_response",
]


_ALLOWED_GAP_TYPES = set(get_args(GapType))
_ALLOWED_SEVERITIES = set(get_args(GapSeverity))
_ALLOWED_TICKET_SEVERITIES = set(get_args(TicketSeverity))


# ---------------------------------------------------------------------------
# 1. Classify ambiguous tracker row (deterministic fallback = stay at unknown)
# ---------------------------------------------------------------------------


def fallback_classify_row(
    *,
    tracker_row: dict[str, Any],
    deterministic_classification: dict[str, Any],
) -> RowClassificationReasoning:
    """Stay at ``unknown`` and surface the absence as a typed result.

    The deterministic phrase rules already ran and chose ``unknown``. The
    fallback's job is to NOT invent — it preserves that decision but presents
    it as an auditable structured record so the caller can decide whether to
    defer the row to an :class:`InformationalTrackerItem`.
    """
    rid = str(tracker_row.get("row_index") or tracker_row.get("source_item_id") or "unknown")
    base_severity = deterministic_classification.get("severity")
    severity = base_severity if base_severity in _ALLOWED_SEVERITIES else "low"
    missing_fields: list[str] = []
    for f in ("request_text", "assessor_comment", "owner", "due_date"):
        v = tracker_row.get(f)
        if v in (None, "", []):
            missing_fields.append(f)
    rationale = (
        "Deterministic phrase rules did not match this row. The conservative fallback keeps "
        "`gap_type=unknown` rather than guessing; route the row to the InformationalTrackerItem "
        "stream until a human classifier provides a label."
    )
    return RowClassificationReasoning(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        source_item_id=rid,
        gap_type="unknown",
        severity=severity,
        confidence="low",
        rationale=rationale,
        cited_phrases=[],
        recommended_artifact=deterministic_classification.get("recommended_artifact"),
        recommended_validation=deterministic_classification.get("recommended_validation"),
        poam_required=bool(deterministic_classification.get("poam_required")),
        citations=[
            EvidenceCitation(
                artifact="assessment_tracker.csv",
                field="request_text",
                note="No phrase rule fired; deterministic fallback in use.",
            )
        ],
        missing_evidence=missing_fields,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
    )


# ---------------------------------------------------------------------------
# 2. Assessor explanation
# ---------------------------------------------------------------------------


def fallback_explain_for_assessor(
    *,
    eval_record: dict[str, Any],
    related_evidence: dict[str, Any] | None = None,
    fedramp20x_context: dict[str, Any] | None = None,
) -> ExplanationResponse:
    eid = str(eval_record.get("eval_id") or "unknown_eval")
    result = str(eval_record.get("result") or "UNKNOWN")
    severity = str(eval_record.get("severity") or "unspecified")
    summary = str(eval_record.get("summary") or "")[:500]
    gap = str(eval_record.get("gap") or "")
    if not gap:
        gaps = eval_record.get("gaps") or []
        if isinstance(gaps, list) and gaps:
            gap = "; ".join(str(g) for g in gaps[:5])[:1000]
    controls = ", ".join(str(c) for c in (eval_record.get("control_refs") or [])[:8]) or "—"

    headline = f"`{eid}` — assessor view: result={result} (severity={severity})"
    body_lines = [
        f"**Eval:** `{eid}` — result `{result}`, severity `{severity}`.",
        f"**Controls:** {controls}.",
        "",
        "**Summary (from `eval_results.json`):**",
        f"> {summary or '_no summary field present_'}",
    ]
    if gap:
        body_lines += [
            "",
            "**Gap (from `eval_results.json` `gap` / `gaps`):**",
            f"> {gap[:1500]}",
        ]
    rec_actions = eval_record.get("recommended_actions") or (
        [eval_record.get("recommended_action")] if eval_record.get("recommended_action") else []
    )
    if rec_actions:
        body_lines += [
            "",
            "**Recommended closure evidence:**",
            *[f"- {str(a)[:300]}" for a in rec_actions[:6]],
        ]
    body_lines += [
        "",
        "_Where any required closure artifact is not present in the package, status remains_ "
        "**missing evidence** _— do not infer implementation from absence._",
    ]
    citations = [
        EvidenceCitation(artifact="eval_results.json", field=f"evaluations[?(@.eval_id=='{eid}')]")
    ]
    if fedramp20x_context:
        citations.append(
            EvidenceCitation(
                artifact="fedramp20x-package.json",
                field="ksi_validation_results / findings (context)",
            )
        )
    missing: list[str] = []
    if not summary:
        missing.append("eval_results.json:evaluations[].summary")
    if not gap:
        missing.append("eval_results.json:evaluations[].gap")
    return ExplanationResponse(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        audience="assessor",
        headline=headline,
        body="\n".join(body_lines),
        citations=citations,
        missing_evidence=missing,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
        referenced_eval_id=eid or None,
    )


# ---------------------------------------------------------------------------
# 3. Executive summary
# ---------------------------------------------------------------------------


def fallback_explain_for_executive(
    *,
    package_summary: dict[str, Any],
    fail_partial_findings: list[dict[str, Any]] | None = None,
    open_poam: list[dict[str, Any]] | None = None,
) -> ExplanationResponse:
    fp = fail_partial_findings or []
    op = open_poam or []
    overall = str(package_summary.get("overall_status") or package_summary.get("status") or "unknown")
    ksi_total = package_summary.get("ksi_total")
    ksi_pass = package_summary.get("ksi_pass")
    ksi_fail = package_summary.get("ksi_fail")
    ksi_partial = package_summary.get("ksi_partial")

    headline = f"FedRAMP 20x readiness: overall_status `{overall}`."
    body_lines = [
        f"**Overall status (from `fedramp20x-package.json`):** `{overall}`.",
        "",
        "**KSI rollup:**",
        f"- KSIs total: `{ksi_total if ksi_total is not None else 'missing evidence'}`",
        f"- KSIs PASS: `{ksi_pass if ksi_pass is not None else 'missing evidence'}`",
        f"- KSIs PARTIAL: `{ksi_partial if ksi_partial is not None else 'missing evidence'}`",
        f"- KSIs FAIL: `{ksi_fail if ksi_fail is not None else 'missing evidence'}`",
        "",
        f"**Open FAIL/PARTIAL findings:** `{len(fp)}` (cited from `fedramp20x-package.json:findings[]`).",
        f"**Open POA&M items:** `{len(op)}` (cited from `fedramp20x-package.json:poam_items[]`).",
        "",
        "_Treat any non-PASS KSI as a readiness signal until closed with cited artifacts._",
    ]
    citations = [EvidenceCitation(artifact="fedramp20x-package.json", field="summary")]
    missing = []
    for k in ("ksi_total", "ksi_pass", "ksi_fail", "ksi_partial"):
        if package_summary.get(k) is None:
            missing.append(f"fedramp20x-package.json:summary.{k}")
    return ExplanationResponse(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        audience="executive",
        headline=headline,
        body="\n".join(body_lines),
        citations=citations,
        missing_evidence=missing,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
    )


# ---------------------------------------------------------------------------
# 4. AO residual risk
# ---------------------------------------------------------------------------


def fallback_explain_residual_risk(
    *,
    finding: dict[str, Any],
    poam: dict[str, Any] | None = None,
    related_ksi: dict[str, Any] | None = None,
) -> ExplanationResponse:
    fid = str(finding.get("finding_id") or "unknown_finding")
    sev = str(finding.get("severity") or "unspecified")
    title = str(finding.get("title") or finding.get("name") or "")[:200]
    poam_id = str((poam or {}).get("poam_id") or "") if poam else ""
    ksi_id = str((related_ksi or {}).get("ksi_id") or "") if related_ksi else ""

    headline = f"Residual risk: `{fid}` (severity `{sev}`)."
    body_lines = [
        f"**Finding:** `{fid}` — severity `{sev}`.",
        f"**Title:** {title or '_missing evidence_'}.",
    ]
    if ksi_id:
        body_lines.append(f"**Linked KSI:** `{ksi_id}`.")
    if poam_id:
        body_lines.append(f"**Tracked POA&M:** `{poam_id}`.")
    else:
        body_lines.append("**Tracked POA&M:** **missing evidence** — no `poam_id` linked in input.")
    body_lines += [
        "",
        "_The AO should accept residual risk only against the documented POA&M and the explicit_ "
        "_severity above; any acceptance not present in the package remains_ **missing evidence**.",
    ]
    citations = [EvidenceCitation(artifact="fedramp20x-package.json", field=f"findings[finding_id=={fid}]")]
    if poam:
        citations.append(EvidenceCitation(artifact="fedramp20x-package.json", field=f"poam_items[poam_id=={poam_id}]"))
    missing: list[str] = []
    if not title:
        missing.append("fedramp20x-package.json:findings[].title")
    if not poam_id:
        missing.append("fedramp20x-package.json:poam_items[].poam_id")
    return ExplanationResponse(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        audience="ao",
        headline=headline,
        body="\n".join(body_lines),
        citations=citations,
        missing_evidence=missing,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
        referenced_finding_id=fid or None,
        referenced_ksi_id=ksi_id or None,
    )


# ---------------------------------------------------------------------------
# 5. Derivation trace narration
# ---------------------------------------------------------------------------


def fallback_explain_derivation_trace(*, trace: dict[str, Any]) -> ExplanationResponse:
    overall = str(trace.get("overall_status") or "unknown")
    halted_by = trace.get("halted_by")
    tasks = trace.get("tasks") or []
    headline = (
        f"Workflow `{trace.get('workflow') or 'unnamed'}` overall_status `{overall}`"
        + (f"; halted at `{halted_by}`" if halted_by else "")
        + "."
    )
    body_lines = [
        f"**Workflow:** `{trace.get('workflow') or 'unnamed'}` started at `{trace.get('started_at') or 'unknown'}`.",
        f"**Overall status:** `{overall}`.",
    ]
    if halted_by:
        body_lines.append(f"**Halted by:** `{halted_by}`.")
    body_lines.append("")
    body_lines.append("**Tasks (from `agent_run_trace.json:tasks[]`):**")
    for t in tasks[:50]:
        if not isinstance(t, dict):
            continue
        tid = t.get("task_id")
        st = t.get("status")
        cat = (t.get("policy_decision") or {}).get("category")
        body_lines.append(f"- `{tid}` — status `{st}` (policy `{cat}`).")
    if not tasks:
        body_lines.append("_missing evidence — no tasks present in trace._")
    citations = [EvidenceCitation(artifact="agent_run_trace.json", field="tasks[]")]
    return ExplanationResponse(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        audience="derivation_trace",
        headline=headline,
        body="\n".join(body_lines),
        citations=citations,
        missing_evidence=[] if tasks else ["agent_run_trace.json:tasks"],
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
    )


# ---------------------------------------------------------------------------
# 6. Remediation ticket draft
# ---------------------------------------------------------------------------


_SEV_TO_TICKET: dict[str, TicketSeverity] = {
    "critical": "critical",
    "high": "high",
    "moderate": "moderate",
    "medium": "moderate",
    "low": "low",
    "informational": "informational",
    "info": "informational",
}


def fallback_draft_remediation_ticket(
    *,
    finding: dict[str, Any],
    eval_record: dict[str, Any] | None = None,
) -> RemediationTicketDraft:
    fid = str(finding.get("finding_id") or "unknown")
    title_raw = str(finding.get("title") or finding.get("name") or "")[:80]
    sev_in = str(finding.get("severity") or "moderate").lower()
    severity = _SEV_TO_TICKET.get(sev_in, "moderate")
    if severity not in _ALLOWED_TICKET_SEVERITIES:
        severity = "moderate"
    controls = list(finding.get("controls") or [])
    if not controls and eval_record:
        controls = list(eval_record.get("control_refs") or [])

    rec = str(finding.get("recommended_remediation") or "").strip()
    if not rec and eval_record:
        rec = str(eval_record.get("recommended_action") or "").strip()
    description = "\n".join(
        [
            f"**Finding:** `{fid}` — severity `{severity}`.",
            f"**Title:** {title_raw or '_missing evidence_'}.",
            f"**Controls:** {', '.join(controls) if controls else '_missing evidence_'}.",
            "",
            "**Why this ticket exists:**",
            f"This draft tracks closure of finding `{fid}`. Recommended remediation (from input):",
            f"> {rec or '_missing evidence — no `recommended_remediation` / `recommended_action` field present._'}",
            "",
            "_Submit nothing externally; this is a local JSON draft only._",
        ]
    )
    acceptance = [
        f"Attach an evidence export proving the gap cited by `{fid}` is closed.",
        "Re-run `agent.py assess` and `agent.py validate-outputs` after closure.",
        f"`fedramp20x-package.json:findings[finding_id=={fid}].status` transitions to `closed`.",
    ]
    citations = [
        EvidenceCitation(artifact="fedramp20x-package.json", field=f"findings[finding_id=={fid}]")
    ]
    if eval_record:
        eid = str(eval_record.get("eval_id") or "")
        if eid:
            citations.append(
                EvidenceCitation(artifact="eval_results.json", field=f"evaluations[?(@.eval_id=='{eid}')]")
            )
    affected: list[str] = ["fedramp20x-package.json"]
    if eval_record:
        affected.append("eval_results.json")
    missing: list[str] = []
    if not rec:
        missing.append("fedramp20x-package.json:findings[].recommended_remediation")
    if not controls:
        missing.append("fedramp20x-package.json:findings[].controls")
    return RemediationTicketDraft(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        draft_ticket_id=f"DRAFT-TICKET-{fid}",
        title=f"Remediate {fid}: {title_raw or 'finding'}"[:100],
        description_md=description,
        severity=severity,
        controls=controls,
        affected_artifacts=affected,
        acceptance_criteria=acceptance,
        citations=citations,
        missing_evidence=missing,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
    )


# ---------------------------------------------------------------------------
# 7. Auditor-response draft
# ---------------------------------------------------------------------------


def fallback_draft_auditor_response(
    *,
    question: str,
    evidence_gap: dict[str, Any] | None = None,
    eval_record: dict[str, Any] | None = None,
    related_artifacts: dict[str, Any] | None = None,
) -> AuditorResponseDraft:
    cited_artifacts: list[str] = []
    cited_fields: list[str] = []
    citations: list[EvidenceCitation] = []
    body_lines: list[str] = [f"**Question:** {question.strip()[:500]}", ""]
    missing: list[str] = []

    if evidence_gap:
        gap_id = str(evidence_gap.get("gap_id") or "")
        gap_type = str(evidence_gap.get("gap_type") or "unknown")
        controls = ", ".join(evidence_gap.get("controls") or []) or "—"
        body_lines += [
            f"**EvidenceGap:** `{gap_id}` (type `{gap_type}`, controls {controls}).",
            f"**Recommended artifact (from `evidence_gaps.json`):** "
            f"`{evidence_gap.get('recommended_artifact') or '_missing evidence_'}`.",
            f"**Recommended validation:** "
            f"`{evidence_gap.get('recommended_validation') or '_missing evidence_'}`.",
        ]
        cited_artifacts.append("evidence_gaps.json")
        cited_fields.append(f"evidence_gaps[gap_id=={gap_id}]")
        citations.append(
            EvidenceCitation(artifact="evidence_gaps.json", field=f"evidence_gaps[gap_id=={gap_id}]")
        )

    if eval_record:
        eid = str(eval_record.get("eval_id") or "")
        body_lines += [
            "",
            f"**Eval row:** `{eid}` — result `{eval_record.get('result')}`, "
            f"severity `{eval_record.get('severity')}`.",
            f"> {str(eval_record.get('summary') or '')[:600] or '_missing evidence — no summary field_'}",
        ]
        cited_artifacts.append("eval_results.json")
        cited_fields.append(f"evaluations[?(@.eval_id=='{eid}')]")
        citations.append(
            EvidenceCitation(artifact="eval_results.json", field=f"evaluations[?(@.eval_id=='{eid}')]")
        )

    if not evidence_gap and not eval_record:
        body_lines += [
            "",
            "**Available evidence:** **missing evidence** — no `evidence_gap` or `eval_record` was supplied.",
            "Provide one of those artifacts before answering this question to the auditor.",
        ]
        missing.append("evidence_gap")
        missing.append("eval_record")

    if related_artifacts:
        body_lines += ["", "**Other artifacts referenced (input):**"]
        for k in related_artifacts.keys():
            body_lines.append(f"- `{k}`")
            cited_artifacts.append(str(k))

    body_lines += [
        "",
        "_This draft cites only the supplied fields. Anything not present above is_ "
        "**missing evidence** _— do not assert it to the auditor._",
    ]

    return AuditorResponseDraft(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        question=question.strip()[:500] or "(empty)",
        response_md="\n".join(body_lines),
        cited_artifacts=sorted(set(cited_artifacts)),
        cited_fields=cited_fields,
        citations=citations,
        missing_evidence=missing,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
        confidence="low" if (not evidence_gap and not eval_record) else "moderate",
    )
