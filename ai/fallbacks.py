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

from functools import lru_cache
from pathlib import Path
from typing import Any, get_args

import yaml

from ai.models import (
    ArtifactSufficiencyFinding,
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
    "fallback_explain_conmon_reasonableness",
    "fallback_explain_residual_risk",
    "fallback_explain_derivation_trace",
    "fallback_draft_remediation_ticket",
    "fallback_draft_auditor_response",
    "fallback_evaluate_3pao_remediation",
]


_ALLOWED_GAP_TYPES = set(get_args(GapType))
_ALLOWED_SEVERITIES = set(get_args(GapSeverity))
_ALLOWED_TICKET_SEVERITIES = set(get_args(TicketSeverity))
_RULES_PATH = Path(__file__).resolve().parents[1] / "config" / "3pao-sufficiency-rules.yaml"


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


def fallback_explain_conmon_reasonableness(
    *,
    conmon_result: dict[str, Any],
) -> ExplanationResponse:
    summary = conmon_result.get("summary") or {}
    obligations = list(conmon_result.get("obligation_assessments") or [])
    ecosystems = conmon_result.get("evidence_ecosystems") or {}
    reasonable = summary.get("reasonable", 0)
    partial = summary.get("partial", 0)
    missing = summary.get("missing", 0)
    headline = (
        "ConMon reasonableness: "
        f"{reasonable} reasonable, {partial} partial, {missing} missing obligations."
    )
    worst = [
        o
        for o in obligations
        if str(o.get("coverage")) in {"missing", "partial"}
    ][:6]
    lines = [
        f"**Catalog:** {conmon_result.get('catalog_name') or 'ConMon reasonableness catalog'}.",
        f"**Obligations:** `{summary.get('obligations', 0)}`; tracker rows loaded: `{summary.get('tracker_rows', 0)}`.",
        f"**Coverage:** reasonable `{reasonable}`, partial `{partial}`, missing `{missing}`.",
        "",
        "**Reasonableness standard:** ticket rows from Smartsheet/Jira/ServiceNow are workflow evidence, not proof by themselves. A 3PAO still needs authoritative source artifacts.",
        "",
        "**Ecosystem evidence expected:**",
    ]
    for key in ("aws", "siem", "os_and_endpoint", "vulnerability", "ticketing", "grc_docs", "training"):
        meta = ecosystems.get(key) or {}
        systems = ", ".join(str(x) for x in (meta.get("systems") or []))
        if systems:
            lines.append(f"- `{key}`: {systems}")
    if worst:
        lines += ["", "**Top open/partial obligations:**"]
        for ob in worst:
            gaps = "; ".join(str(x) for x in (ob.get("reasonableness_gaps") or [])) or "No detail supplied."
            lines.append(
                f"- `{ob.get('obligation_id')}` ({ob.get('cadence')}): {ob.get('coverage')} — {gaps}"
            )
    lines += [
        "",
        "_LLM/fallback reasoning may summarize and prioritize, but it does not convert missing evidence into a pass._",
    ]
    missing_evidence: list[str] = []
    if not obligations:
        missing_evidence.append("conmon_reasonableness.json:obligation_assessments")
    if not ecosystems:
        missing_evidence.append("conmon_reasonableness.json:evidence_ecosystems")
    return ExplanationResponse(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        audience="assessor",
        headline=headline,
        body="\n".join(lines),
        citations=[
            EvidenceCitation(artifact="conmon_reasonableness.json", field="summary"),
            EvidenceCitation(artifact="conmon_reasonableness.json", field="obligation_assessments"),
            EvidenceCitation(artifact="conmon_reasonableness.json", field="evidence_ecosystems"),
        ],
        missing_evidence=missing_evidence,
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
        referenced_eval_id="CONMON_REASONABLENESS",
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


# ---------------------------------------------------------------------------
# 8. 3PAO Remediation Evaluation
# ---------------------------------------------------------------------------


def fallback_evaluate_3pao_remediation(
    *,
    evidence_gap: dict[str, Any],
    ksi_context: str | None = None,
    related_artifacts: dict[str, Any] | None = None,
) -> Any:
    from ai.models import ThreePaoRemediationEvaluation

    gap_id = str(evidence_gap.get("gap_id") or "unknown_gap")
    title = str(evidence_gap.get("title") or "Unnamed Evidence Gap")
    rec_artifact = str(evidence_gap.get("recommended_artifact") or "TBD Artifact")
    gap_type = str(evidence_gap.get("gap_type") or "unknown")
    desc = str(evidence_gap.get("description") or "").strip()
    controls = evidence_gap.get("controls") or []
    ctrl_line = ", ".join(str(c) for c in controls[:14])
    if len(controls) > 14:
        ctrl_line += ", …"
    poam_req = evidence_gap.get("poam_required")

    ksi_note = ""
    if ksi_context and str(ksi_context).strip():
        ksi_note = "\n\n" + str(ksi_context).strip() + "\n"

    sufficiency = _artifact_sufficiency_for_gap(
        evidence_gap=evidence_gap,
        related_artifacts=related_artifacts or {},
    )
    sufficiency_lines: list[str] = []
    for finding in sufficiency:
        mark = "PASS" if finding.status == "pass" else "FAIL" if finding.status == "fail" else "UNKNOWN"
        sufficiency_lines.append(
            f"- **{mark}:** {finding.requirement} — {finding.evidence}"
            + (f" Remediation: {finding.remediation}" if finding.remediation else "")
        )

    remediation_plan = (
        "### Context (deterministic fallback)\n"
        f"- **Gap type:** `{gap_type}`\n"
        f"- **Title:** {title}\n"
        + (f"- **Controls:** {ctrl_line}\n" if ctrl_line else "")
        + (f"- **POA&M likely:** `{poam_req}`\n" if poam_req is not None else "")
        + "\n### Reasonable-person checklist\n"
        "1. **Assessor thread:** From `assessor_comment`, list each still-unanswered question "
        "(multi-turn rows often end with an assessor prompt).\n"
        "2. **CSP thread:** From `csp_comment`, state the latest CSP position — does it cite "
        "primary or system-generated artifacts, or only narrative?\n"
        "3. **Row archetype:** SAP/pen-test logistics vs ConMon sample vs SSP attachment vs "
        "operational control — expectations differ (e.g., pen-test rows need scope/POC/logistics; "
        "RA-5 rows need scan exports + trending + scope).\n"
        "4. **Closure:** Attach or reference each missing element explicitly; avoid generic language.\n"
        + ksi_note
        + (
            "\n### Artifact sufficiency check\n"
            + "\n".join(sufficiency_lines)
            + "\n"
            if sufficiency_lines
            else ""
        )
        + "\n### Minimal next steps\n"
        f"1. Re-read gap `{gap_id}` against the request text"
        + (f": _{desc[:280]}{'…' if len(desc) > 280 else ''}_" if desc else ".")
        + "\n"
        f"2. Produce the structured / recommended artifact: `{rec_artifact}`.\n"
        "3. Upload to the tracker row and **quote** filenames or ticket IDs in the CSP reply so "
        "the assessor can trace evidence.\n"
        "4. Re-open the thread only after each numbered sub-requirement (i)(ii)… is addressed.\n"
    )

    citations = [
        EvidenceCitation(artifact="evidence_gaps.json", field=f"evidence_gaps[gap_id=={gap_id}]")
    ]
    missing: list[str] = []
    if not evidence_gap.get("recommended_artifact"):
        missing.append("recommended_artifact")
    for finding in sufficiency:
        if finding.status != "pass":
            missing.append(f"artifact_sufficiency:{finding.requirement}")

    passed = bool(sufficiency) and all(f.status == "pass" for f in sufficiency)

    rec_line = f"Produce `{rec_artifact}`" if rec_artifact != "TBD Artifact" else "Clarify artifact class with ISSO"
    if passed:
        rec_line = "Current related artifacts appear sufficient for reviewer follow-up"

    return ThreePaoRemediationEvaluation(
        source=ReasoningSource.DETERMINISTIC_FALLBACK,
        gap_id=gap_id,
        recommendation=f"{rec_line}; map replies to each open assessor bullet.",
        remediation_plan_md=remediation_plan,
        reasonable_test_passed=passed,
        citations=citations,
        artifact_sufficiency=sufficiency,
        missing_evidence=sorted({m for m in missing if m}),
        warnings=["AI_API_KEY not set or LLM unavailable; using deterministic fallback."],
    )


def _flatten_artifact_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.lower()
    if isinstance(value, (int, float, bool)):
        return str(value).lower()
    if isinstance(value, dict):
        parts: list[str] = []
        for k, v in value.items():
            parts.append(str(k))
            parts.append(_flatten_artifact_text(v))
        return " ".join(parts).lower()
    if isinstance(value, list):
        return " ".join(_flatten_artifact_text(v) for v in value).lower()
    return str(value).lower()


def _artifact_has(text: str, phrases: tuple[str, ...]) -> bool:
    return any(p in text for p in phrases)


@lru_cache(maxsize=1)
def _load_3pao_sufficiency_rules() -> dict[str, Any]:
    data = yaml.safe_load(_RULES_PATH.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"3PAO sufficiency rules must be a mapping: {_RULES_PATH}")
    checks = data.get("checks")
    if not isinstance(checks, dict) or not checks:
        raise ValueError(f"3PAO sufficiency rules missing checks: {_RULES_PATH}")
    return data


def _rule_checks_for_gap(gap_type: str, recommended_artifact: str) -> list[tuple[str, tuple[str, ...], str]]:
    rules = _load_3pao_sufficiency_rules()
    raw_checks = (rules.get("checks") or {}).get(gap_type)
    if not raw_checks:
        default = rules.get("default_check") or {}
        phrases = tuple(
            p for p in recommended_artifact.lower().replace("+", " ").split() if len(p) > 4
        )
        remediation_template = str(default.get("remediation_template") or "Attach the recommended artifact: {recommended_artifact}.")
        return [
            (
                str(default.get("requirement") or "recommended artifact present"),
                phrases,
                remediation_template.format(recommended_artifact=recommended_artifact or "artifact class TBD"),
            )
        ]
    out: list[tuple[str, tuple[str, ...], str]] = []
    for item in raw_checks:
        if not isinstance(item, dict):
            continue
        phrases = tuple(str(p).lower() for p in (item.get("phrases") or []) if str(p).strip())
        out.append(
            (
                str(item.get("requirement") or "configured sufficiency check"),
                phrases,
                str(item.get("remediation") or "Attach authoritative proof for this requirement."),
            )
        )
    return out


def _proof_artifact_text(related_artifacts: dict[str, Any]) -> tuple[str, list[str]]:
    """Return text from artifacts that can be proof, excluding tracker request wrappers.

    Assessment tracker rows, evidence_gaps.json, and reasonableness summaries are workflow
    context. They are useful citations, but a 3PAO should not treat the request text itself
    as evidence that the requested system-generated artifact exists.
    """
    rules = _load_3pao_sufficiency_rules()
    excluded_markers = tuple(str(x) for x in (rules.get("context_artifact_exclusions") or []))
    proof_chunks: list[str] = []
    ignored: list[str] = []
    for name, payload in related_artifacts.items():
        low_name = str(name).lower()
        if any(marker in low_name for marker in excluded_markers):
            ignored.append(str(name))
            continue
        proof_chunks.append(_flatten_artifact_text(payload))
    return " ".join(proof_chunks).lower(), ignored


def _finding(
    requirement: str,
    ok: bool,
    evidence: str,
    remediation: str,
) -> ArtifactSufficiencyFinding:
    return ArtifactSufficiencyFinding(
        requirement=requirement,
        status="pass" if ok else "fail",
        evidence=evidence if ok else "No supplied related artifact satisfied this check.",
        remediation=None if ok else remediation,
    )


def _artifact_sufficiency_for_gap(
    *,
    evidence_gap: dict[str, Any],
    related_artifacts: dict[str, Any],
) -> list[ArtifactSufficiencyFinding]:
    gap_type = str(evidence_gap.get("gap_type") or "")
    rec_artifact = str(evidence_gap.get("recommended_artifact") or "")
    haystack, ignored_context = _proof_artifact_text(related_artifacts)
    if not related_artifacts:
        miss = _load_3pao_sufficiency_rules().get("no_related_artifacts") or {}
        return [
            ArtifactSufficiencyFinding(
                requirement=str(miss.get("requirement") or "related_artifacts supplied"),
                status="fail",
                evidence=str(miss.get("evidence") or "No related artifacts were provided to evaluate the current CSP stance."),
                remediation=str(miss.get("remediation") or "Pass authoritative artifacts into `related_artifacts`."),
            )
        ]
    if not haystack.strip():
        ignored = ", ".join(ignored_context) if ignored_context else "none"
        ctx = _load_3pao_sufficiency_rules().get("only_context_artifacts") or {}
        evidence_template = str(
            ctx.get("evidence_template")
            or "Only tracker/request-context artifacts were supplied; ignored as proof: {ignored}."
        )
        return [
            ArtifactSufficiencyFinding(
                requirement=str(ctx.get("requirement") or "authoritative proof artifact supplied"),
                status="fail",
                evidence=evidence_template.format(ignored=ignored),
                remediation=str(ctx.get("remediation") or "Supply primary/system-generated artifacts."),
            )
        ]

    checks = _rule_checks_for_gap(gap_type, rec_artifact)
    findings: list[ArtifactSufficiencyFinding] = []
    for requirement, phrases, remediation in checks:
        ok = _artifact_has(haystack, phrases)
        evidence = f"Related artifacts contain one of: {', '.join(phrases[:6])}."
        findings.append(_finding(requirement, ok, evidence, remediation))
    return findings
