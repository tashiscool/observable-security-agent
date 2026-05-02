"""Writers for the TRACKER_EVIDENCE_GAP_ANALYSIS eval outputs.

Given a :class:`evals.tracker_evidence_gap_eval.TrackerGapEvalResult`, produce:

* ``tracker_gap_report.md`` — human-readable per-group breakdown
* ``tracker_gap_matrix.csv`` — gap-by-control matrix (one row per gap)
* ``tracker_gap_eval_results.json`` — machine-readable eval result + group summaries
* ``poam.csv`` — POA&M rows for every gap with ``poam_required=True``
* ``instrumentation_plan.md`` — only when logging or alerting groups have open gaps
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Mapping

from .tracker_evidence_gap_eval import (
    EVAL_ID,
    EVAL_NAME,
    GROUP_LABELS,
    GroupSummary,
    TrackerGapEvalResult,
)


__all__ = [
    "write_tracker_gap_report_md",
    "write_tracker_gap_matrix_csv",
    "write_tracker_gap_eval_results_json",
    "write_tracker_gap_poam_csv",
    "write_tracker_gap_instrumentation_plan_md",
    "write_all_tracker_gap_outputs",
]


# ---------------------------------------------------------------------------
# tracker_gap_report.md
# ---------------------------------------------------------------------------


def _gap_index(envelope: Mapping[str, Any]) -> dict[str, dict[str, Any]]:
    raw_gaps = envelope.get("evidence_gaps") or envelope.get("gaps") or []
    out: dict[str, dict[str, Any]] = {}
    for g in raw_gaps:
        gid = str(g.get("gap_id") or "")
        if gid:
            out[gid] = dict(g)
    return out


def write_tracker_gap_report_md(result: TrackerGapEvalResult, dest: Path) -> Path:
    """Write the markdown report. Returns the written path."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    er = result.eval_result
    lines: list[str] = []
    lines.append(f"# {EVAL_NAME}")
    lines.append("")
    lines.append(f"- Eval ID: `{EVAL_ID}`")
    lines.append(f"- Result: **{er.result}**")
    lines.append(f"- Severity: `{er.severity}`")
    lines.append(f"- Open evidence gaps: {result.total_open_gaps}")
    lines.append(f"- High/Critical gaps: {result.high_impact_count}")
    lines.append(f"- Gaps requiring POA&M: {result.poam_required_count}")
    lines.append(f"- Informational tracker items: {result.informational_count}")
    lines.append("")
    lines.append(f"## Summary")
    lines.append("")
    lines.append(er.summary)
    lines.append("")

    gap_idx = _gap_index(result.source_envelope)

    lines.append("## Group breakdown")
    lines.append("")
    for grp in result.groups:
        lines.append(f"### {grp.label}")
        lines.append("")
        lines.append(f"- Group key: `{grp.group}`")
        lines.append(f"- Open gaps: **{grp.count_open_gaps}**")
        if grp.count_open_gaps == 0:
            lines.append("- Status: no open gaps in this group")
            lines.append("")
            continue
        lines.append(f"- Max severity: `{grp.max_severity}`")
        lines.append(
            f"- POA&M required: **{'yes' if grp.poam_required else 'no'}**"
        )
        lines.append(
            f"- Controls impacted: {', '.join(f'`{c}`' for c in grp.controls_impacted) or '_(none cited)_'}"
        )
        lines.append(
            f"- Linked KSI IDs: {', '.join(f'`{k}`' for k in grp.linked_ksi_ids) or '_(none)_'}"
        )
        lines.append(
            f"- Gap types observed: {', '.join(f'`{t}`' for t in grp.gap_types) or '_(none)_'}"
        )
        lines.append(
            f"- Tracker rows: {', '.join(f'`{r}`' for r in grp.tracker_rows) or '_(none)_'}"
        )
        if grp.recommended_closure_artifacts:
            lines.append("- Recommended closure artifacts:")
            for art in grp.recommended_closure_artifacts:
                lines.append(f"  - {art}")
        lines.append("")
        lines.append("| Gap ID | Source row | Severity | Gap type | Controls | Title |")
        lines.append("|---|---|---|---|---|---|")
        for gid in grp.gap_ids:
            g = gap_idx.get(gid, {})
            ctrls = ", ".join(g.get("controls") or []) or "_(none)_"
            title = (g.get("title") or "").replace("|", "\\|")
            lines.append(
                f"| `{gid}` | `{g.get('source_item_id', '')}` | "
                f"{g.get('severity', '')} | {g.get('gap_type', '')} | "
                f"{ctrls} | {title} |"
            )
        lines.append("")

    if er.recommended_actions:
        lines.append("## Recommended closure actions")
        lines.append("")
        for a in er.recommended_actions:
            lines.append(f"- {a}")
        lines.append("")

    lines.append("## All open evidence gaps")
    lines.append("")
    if not er.gaps:
        lines.append("_No open evidence gaps._")
    else:
        for g in er.gaps:
            lines.append(f"- {g}")
    lines.append("")

    dest.write_text("\n".join(lines), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# tracker_gap_matrix.csv
# ---------------------------------------------------------------------------


_MATRIX_HEADERS: list[str] = [
    "gap_id",
    "source_item_id",
    "group",
    "gap_type",
    "severity",
    "poam_required",
    "controls",
    "linked_ksi_ids",
    "recommended_artifact",
    "recommended_validation",
    "owner",
    "status",
    "due_date",
    "title",
]


def write_tracker_gap_matrix_csv(result: TrackerGapEvalResult, dest: Path) -> Path:
    """Write one CSV row per evidence gap. Always writes the header even when empty."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    raw_gaps = list(
        result.source_envelope.get("evidence_gaps")
        or result.source_envelope.get("gaps")
        or []
    )
    # Build a quick lookup gap_id -> primary group from result.groups.
    gid_to_groups: dict[str, list[str]] = {}
    for grp in result.groups:
        for gid in grp.gap_ids:
            gid_to_groups.setdefault(gid, []).append(grp.group)

    with dest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(_MATRIX_HEADERS)
        for g in raw_gaps:
            gid = str(g.get("gap_id") or "")
            groups = "|".join(gid_to_groups.get(gid, [])) or "(unmapped)"
            writer.writerow(
                [
                    gid,
                    g.get("source_item_id") or "",
                    groups,
                    g.get("gap_type") or "",
                    g.get("severity") or "",
                    "yes" if g.get("poam_required") else "no",
                    ", ".join(g.get("controls") or []),
                    ", ".join(g.get("linked_ksi_ids") or []),
                    g.get("recommended_artifact") or "",
                    g.get("recommended_validation") or "",
                    g.get("owner") or "",
                    g.get("status") or "",
                    g.get("due_date") or "",
                    (g.get("title") or "").replace("\n", " "),
                ]
            )
    return dest


# ---------------------------------------------------------------------------
# tracker_gap_eval_results.json
# ---------------------------------------------------------------------------


def write_tracker_gap_eval_results_json(result: TrackerGapEvalResult, dest: Path) -> Path:
    """Write the machine-readable eval result envelope."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    payload = result.to_dict()
    dest.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# poam.csv (POA&M-required gaps only)
# ---------------------------------------------------------------------------


_POAM_HEADERS: list[str] = [
    "poam_id",
    "weakness_name",
    "weakness_description",
    "controls",
    "severity",
    "source_identifying_vulnerability",
    "asset_identifier",
    "point_of_contact",
    "scheduled_completion_date",
    "milestones",
    "status",
    "linked_evidence_gap_id",
    "linked_ksi_ids",
]


def write_tracker_gap_poam_csv(result: TrackerGapEvalResult, dest: Path) -> Path:
    """Emit a POA&M CSV row for every gap that requires POA&M tracking."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    raw_gaps = list(
        result.source_envelope.get("evidence_gaps")
        or result.source_envelope.get("gaps")
        or []
    )
    with dest.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(_POAM_HEADERS)
        idx = 1
        for g in raw_gaps:
            if not g.get("poam_required"):
                continue
            poam_id = f"POAM-TRK-{idx:04d}"
            idx += 1
            milestones = (
                f"Produce: {g.get('recommended_artifact') or '(artifact tbd)'} | "
                f"Validate via: {g.get('recommended_validation') or '(validation tbd)'}"
            )
            writer.writerow(
                [
                    poam_id,
                    g.get("title") or "",
                    (g.get("description") or "").replace("\n", " "),
                    ", ".join(g.get("controls") or []),
                    g.get("severity") or "",
                    f"FedRAMP assessment tracker row {g.get('source_item_id') or ''}",
                    g.get("source_item_id") or "",
                    g.get("owner") or "(unassigned)",
                    g.get("due_date") or "",
                    milestones,
                    g.get("status") or "Open",
                    g.get("gap_id") or "",
                    ", ".join(g.get("linked_ksi_ids") or []),
                ]
            )
    return dest


# ---------------------------------------------------------------------------
# instrumentation_plan.md (only when logging/alerting groups have open gaps)
# ---------------------------------------------------------------------------


_INSTRUMENTATION_GROUPS: tuple[str, ...] = ("logging", "alerting", "incident_response")


def _has_instrumentation_work(result: TrackerGapEvalResult) -> bool:
    return any(
        g.count_open_gaps > 0
        for g in result.groups
        if g.group in _INSTRUMENTATION_GROUPS
    )


def write_tracker_gap_instrumentation_plan_md(
    result: TrackerGapEvalResult, dest: Path
) -> Path | None:
    """Write an instrumentation plan if logging/alerting/IR have open gaps. Otherwise no-op.

    Returns the written path, or ``None`` if no plan was applicable.
    """
    if not _has_instrumentation_work(result):
        return None

    dest.parent.mkdir(parents=True, exist_ok=True)
    gap_idx = _gap_index(result.source_envelope)

    lines: list[str] = []
    lines.append("# Tracker-driven Instrumentation Plan")
    lines.append("")
    lines.append(
        "Generated from open evidence gaps in the logging, alerting, and "
        "incident-response groups."
    )
    lines.append("")

    by_group = {grp.group: grp for grp in result.groups}

    for group_key in _INSTRUMENTATION_GROUPS:
        grp = by_group.get(group_key)
        if not grp or grp.count_open_gaps == 0:
            continue
        lines.append(f"## {grp.label}")
        lines.append("")
        lines.append(f"- Open gaps: **{grp.count_open_gaps}**")
        lines.append(f"- Controls impacted: {', '.join(f'`{c}`' for c in grp.controls_impacted) or '_(none)_'}")
        lines.append(f"- Linked KSI IDs: {', '.join(f'`{k}`' for k in grp.linked_ksi_ids) or '_(none)_'}")
        lines.append(f"- POA&M required: {'yes' if grp.poam_required else 'no'}")
        lines.append("")
        lines.append("### Required instrumentation actions")
        lines.append("")
        for gid in grp.gap_ids:
            g = gap_idx.get(gid, {})
            controls = ", ".join(g.get("controls") or []) or "_(none cited)_"
            artifact = g.get("recommended_artifact") or "(artifact tbd)"
            validation = g.get("recommended_validation") or "(validation tbd)"
            lines.append(
                f"- `{gid}` (row `{g.get('source_item_id', '')}`, "
                f"severity `{g.get('severity', '')}`, type `{g.get('gap_type', '')}`, "
                f"controls {controls})"
            )
            lines.append(f"  - Produce: {artifact}")
            lines.append(f"  - Validate via: {validation}")
            if g.get("description"):
                lines.append(f"  - Context: {g['description']}")
        lines.append("")

    lines.append("## Operational guidance")
    lines.append("")
    lines.append("- Confirm centralized log aggregation (Splunk / SIEM / CloudWatch) covers")
    lines.append("  every audit source cited above; capture local-vs-central correlation samples.")
    lines.append("- For alerting gaps, attach the enabled rule, recipient list, and a recent")
    lines.append("  fired-alert sample for each required semantic detection.")
    lines.append("- For incident response gaps, attach the IR ticket, response timeline, and")
    lines.append("  any US-CERT/CISA notification artifacts.")
    lines.append("")

    dest.write_text("\n".join(lines), encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# auditor_questions.md (forwarder)
# ---------------------------------------------------------------------------


def write_tracker_gap_auditor_questions_md(
    *, source_questions_md: Path | None, dest: Path, result: TrackerGapEvalResult
) -> Path:
    """Place an ``auditor_questions.md`` next to the eval outputs.

    If the importer-produced ``auditor_questions.md`` was passed in via
    ``source_questions_md`` and exists, its content is reused. Otherwise we
    synthesize a minimal one from the eval gaps so the file always exists in the
    output directory.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    if source_questions_md and source_questions_md.exists():
        dest.write_text(source_questions_md.read_text(encoding="utf-8"), encoding="utf-8")
        return dest

    raw_gaps = list(
        result.source_envelope.get("evidence_gaps")
        or result.source_envelope.get("gaps")
        or []
    )
    lines = ["# Auditor Questions (synthesized from open evidence gaps)", ""]
    if not raw_gaps:
        lines.append("_No open gaps; no clarifying questions._")
    else:
        for g in raw_gaps:
            controls = ", ".join(g.get("controls") or []) or "(no controls cited)"
            lines.append(
                f"- ({g.get('gap_id', '')}) Row `{g.get('source_item_id', '')}` — "
                f"controls {controls}: please provide "
                f"{g.get('recommended_artifact') or 'the requested evidence'}."
            )
    dest.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return dest


# ---------------------------------------------------------------------------
# Aggregator
# ---------------------------------------------------------------------------


def write_all_tracker_gap_outputs(
    result: TrackerGapEvalResult,
    *,
    output_dir: Path,
    source_questions_md: Path | None = None,
) -> dict[str, Path]:
    """Write every output file the spec requires; return a mapping of name -> path.

    Always writes:
      * tracker_gap_report.md
      * tracker_gap_matrix.csv
      * tracker_gap_eval_results.json
      * poam.csv (header always; rows when poam_required gaps exist)
      * auditor_questions.md
    Conditionally writes:
      * instrumentation_plan.md (only when logging/alerting/IR have open gaps)
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    written: dict[str, Path] = {}
    written["tracker_gap_report.md"] = write_tracker_gap_report_md(
        result, output_dir / "tracker_gap_report.md"
    )
    written["tracker_gap_matrix.csv"] = write_tracker_gap_matrix_csv(
        result, output_dir / "tracker_gap_matrix.csv"
    )
    written["tracker_gap_eval_results.json"] = write_tracker_gap_eval_results_json(
        result, output_dir / "tracker_gap_eval_results.json"
    )
    written["poam.csv"] = write_tracker_gap_poam_csv(result, output_dir / "poam.csv")
    written["auditor_questions.md"] = write_tracker_gap_auditor_questions_md(
        source_questions_md=source_questions_md,
        dest=output_dir / "auditor_questions.md",
        result=result,
    )
    plan_path = write_tracker_gap_instrumentation_plan_md(
        result, output_dir / "instrumentation_plan.md"
    )
    if plan_path is not None:
        written["instrumentation_plan.md"] = plan_path
    return written
