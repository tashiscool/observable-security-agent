"""
Binding evidence contract for AI explanations (LLM and deterministic fallback).

All user-visible explain paths should include :func:`evidence_contract_markdown`
in the system prompt and honor :func:`deterministic_eval_footer`.
"""

from __future__ import annotations

from typing import Any

EVIDENCE_CONTRACT_MARKDOWN = """
## Evidence contract (binding)

1. **Artifact names:** Every substantive claim must name the artifact or structured field it rests on
   (for example `eval_results.json`, `correlations.json`, `alert_rules.json`, `tickets.json`,
   `scanner_findings.json`, `fedramp20x-package.json`).
2. **Missing evidence:** If a required artifact, field, linkage, or proof object is absent from the
   provided payload, say exactly **missing evidence**. Do not soften into “likely fine” or
   “control implemented.”
3. **No gap-to-pass inversion:** Never treat **missing evidence** as proof that a control is
   implemented, effective, or passing.
4. **Alerts / firing:** Never state or imply that an alert **fired** (or equivalent) unless
   `sample_alert_ref` and/or explicit firing/event evidence appears in the provided structured
   inputs (for example an alert rule row with a recorded `last_fired`, or a cited event record).
   Otherwise state **missing evidence** for alert firing proof.
5. **Tickets:** Never invent or assert a concrete ticket identifier unless `linked_ticket_id` (or
   an equivalent field) is present in the provided payload or an included `tickets.json` slice.
   Otherwise state **missing evidence** for ticket linkage.
6. **Exploitation review:** Never claim exploitation review was completed unless
   `scanner_findings.json` (or package finding) shows exploitation-review fields, a linked ticket,
   or another cited review artifact (for example exploitation review queries) appears in the
   payload. Otherwise state **missing evidence** for exploitation review.

### Distinguish these outcomes (use the correct label when applicable)

- **Technical failure:** Evidence in the artifacts shows a misconfiguration, break, or control
  weakness (not merely absent files).
- **Evidence gap:** A required proof artifact or field was not supplied in this package.
- **Policy gap:** Evidence shows behavior outside documented policy even when telemetry exists.
- **Instrumentation gap:** Monitoring or detection is missing, disabled, or not proven for the
  required scope.
- **Unresolved risk:** Findings or evaluations remain open without accepted closure evidence.
- **Risk accepted:** Explicit acceptance / residual-risk posture is documented in provided
  artifacts (do not invent acceptance).
""".strip()

CLASSIFICATION_AXIS_MARKDOWN = """
### Outcome labels (use when applicable)

| Label | When to use |
|-------|----------------|
| Technical failure | Artifact content shows the control failed or was misconfigured. |
| Evidence gap | Required proof missing from the payload (**missing evidence**). |
| Policy gap | Behavior contradicts stated policy with evidence present. |
| Instrumentation gap | Logging/alerting/scanner coverage not demonstrated for required scope. |
| Unresolved risk | Open findings / PARTIAL / FAIL without closure evidence shown. |
| Risk accepted | Acceptance or AO posture explicitly documented in supplied artifacts. |
""".strip()


def evidence_contract_markdown(*, include_classification_table: bool = True) -> str:
    parts = [EVIDENCE_CONTRACT_MARKDOWN]
    if include_classification_table:
        parts.append(CLASSIFICATION_AXIS_MARKDOWN)
    return "\n\n".join(parts).strip()


def primary_artifacts_for_prompt(
    *,
    related_evidence: dict[str, Any] | None,
    related_graph: dict[str, Any] | None,
    selected_eval: dict[str, Any] | None,
    fedramp20x_context: dict[str, Any] | None,
    related_reconciliation: dict[str, Any] | None,
) -> list[str]:
    """Heuristic list of artifact filenames the model must be prepared to cite."""
    names: set[str] = {"eval_results.json"}
    if related_evidence:
        if related_evidence.get("correlations") is not None or any(
            "correlation" in str(k).lower() for k in related_evidence
        ):
            names.add("correlations.json")
        if "control_crosswalk" in related_evidence:
            names.add("fedramp20x-package.json")
        if "ksi_validation_row" in related_evidence or "package_summary" in related_evidence:
            names.add("fedramp20x-package.json")
    if related_graph and (
        related_graph.get("nodes")
        or related_graph.get("edges")
        or related_graph.get("root_event")
    ):
        names.add("evidence_graph.json")
    if related_reconciliation:
        names.add("fedramp20x-package.json")
    if fedramp20x_context:
        names.add("fedramp20x-package.json")
    ga = (selected_eval or {}).get("generated_artifacts")
    if isinstance(ga, list):
        for x in ga:
            if isinstance(x, str) and x.endswith((".json", ".csv", ".md")):
                # Normalize to basename for display
                names.add(x.split("/")[-1])
    return sorted(names)


def user_message_artifact_clause(artifact_names: list[str]) -> str:
    joined = ", ".join(f"`{n}`" for n in artifact_names)
    return (
        f"You must tie substantive claims to named artifacts. Primary artifacts for this turn: {joined}. "
        "Where a needed field or file is not in the JSON above, state **missing evidence**."
    )


def _gap_text(ev: dict[str, Any] | None) -> str:
    if not ev:
        return ""
    parts: list[str] = []
    g = ev.get("gap")
    if g:
        parts.append(str(g))
    for x in ev.get("gaps") or []:
        parts.append(str(x))
    for x in ev.get("evidence") or []:
        parts.append(str(x))
    return " ".join(parts).lower()


def deterministic_eval_footer(
    *,
    mode: str,
    selected_eval: dict[str, Any] | None,
) -> str:
    """
    Extra paragraphs for deterministic paths so they obey the same contract as LLM prompts.
    """
    lines: list[str] = [
        "",
        "---",
        "**Evidence contract (deterministic):** The template above cites **eval_results.json** "
        "and TRACE_RULES text where applicable. Any required proof not shown in the excerpt is "
        "**missing evidence** — not a claim that the control is implemented or passing.",
    ]
    ev = selected_eval or {}
    eid = str(ev.get("eval_id") or "")
    gap_l = _gap_text(ev)

    if mode in ("explain_eval", "trace_derivation") and eid == "SI4_ALERT_INSTRUMENTATION":
        if "sample_alert_ref" in gap_l or "last_fired" in gap_l or "proof of firing" in gap_l:
            lines.append(
                "**missing evidence** for alert firing proof (no `sample_alert_ref` / firing record "
                "in the provided row). Do not infer operational alert activation without that evidence."
            )

    if mode in ("explain_eval", "trace_derivation") and eid == "CM3_CHANGE_EVIDENCE_LINKAGE":
        if "ticket" in gap_l or "linked" in gap_l:
            lines.append(
                "**missing evidence** for `linked_ticket_id` / `tickets.json` linkage unless a "
                "ticket id appears in the provided payload. Do not invent a ticket identifier."
            )

    if mode in ("explain_eval", "trace_derivation") and eid == "RA5_EXPLOITATION_REVIEW":
        if "exploit" in gap_l or "review" in gap_l:
            lines.append(
                "**missing evidence** for exploitation review unless `scanner_findings.json` (or "
                "linked ticket / review query artifact) appears in the provided inputs."
            )

    return "\n".join(lines)


def deterministic_package_footer() -> str:
    """Appended to FedRAMP 20x deterministic templates."""
    return (
        "**Evidence contract (deterministic):** The text above cites only named package or "
        "eval fields shown in this response. Any required proof absent from that excerpt is "
        "**missing evidence**, not confirmation that a control is implemented."
    )
