"""Human-readable and machine-readable reports; rebuild correlation bundle from saved JSON."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from core.models import AssessmentBundle
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineCorrelationBundle as CorrelationBundle,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineEvalResult as EvalResult,
    PipelineSemanticEvent as SemanticEvent,
)
from core.failure_narrative_contract import infer_remediation_disposition
from instrumentation.context import (
    InstrumentationArtifact,
    InstrumentationInput,
    instrumentation_input_from_pipeline_event,
)


def result_str(v: EvalStatus | str) -> str:
    return v.value if isinstance(v, EvalStatus) else str(v)


def _pipeline_eval_to_record(r: EvalResult) -> dict[str, Any]:
    m = dict(r.machine or {})
    gaps = m.get("gaps")
    if gaps is None:
        gaps = [r.gap] if (r.gap or "").strip() else []
    elif isinstance(gaps, str):
        gaps = [gaps]
    elif not isinstance(gaps, list):
        gaps = []
    actions = m.get("recommended_actions")
    if actions is None:
        actions = [x.strip() for x in (r.recommended_action or "").split(";") if x.strip()]
    elif isinstance(actions, str):
        actions = [actions]
    elif not isinstance(actions, list):
        actions = []
    disp = m.get("remediation_disposition")
    if not isinstance(disp, str) or not disp.strip():
        disp = infer_remediation_disposition(
            recommended_actions=[str(x) for x in actions if str(x).strip()],
            recommended_action=str(r.recommended_action or ""),
        )
    ksi_ids = m.get("linked_ksi_ids")
    if not isinstance(ksi_ids, list):
        ksi_ids = []
    return {
        "eval_id": r.eval_id,
        "name": str(m.get("name", r.eval_id)),
        "controls": list(r.control_refs or []),
        "result": result_str(r.result),
        "severity": str(m.get("severity", "unknown")),
        "summary": str(m.get("summary", (r.gap or "").strip() or r.eval_id)),
        "evidence": list(r.evidence or []),
        "gaps": list(gaps),
        "affected_assets": list(m.get("affected_assets", []) or []),
        "recommended_actions": list(actions),
        "generated_artifacts": list(m.get("generated_artifacts", []) or []),
        "linked_ksi_ids": [str(x).strip() for x in ksi_ids if str(x).strip()],
        "remediation_disposition": str(disp).strip(),
    }


def build_eval_results_document(
    bundle: CorrelationBundle,
    *,
    assessment: AssessmentBundle | None = None,
    correlations_data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build ``eval_results.json`` payload including normalized ``eval_result_records``."""

    def er(r: EvalResult) -> dict[str, Any]:
        base = {
            "eval_id": r.eval_id,
            "control_refs": r.control_refs,
            "result": result_str(r.result),
            "evidence": r.evidence,
            "gap": r.gap,
            "recommended_action": r.recommended_action,
        }
        base.update(r.machine)
        return base

    eval_rows = [er(r) for r in bundle.eval_results]
    eval_records = [_pipeline_eval_to_record(r) for r in bundle.eval_results]
    for row, rec in zip(eval_rows, eval_records):
        disp = rec.get("remediation_disposition")
        if disp:
            row["remediation_disposition"] = disp
        lk = rec.get("linked_ksi_ids")
        if lk:
            row["linked_ksi_ids"] = lk

    doc: dict[str, Any] = {
        "schema_version": "1.2",
        "correlation_id": bundle.correlation_id,
        "overall_result": bundle.overall_result,
        "semantic_event": bundle.semantic_event.model_dump(mode="json"),
        "asset_evidence": bundle.asset_evidence.model_dump(mode="json"),
        "event": bundle.semantic_event.model_dump(mode="json"),
        "evidence_chain": bundle.evidence_chain,
        "evaluations": eval_rows,
        "eval_result_records": eval_records,
    }
    if correlations_data is not None:
        doc["correlations"] = {"source": "correlations.json", "embedded": False}
    if assessment is not None:
        doc["assessment_bundle_present"] = True
    else:
        doc["assessment_bundle_present"] = False
    return doc


def eval_results_to_json_serializable(bundle: CorrelationBundle) -> dict[str, Any]:
    """Backward-compatible alias for :func:`build_eval_results_document` without optional enrichments."""
    return build_eval_results_document(bundle, assessment=None, correlations_data=None)


def correlation_bundle_from_eval_results(data: dict[str, Any]) -> CorrelationBundle:
    """Rebuild CorrelationBundle from eval_results.json (for `agent.py report`)."""
    sem_raw = dict(data.get("semantic_event") or data.get("event") or {})
    if not sem_raw:
        raise ValueError("eval_results.json must contain semantic_event or event")
    sem_raw.setdefault("metadata", {})
    sem_raw.setdefault("raw_event_ref", "imported")
    sem_raw.setdefault("timestamp", "")
    semantic_event = SemanticEvent.model_validate(sem_raw)

    ae_raw = data.get("asset_evidence")
    if ae_raw:
        asset_evidence = AssetEvidence.model_validate(ae_raw)
    else:
        asset_evidence = AssetEvidence(
            declared_inventory=False,
            discovered_cloud_asset=False,
            scanner_scope=False,
            central_log_seen_last_24h=False,
            criticality="unknown",
        )

    known_eval_keys = {
        "eval_id",
        "control_refs",
        "result",
        "evidence",
        "gap",
        "recommended_action",
    }
    eval_results: list[EvalResult] = []
    for e in data.get("evaluations", []):
        machine = {k: v for k, v in e.items() if k not in known_eval_keys}
        eval_results.append(
            EvalResult(
                eval_id=e["eval_id"],
                control_refs=list(e.get("control_refs", [])),
                result=EvalStatus(e["result"]),
                evidence=list(e.get("evidence", [])),
                gap=e.get("gap", ""),
                recommended_action=e.get("recommended_action", ""),
                machine=machine,
            )
        )

    return CorrelationBundle(
        correlation_id=data.get("correlation_id", "CORR-001"),
        semantic_event=semantic_event,
        asset_evidence=asset_evidence,
        eval_results=eval_results,
        overall_result=data.get("overall_result", "UNKNOWN"),
        evidence_chain=dict(data.get("evidence_chain", {})),
    )


def _section_lines(title: str, body: list[str]) -> list[str]:
    out = [f"## {title}", ""]
    if body and any((b or "").strip() for b in body):
        out.extend(body)
    else:
        out.append("*missing: no content available for this section.*")
    out.append("")
    return out


def _first_high_critical_finding_id(assessment: AssessmentBundle | None) -> str | None:
    if assessment is None:
        return None
    for f in assessment.scanner_findings:
        if str(f.severity).lower() in ("high", "critical") and str(f.status).lower() == "open":
            return f.finding_id
    return None


def write_correlation_report(
    path: Path,
    bundle: CorrelationBundle,
    *,
    assessment: AssessmentBundle | None = None,
    evidence_graph: dict[str, Any] | None = None,
    correlations_data: dict[str, Any] | None = None,
    poam_rows_generated: int = 0,
    instrumentation_note: str = "missing",
) -> None:
    se = bundle.semantic_event
    lines: list[str] = ["# Correlation assessment report", ""]

    fail = [r for r in bundle.eval_results if r.result == EvalStatus.FAIL]
    partial = [r for r in bundle.eval_results if r.result == EvalStatus.PARTIAL]
    passed = [r for r in bundle.eval_results if r.result == EvalStatus.PASS]

    exec_lines = [
        f"Overall result: **{bundle.overall_result}**.",
        f"Evaluations: {len(passed)} PASS, {len(partial)} PARTIAL, {len(fail)} FAIL, "
        f"{sum(1 for r in bundle.eval_results if r.result == EvalStatus.OPEN)} OPEN.",
        f"Primary semantic type: `{se.event_type}` on asset `{se.asset_id}` (provider `{se.provider}`).",
    ]
    lines.extend(_section_lines("Executive summary", exec_lines))

    assessed = [
        f"- **Semantic event:** `{se.event_type}` (ref `{se.raw_event_ref or 'missing'}`).",
        f"- **Asset evidence:** declared_inventory={bundle.asset_evidence.declared_inventory}, "
        f"discovered_cloud_asset={bundle.asset_evidence.discovered_cloud_asset}, "
        f"scanner_scope={bundle.asset_evidence.scanner_scope}, "
        f"central_log_seen_last_24h={bundle.asset_evidence.central_log_seen_last_24h}, "
        f"criticality={bundle.asset_evidence.criticality}.",
    ]
    if assessment is not None:
        assessed.append(
            f"- **AssessmentBundle:** {len(assessment.assets)} assets, {len(assessment.events)} events, "
            f"{len(assessment.scanner_findings)} findings, {len(assessment.alert_rules)} alert rules, "
            f"{len(assessment.tickets)} tickets."
        )
    else:
        assessed.append("*missing: AssessmentBundle not supplied — inventory/event counts omitted.*")
    lines.extend(_section_lines("What was assessed", assessed))

    chain_lines = [f"- **{k}**: {v}" for k, v in sorted(bundle.evidence_chain.items())]
    lines.extend(_section_lines("Evidence chain summary", chain_lines))

    def _eval_bullets(rows: list[EvalResult]) -> list[str]:
        out: list[str] = []
        for r in rows:
            ev = (r.evidence or [])[:5]
            if ev:
                for x in ev:
                    out.append(f"- **{r.eval_id}** ({result_str(r.result)}): {x}")
            elif (r.gap or "").strip():
                out.append(f"- **{r.eval_id}** ({result_str(r.result)}): {r.gap}")
            else:
                out.append(f"- **{r.eval_id}** ({result_str(r.result)}): *missing: no evidence lines recorded.*")
        return out or ["*missing: no evaluations in this category.*"]

    lines.extend(_section_lines("Failed evaluations", _eval_bullets(fail)))
    lines.extend(_section_lines("Partial evaluations", _eval_bullets(partial)))

    risky: list[str] = [
        "A **correlated risky event** is a semantically typed signal listed in the scenario's "
        "`correlations.json`. Each row is checked against the same cross-domain expectations as the "
        "primary incident: authoritative inventory, scanner scope, active central logging, enabled "
        "alerts with recipients, and change or vulnerability linkage. Missing links are reported as "
        "gaps (FAIL/PARTIAL)—they are not treated as if evidence were present.",
        "",
    ]
    if correlations_data and isinstance(correlations_data.get("correlations"), list):
        for row in correlations_data["correlations"][:50]:
            if not isinstance(row, dict):
                continue
            eid = row.get("event_id", "unknown")
            st = row.get("semantic_type", "unknown")
            aid = row.get("asset_id", "unknown")
            risky.append(f"- Event `{eid}` **{st}** on `{aid}` (from correlations.json).")
    else:
        risky.append("*missing: correlations.json not provided or has no `correlations` array.*")
    lines.extend(_section_lines("Correlated risky events", risky))

    controls: set[str] = set()
    for r in bundle.eval_results:
        controls.update(r.control_refs)
    ctrl_lines = [f"- {c}" for c in sorted(controls)] or ["*missing: no control references on evaluations.*"]
    lines.extend(_section_lines("Control impact", ctrl_lines))

    rem: list[str] = []
    for i, r in enumerate(fail + partial, start=1):
        if (r.recommended_action or "").strip():
            rem.append(f"{i}. **{r.eval_id}**: {r.recommended_action.strip()}")
        elif (r.machine or {}).get("recommended_actions"):
            ra = (r.machine or {})["recommended_actions"]
            if isinstance(ra, list) and ra:
                rem.append(f"{i}. **{r.eval_id}**: {'; '.join(str(x) for x in ra)}")
            else:
                rem.append(f"{i}. **{r.eval_id}**: *missing: no recommended_action string.*")
        else:
            rem.append(f"{i}. **{r.eval_id}**: *missing: no recommended_action string.*")
    lines.extend(_section_lines("Recommended remediation sequence", rem or ["*missing: no FAIL/PARTIAL evaluations.*"]))

    arts: list[str] = [
        f"- `eval_results.json` (machine-readable evaluations).",
        f"- `correlations.json` ({'present' if correlations_data else 'missing'}).",
        f"- `poam.csv` (rows generated this run, best-effort count: {poam_rows_generated}).",
        f"- `instrumentation_plan.md` ({instrumentation_note}).",
    ]
    if evidence_graph is not None:
        arts.append(f"- `evidence_graph.json` (nodes: {len(evidence_graph.get('nodes', []))}, edges: {len(evidence_graph.get('edges', []))}).")
    else:
        arts.append("- `evidence_graph.json`: *missing: graph not passed to report writer.*")
    lines.extend(_section_lines("Generated artifacts", arts))

    lines.extend(
        [
            "---",
            "",
            "## Detailed evaluation results",
            "",
            "Per-evaluation evidence and gaps exactly as emitted by the evaluation engine.",
            "",
        ]
    )
    for r in bundle.eval_results:
        lines.append(f"#### {r.eval_id} — **{result_str(r.result)}**")
        lines.append("")
        for ev in r.evidence or []:
            lines.append(f"- {ev}")
        if r.gap:
            lines.append(f"- **Gap:** {r.gap}")
        lines.append("")

    path.write_text("\n".join(lines), encoding="utf-8")


def write_auditor_questions(
    path: Path,
    bundle: CorrelationBundle,
    *,
    assessment: AssessmentBundle | None = None,
) -> None:
    se = bundle.semantic_event
    asset = se.asset_id
    et = se.event_type
    finding_id = _first_high_critical_finding_id(assessment)

    qs: list[str] = [
        "# Auditor questions (evidence-based)",
        "",
        "## Control-family prompts",
        "",
        "1. **CM-8**: How does authoritative inventory reconcile duplicate declared names, "
        "duplicate `asset_id` rows, stale CMDB attributes versus live discovery, and any "
        "production-class assets present in cloud discovery that are absent from the declared list?",
        f"2. **RA-5**: Is `{asset}` intentionally excluded from vulnerability scanning? "
        "If so, where is the approved deviation?",
        "3. **AU-6/AU-12**: Can you provide a local log event from this asset and the same event "
        "in the central logging platform?",
        f"4. **SI-4**: Which enabled alert rule detects event type `{et}`?",
        f"5. **CM-3**: Was event `{se.raw_event_ref or 'missing'}` covered by an approved change ticket?",
    ]
    if finding_id:
        qs.append(
            f"6. **RA-5(8)**: Where is exploitation-review evidence for High finding `{finding_id}`?"
        )
    else:
        qs.append(
            "6. **RA-5(8)**: *missing: no open High/Critical scanner finding id in AssessmentBundle to anchor this question.*"
        )
    qs.extend(
        [
            "7. **CA-5**: Should this be tracked in the POA&M?",
            "",
            "## Evaluation gaps (verbatim from assessment)",
            "",
        ]
    )
    gap_lines: list[str] = []
    for r in bundle.eval_results:
        if r.result not in (EvalStatus.FAIL, EvalStatus.PARTIAL):
            continue
        if (r.gap or "").strip():
            gap_lines.append(f"- **{r.eval_id}**: {r.gap.strip()}")
        elif r.evidence:
            gap_lines.append(f"- **{r.eval_id}**: {r.evidence[0]}")
        else:
            gap_lines.append(f"- **{r.eval_id}**: *missing: no gap or evidence text in evaluation output.*")
    if gap_lines:
        qs.extend(gap_lines)
    else:
        qs.append("*missing: no FAIL/PARTIAL evaluations.*")
    qs.append("")

    path.write_text("\n".join(qs), encoding="utf-8")


def _count_csv_body_rows(path: Path) -> int:
    if not path.is_file():
        return 0
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return 0
    return max(0, len(text.splitlines()) - 1)


def write_evidence_gap_matrix_csv(path: Path, bundle: CorrelationBundle) -> None:
    """Write ``evidence_gap_matrix.csv`` — one row per evaluation."""
    path.parent.mkdir(parents=True, exist_ok=True)
    asset_id = bundle.semantic_event.asset_id
    fieldnames = [
        "eval_id",
        "control",
        "result",
        "severity",
        "asset_id",
        "gap",
        "recommended_action",
        "artifact_needed",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=fieldnames)
        w.writeheader()
        for r in bundle.eval_results:
            m = dict(r.machine or [])
            sev = str(m.get("severity", "unknown"))
            arts = m.get("generated_artifacts", [])
            if isinstance(arts, list):
                art_needed = "; ".join(str(x) for x in arts)
            else:
                art_needed = str(arts) if arts else ""
            w.writerow(
                {
                    "eval_id": r.eval_id,
                    "control": ";".join(r.control_refs or []),
                    "result": result_str(r.result),
                    "severity": sev,
                    "asset_id": asset_id,
                    "gap": (r.gap or "").strip() or "missing",
                    "recommended_action": (r.recommended_action or "").strip() or "missing",
                    "artifact_needed": art_needed or "missing",
                }
            )


def write_assessment_summary_json(
    path: Path,
    assessment: AssessmentBundle | None,
    bundle: CorrelationBundle,
    poam_rows_generated: int,
) -> None:
    """Write ``assessment_summary.json`` with inventory counts and eval outcome tallies."""
    pass_count = sum(1 for r in bundle.eval_results if r.result == EvalStatus.PASS)
    fail_count = sum(1 for r in bundle.eval_results if r.result == EvalStatus.FAIL)
    partial_count = sum(1 for r in bundle.eval_results if r.result == EvalStatus.PARTIAL)
    open_count = sum(1 for r in bundle.eval_results if r.result == EvalStatus.OPEN)

    if assessment is None:
        payload = {
            "assets": None,
            "events": None,
            "findings": None,
            "alert_rules": None,
            "tickets": None,
            "assessment_bundle": "missing",
            "eval_pass": pass_count,
            "eval_fail": fail_count,
            "eval_partial": partial_count,
            "eval_open": open_count,
            "poam_rows_generated": poam_rows_generated,
        }
    else:
        payload = {
            "assets": len(assessment.assets),
            "events": len(assessment.events),
            "findings": len(assessment.scanner_findings),
            "alert_rules": len(assessment.alert_rules),
            "tickets": len(assessment.tickets),
            "assessment_bundle": "present",
            "eval_pass": pass_count,
            "eval_fail": fail_count,
            "eval_partial": partial_count,
            "eval_open": open_count,
            "poam_rows_generated": poam_rows_generated,
        }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_output_bundle(
    output_dir: Path,
    correlation_bundle: CorrelationBundle,
    *,
    assessment: AssessmentBundle | None = None,
    evidence_graph: dict[str, Any] | None = None,
    correlations_data: dict[str, Any] | None = None,
) -> None:
    """
    Write standard assessment outputs under ``output_dir``:

    ``eval_results.json``, ``correlation_report.md``, ``auditor_questions.md``,
    ``evidence_gap_matrix.csv``, ``assessment_summary.json``.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    poam_rows = _count_csv_body_rows(output_dir / "poam.csv")
    inst = output_dir / "instrumentation_plan.md"
    inst_note = "present" if inst.is_file() else "missing"

    doc = build_eval_results_document(
        correlation_bundle,
        assessment=assessment,
        correlations_data=correlations_data,
    )
    (output_dir / "eval_results.json").write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")

    write_correlation_report(
        output_dir / "correlation_report.md",
        correlation_bundle,
        assessment=assessment,
        evidence_graph=evidence_graph,
        correlations_data=correlations_data,
        poam_rows_generated=poam_rows,
        instrumentation_note=inst_note,
    )
    write_auditor_questions(output_dir / "auditor_questions.md", correlation_bundle, assessment=assessment)
    write_evidence_gap_matrix_csv(output_dir / "evidence_gap_matrix.csv", correlation_bundle)
    write_assessment_summary_json(
        output_dir / "assessment_summary.json",
        assessment,
        correlation_bundle,
        poam_rows,
    )


def _instrumentation_input_from_bundle(bundle: CorrelationBundle) -> InstrumentationInput:
    se = bundle.semantic_event
    md = dict(se.metadata) if getattr(se, "metadata", None) else {}
    controls = tuple(sorted({c for r in bundle.eval_results for c in (r.control_refs or [])}))
    return instrumentation_input_from_pipeline_event(
        semantic_type=se.event_type,
        asset_id=se.asset_id,
        asset_name=md.get("asset_name") or md.get("name"),
        provider=se.provider,
        raw_event_ref=se.raw_event_ref,
        timestamp=se.timestamp,
        controls=controls,
        metadata=md,
    )


def _format_artifact_block(art: InstrumentationArtifact, code_lang: str) -> list[str]:
    return [
        f"### {art.platform}",
        "",
        f"- **Alert rule name:** {art.alert_rule_name}",
        f"- **Suggested schedule:** `{art.suggested_schedule}`",
        f"- **Suggested severity:** {art.suggested_severity}",
        f"- **Recipients (placeholder):** {art.suggested_recipients_placeholder}",
        f"- **Evidence to close gap:** {art.evidence_required}",
        "",
        f"```{code_lang}",
        art.query_text.strip(),
        "```",
        "",
    ]


def write_instrumentation_plan(path: Path, bundle: CorrelationBundle) -> None:
    """Write ``instrumentation_plan.md`` using platform generators for the bundle semantic type."""
    from instrumentation.aws_cloudtrail import aws_cloudtrail_instrumentation
    from instrumentation.gcp_logging import gcp_logging_instrumentation
    from instrumentation.sentinel import sentinel_instrumentation
    from instrumentation.splunk import splunk_instrumentation

    inp = _instrumentation_input_from_bundle(bundle)
    se = bundle.semantic_event
    spl = splunk_instrumentation(inp)
    sen = sentinel_instrumentation(inp)
    gcp = gcp_logging_instrumentation(inp)
    aws = aws_cloudtrail_instrumentation(inp)

    lines = [
        "# Instrumentation plan",
        "",
        f"**Correlation:** {bundle.correlation_id}",
        f"**Semantic type:** `{se.event_type}`",
        f"**Asset:** `{se.asset_id}` (provider **{se.provider}**, ref `{se.raw_event_ref}`)",
        f"**Controls (from eval bundle):** {', '.join(inp.controls) if inp.controls else '(none aggregated)'}",
        "",
    ]
    from providers.exposure_policy import merged_query_keywords_for_semantic

    kws = merged_query_keywords_for_semantic(se.event_type)
    if kws:
        lines.append("**Public-exposure policy keywords (for log detection tuning):**")
        lines.extend(f"- `{k}`" for k in kws[:40])
        lines.append("")
    lines.extend(
        [
            "---",
            "",
        ]
    )
    lines.extend(_format_artifact_block(spl, "spl"))
    lines.extend(_format_artifact_block(sen, "kql"))
    lines.extend(_format_artifact_block(gcp, "text"))
    lines.extend(_format_artifact_block(aws, "text"))
    lines.extend(
        [
            "### Evidence collection checklist",
            "",
            "1. Export saved search / analytic rule / log-based metric configuration showing **enabled** status.",
            "2. Capture suggested recipients or distribution list IDs used in production.",
            "3. Attach one sample detection, notable, or finding tied to the asset and time window.",
            "4. Link IR or change ticket demonstrating review, approval, and closure where applicable.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def write_agent_instrumentation_plan(
    path: Path,
    *,
    bundle: CorrelationBundle,
    evidence_bundle: EvidenceBundle | None = None,
) -> None:
    """Write ``agent_instrumentation_plan.md`` — agentic AI telemetry detection stubs (Splunk, Sentinel, GCP, AWS)."""
    from instrumentation.agent_telemetry import build_agent_instrumentation_markdown

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        build_agent_instrumentation_markdown(correlation_bundle=bundle, evidence_bundle=evidence_bundle),
        encoding="utf-8",
    )
