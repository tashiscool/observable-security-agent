"""Act phase: bounded operations delegated to existing CLI / libraries (local artifacts only)."""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.output_validation import validate_output_directory


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_subprocess(
    repo_root: Path,
    argv: list[str],
    *,
    timeout: int = 900,
) -> tuple[int, str]:
    cmd = [sys.executable, str(repo_root / "agent.py"), *argv]
    r = subprocess.run(
        cmd,
        cwd=str(repo_root),
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    tail = (r.stdout or "") + (r.stderr or "")
    if len(tail) > 6000:
        tail = tail[-6000:]
    return r.returncode, tail


def action_assess_run_evals(
    repo_root: Path,
    *,
    provider: str,
    scenario: str,
    output_dir: Path,
    include_agent_security: bool,
) -> tuple[bool, str, str | None]:
    args = [
        "assess",
        "--provider",
        provider,
        "--scenario",
        scenario,
        "--output-dir",
        str(output_dir),
    ]
    if include_agent_security:
        args.append("--include-agent-security")
    code, tail = run_subprocess(repo_root, args)
    ok = code == 0 and (output_dir / "eval_results.json").is_file()
    art = str(output_dir / "eval_results.json") if ok else None
    return ok, tail, art


def action_threat_hunt_agentic(
    repo_root: Path,
    *,
    provider: str,
    scenario: str,
    output_dir: Path,
) -> tuple[bool, str, str | None]:
    args = [
        "threat-hunt",
        "--provider",
        provider,
        "--scenario",
        scenario,
        "--output-dir",
        str(output_dir),
    ]
    code, tail = run_subprocess(repo_root, args)
    hunt = output_dir / "agent_threat_hunt_findings.json"
    ok = code == 0 and hunt.is_file()
    return ok, tail, str(hunt) if ok else None


def action_normalize_findings(output_dir: Path) -> tuple[bool, str, str | None]:
    """Summarize eval rows (core + agent) into a stable JSON summary."""
    out_path = output_dir / "agent_normalized_findings.json"
    rows: list[dict[str, Any]] = []
    for name in ("eval_results.json", "agent_eval_results.json"):
        p = output_dir / name
        if not p.is_file():
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        for ev in doc.get("evaluations") or []:
            if not isinstance(ev, dict):
                continue
            eid = str(ev.get("eval_id") or "")
            rows.append(
                {
                    "source_artifact": name,
                    "eval_id": eid,
                    "result": ev.get("result"),
                    "severity": ev.get("severity"),
                    "gap_count": len(ev.get("gaps") or []) if isinstance(ev.get("gaps"), list) else (1 if ev.get("gap") else 0),
                }
            )
    payload = {
        "schema_version": "1.0",
        "generated_at": _now(),
        "summary_rows": rows,
    }
    out_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return True, f"wrote {len(rows)} rows", str(out_path)


def action_generate_instrumentation_recommendations(output_dir: Path) -> tuple[bool, str, str | None]:
    """Assess already writes instrumentation plans; verify they exist."""
    inst = output_dir / "instrumentation_plan.md"
    ag = output_dir / "agent_instrumentation_plan.md"
    ok = inst.is_file()
    detail = f"instrumentation_plan.md={'yes' if inst.is_file() else 'no'}; agent_instrumentation_plan.md={'yes' if ag.is_file() else 'no'}"
    return ok, detail, str(inst) if ok else None


def action_generate_poam_drafts(output_dir: Path) -> tuple[bool, str, str | None]:
    poam = output_dir / "poam.csv"
    ag = output_dir / "agent_poam.csv"
    ok = poam.is_file()
    detail = f"poam.csv={'yes' if poam.is_file() else 'no'}; agent_poam.csv={'yes' if ag.is_file() else 'no'}"
    primary = str(poam) if ok else None
    return ok, detail, primary


def action_draft_tickets_json_only(output_dir: Path) -> tuple[bool, str, str | None]:
    """Draft ticket-shaped JSON only (no Jira/ServiceNow/API)."""
    out_path = output_dir / "agent_draft_tickets.json"
    tickets: list[dict[str, Any]] = []
    for src_name in ("eval_results.json", "agent_eval_results.json"):
        p = output_dir / src_name
        if not p.is_file():
            continue
        doc = json.loads(p.read_text(encoding="utf-8"))
        for ev in doc.get("evaluations") or []:
            if not isinstance(ev, dict):
                continue
            res = str(ev.get("result") or "").upper()
            if res not in ("FAIL", "PARTIAL", "OPEN"):
                continue
            eid = str(ev.get("eval_id") or "")
            tid = f"DRAFT-TICKET-{eid}"
            tickets.append(
                {
                    "draft_ticket_id": tid,
                    "status": "draft_json_only",
                    "source_eval_id": eid,
                    "title": f"Remediate: {ev.get('name') or eid}",
                    "body": str(ev.get("recommended_action") or ev.get("summary") or "")[:4000],
                    "severity": ev.get("severity"),
                    "would_target_system": "none — not submitted to any external ticket system",
                }
            )
    doc = {
        "schema_version": "1.0",
        "draft_only": True,
        "notice": "Autonomous loop: draft JSON for human review only. No external ticket created.",
        "tickets": tickets,
    }
    out_path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return True, f"draft tickets: {len(tickets)}", str(out_path)


def action_build_20x_package(
    repo_root: Path,
    *,
    assessment_dir: Path,
    package_dir: Path,
    config_dir: Path,
    schemas_dir: Path,
    mappings_dir: Path,
) -> tuple[bool, str, str | None]:
    package_dir.mkdir(parents=True, exist_ok=True)
    args = [
        "build-20x-package",
        "--assessment-output",
        str(assessment_dir),
        "--config",
        str(config_dir),
        "--package-output",
        str(package_dir),
        "--schemas",
        str(schemas_dir),
        "--mappings",
        str(mappings_dir),
    ]
    code, tail = run_subprocess(repo_root, args)
    pkg = package_dir / "fedramp20x-package.json"
    ok = code == 0 and pkg.is_file()
    return ok, tail, str(pkg) if ok else None


def action_validate_assessment_outputs(output_dir: Path) -> tuple[bool, str, str | None]:
    errs, _warns = validate_output_directory(output_dir.resolve())
    ok = not errs
    detail = "VALIDATION PASSED" if ok else "\n".join(errs[:20])
    return ok, detail, str(output_dir / "eval_results.json") if ok else None


def action_validate_20x_package(repo_root: Path, package_dir: Path, schemas_dir: Path) -> tuple[bool, str, str | None]:
    from fedramp20x.schema_validator import validate_package

    pkg = package_dir / "fedramp20x-package.json"
    if not pkg.is_file():
        return False, "missing fedramp20x-package.json", None
    rep = validate_package(pkg, schemas_dir)
    ok = rep.valid
    detail = "FEDRAMP 20X PACKAGE SCHEMA: OK" if ok else "\n".join(rep.errors[:25])
    return ok, detail, str(pkg) if ok else str(pkg)


def action_reconcile_20x_reports(repo_root: Path, package_dir: Path) -> tuple[bool, str, str | None]:
    args = ["reconcile-reports", "--package-output", str(package_dir)]
    code, tail = run_subprocess(repo_root, args)
    ok = code == 0
    return ok, tail, str(package_dir) if ok else None


EXECUTORS: dict[str, Any] = {
    "assess_run_evals": action_assess_run_evals,
    "threat_hunt_agentic": action_threat_hunt_agentic,
    "normalize_findings": action_normalize_findings,
    "generate_instrumentation_recommendations": action_generate_instrumentation_recommendations,
    "generate_poam_drafts": action_generate_poam_drafts,
    "draft_tickets_json_only": action_draft_tickets_json_only,
    "build_20x_package": action_build_20x_package,
    "validate_assessment_outputs": action_validate_assessment_outputs,
    "validate_20x_package": action_validate_20x_package,
    "reconcile_20x_reports": action_reconcile_20x_reports,
}


# ===========================================================================
# Categorical workflow tasks (used by run_tracker_to_20x_workflow).
#
# Each function takes a WorkflowMemory + explicit kwargs from the runner and
# returns a TaskActionResult describing inputs / outputs / artifacts / errors.
# Side effects are LOCAL only (writes artifacts inside output_dir / package_out).
# ===========================================================================


from dataclasses import dataclass, field

from agent_loop.memory import WorkflowMemory


@dataclass
class TaskActionResult:
    """Return value of every workflow task action (memory-aware contract)."""

    ok: bool
    inputs: dict[str, Any] = field(default_factory=dict)
    outputs: dict[str, Any] = field(default_factory=dict)
    artifacts: list[Path] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    detail: str = ""


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _has_agent_telemetry(scenario_dir: Path) -> bool:
    """The fixture provider treats either ``agent_identities.json`` or
    ``agent_security/agent_assessment.json`` as "agent telemetry present"."""
    return (scenario_dir / "agent_identities.json").is_file() or (
        scenario_dir / "agent_security" / "agent_assessment.json"
    ).is_file()


# --- 1. ingest_tracker (parse) ----------------------------------------------


def task_ingest_tracker(
    memory: WorkflowMemory,
    *,
    input_path: Path,
    scenario_dir: Path,
) -> TaskActionResult:
    from normalization.assessment_tracker_import import import_assessment_tracker_to_dir

    inputs = {"input_path": str(input_path), "scenario_dir": str(scenario_dir)}
    memory.record_inputs("ingest_tracker", inputs)
    if not input_path.is_file():
        return TaskActionResult(
            ok=False, inputs=inputs, errors=[f"input not found: {input_path}"]
        )
    result = import_assessment_tracker_to_dir(
        input_path=input_path, output_dir=scenario_dir, with_meta_event=True
    )
    artifacts = [p for p in result.files_written if p.is_file()]
    outputs = {
        "row_count": len(result.rows),
        "evidence_gap_count": len(result.evidence_gaps),
        "scenario_dir": str(scenario_dir),
        "counts_by_category": dict(result.counts_by_category),
    }
    memory.record_outputs("ingest_tracker", outputs)
    for a in artifacts:
        memory.record_artifact("ingest_tracker", a.name, a)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        detail=f"parsed {len(result.rows)} rows; {len(result.evidence_gaps)} evidence gaps",
    )


# --- 2. classify_rows (classify) -------------------------------------------


def task_classify_rows(
    memory: WorkflowMemory, *, scenario_dir: Path
) -> TaskActionResult:
    inputs = {"scenario_dir": str(scenario_dir)}
    memory.record_inputs("classify_rows", inputs)
    gaps_file = scenario_dir / "evidence_gaps.json"
    if not gaps_file.is_file():
        return TaskActionResult(
            ok=False,
            inputs=inputs,
            errors=[f"missing evidence_gaps.json (importer must run first): {gaps_file}"],
        )
    envelope = _read_json(gaps_file)
    egs = envelope.get("evidence_gaps") or envelope.get("gaps") or []
    info = envelope.get("informational_tracker_items") or []
    by_type: dict[str, int] = {}
    for g in egs:
        gt = str(g.get("gap_type") or "unknown")
        by_type[gt] = by_type.get(gt, 0) + 1
    outputs = {
        "evidence_gap_count": len(egs),
        "informational_count": len(info),
        "by_gap_type": dict(sorted(by_type.items())),
        "coverage_invariant_holds": bool(envelope.get("coverage_invariant_holds")),
    }
    memory.record_outputs("classify_rows", outputs)
    memory.record_artifact("classify_rows", "evidence_gaps.json", gaps_file)
    return TaskActionResult(
        ok=outputs["coverage_invariant_holds"],
        inputs=inputs,
        outputs=outputs,
        artifacts=[gaps_file],
        detail=f"classified {len(egs)} gaps + {len(info)} informational rows",
        errors=(
            []
            if outputs["coverage_invariant_holds"]
            else ["coverage_invariant_holds=False; some tracker rows were dropped"]
        ),
    )


# --- 3. normalize_evidence (normalize) -------------------------------------


def task_normalize_evidence(
    memory: WorkflowMemory, *, scenario_dir: Path
) -> TaskActionResult:
    """Verify the importer produced empty / header-only fixture envelopes; never invents data."""
    inputs = {"scenario_dir": str(scenario_dir)}
    memory.record_inputs("normalize_evidence", inputs)
    expected = (
        "declared_inventory.csv",
        "scanner_targets.csv",
        "scanner_findings.json",
        "central_log_sources.json",
        "alert_rules.json",
        "tickets.json",
        "poam.csv",
        "discovered_assets.json",
        "cloud_events.json",
    )
    missing: list[str] = []
    artifacts: list[Path] = []
    for name in expected:
        p = scenario_dir / name
        if not p.is_file():
            missing.append(name)
        else:
            artifacts.append(p)
    outputs = {"normalized_files": [str(p) for p in artifacts], "missing": missing}
    memory.record_outputs("normalize_evidence", outputs)
    for a in artifacts:
        memory.record_artifact("normalize_evidence", a.name, a)
    return TaskActionResult(
        ok=not missing,
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        errors=[f"missing normalized fixture file: {m}" for m in missing],
        detail=f"normalized {len(artifacts)} envelope files",
    )


# --- 4. build_evidence_graph (evaluate) ------------------------------------


def task_build_evidence_graph(
    memory: WorkflowMemory, *, scenario_dir: Path
) -> TaskActionResult:
    """Load the FixtureProvider bundle and verify a primary event exists.

    The actual evidence_graph.json is written by the assess pipeline (next task),
    but this step proves the bundle is *loadable* before we run the heavyweight
    eval pipeline. Failing here halts the workflow with a precise error.
    """
    from providers.fixture import FixtureProvider
    from core.normalizer import load_normalized_primary_event

    inputs = {"scenario_dir": str(scenario_dir)}
    memory.record_inputs("build_evidence_graph", inputs)
    try:
        bundle = FixtureProvider(scenario_dir).load()
    except Exception as e:  # noqa: BLE001 — surface any provider error precisely.
        return TaskActionResult(
            ok=False,
            inputs=inputs,
            errors=[f"FixtureProvider failed to load scenario: {e}"],
            detail=str(e),
        )
    try:
        sem_event, all_events = load_normalized_primary_event(bundle)
    except Exception as e:  # noqa: BLE001
        return TaskActionResult(
            ok=False,
            inputs=inputs,
            errors=[f"could not normalize a primary event: {e}"],
        )
    outputs = {
        "asset_id": getattr(sem_event, "asset_id", None),
        "event_type": getattr(sem_event, "event_type", None)
        or getattr(sem_event, "semantic_type", None),
        "event_count": len(all_events),
        "inventory_count": len(bundle.declared_inventory_rows or []),
        "scanner_finding_count": len(bundle.scanner_findings or []),
        "alert_rule_count": len(bundle.alert_rules or []),
    }
    memory.record_outputs("build_evidence_graph", outputs)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs=outputs,
        detail=f"loaded scenario; primary asset={sem_event.asset_id}, events={len(all_events)}",
    )


# --- 5. run_cloud_evals (evaluate) -----------------------------------------


def task_run_cloud_evals(
    memory: WorkflowMemory,
    *,
    repo_root: Path,
    scenario_dir: Path,
    output_dir: Path,
    include_agent_security: bool = False,
) -> TaskActionResult:
    """Delegate to the existing assess subcommand; produces eval_results.json + graph + reports."""
    inputs = {
        "scenario_dir": str(scenario_dir),
        "output_dir": str(output_dir),
        "include_agent_security": include_agent_security,
    }
    memory.record_inputs("run_cloud_evals", inputs)
    args = [
        "assess",
        "--provider",
        "fixture",
        "--scenario",
        "_",
        "--fixture-dir",
        str(scenario_dir),
        "--output-dir",
        str(output_dir),
    ]
    if include_agent_security:
        args.append("--include-agent-security")
    code, tail = run_subprocess(repo_root, args)
    eval_results = output_dir / "eval_results.json"
    graph = output_dir / "evidence_graph.json"
    artifacts: list[Path] = [p for p in (eval_results, graph) if p.is_file()]
    ok = code == 0 and eval_results.is_file()
    if ok:
        eval_doc = _read_json(eval_results)
        outputs = {
            "eval_results_path": str(eval_results),
            "eval_count": len(eval_doc.get("evaluations") or []),
            "fail_count": sum(
                1
                for e in (eval_doc.get("evaluations") or [])
                if str(e.get("result") or "").upper() == "FAIL"
            ),
        }
    else:
        outputs = {"eval_results_path": str(eval_results), "subprocess_rc": code}
    memory.record_outputs("run_cloud_evals", outputs)
    for a in artifacts:
        memory.record_artifact("run_cloud_evals", a.name, a)
    return TaskActionResult(
        ok=ok,
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        errors=([] if ok else [f"assess subprocess rc={code}", tail[-2000:]]),
        detail=tail if ok else f"assess failed rc={code}: {tail[-1000:]}",
    )


# --- 6. run_tracker_gap_evals (evaluate) -----------------------------------


def task_run_tracker_gap_evals(
    memory: WorkflowMemory, *, scenario_dir: Path, output_dir: Path
) -> TaskActionResult:
    from evals.tracker_evidence_gap_eval import run_tracker_evidence_gap_eval
    from evals.tracker_evidence_gap_report import write_all_tracker_gap_outputs

    inputs = {"scenario_dir": str(scenario_dir), "output_dir": str(output_dir)}
    memory.record_inputs("run_tracker_gap_evals", inputs)
    gaps_file = scenario_dir / "evidence_gaps.json"
    if not gaps_file.is_file():
        return TaskActionResult(
            ok=False,
            inputs=inputs,
            errors=[f"missing evidence_gaps.json: {gaps_file}"],
        )
    envelope = _read_json(gaps_file)
    eval_result = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
    artifact_dir = output_dir / ".tracker_artifacts"
    written = write_all_tracker_gap_outputs(
        eval_result,
        output_dir=artifact_dir,
        source_questions_md=scenario_dir / "auditor_questions.md",
    )
    # Promote the unique tracker_gap_*.* outputs to the canonical output_dir.
    promoted: list[Path] = []
    import shutil as _shutil

    for name in (
        "tracker_gap_report.md",
        "tracker_gap_matrix.csv",
        "tracker_gap_eval_results.json",
    ):
        src = artifact_dir / name
        if src.is_file():
            dst = output_dir / name
            _shutil.copy2(src, dst)
            promoted.append(dst)
    if (artifact_dir / "instrumentation_plan.md").is_file():
        dst = output_dir / "tracker_instrumentation_plan.md"
        _shutil.copy2(artifact_dir / "instrumentation_plan.md", dst)
        promoted.append(dst)
    if (artifact_dir / "poam.csv").is_file():
        dst = output_dir / "tracker_poam.csv"
        _shutil.copy2(artifact_dir / "poam.csv", dst)
        promoted.append(dst)

    outputs = {
        "result": eval_result.eval_result.result,
        "severity": eval_result.eval_result.severity,
        "open_gaps": eval_result.total_open_gaps,
        "high_impact_count": eval_result.high_impact_count,
        "poam_required_count": eval_result.poam_required_count,
        "tracker_eval_record": eval_result.eval_result.model_dump(),
    }
    memory.record_outputs("run_tracker_gap_evals", outputs)
    for a in promoted:
        memory.record_artifact("run_tracker_gap_evals", a.name, a)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs=outputs,
        artifacts=promoted,
        detail=(
            f"tracker eval result={eval_result.eval_result.result} "
            f"open={eval_result.total_open_gaps} "
            f"high_impact={eval_result.high_impact_count}"
        ),
    )


# --- 7. run_agent_security_evals (evaluate, optional) ----------------------


def task_run_agent_security_evals(
    memory: WorkflowMemory,
    *,
    repo_root: Path,
    scenario_dir: Path,
    output_dir: Path,
) -> TaskActionResult:
    """Re-run assess with --include-agent-security only when agent telemetry exists."""
    inputs = {
        "scenario_dir": str(scenario_dir),
        "output_dir": str(output_dir),
        "agent_telemetry_present": _has_agent_telemetry(scenario_dir),
    }
    memory.record_inputs("run_agent_security_evals", inputs)
    if not _has_agent_telemetry(scenario_dir):
        outputs = {"skipped_reason": "no agent telemetry present in scenario"}
        memory.record_outputs("run_agent_security_evals", outputs)
        return TaskActionResult(
            ok=True,
            inputs=inputs,
            outputs=outputs,
            detail="SKIPPED: no agent telemetry present in scenario",
        )
    args = [
        "assess",
        "--provider",
        "fixture",
        "--scenario",
        "_",
        "--fixture-dir",
        str(scenario_dir),
        "--output-dir",
        str(output_dir),
        "--include-agent-security",
    ]
    code, tail = run_subprocess(repo_root, args)
    agent_eval = output_dir / "agent_eval_results.json"
    artifacts = [agent_eval] if agent_eval.is_file() else []
    ok = code == 0
    outputs = {"agent_eval_results_path": str(agent_eval), "subprocess_rc": code}
    memory.record_outputs("run_agent_security_evals", outputs)
    for a in artifacts:
        memory.record_artifact("run_agent_security_evals", a.name, a)
    return TaskActionResult(
        ok=ok,
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        errors=([] if ok else [f"agent-security assess rc={code}", tail[-2000:]]),
    )


# --- 8. map_to_ksi (map) ---------------------------------------------------


def task_map_to_ksi(memory: WorkflowMemory, *, output_dir: Path) -> TaskActionResult:
    """Fold TRACKER_EVIDENCE_GAP_ANALYSIS into eval_results.json so build_20x_package picks it up."""
    inputs = {"output_dir": str(output_dir)}
    memory.record_inputs("map_to_ksi", inputs)
    eval_results_path = output_dir / "eval_results.json"
    if not eval_results_path.is_file():
        return TaskActionResult(
            ok=False, inputs=inputs, errors=[f"missing {eval_results_path}"]
        )
    tracker_record = (memory.get_outputs("run_tracker_gap_evals") or {}).get(
        "tracker_eval_record"
    )
    if not isinstance(tracker_record, dict) or not tracker_record.get("eval_id"):
        return TaskActionResult(
            ok=False,
            inputs=inputs,
            errors=["run_tracker_gap_evals did not record a tracker_eval_record"],
        )
    eval_doc = _read_json(eval_results_path)
    evaluations = list(eval_doc.get("evaluations") or [])
    legacy = {
        "eval_id": tracker_record["eval_id"],
        "name": tracker_record["name"],
        "control_refs": list(tracker_record.get("controls") or []),
        "result": tracker_record["result"],
        "evidence": list(tracker_record.get("evidence") or []),
        "gap": (tracker_record.get("gaps") or [tracker_record.get("summary") or ""])[0],
        "gaps": list(tracker_record.get("gaps") or []),
        "recommended_action": "; ".join(tracker_record.get("recommended_actions") or []),
        "recommended_actions": list(tracker_record.get("recommended_actions") or []),
        "severity": tracker_record["severity"],
        "summary": tracker_record["summary"],
        "affected_assets": list(tracker_record.get("affected_assets") or []),
        "remediation_disposition": "poam_or_risk_acceptance",
    }
    if not any(str(e.get("eval_id")) == legacy["eval_id"] for e in evaluations):
        evaluations.append(legacy)
    eval_doc["evaluations"] = evaluations
    records = list(eval_doc.get("eval_result_records") or [])
    canonical = dict(tracker_record)
    canonical.setdefault("remediation_disposition", "poam_or_risk_acceptance")
    canonical.setdefault("linked_ksi_ids", [])
    if not any(str(r.get("eval_id")) == canonical["eval_id"] for r in records):
        records.append(canonical)
    eval_doc["eval_result_records"] = records
    eval_results_path.write_text(json.dumps(eval_doc, indent=2), encoding="utf-8")
    outputs = {
        "evaluations_total": len(evaluations),
        "tracker_eval_id": tracker_record["eval_id"],
        "controls_attached": len(legacy["control_refs"]),
    }
    memory.record_outputs("map_to_ksi", outputs)
    memory.record_artifact("map_to_ksi", "eval_results.json", eval_results_path)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs=outputs,
        artifacts=[eval_results_path],
        detail=f"folded {tracker_record['eval_id']} into eval_results.json",
    )


# --- 9. generate_findings (evaluate, preview) ------------------------------


def task_generate_findings(
    memory: WorkflowMemory, *, output_dir: Path
) -> TaskActionResult:
    """Produce a preview findings.json summary so the package builder's input is observable.

    The package builder computes the canonical findings list from the same
    eval_results.json as input. This task records a *preview* of that work
    (count of FAIL/PARTIAL/OPEN rows + their controls) so the trace shows
    explicitly what feeds findings generation.
    """
    inputs = {"output_dir": str(output_dir)}
    memory.record_inputs("generate_findings", inputs)
    eval_results = output_dir / "eval_results.json"
    if not eval_results.is_file():
        return TaskActionResult(
            ok=False, inputs=inputs, errors=[f"missing {eval_results}"]
        )
    doc = _read_json(eval_results)
    candidates: list[dict[str, Any]] = []
    for ev in doc.get("evaluations") or []:
        if not isinstance(ev, dict):
            continue
        res = str(ev.get("result") or "").upper()
        if res in {"FAIL", "PARTIAL", "OPEN"}:
            candidates.append(
                {
                    "eval_id": ev.get("eval_id"),
                    "result": res,
                    "severity": ev.get("severity"),
                    "controls": list(ev.get("control_refs") or []),
                }
            )
    preview = {
        "schema_version": "1.0",
        "preview_only": True,
        "candidate_finding_count": len(candidates),
        "candidates": candidates,
    }
    out = output_dir / "preview_findings.json"
    out.write_text(json.dumps(preview, indent=2), encoding="utf-8")
    outputs = {
        "candidate_finding_count": len(candidates),
        "by_result": {
            r: sum(1 for c in candidates if c["result"] == r)
            for r in ("FAIL", "PARTIAL", "OPEN")
        },
    }
    memory.record_outputs("generate_findings", outputs)
    memory.record_artifact("generate_findings", out.name, out)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs=outputs,
        artifacts=[out],
        detail=f"{len(candidates)} candidate findings (FAIL/PARTIAL/OPEN evals)",
    )


# --- 10. generate_poam (package) -------------------------------------------


def task_generate_poam(
    memory: WorkflowMemory, *, output_dir: Path
) -> TaskActionResult:
    """Both `assess` and the tracker eval already wrote POA&M files; this task
    aggregates them into a single ``preview_poam_summary.json`` that the package
    builder consumes implicitly via its own POA&M pipeline."""
    inputs = {"output_dir": str(output_dir)}
    memory.record_inputs("generate_poam", inputs)
    main_poam = output_dir / "poam.csv"
    tracker_poam = output_dir / "tracker_poam.csv"
    summary = {
        "schema_version": "1.0",
        "preview_only": True,
        "main_poam_csv": str(main_poam) if main_poam.is_file() else None,
        "tracker_poam_csv": str(tracker_poam) if tracker_poam.is_file() else None,
    }
    artifacts: list[Path] = []
    for p in (main_poam, tracker_poam):
        if p.is_file():
            artifacts.append(p)
    out = output_dir / "preview_poam_summary.json"
    out.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    artifacts.append(out)
    outputs = {
        "main_poam_present": main_poam.is_file(),
        "tracker_poam_present": tracker_poam.is_file(),
    }
    memory.record_outputs("generate_poam", outputs)
    for a in artifacts:
        memory.record_artifact("generate_poam", a.name, a)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        detail=(
            f"main_poam={'yes' if main_poam.is_file() else 'no'}; "
            f"tracker_poam={'yes' if tracker_poam.is_file() else 'no'}"
        ),
    )


# --- 11. build_package (package) -------------------------------------------


def task_build_package(
    memory: WorkflowMemory,
    *,
    output_dir: Path,
    package_output: Path,
    config_dir: Path,
    schemas_dir: Path,
    mappings_dir: Path,
) -> TaskActionResult:
    from fedramp20x.package_builder import build_20x_package

    inputs = {
        "output_dir": str(output_dir),
        "package_output": str(package_output),
        "config_dir": str(config_dir),
    }
    memory.record_inputs("build_package", inputs)
    package_output.mkdir(parents=True, exist_ok=True)
    try:
        rc = build_20x_package(
            assessment_output=output_dir,
            config_dir=config_dir,
            package_output=package_output,
            mappings_dir=mappings_dir,
            schemas_dir=schemas_dir,
            validation_artifact_root=None,
        )
    except Exception as e:  # noqa: BLE001
        return TaskActionResult(
            ok=False, inputs=inputs, errors=[f"build_20x_package raised: {e}"]
        )
    pkg_path = package_output / "fedramp20x-package.json"
    ok = rc == 0 and pkg_path.is_file()
    outputs = {"package_path": str(pkg_path), "subprocess_rc": rc}
    if ok:
        pkg = _read_json(pkg_path)
        outputs.update(
            {
                "ksi_validation_results_count": len(pkg.get("ksi_validation_results") or []),
                "findings_count": len(pkg.get("findings") or []),
                "poam_items_count": len(pkg.get("poam_items") or []),
            }
        )
    memory.record_outputs("build_package", outputs)
    if pkg_path.is_file():
        memory.record_artifact("build_package", pkg_path.name, pkg_path)
    return TaskActionResult(
        ok=ok,
        inputs=inputs,
        outputs=outputs,
        artifacts=[pkg_path] if pkg_path.is_file() else [],
        errors=([] if ok else [f"build_20x_package returned {rc}"]),
    )


# --- 12. generate_reports (report) -----------------------------------------


def task_generate_reports(
    memory: WorkflowMemory, *, package_output: Path, config_dir: Path
) -> TaskActionResult:
    import yaml as _yaml
    from fedramp20x.poam_builder import write_poam_markdown
    from fedramp20x.report_builder import (
        POAM_MD,
        write_agency_ao_report,
        write_assessor_report,
        write_executive_report,
        write_reconciliation_markdown,
    )

    inputs = {"package_output": str(package_output), "config_dir": str(config_dir)}
    memory.record_inputs("generate_reports", inputs)
    pkg_path = package_output / "fedramp20x-package.json"
    if not pkg_path.is_file():
        return TaskActionResult(
            ok=False, inputs=inputs, errors=[f"missing package json: {pkg_path}"]
        )
    package = _read_json(pkg_path)
    rp = config_dir / "reporting-policy.yaml"
    rp_reports: dict[str, Any] = {}
    if rp.is_file():
        reporting = _yaml.safe_load(rp.read_text(encoding="utf-8")) or {}
        rp_reports = (reporting.get("reports") or {}) if isinstance(reporting, dict) else {}
    assess_fn = (rp_reports.get("assessor") or {}).get("filename") or "assessor-summary.md"
    exec_fn = (rp_reports.get("executive") or {}).get("filename") or "executive-summary.md"
    ao_fn = (rp_reports.get("agency_ao") or {}).get("filename") or "ao-risk-brief.md"
    assessor_path = package_output / "reports" / "assessor" / assess_fn
    executive_path = package_output / "reports" / "executive" / exec_fn
    ao_path = package_output / "reports" / "agency-ao" / ao_fn
    recon_md = package_output / "reports" / "reconciliation_report.md"
    for d in (assessor_path.parent, executive_path.parent, ao_path.parent, recon_md.parent):
        d.mkdir(parents=True, exist_ok=True)
    write_assessor_report(assessor_path, package)
    write_executive_report(executive_path, package)
    write_agency_ao_report(ao_path, package)
    write_reconciliation_markdown(recon_md, package)
    write_poam_markdown(assessor_path.parent / POAM_MD, package.get("poam_items") or [])
    artifacts = [assessor_path, executive_path, ao_path, recon_md]
    outputs = {
        "assessor_report": str(assessor_path),
        "executive_report": str(executive_path),
        "ao_risk_brief": str(ao_path),
        "reconciliation_report": str(recon_md),
    }
    memory.record_outputs("generate_reports", outputs)
    for a in artifacts:
        memory.record_artifact("generate_reports", a.name, a)
    return TaskActionResult(
        ok=all(p.is_file() for p in artifacts),
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        detail=f"wrote {len(artifacts)} reports under {package_output / 'reports'}",
    )


# --- 13. reconcile (reconcile) ---------------------------------------------


def task_reconcile(
    memory: WorkflowMemory, *, package_output: Path
) -> TaskActionResult:
    from fedramp20x.reconciliation import run_reconciliation_cli

    inputs = {"package_output": str(package_output)}
    memory.record_inputs("reconcile", inputs)
    rc, result = run_reconciliation_cli(package_dir=package_output)
    outputs = {
        "overall_status": result.get("overall_status"),
        "checks_total": len(result.get("checks") or []),
        "checks_failed": sum(
            1
            for c in (result.get("checks") or [])
            if isinstance(c, dict) and c.get("status") != "pass"
        ),
    }
    memory.record_outputs("reconcile", outputs)
    artifacts: list[Path] = []
    rec_json = package_output / "evidence" / "validation-results" / "reconciliation.json"
    if rec_json.is_file():
        artifacts.append(rec_json)
        memory.record_artifact("reconcile", rec_json.name, rec_json)
    return TaskActionResult(
        ok=rc == 0,
        inputs=inputs,
        outputs=outputs,
        artifacts=artifacts,
        errors=(
            []
            if rc == 0
            else [
                f"reconciliation rc={rc}; status={result.get('overall_status')}",
                json.dumps(
                    [
                        c
                        for c in (result.get("checks") or [])
                        if isinstance(c, dict) and c.get("status") != "pass"
                    ],
                    indent=2,
                )[:4000],
            ]
        ),
    )


# --- 14. validate_outputs (validate) ---------------------------------------


def task_validate_outputs(
    memory: WorkflowMemory, *, output_dir: Path, package_output: Path, schemas_dir: Path
) -> TaskActionResult:
    from core.failure_narrative_contract import (
        validate_eval_results_fail_partial_contracts,
    )
    from fedramp20x.schema_validator import validate_package

    inputs = {
        "output_dir": str(output_dir),
        "package_output": str(package_output),
        "schemas_dir": str(schemas_dir),
    }
    memory.record_inputs("validate_outputs", inputs)
    errors: list[str] = []

    pkg_path = package_output / "fedramp20x-package.json"
    if not pkg_path.is_file():
        errors.append(f"missing {pkg_path}")
        memory.record_outputs("validate_outputs", {"errors": errors})
        return TaskActionResult(ok=False, inputs=inputs, errors=errors)

    rep = validate_package(pkg_path, schemas_dir)
    schema_ok = bool(rep.valid)
    if not schema_ok:
        errors.extend(["schema validation failed:", *rep.errors[:25]])

    eval_results = output_dir / "eval_results.json"
    contract_ok = True
    if eval_results.is_file():
        eval_doc = _read_json(eval_results)
        contract_errs = validate_eval_results_fail_partial_contracts(eval_doc)
        if contract_errs:
            contract_ok = False
            errors.extend(["narrative contract failed:", *[f"  {e}" for e in contract_errs]])

    ok = schema_ok and contract_ok
    outputs = {"schema_valid": schema_ok, "narrative_contract_valid": contract_ok}
    memory.record_outputs("validate_outputs", outputs)
    if pkg_path.is_file():
        memory.record_artifact("validate_outputs", pkg_path.name, pkg_path)
    if eval_results.is_file():
        memory.record_artifact("validate_outputs", eval_results.name, eval_results)
    return TaskActionResult(
        ok=ok,
        inputs=inputs,
        outputs=outputs,
        artifacts=[p for p in (pkg_path, eval_results) if p.is_file()],
        errors=errors,
        detail=(
            f"schema={'OK' if schema_ok else 'FAIL'} contract={'OK' if contract_ok else 'FAIL'}"
        ),
    )


# --- 15. explain_summary (explain) -----------------------------------------


def task_explain_summary(
    memory: WorkflowMemory,
    *,
    output_dir: Path,
    trace: dict[str, Any],
) -> TaskActionResult:
    """Write agent_run_summary.md derived from trace + memory."""
    inputs = {"output_dir": str(output_dir)}
    memory.record_inputs("explain_summary", inputs)
    summary_path = output_dir / "agent_run_summary.md"
    summary_path.write_text(_render_summary_md(trace, memory), encoding="utf-8")
    memory.record_outputs("explain_summary", {"summary_path": str(summary_path)})
    memory.record_artifact("explain_summary", summary_path.name, summary_path)
    return TaskActionResult(
        ok=True,
        inputs=inputs,
        outputs={"summary_path": str(summary_path)},
        artifacts=[summary_path],
        detail=f"wrote {summary_path}",
    )


def _render_summary_md(trace: dict[str, Any], memory: WorkflowMemory) -> str:
    from agent_loop.policy import (
        autonomous_categories_reference,
        blocked_categories_reference,
    )

    lines: list[str] = []
    lines.append(f"# Agent run summary — workflow `{trace.get('workflow') or memory.workflow_name}`")
    lines.append("")
    lines.append(f"**Started:** {memory.started_at}  ")
    lines.append(f"**Output directory:** `{memory.get_global('output_dir')}`  ")
    lines.append(f"**Package output:** `{memory.get_global('package_output')}`  ")
    lines.append(f"**Input:** `{memory.get_global('input_path')}`  ")
    lines.append(f"**Status:** **{trace.get('overall_status', 'unknown').upper()}**  ")
    lines.append("")

    lines.append("## Autonomy contract")
    lines.append("")
    lines.append("Allowed autonomous actions (categorical contract):")
    for c in autonomous_categories_reference():
        lines.append(f"- **{c['id']}** — {c['rationale']}")
    lines.append("")
    lines.append("Blocked actions (require human approval):")
    for b in blocked_categories_reference():
        lines.append(f"- **{b['id']}** — {b['rationale']}")
    lines.append("")

    lines.append("## Task graph")
    lines.append("")
    lines.append(
        "| # | Task | Category | Action | Status | Started | Completed | Artifacts |"
    )
    lines.append("|---|------|----------|--------|--------|---------|-----------|-----------|")
    for i, step in enumerate(trace.get("tasks") or [], start=1):
        arts = ", ".join(
            f"`{a.get('name')}`" for a in (step.get("artifacts") or [])
        ) or "—"
        lines.append(
            f"| {i} | `{step.get('task_id')}` | `{step.get('action_category')}` | "
            f"`{step.get('action_id')}` | **{step.get('status')}** | "
            f"{step.get('started_at') or '—'} | {step.get('completed_at') or '—'} | {arts} |"
        )
    lines.append("")

    lines.append("## Errors")
    lines.append("")
    saw_err = False
    for step in trace.get("tasks") or []:
        if step.get("errors"):
            saw_err = True
            lines.append(f"### `{step.get('task_id')}`")
            for e in step["errors"]:
                lines.append(f"- {e}")
            lines.append("")
    if not saw_err:
        lines.append("_No errors recorded._")
        lines.append("")

    lines.append("## Trace")
    lines.append("")
    lines.append(
        "See `agent_run_trace.json` for the full machine-readable trace including "
        "per-task inputs, outputs, policy decisions, and artifact paths."
    )
    lines.append("")
    return "\n".join(lines)
