"""Orchestrate observe → plan → act → explain and emit trace + summary."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from agent_loop import actions
from agent_loop.memory import WorkflowMemory, _now_iso
from agent_loop.planner import Observation, build_plan, gather_observation
from agent_loop.policy import (
    autonomous_categories_reference,
    blocked_categories_reference,
    classify_action,
    policy_dict,
)
from agent_loop.task_graph import TaskDef, TaskGraph, get_workflow


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_fixture_root(repo_root: Path, scenario: str | None, fixture_dir: Path | None) -> Path:
    if fixture_dir is not None:
        return fixture_dir.resolve()
    scen = scenario or "scenario_public_admin_vuln_event"
    return (repo_root / "fixtures" / scen).resolve()


def write_agent_run_summary(trace: dict[str, Any], path: Path) -> None:
    steps = trace.get("steps") or []
    lines = [
        "# Agent run summary (bounded autonomous loop)",
        "",
        f"**Provider:** `{trace.get('provider')}`  ",
        f"**Scenario:** `{trace.get('scenario')}`  ",
        f"**Output directory:** `{trace.get('output_dir')}`  ",
        f"**20x package directory:** `{trace.get('package_output')}`  ",
        "",
        "## Playbook",
        "",
        str(trace.get("plan_rationale") or ""),
        "",
        "## Policy",
        "",
        "Autonomous actions are limited to **local evidence generation** (assess, threat hunt, drafts, package, validate, reconcile).",
        "The following categories **require human approval** and are **not** executed by this loop:",
        "",
    ]
    for b in trace.get("blocked_categories_reference") or []:
        lines.append(f"- **{b.get('id')}**: {b.get('rationale')}")
    lines.extend(["", "## Derivation trace (high level)", ""])
    for s in steps:
        idx = s.get("step_index")
        ph = s.get("phase")
        act = s.get("chosen_action") or "—"
        pol = s.get("policy") or {}
        ver = (s.get("verification") or {}).get("status", "—")
        art = s.get("output_artifact") or "—"
        lines.append(
            f"{idx}. **{ph}** — `{act}` — policy: {'ALLOW' if pol.get('allowed') else 'DENY'} — "
            f"verify: **{ver}** — artifact: `{art}`"
        )
    lines.extend(
        [
            "",
            "## Full trace",
            "",
            f"See `{trace.get('outputs', {}).get('trace_json', 'agent_run_trace.json')}` for machine-readable steps.",
            "",
        ]
    )
    path.write_text("\n".join(lines), encoding="utf-8")


def run_bounded_agent_loop(
    *,
    repo_root: Path,
    provider: str,
    scenario: str | None,
    fixture_dir: Path | None,
    output_dir: Path,
    package_output: Path,
    config_dir: Path | None = None,
    schemas_dir: Path | None = None,
    mappings_dir: Path | None = None,
    include_agent_security: bool = True,
) -> int:
    scen = scenario or "scenario_public_admin_vuln_event"
    root = _resolve_fixture_root(repo_root, scen, fixture_dir)
    out = output_dir.resolve()
    pkg = package_output.resolve()
    cfg = (config_dir or repo_root / "config").resolve()
    sch = (schemas_dir or repo_root / "schemas").resolve()
    mapd = (mappings_dir or repo_root / "mappings").resolve()
    out.mkdir(parents=True, exist_ok=True)
    pkg.mkdir(parents=True, exist_ok=True)

    trace: dict[str, Any] = {
        "schema_version": "1.0",
        "bounded_playbook": True,
        "provider": provider,
        "scenario": scen,
        "scenario_root": str(root),
        "output_dir": str(out),
        "package_output": str(pkg),
        "blocked_categories_reference": blocked_categories_reference(),
        "outputs": {
            "trace_json": str(out / "agent_run_trace.json"),
            "summary_md": str(out / "agent_run_summary.md"),
        },
        "steps": [],
    }

    def push_step(row: dict[str, Any]) -> None:
        row["step_index"] = len(trace["steps"])
        row.setdefault("timestamp", _ts())
        trace["steps"].append(row)

    obs: Observation = gather_observation(
        provider=provider,
        scenario=scen,
        scenario_root=root,
        output_dir=out,
        package_output=pkg,
    )
    obs_dec = classify_action("observe")
    push_step(
        {
            "phase": "observe",
            "observation": {
                "scenario_root": str(obs.scenario_root),
                "evidence_file_count": obs.evidence_file_count,
                "agent_telemetry_present": obs.agent_telemetry_present,
                "prior_artifacts": obs.prior_artifacts,
            },
            "chosen_action": None,
            "policy": policy_dict(obs_dec),
            "output_artifact": None,
            "verification": {"status": "PASS" if obs_dec.allowed else "FAIL", "detail": obs_dec.reason},
        }
    )

    plan = build_plan(obs)
    trace["plan_rationale"] = plan.rationale
    trace["plan_notes"] = plan.notes
    plan_dec = classify_action("plan")
    push_step(
        {
            "phase": "plan",
            "observation": {"action_ids": plan.action_ids, "notes": plan.notes},
            "chosen_action": "plan",
            "policy": policy_dict(plan_dec),
            "output_artifact": None,
            "verification": {"status": "PASS" if plan_dec.allowed else "FAIL", "detail": plan_dec.reason},
        }
    )

    exit_code = 0

    for aid in plan.action_ids:
        pol = classify_action(aid)
        if not pol.allowed:
            push_step(
                {
                    "phase": "act",
                    "observation": None,
                    "chosen_action": aid,
                    "policy": policy_dict(pol),
                    "output_artifact": None,
                    "verification": {"status": "SKIP", "detail": pol.reason},
                }
            )
            continue

        ok = False
        detail = ""
        artifact: str | None = None

        if aid == "assess_run_evals":
            ok, detail, artifact = actions.action_assess_run_evals(
                repo_root.resolve(),
                provider=provider,
                scenario=scen,
                output_dir=out,
                include_agent_security=include_agent_security,
            )
        elif aid == "threat_hunt_agentic":
            ok, detail, artifact = actions.action_threat_hunt_agentic(
                repo_root.resolve(),
                provider=provider,
                scenario=scen,
                output_dir=out,
            )
        elif aid == "normalize_findings":
            ok, detail, artifact = actions.action_normalize_findings(out)
        elif aid == "generate_instrumentation_recommendations":
            ok, detail, artifact = actions.action_generate_instrumentation_recommendations(out)
        elif aid == "generate_poam_drafts":
            ok, detail, artifact = actions.action_generate_poam_drafts(out)
        elif aid == "draft_tickets_json_only":
            ok, detail, artifact = actions.action_draft_tickets_json_only(out)
        elif aid == "build_20x_package":
            ok, detail, artifact = actions.action_build_20x_package(
                repo_root.resolve(),
                assessment_dir=out,
                package_dir=pkg,
                config_dir=cfg,
                schemas_dir=sch,
                mappings_dir=mapd,
            )
        elif aid == "validate_assessment_outputs":
            ok, detail, artifact = actions.action_validate_assessment_outputs(out)
        elif aid == "validate_20x_package":
            ok, detail, artifact = actions.action_validate_20x_package(repo_root.resolve(), pkg, sch)
        elif aid == "reconcile_20x_reports":
            ok, detail, artifact = actions.action_reconcile_20x_reports(repo_root.resolve(), pkg)
        else:
            detail = f"unknown action {aid!r}"
            ok = False

        if not ok:
            exit_code = 1
        push_step(
            {
                "phase": "act",
                "observation": None,
                "chosen_action": aid,
                "policy": policy_dict(pol),
                "output_artifact": artifact,
                "verification": {"status": "PASS" if ok else "FAIL", "detail": (detail or "")[:8000]},
            }
        )

    summary_path = out / "agent_run_summary.md"
    trace_path = out / "agent_run_trace.json"
    sum_pol = classify_action("write_agent_run_summary")
    push_step(
        {
            "phase": "explain",
            "observation": {"steps_completed": len(trace["steps"])},
            "chosen_action": "write_agent_run_summary",
            "policy": policy_dict(sum_pol),
            "output_artifact": str(summary_path),
            "verification": {"status": "PASS" if sum_pol.allowed else "FAIL", "detail": sum_pol.reason},
        }
    )
    trace_pol = classify_action("write_trace_json")
    push_step(
        {
            "phase": "explain",
            "observation": None,
            "chosen_action": "write_trace_json",
            "policy": policy_dict(trace_pol),
            "output_artifact": str(trace_path),
            "verification": {"status": "PASS" if trace_pol.allowed else "FAIL", "detail": trace_pol.reason},
        }
    )
    write_agent_run_summary(trace, summary_path)
    trace_path.write_text(json.dumps(trace, indent=2, default=str), encoding="utf-8")

    print(f"Wrote {trace_path}")
    print(f"Wrote {summary_path}")
    return exit_code


# ===========================================================================
# Categorical task-graph workflow runner (NEW)
# ===========================================================================


def _build_task_dispatcher(
    *,
    repo_root: Path,
    input_path: Path,
    output_dir: Path,
    package_output: Path,
    config_dir: Path,
    schemas_dir: Path,
    mappings_dir: Path,
    scenario_dir: Path,
    trace_so_far: dict[str, Any],
) -> dict[str, Callable[[WorkflowMemory], actions.TaskActionResult]]:
    """Map task_id → callable. Each callable takes only ``WorkflowMemory``."""
    return {
        "ingest_tracker": lambda m: actions.task_ingest_tracker(
            m, input_path=input_path, scenario_dir=scenario_dir
        ),
        "classify_rows": lambda m: actions.task_classify_rows(m, scenario_dir=scenario_dir),
        "normalize_evidence": lambda m: actions.task_normalize_evidence(
            m, scenario_dir=scenario_dir
        ),
        "build_evidence_graph": lambda m: actions.task_build_evidence_graph(
            m, scenario_dir=scenario_dir
        ),
        "run_cloud_evals": lambda m: actions.task_run_cloud_evals(
            m,
            repo_root=repo_root,
            scenario_dir=scenario_dir,
            output_dir=output_dir,
            include_agent_security=False,
        ),
        "run_tracker_gap_evals": lambda m: actions.task_run_tracker_gap_evals(
            m, scenario_dir=scenario_dir, output_dir=output_dir
        ),
        "run_agent_security_evals": lambda m: actions.task_run_agent_security_evals(
            m, repo_root=repo_root, scenario_dir=scenario_dir, output_dir=output_dir
        ),
        "map_to_ksi": lambda m: actions.task_map_to_ksi(m, output_dir=output_dir),
        "generate_findings": lambda m: actions.task_generate_findings(
            m, output_dir=output_dir
        ),
        "generate_poam": lambda m: actions.task_generate_poam(m, output_dir=output_dir),
        "build_package": lambda m: actions.task_build_package(
            m,
            output_dir=output_dir,
            package_output=package_output,
            config_dir=config_dir,
            schemas_dir=schemas_dir,
            mappings_dir=mappings_dir,
        ),
        "generate_reports": lambda m: actions.task_generate_reports(
            m, package_output=package_output, config_dir=config_dir
        ),
        "reconcile": lambda m: actions.task_reconcile(m, package_output=package_output),
        "validate_outputs": lambda m: actions.task_validate_outputs(
            m,
            output_dir=output_dir,
            package_output=package_output,
            schemas_dir=schemas_dir,
        ),
        "explain_summary": lambda m: actions.task_explain_summary(
            m, output_dir=output_dir, trace=trace_so_far
        ),
    }


def _task_record(
    *,
    task: TaskDef,
    started_at: str,
    completed_at: str,
    policy_decision: dict[str, Any],
    status: str,
    inputs: dict[str, Any],
    outputs: dict[str, Any],
    artifacts: list[dict[str, str]],
    errors: list[str],
    detail: str,
) -> dict[str, Any]:
    """Build a JSON-serializable per-task trace entry per the spec."""
    return {
        "task_id": task.task_id,
        "description": task.description,
        "action_category": task.action_category,
        "action_id": task.action_id,
        "depends_on": list(task.depends_on),
        "optional": task.optional,
        "policy_decision": policy_decision,
        "status": status,
        "started_at": started_at,
        "completed_at": completed_at,
        "inputs": inputs,
        "outputs": outputs,
        "artifacts": artifacts,
        "errors": errors,
        "detail": detail,
    }


def run_tracker_to_20x_workflow(
    *,
    repo_root: Path,
    input_path: Path,
    output_dir: Path,
    package_output: Path,
    config_dir: Path,
    schemas_dir: Path | None = None,
    mappings_dir: Path | None = None,
    workflow_name: str = "tracker-to-20x",
) -> int:
    """Execute the categorical tracker-to-20x task graph end to end.

    Each task runs its policy check first; if blocked, it is skipped and all
    downstream tasks are also marked ``skipped`` (the workflow halts on the
    first failure or blocked-non-optional task). The complete trace is written
    to ``output_dir/agent_run_trace.json`` and a markdown summary to
    ``output_dir/agent_run_summary.md``.

    Returns 0 on overall ``success``, 1 if any non-optional task failed or was
    blocked.
    """
    output_dir = output_dir.resolve()
    package_output = package_output.resolve()
    config_dir = config_dir.resolve()
    sch = (schemas_dir or repo_root / "schemas").resolve()
    mapd = (mappings_dir or repo_root / "mappings").resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    package_output.mkdir(parents=True, exist_ok=True)

    scenario_dir = output_dir / "scenario_from_tracker"

    workflow = get_workflow(workflow_name)

    memory = WorkflowMemory(workflow_name=workflow_name)
    for k, v in {
        "input_path": input_path,
        "output_dir": output_dir,
        "package_output": package_output,
        "config_dir": config_dir,
        "schemas_dir": sch,
        "mappings_dir": mapd,
        "scenario_dir": scenario_dir,
    }.items():
        memory.set_global(k, v)

    trace: dict[str, Any] = {
        "schema_version": "2.0",
        "workflow": workflow_name,
        "started_at": memory.started_at,
        "input_path": str(input_path),
        "output_dir": str(output_dir),
        "package_output": str(package_output),
        "config_dir": str(config_dir),
        "autonomous_categories_reference": autonomous_categories_reference(),
        "blocked_categories_reference": blocked_categories_reference(),
        "task_graph": [
            {
                "task_id": t.task_id,
                "description": t.description,
                "action_category": t.action_category,
                "action_id": t.action_id,
                "depends_on": list(t.depends_on),
                "optional": t.optional,
            }
            for t in workflow.topological_order()
        ],
        "tasks": [],
        "overall_status": "running",
    }

    dispatcher = _build_task_dispatcher(
        repo_root=repo_root,
        input_path=input_path,
        output_dir=output_dir,
        package_output=package_output,
        config_dir=config_dir,
        schemas_dir=sch,
        mappings_dir=mapd,
        scenario_dir=scenario_dir,
        trace_so_far=trace,
    )

    halted = False
    halted_by: str | None = None
    blocked_remaining = False

    for task in workflow.topological_order():
        # Policy gate.
        decision = classify_action(task.action_id)
        pol = policy_dict(decision)
        started = _now_iso()

        if halted or blocked_remaining:
            # Already past the failure boundary — every downstream task is "skipped".
            trace["tasks"].append(
                _task_record(
                    task=task,
                    started_at=started,
                    completed_at=_now_iso(),
                    policy_decision=pol,
                    status="skipped",
                    inputs={},
                    outputs={},
                    artifacts=[],
                    errors=[
                        f"upstream task {halted_by!r} failed; workflow halted"
                        if halted
                        else "blocked by policy upstream"
                    ],
                    detail="not executed due to upstream halt",
                )
            )
            continue

        if not decision.allowed:
            # Blocked task. Per the autonomy contract this requires human approval
            # and the workflow halts immediately.
            trace["tasks"].append(
                _task_record(
                    task=task,
                    started_at=started,
                    completed_at=_now_iso(),
                    policy_decision=pol,
                    status="blocked",
                    inputs={},
                    outputs={},
                    artifacts=[],
                    errors=[f"policy denied: {decision.reason}"],
                    detail="policy block — requires human approval",
                )
            )
            blocked_remaining = True
            halted_by = task.task_id
            continue

        # Execute.
        executor = dispatcher.get(task.task_id)
        if executor is None:
            trace["tasks"].append(
                _task_record(
                    task=task,
                    started_at=started,
                    completed_at=_now_iso(),
                    policy_decision=pol,
                    status="failed",
                    inputs={},
                    outputs={},
                    artifacts=[],
                    errors=[f"no executor registered for {task.task_id!r}"],
                    detail="implementation gap",
                )
            )
            halted = True
            halted_by = task.task_id
            continue

        try:
            res: actions.TaskActionResult = executor(memory)
        except Exception as e:  # noqa: BLE001 — surface a failed task with the precise exception.
            trace["tasks"].append(
                _task_record(
                    task=task,
                    started_at=started,
                    completed_at=_now_iso(),
                    policy_decision=pol,
                    status="failed",
                    inputs=memory.get_inputs(task.task_id),
                    outputs={},
                    artifacts=memory.get_artifacts(task.task_id),
                    errors=[f"unhandled exception: {e!r}"],
                    detail=str(e),
                )
            )
            halted = True
            halted_by = task.task_id
            continue

        completed = _now_iso()
        # Treat skipped optional tasks (e.g. agent_security when no telemetry) as success.
        if task.optional and res.outputs.get("skipped_reason"):
            status = "skipped"
        else:
            status = "success" if res.ok else "failed"

        trace["tasks"].append(
            _task_record(
                task=task,
                started_at=started,
                completed_at=completed,
                policy_decision=pol,
                status=status,
                inputs=memory.get_inputs(task.task_id) or res.inputs,
                outputs=memory.get_outputs(task.task_id) or res.outputs,
                artifacts=memory.get_artifacts(task.task_id),
                errors=list(res.errors),
                detail=res.detail,
            )
        )
        if status == "failed":
            halted = True
            halted_by = task.task_id

    trace["completed_at"] = _now_iso()
    trace["overall_status"] = (
        "success" if all(t["status"] in {"success", "skipped"} for t in trace["tasks"]) else "failed"
    )
    trace["halted_by"] = halted_by

    # Always write the trace + summary, even on failure (this is the explanation contract).
    trace_path = output_dir / "agent_run_trace.json"
    summary_path = output_dir / "agent_run_summary.md"
    trace_path.write_text(json.dumps(trace, indent=2, default=str), encoding="utf-8")

    # Re-render the summary at the very end so it includes the explain_summary task row
    # itself plus any halt-on-failure information added after the loop.
    summary_path.write_text(
        actions._render_summary_md(trace, memory), encoding="utf-8"
    )

    print(f"workflow {workflow_name}: {trace['overall_status']}")
    print(f"  trace:    {trace_path}")
    print(f"  summary:  {summary_path}")
    if halted_by:
        print(f"  halted_by: {halted_by}")
    return 0 if trace["overall_status"] == "success" else 1
