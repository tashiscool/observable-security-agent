"""Tests for the tracker-to-20x agentic workflow.

Covers the categorical autonomy contract, the 15-task DAG, halt-on-failure,
policy decision logging, memory bookkeeping, and the end-to-end CLI wiring.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from agent_loop.actions import TaskActionResult, task_ingest_tracker
from agent_loop.memory import WorkflowMemory
from agent_loop.policy import (
    AUTONOMOUS_CATEGORY_IDS,
    BLOCKED_ACTION_PREFIXES,
    autonomous_categories_reference,
    blocked_categories_reference,
    classify_action,
)
from agent_loop.runner import run_tracker_to_20x_workflow
from agent_loop.task_graph import (
    TRACKER_TO_20X_TASKS,
    TRACKER_TO_20X_WORKFLOW,
    WORKFLOWS,
    get_workflow,
    required_action_categories,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_TRACKER = REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv"
CONFIG_DIR = REPO_ROOT / "config"


# ---------------------------------------------------------------------------
# Task graph: spec-mandated order and shape
# ---------------------------------------------------------------------------


EXPECTED_TASK_ORDER: tuple[str, ...] = (
    "ingest_tracker",
    "classify_rows",
    "normalize_evidence",
    "build_evidence_graph",
    "run_cloud_evals",
    "run_tracker_gap_evals",
    "run_agent_security_evals",
    "map_to_ksi",
    "generate_findings",
    "generate_poam",
    "build_package",
    "generate_reports",
    "reconcile",
    "validate_outputs",
    "explain_summary",
)


class TestTaskGraphShape:
    def test_workflow_registered(self) -> None:
        assert "tracker-to-20x" in WORKFLOWS
        assert get_workflow("tracker-to-20x").name == "tracker-to-20x"

    def test_unknown_workflow_raises(self) -> None:
        with pytest.raises(KeyError):
            get_workflow("nonexistent-workflow")

    def test_fifteen_tasks_in_spec_order(self) -> None:
        assert tuple(t.task_id for t in TRACKER_TO_20X_TASKS) == EXPECTED_TASK_ORDER
        assert len(TRACKER_TO_20X_TASKS) == 15

    def test_topological_order_is_stable_and_complete(self) -> None:
        order = TRACKER_TO_20X_WORKFLOW.topological_order()
        ids = [t.task_id for t in order]
        assert tuple(ids) == EXPECTED_TASK_ORDER
        # No cycles, no duplicates.
        assert len(set(ids)) == len(ids)

    def test_dependencies_resolve(self) -> None:
        for task in TRACKER_TO_20X_TASKS:
            for dep in task.depends_on:
                assert TRACKER_TO_20X_WORKFLOW.task_by_id(dep) is not None, (
                    f"task {task.task_id} depends on unknown {dep}"
                )

    def test_only_run_agent_security_is_optional(self) -> None:
        optionals = [t.task_id for t in TRACKER_TO_20X_TASKS if t.optional]
        assert optionals == ["run_agent_security_evals"]

    def test_action_categories_align_with_policy(self) -> None:
        cats = required_action_categories(TRACKER_TO_20X_WORKFLOW)
        # Every category the workflow needs must be in the policy allow-list.
        for c in cats:
            assert c in AUTONOMOUS_CATEGORY_IDS, c

    def test_downstream_of_ingest_includes_everything(self) -> None:
        downstream = {
            t.task_id for t in TRACKER_TO_20X_WORKFLOW.downstream_of("ingest_tracker")
        }
        # All other 14 tasks must transitively depend on ingest_tracker.
        expected = set(EXPECTED_TASK_ORDER) - {"ingest_tracker"}
        assert expected.issubset(downstream), expected - downstream


# ---------------------------------------------------------------------------
# Policy: categorical autonomy contract
# ---------------------------------------------------------------------------


class TestPolicy:
    def test_autonomous_categories_match_user_spec(self) -> None:
        ids = {c["id"] for c in autonomous_categories_reference()}
        # The user's spec required: parse, classify, evaluate, package, report, explain.
        for required in ("parse", "classify", "evaluate", "package", "report", "explain"):
            assert required in ids

    def test_blocked_categories_cover_user_spec(self) -> None:
        ids = {b["id"] for b in blocked_categories_reference()}
        # Spec: cloud modification, ticket creation in external systems, sending emails,
        # deleting/modifying resources.
        assert "cloud_modification" in ids
        assert "real_ticket_create" in ids
        assert "email_send" in ids or "external_notification" in ids
        assert "destructive_change" in ids or "permission_change" in ids

    def test_parse_classify_evaluate_actions_are_allowed(self) -> None:
        for action_id in (
            "parse.assessment_tracker",
            "classify.tracker_rows_to_evidence_gaps",
            "normalize.scenario_evidence_envelopes",
            "evaluate.run_cloud_control_evals",
            "evaluate.tracker_evidence_gap_analysis",
            "map.controls_evals_to_ksis",
            "package.build_fedramp20x_package",
            "report.generate_20x_reports",
            "reconcile.deep_reconciliation",
            "validate.package_schema_and_narrative_contract",
            "explain.write_agent_run_summary",
        ):
            d = classify_action(action_id)
            assert d.allowed, f"expected {action_id} ALLOWED, got {d}"
            assert d.category == "autonomous"

    def test_blocked_actions_are_denied(self) -> None:
        for blocked in (
            "cloud_modification.update_security_group",
            "cloud_remediation.disable_user",
            "real_ticket_create.jira_issue",
            "ticket_create.servicenow",
            "send_email.notify_assessor",
            "email.send_summary",
            "delete.s3_bucket",
            "modify_resource.iam_policy",
            "permission_change.add_admin",
            "destructive_change.terminate_instance",
            "external_notification.slack",
        ):
            d = classify_action(blocked)
            assert not d.allowed, f"expected {blocked} BLOCKED, got {d}"
            assert d.category == "blocked"

    def test_unknown_action_fails_closed(self) -> None:
        d = classify_action("totally.unknown.action")
        assert not d.allowed
        assert d.category == "unknown"

    def test_empty_action_fails_closed(self) -> None:
        d = classify_action("")
        assert not d.allowed
        assert d.category == "unknown"

    def test_legacy_action_ids_still_work(self) -> None:
        d = classify_action("assess_run_evals")
        assert d.allowed and d.category == "autonomous"
        d = classify_action("write_agent_run_summary")
        assert d.allowed and d.category == "autonomous"

    def test_blocked_prefixes_table_nonempty(self) -> None:
        assert "cloud_modification." in BLOCKED_ACTION_PREFIXES
        assert "send_email." in BLOCKED_ACTION_PREFIXES


# ---------------------------------------------------------------------------
# Memory
# ---------------------------------------------------------------------------


class TestMemory:
    def test_record_and_get_roundtrip(self) -> None:
        m = WorkflowMemory(workflow_name="tracker-to-20x")
        m.set_global("output_dir", Path("/tmp/x"))
        m.record_inputs("ingest_tracker", {"input_path": Path("/tmp/in.csv")})
        m.record_outputs("ingest_tracker", {"row_count": 10})
        m.record_artifact("ingest_tracker", "evidence_gaps.json", Path("/tmp/x/evidence_gaps.json"))
        assert m.get_inputs("ingest_tracker")["input_path"] == "/tmp/in.csv"
        assert m.get_outputs("ingest_tracker")["row_count"] == 10
        assert m.get_artifacts("ingest_tracker") == [
            {"name": "evidence_gaps.json", "path": "/tmp/x/evidence_gaps.json"}
        ]

    def test_to_dict_is_json_safe(self) -> None:
        m = WorkflowMemory(workflow_name="tracker-to-20x")
        m.set_global("p", Path("/tmp"))
        m.record_outputs("t", {"path": Path("/tmp/a"), "items": [Path("/tmp/b")]})
        # Round-trip via JSON to prove no Path leaks.
        round_trip = json.loads(json.dumps(m.to_dict()))
        assert round_trip["globals"]["p"] == "/tmp"
        assert round_trip["per_task"]["t"]["outputs"]["items"] == ["/tmp/b"]


# ---------------------------------------------------------------------------
# Single-task action: ingest_tracker
# ---------------------------------------------------------------------------


class TestIngestTrackerAction:
    def test_ingest_real_sample_succeeds(self, tmp_path: Path) -> None:
        m = WorkflowMemory(workflow_name="tracker-to-20x")
        scen = tmp_path / "scen"
        res = task_ingest_tracker(m, input_path=SAMPLE_TRACKER, scenario_dir=scen)
        assert isinstance(res, TaskActionResult)
        assert res.ok
        assert res.outputs["row_count"] == 16
        assert (scen / "evidence_gaps.json").is_file()
        # Memory was recorded.
        assert m.get_inputs("ingest_tracker")["input_path"] == str(SAMPLE_TRACKER)
        assert m.get_outputs("ingest_tracker")["row_count"] == 16
        assert any(
            a["name"] == "evidence_gaps.json" for a in m.get_artifacts("ingest_tracker")
        )

    def test_ingest_missing_input_fails_cleanly(self, tmp_path: Path) -> None:
        m = WorkflowMemory(workflow_name="tracker-to-20x")
        res = task_ingest_tracker(
            m, input_path=tmp_path / "nope.csv", scenario_dir=tmp_path / "scen"
        )
        assert not res.ok
        assert res.errors and "input not found" in res.errors[0]


# ---------------------------------------------------------------------------
# Full workflow run (in-process, NOT subprocess) — covers all 15 tasks
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def workflow_run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    base = tmp_path_factory.mktemp("agent_workflow_inproc")
    out_dir = base / "agent_run"
    pkg_out = out_dir / "package_tracker"
    rc = run_tracker_to_20x_workflow(
        repo_root=REPO_ROOT,
        input_path=SAMPLE_TRACKER,
        output_dir=out_dir,
        package_output=pkg_out,
        config_dir=CONFIG_DIR,
    )
    trace = json.loads((out_dir / "agent_run_trace.json").read_text(encoding="utf-8"))
    return {"rc": rc, "out_dir": out_dir, "pkg_out": pkg_out, "trace": trace}


class TestWorkflowSuccess:
    def test_overall_success(self, workflow_run: dict[str, Path]) -> None:
        assert workflow_run["rc"] == 0
        assert workflow_run["trace"]["overall_status"] == "success"
        assert workflow_run["trace"]["halted_by"] is None

    def test_trace_has_all_fifteen_task_records_in_order(
        self, workflow_run: dict[str, Path]
    ) -> None:
        ids = [t["task_id"] for t in workflow_run["trace"]["tasks"]]
        assert tuple(ids) == EXPECTED_TASK_ORDER

    def test_each_task_has_required_fields(self, workflow_run: dict[str, Path]) -> None:
        required = (
            "task_id",
            "inputs",
            "outputs",
            "policy_decision",
            "status",
            "started_at",
            "completed_at",
            "errors",
            "artifacts",
        )
        for t in workflow_run["trace"]["tasks"]:
            for f in required:
                assert f in t, f"task {t.get('task_id')} missing field {f!r}"
            # Policy decision shape.
            pd = t["policy_decision"]
            assert "allowed" in pd and "reason" in pd and "category" in pd
            # Timestamps are strings.
            assert isinstance(t["started_at"], str)
            assert isinstance(t["completed_at"], str)

    def test_each_task_status_is_success_or_skipped(
        self, workflow_run: dict[str, Path]
    ) -> None:
        for t in workflow_run["trace"]["tasks"]:
            assert t["status"] in {"success", "skipped"}, (
                f"task {t['task_id']} status={t['status']} errors={t.get('errors')}"
            )

    def test_optional_agent_security_skipped_when_no_telemetry(
        self, workflow_run: dict[str, Path]
    ) -> None:
        agent_task = next(
            t
            for t in workflow_run["trace"]["tasks"]
            if t["task_id"] == "run_agent_security_evals"
        )
        assert agent_task["status"] == "skipped"
        assert "skipped_reason" in agent_task["outputs"]

    def test_policy_decisions_logged_and_autonomous(
        self, workflow_run: dict[str, Path]
    ) -> None:
        for t in workflow_run["trace"]["tasks"]:
            assert t["policy_decision"]["allowed"] is True
            assert t["policy_decision"]["category"] == "autonomous"

    def test_required_artifacts_exist_on_disk(
        self, workflow_run: dict[str, Path]
    ) -> None:
        out = workflow_run["out_dir"]
        pkg = workflow_run["pkg_out"]
        for name in (
            "agent_run_trace.json",
            "agent_run_summary.md",
            "tracker_gap_report.md",
            "tracker_gap_matrix.csv",
            "tracker_gap_eval_results.json",
            "tracker_poam.csv",
            "eval_results.json",
            "evidence_graph.json",
            "auditor_questions.md",
            "instrumentation_plan.md",
            "poam.csv",
            "preview_findings.json",
            "preview_poam_summary.json",
        ):
            assert (out / name).is_file(), f"missing {name} under {out}"
        for rel in (
            "fedramp20x-package.json",
            "evidence/validation-results/ksi-results.json",
            "evidence/validation-results/findings.json",
            "evidence/validation-results/poam-items.json",
            "evidence/validation-results/reconciliation.json",
            "reports/assessor/assessor-summary.md",
            "reports/assessor/ksi-by-ksi-assessment.md",
            "reports/executive/executive-summary.md",
            "reports/agency-ao/ao-risk-brief.md",
            "reports/reconciliation_report.md",
        ):
            assert (pkg / rel).is_file(), f"missing {rel} under {pkg}"

    def test_artifacts_recorded_per_task(self, workflow_run: dict[str, Path]) -> None:
        # Every NON-skipped task must have at least one recorded artifact OR
        # explicit empty list (e.g. evaluation-only tasks like build_evidence_graph).
        produced_artifacts: set[str] = set()
        for t in workflow_run["trace"]["tasks"]:
            for a in t["artifacts"]:
                produced_artifacts.add(a["name"])
        # The signature artifacts must be tied back to specific tasks.
        expected_some = {
            "evidence_gaps.json",
            "eval_results.json",
            "tracker_gap_report.md",
            "fedramp20x-package.json",
            "agent_run_summary.md",
        }
        assert expected_some.issubset(produced_artifacts), (
            expected_some - produced_artifacts
        )

    def test_summary_md_rendered(self, workflow_run: dict[str, Path]) -> None:
        text = (workflow_run["out_dir"] / "agent_run_summary.md").read_text(encoding="utf-8")
        assert "Agent run summary" in text
        for tid in EXPECTED_TASK_ORDER:
            assert tid in text, f"summary missing task id {tid!r}"
        assert "Autonomy contract" in text
        assert "Blocked actions" in text


# ---------------------------------------------------------------------------
# Halt-on-failure: missing input file
# ---------------------------------------------------------------------------


class TestWorkflowHaltsOnFailure:
    def test_missing_input_halts_at_ingest_and_skips_downstream(
        self, tmp_path: Path
    ) -> None:
        out_dir = tmp_path / "agent_run"
        rc = run_tracker_to_20x_workflow(
            repo_root=REPO_ROOT,
            input_path=tmp_path / "does_not_exist.csv",
            output_dir=out_dir,
            package_output=out_dir / "pkg",
            config_dir=CONFIG_DIR,
        )
        assert rc == 1
        trace = json.loads((out_dir / "agent_run_trace.json").read_text(encoding="utf-8"))
        assert trace["overall_status"] == "failed"
        assert trace["halted_by"] == "ingest_tracker"
        statuses = {t["task_id"]: t["status"] for t in trace["tasks"]}
        assert statuses["ingest_tracker"] == "failed"
        # All downstream tasks (everything after ingest) must be skipped.
        for tid in EXPECTED_TASK_ORDER[1:]:
            assert statuses[tid] == "skipped", (
                f"expected {tid} to be skipped, got {statuses[tid]}"
            )
        # Failed task must have a clear error message.
        ingest = next(t for t in trace["tasks"] if t["task_id"] == "ingest_tracker")
        assert ingest["errors"]
        assert any("input not found" in e for e in ingest["errors"])
        # Summary file must be written even when the workflow fails.
        assert (out_dir / "agent_run_summary.md").is_file()


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestRunAgentCli:
    def test_cli_run_agent_workflow_tracker_to_20x(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "cli_agent_run"
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "agent.py"),
                "run-agent",
                "--workflow",
                "tracker-to-20x",
                "--input",
                str(SAMPLE_TRACKER),
                "--output-dir",
                str(out_dir),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"run-agent exited {result.returncode}\n"
            f"stdout=\n{result.stdout}\n"
            f"stderr=\n{result.stderr}"
        )
        # Trace + summary always exist.
        trace_path = out_dir / "agent_run_trace.json"
        summary_path = out_dir / "agent_run_summary.md"
        assert trace_path.is_file()
        assert summary_path.is_file()
        trace = json.loads(trace_path.read_text(encoding="utf-8"))
        assert trace["overall_status"] == "success"
        assert len(trace["tasks"]) == 15
        # Default package output is <output-dir>/package_tracker.
        assert (out_dir / "package_tracker" / "fedramp20x-package.json").is_file()

    def test_cli_workflow_requires_input(self, tmp_path: Path) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "agent.py"),
                "run-agent",
                "--workflow",
                "tracker-to-20x",
                "--output-dir",
                str(tmp_path / "x"),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert "requires --input" in (result.stderr or "")
