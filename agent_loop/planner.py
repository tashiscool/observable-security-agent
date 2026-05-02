"""Plan phase: choose evals (via assess), threat hunts, and artifacts for a bounded run."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from evals.agent_eval_support import load_agent_assessment_bundle


@dataclass
class Observation:
    """Snapshot from the Observe phase."""

    provider: str
    scenario: str
    scenario_root: Path
    output_dir: Path
    package_output: Path
    prior_artifacts: dict[str, bool] = field(default_factory=dict)
    agent_telemetry_present: bool = False
    evidence_file_count: int = 0


def gather_observation(
    *,
    provider: str,
    scenario: str,
    scenario_root: Path,
    output_dir: Path,
    package_output: Path,
) -> Observation:
    prior: dict[str, bool] = {}
    for name in (
        "eval_results.json",
        "evidence_graph.json",
        "agent_run_trace.json",
        "agent_eval_results.json",
    ):
        prior[name] = (output_dir / name).is_file()
    agent_ok = load_agent_assessment_bundle(scenario_root) is not None
    n_files = sum(1 for _ in scenario_root.rglob("*") if _.is_file())
    return Observation(
        provider=provider,
        scenario=scenario,
        scenario_root=scenario_root.resolve(),
        output_dir=output_dir.resolve(),
        package_output=package_output.resolve(),
        prior_artifacts=prior,
        agent_telemetry_present=agent_ok,
        evidence_file_count=n_files,
    )


@dataclass
class Plan:
    """Ordered autonomous actions (each checked against policy before execution)."""

    action_ids: list[str]
    rationale: str
    notes: dict[str, Any] = field(default_factory=dict)


def build_plan(obs: Observation) -> Plan:
    """
    Default playbook: full fixture assess (includes evals, graph, reports, instrumentation),
    optional agentic threat hunt, normalization + draft tickets, FedRAMP 20x package, verify, explain.
    """
    actions: list[str] = [
        "assess_run_evals",
    ]
    if obs.agent_telemetry_present:
        actions.append("threat_hunt_agentic")
    actions.extend(
        [
            "normalize_findings",
            "generate_instrumentation_recommendations",
            "generate_poam_drafts",
            "draft_tickets_json_only",
            "build_20x_package",
            "validate_assessment_outputs",
            "validate_20x_package",
            "reconcile_20x_reports",
        ]
    )
    notes: dict[str, Any] = {
        "eval_execution": "delegated to `agent.py assess` (all registered evals for bundle).",
        "graph_and_reports": "produced inside assess (evidence_graph.json, markdown reports).",
        "instrumentation": "instrumentation_plan.md and agent_instrumentation_plan.md from assess path.",
        "poam_drafts": "poam.csv includes generated rows; agent_poam.csv when agent path runs.",
        "tickets": "agent_draft_tickets.json only — no external systems.",
        "blocked_categories": "cloud_remediation, permission_change, destructive_change, external_notification, real_ticket_create",
    }
    rationale = (
        f"Fixture `{obs.scenario}` with agent_telemetry={obs.agent_telemetry_present}: "
        "run correlation evals + optional threat hunt, normalize outputs, emit draft ticket JSON, "
        "build and validate 20x package, reconcile, then summarize."
    )
    return Plan(action_ids=actions, rationale=rationale, notes=notes)
