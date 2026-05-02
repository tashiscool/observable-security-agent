"""Task graph for the bounded autonomous tracker-to-20x workflow.

Every task carries:

* a ``task_id``
* a human-readable ``description``
* an ``action_category`` (parse | classify | normalize | evaluate | map | package |
  report | reconcile | validate | explain) — used by :mod:`agent_loop.policy` to
  classify the task as autonomous-allowed
* an ``action_id`` (concrete autonomous action handle inside :mod:`agent_loop.actions`)
* explicit ``depends_on`` task ids (DAG edges)
* an ``optional`` flag (when True a ``skipped`` status is allowed without halting
  the workflow — used for the agent-security branch which only runs when agent
  telemetry is present in the imported scenario)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Literal


# Categories the policy module knows how to classify. Each maps to multiple
# concrete action_ids. Mirrors the user-facing autonomy contract.
ActionCategory = Literal[
    "parse",
    "classify",
    "normalize",
    "evaluate",
    "map",
    "package",
    "report",
    "reconcile",
    "validate",
    "explain",
]


@dataclass(frozen=True)
class TaskDef:
    """Static definition of a single task in the workflow."""

    task_id: str
    description: str
    action_category: ActionCategory
    action_id: str
    depends_on: tuple[str, ...] = field(default_factory=tuple)
    optional: bool = False


# ---------------------------------------------------------------------------
# tracker-to-20x workflow (15 tasks, in the order required by the spec)
# ---------------------------------------------------------------------------


TRACKER_TO_20X_TASKS: tuple[TaskDef, ...] = (
    TaskDef(
        task_id="ingest_tracker",
        description="Parse the FedRAMP assessment tracker file (CSV/TSV/text) into structured rows.",
        action_category="parse",
        action_id="parse.assessment_tracker",
        depends_on=(),
    ),
    TaskDef(
        task_id="classify_rows",
        description="Classify each tracker row into a GapType + recommended artifact / KSI.",
        action_category="classify",
        action_id="classify.tracker_rows_to_evidence_gaps",
        depends_on=("ingest_tracker",),
    ),
    TaskDef(
        task_id="normalize_evidence",
        description="Normalize partial/empty evidence files (no invented assets) so downstream loaders accept them.",
        action_category="normalize",
        action_id="normalize.scenario_evidence_envelopes",
        depends_on=("classify_rows",),
    ),
    TaskDef(
        task_id="build_evidence_graph",
        description="Build the evidence graph (root event + nodes + edges) for the imported scenario.",
        action_category="evaluate",
        action_id="evaluate.build_evidence_graph",
        depends_on=("normalize_evidence",),
    ),
    TaskDef(
        task_id="run_cloud_evals",
        description="Run the registered cloud-control evaluations (CM-8, RA-5, AU-6, SI-4, etc.).",
        action_category="evaluate",
        action_id="evaluate.run_cloud_control_evals",
        depends_on=("build_evidence_graph",),
    ),
    TaskDef(
        task_id="run_tracker_gap_evals",
        description="Run TRACKER_EVIDENCE_GAP_ANALYSIS over the structured evidence-gap records.",
        action_category="evaluate",
        action_id="evaluate.tracker_evidence_gap_analysis",
        depends_on=("classify_rows",),
    ),
    TaskDef(
        task_id="run_agent_security_evals",
        description="Run agent-security evaluations IF agent telemetry exists in the scenario.",
        action_category="evaluate",
        action_id="evaluate.agent_security_evals",
        depends_on=("run_cloud_evals",),
        optional=True,
    ),
    TaskDef(
        task_id="map_to_ksi",
        description="Fold the tracker eval into eval_results.json so the KSI rollup picks it up.",
        action_category="map",
        action_id="map.controls_evals_to_ksis",
        depends_on=("run_cloud_evals", "run_tracker_gap_evals"),
    ),
    TaskDef(
        task_id="generate_findings",
        description="Build the canonical findings list (one finding per FAIL/PARTIAL eval row).",
        action_category="evaluate",
        action_id="evaluate.generate_findings",
        depends_on=("map_to_ksi",),
    ),
    TaskDef(
        task_id="generate_poam",
        description="Generate POA&M items (assess + tracker-derived) and the tracker_poam.csv artifact.",
        action_category="package",
        action_id="package.generate_poam_drafts",
        depends_on=("generate_findings",),
    ),
    TaskDef(
        task_id="build_package",
        description="Build the FedRAMP 20x package (KSIs, findings, POA&M, evidence links, reconciliation).",
        action_category="package",
        action_id="package.build_fedramp20x_package",
        depends_on=("generate_poam",),
    ),
    TaskDef(
        task_id="generate_reports",
        description="Generate assessor / executive / agency-AO / reconciliation markdown reports.",
        action_category="report",
        action_id="report.generate_20x_reports",
        depends_on=("build_package",),
    ),
    TaskDef(
        task_id="reconcile",
        description="Run REC-001..REC-010 reconciliation across machine + human report views.",
        action_category="reconcile",
        action_id="reconcile.deep_reconciliation",
        depends_on=("generate_reports",),
    ),
    TaskDef(
        task_id="validate_outputs",
        description="Validate package schema + FAIL/PARTIAL narrative contract on eval_results.json.",
        action_category="validate",
        action_id="validate.package_schema_and_narrative_contract",
        depends_on=("reconcile",),
    ),
    TaskDef(
        task_id="explain_summary",
        description="Write agent_run_summary.md explaining tasks, policy decisions, and outcomes.",
        action_category="explain",
        action_id="explain.write_agent_run_summary",
        depends_on=("validate_outputs",),
    ),
)


# ---------------------------------------------------------------------------
# DAG operations
# ---------------------------------------------------------------------------


@dataclass
class TaskGraph:
    """A named, ordered DAG of :class:`TaskDef`."""

    name: str
    tasks: tuple[TaskDef, ...]

    def task_by_id(self, task_id: str) -> TaskDef | None:
        for t in self.tasks:
            if t.task_id == task_id:
                return t
        return None

    def topological_order(self) -> list[TaskDef]:
        """Return the tasks in a stable topological order.

        The graph is small (~15 nodes) and human-authored to already be in
        topological order; this helper formally validates that and returns the
        same list. Cycles raise ``ValueError``.
        """
        visited: dict[str, bool] = {}
        out: list[TaskDef] = []

        def visit(t: TaskDef, path: tuple[str, ...]) -> None:
            if t.task_id in path:
                raise ValueError(
                    f"Cycle detected in task graph at {t.task_id!r} via {' -> '.join(path)}"
                )
            if visited.get(t.task_id):
                return
            visited[t.task_id] = True
            for dep_id in t.depends_on:
                dep = self.task_by_id(dep_id)
                if dep is None:
                    raise ValueError(f"Unknown dependency {dep_id!r} from task {t.task_id!r}")
                visit(dep, path + (t.task_id,))
            out.append(t)

        for t in self.tasks:
            visit(t, ())
        return out

    def downstream_of(self, task_id: str) -> list[TaskDef]:
        """Return all tasks that transitively depend on ``task_id`` (excluding itself)."""
        result: list[TaskDef] = []
        seen: set[str] = set()

        def collect(parent_id: str) -> None:
            for t in self.tasks:
                if parent_id in t.depends_on and t.task_id not in seen:
                    seen.add(t.task_id)
                    result.append(t)
                    collect(t.task_id)

        collect(task_id)
        return result

    def task_ids(self) -> list[str]:
        return [t.task_id for t in self.tasks]


TRACKER_TO_20X_WORKFLOW: TaskGraph = TaskGraph(
    name="tracker-to-20x", tasks=TRACKER_TO_20X_TASKS
)


WORKFLOWS: dict[str, TaskGraph] = {
    "tracker-to-20x": TRACKER_TO_20X_WORKFLOW,
}


def get_workflow(name: str) -> TaskGraph:
    if name not in WORKFLOWS:
        raise KeyError(
            f"Unknown workflow {name!r}. Known workflows: {sorted(WORKFLOWS)}"
        )
    return WORKFLOWS[name]


def required_action_categories(graph: Iterable[TaskDef] | TaskGraph) -> list[str]:
    """Return the distinct action_categories a graph needs (used by policy reports)."""
    if isinstance(graph, TaskGraph):
        tasks = graph.tasks
    else:
        tasks = tuple(graph)
    seen: list[str] = []
    for t in tasks:
        if t.action_category not in seen:
            seen.append(t.action_category)
    return seen
