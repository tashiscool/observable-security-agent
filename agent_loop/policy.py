"""Autonomy policy for the bounded agent loop.

Two contracts are enforced here:

1. The **legacy single-action** contract used by the older
   ``run_bounded_agent_loop`` (assess + threat-hunt + reports). Every legacy
   action_id is listed in :data:`AUTONOMOUS_ACTION_IDS` and classified by
   :func:`classify_action`.

2. The **categorical autonomy contract** used by the new task-graph workflow
   runner. Every task in the graph carries an ``action_category`` from
   :data:`AUTONOMOUS_CATEGORIES`. Concrete action ids are classified by their
   prefix (``parse.*``, ``classify.*``, ``evaluate.*``, ``map.*``, ``package.*``,
   ``report.*``, ``reconcile.*``, ``validate.*``, ``explain.*``, ``normalize.*``).
   Anything that does NOT match an autonomous prefix is BLOCKED.

In both contracts the following remain **blocked until human approval**: cloud
modification, ticket creation in external systems, sending emails / external
notifications, deleting / modifying live resources.

Draft outputs (``*.draft``, ``draft_tickets_json_only``, ``draft_*``) are
explicitly allowed because they only produce local files for human review.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal


# ---------------------------------------------------------------------------
# Categorical contract (used by the new task-graph workflow)
# ---------------------------------------------------------------------------


# Autonomous categories the agent may execute on its own (local-only artifacts).
AUTONOMOUS_CATEGORIES: tuple[tuple[str, str], ...] = (
    ("parse", "Parse user-supplied input files (CSV/TSV/text/JSON) into typed records."),
    ("classify", "Classify records into typed buckets (gap types, severities, owners)."),
    ("normalize", "Normalize partial / empty evidence envelopes; never invent assets."),
    ("evaluate", "Run registered evaluations against loaded evidence and emit EvalResults."),
    ("map", "Map controls / evals to KSIs; map evidence into the package graph."),
    ("package", "Build the FedRAMP 20x package and POA&M items from typed records."),
    ("report", "Render assessor / executive / agency-AO / reconciliation markdown reports."),
    ("reconcile", "Run REC-001..REC-010 deterministic parity checks across machine + human views."),
    ("validate", "Validate output schemas + FAIL/PARTIAL narrative contract."),
    ("explain", "Write the agent_run_summary.md / agent_run_trace.json explanation files."),
)

AUTONOMOUS_CATEGORY_IDS: frozenset[str] = frozenset(c for c, _ in AUTONOMOUS_CATEGORIES)


# Action-id prefixes that the categorical contract permits. Each maps to its
# autonomous category. An action_id like ``parse.assessment_tracker`` is allowed
# because its prefix is in this map.
AUTONOMOUS_ACTION_PREFIXES: dict[str, str] = {
    "parse.": "parse",
    "classify.": "classify",
    "normalize.": "normalize",
    "evaluate.": "evaluate",
    "map.": "map",
    "package.": "package",
    "report.": "report",
    "reconcile.": "reconcile",
    "validate.": "validate",
    "explain.": "explain",
    # Draft outputs are local-only and explicitly allowed.
    "draft.": "draft",
}


# ---------------------------------------------------------------------------
# Legacy single-action contract (still used by run_bounded_agent_loop)
# ---------------------------------------------------------------------------


# Bounded actions the legacy loop may execute without external approval.
AUTONOMOUS_ACTION_IDS: frozenset[str] = frozenset(
    {
        "observe",
        "plan",
        "assess_run_evals",
        "threat_hunt_agentic",
        "normalize_findings",
        "evidence_graph_assess",
        "generate_reports_assess",
        "generate_instrumentation_recommendations",
        "generate_poam_drafts",
        "draft_tickets_json_only",
        "build_20x_package",
        "validate_assessment_outputs",
        "validate_20x_package",
        "reconcile_20x_reports",
        "write_agent_run_summary",
        "write_trace_json",
    }
)


# ---------------------------------------------------------------------------
# Blocked categories (apply to BOTH contracts)
# ---------------------------------------------------------------------------


BLOCKED_UNTIL_APPROVAL: tuple[tuple[str, str], ...] = (
    (
        "cloud_modification",
        "Apply, mutate, or revert resources via cloud-provider APIs (AWS/Azure/GCP).",
    ),
    (
        "permission_change",
        "Modify IAM / RBAC / policies in live directories or cloud accounts.",
    ),
    (
        "destructive_change",
        "Delete or overwrite production data; modify any non-local resource.",
    ),
    (
        "external_notification",
        "Send email, Slack, PagerDuty, SMS, webhooks, or any external alert.",
    ),
    (
        "real_ticket_create",
        "Create or update tickets in Jira / ServiceNow / GitHub / external systems.",
    ),
    (
        "email_send",
        "Compose or send any email (transactional or otherwise).",
    ),
)

# Action-id prefixes that are explicitly blocked. Used by classify_action() and
# also enumerated in agent_run_summary.md so reviewers see the contract.
BLOCKED_ACTION_PREFIXES: dict[str, str] = {
    "cloud_modification.": "cloud_modification",
    "cloud_remediation.": "cloud_modification",
    "permission_change.": "permission_change",
    "destructive_change.": "destructive_change",
    "external_notification.": "external_notification",
    "send_email.": "email_send",
    "email.": "email_send",
    "real_ticket_create.": "real_ticket_create",
    "ticket_create.": "real_ticket_create",
    "jira.create_": "real_ticket_create",
    "servicenow.create_": "real_ticket_create",
    "github.create_issue": "real_ticket_create",
    "delete.": "destructive_change",
    "modify_resource.": "destructive_change",
}


# ---------------------------------------------------------------------------
# Decision API
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class PolicyDecision:
    allowed: bool
    reason: str
    category: Literal[
        "autonomous", "blocked", "unknown", "draft", "agent_security"
    ]


def classify_action(action_id: str) -> PolicyDecision:
    """Classify an action for either the legacy or categorical contract.

    Resolution order:
    1. Empty → unknown / blocked.
    2. Explicit blocked prefix → blocked.
    3. Listed legacy autonomous id → autonomous.
    4. Categorical autonomous prefix → autonomous (or "draft").
    5. Otherwise fail-closed → unknown / blocked.
    """
    aid = (action_id or "").strip()
    if not aid:
        return PolicyDecision(False, "empty action id", "unknown")

    # 1) Explicit blocked prefixes take priority.
    for prefix, category in BLOCKED_ACTION_PREFIXES.items():
        if aid == prefix.rstrip(".") or aid.startswith(prefix):
            return PolicyDecision(False, f"blocked category: {category}", "blocked")

    # 2) Legacy single-action contract.
    if aid in AUTONOMOUS_ACTION_IDS:
        return PolicyDecision(
            True,
            "listed in AUTONOMOUS_ACTION_IDS (legacy bounded action)",
            "autonomous",
        )

    # 3) Categorical contract — match by prefix.
    for prefix, category in AUTONOMOUS_ACTION_PREFIXES.items():
        if aid.startswith(prefix):
            policy_category: Literal["autonomous", "draft"] = (
                "draft" if category == "draft" else "autonomous"
            )
            return PolicyDecision(
                True,
                f"matches autonomous category: {category}",
                policy_category,
            )

    return PolicyDecision(
        False,
        f"action {aid!r} is not in the autonomous contract (fail closed)",
        "unknown",
    )


def policy_dict(decision: PolicyDecision) -> dict[str, Any]:
    return {
        "allowed": decision.allowed,
        "reason": decision.reason,
        "category": decision.category,
    }


def blocked_categories_reference() -> list[dict[str, str]]:
    return [{"id": bid, "rationale": why} for bid, why in BLOCKED_UNTIL_APPROVAL]


def autonomous_categories_reference() -> list[dict[str, str]]:
    return [{"id": cid, "rationale": why} for cid, why in AUTONOMOUS_CATEGORIES]
