"""
Deterministic FedRAMP / NIST 800-53 control references for eval categories,
semantic event types, and asset-level evidence gaps.
"""

from __future__ import annotations

# --- Canonical control sets (fixed order; FedRAMP-oriented) ---

_INVENTORY_COMPLETENESS: tuple[str, ...] = ("CM-8", "CM-8(1)", "CM-8(3)")

_SCANNER_AND_VULN_SCANNING: tuple[str, ...] = (
    "RA-5",
    "RA-5(3)",
    "RA-5(5)",
    "RA-5(6)",
    "CA-7",
    "SI-2",
)

# RA-5(8) exploitation review — scoped to vulnerability/log controls; IR-4 is not rolled here so
# KSI-IR-01 is driven by incident/correlation evals rather than exploitation-review gaps alone.
_VULN_EXPLOITATION_REVIEW: tuple[str, ...] = ("RA-5(8)",)

_CENTRALIZED_AUDIT_LOGGING: tuple[str, ...] = (
    "AU-2",
    "AU-3",
    "AU-3(1)",
    "AU-6",
    "AU-6(1)",
    "AU-6(3)",
    "AU-7",
    "AU-8",
    "AU-12",
    "AU-9(2)",
    "SI-4",
)

_ALERT_INSTRUMENTATION: tuple[str, ...] = (
    "SI-4",
    "SI-4(1)",
    "SI-4(4)",
    "SI-4(16)",
    "AU-5",
    "AU-6",
    "AC-2(4)",
    "AC-2(7)",
    "CM-8(3)",
    "CM-10",
    "CM-11",
    "SI-3",
)

_CHANGE_LINKAGE: tuple[str, ...] = (
    "CM-3",
    "CM-4",
    "CM-5",
    "CM-6",
    "MA-2",
    "MA-3",
    "MA-4",
    "MA-5",
    "SI-2",
    "SA-10",
)

# CP-9/CP-10 tie CA-5 POA&M tracking to KSI-REC-01 when eval results roll up to recovery KSI.
_POAM: tuple[str, ...] = ("CA-5", "CA-7", "RA-5", "CP-9", "CP-10")

_BOUNDARY_NETWORK_FLOW: tuple[str, ...] = (
    "AC-4",
    "AC-17",
    "SC-7",
    "SC-7(3)",
    "SC-7(4)",
    "SC-7(5)",
    "CM-7",
)

_IDENTITY_ACCOUNT_MANAGEMENT: tuple[str, ...] = (
    "AC-2",
    "AC-2(1)",
    "AC-2(3)",
    "AC-2(4)",
    "AC-2(7)",
    "AC-3",
    "AC-5",
    "AC-6",
    "IA-2",
    "IA-4",
    "IA-5",
)

# Cross-domain event correlation (inventory, vuln scanning, logging, alerts, change, POA&M).
_EVENT_CORRELATION: tuple[str, ...] = (
    "CM-8",
    "RA-5",
    "AU-2",
    "AU-3",
    "AU-6",
    "AU-12",
    "SI-4",
    "CM-3",
    "CA-5",
    "SC-7",
    "AC-2",
    "IR-4",
    "SA-9",
)

# --- Eval engine identifiers -> category ---

_AGENT_TOOL_GOVERNANCE: tuple[str, ...] = ("AC-6", "CM-10", "CM-11", "SA-9")
_AGENT_PERMISSION_SCOPE: tuple[str, ...] = ("AC-2", "AC-3", "AC-6", "IA-5")
_AGENT_MEMORY_SAFETY: tuple[str, ...] = ("SC-28", "AC-4", "AU-9", "SI-12")
_AGENT_APPROVAL_GATES: tuple[str, ...] = ("CM-3", "CM-5", "CA-7", "SA-9")
_AGENT_POLICY_VIOLATIONS: tuple[str, ...] = ("IR-4", "SI-4", "AC-2", "AC-6")
_AGENT_AUDITABILITY: tuple[str, ...] = ("AU-2", "AU-3", "AU-6", "AU-9")

_EVAL_TYPE_CONTROLS: dict[str, tuple[str, ...]] = {
    "CM8_INVENTORY_RECONCILIATION": _INVENTORY_COMPLETENESS,
    "RA5_SCANNER_SCOPE_COVERAGE": _SCANNER_AND_VULN_SCANNING,
    "RA5_EXPLOITATION_REVIEW": _VULN_EXPLOITATION_REVIEW,
    "AU6_CENTRALIZED_LOG_COVERAGE": _CENTRALIZED_AUDIT_LOGGING,
    "SI4_ALERT_INSTRUMENTATION": _ALERT_INSTRUMENTATION,
    "CROSS_DOMAIN_EVENT_CORRELATION": _EVENT_CORRELATION,
    "CM3_CHANGE_EVIDENCE_LINKAGE": _CHANGE_LINKAGE,
    "AGENT_TOOL_GOVERNANCE": _AGENT_TOOL_GOVERNANCE,
    "AGENT_PERMISSION_SCOPE": _AGENT_PERMISSION_SCOPE,
    "AGENT_MEMORY_CONTEXT_SAFETY": _AGENT_MEMORY_SAFETY,
    "AGENT_APPROVAL_GATES": _AGENT_APPROVAL_GATES,
    "AGENT_POLICY_VIOLATIONS": _AGENT_POLICY_VIOLATIONS,
    "AGENT_AUDITABILITY": _AGENT_AUDITABILITY,
    "CA5_POAM_STATUS": _POAM,
}

# --- Semantic event types (canonical vocabulary) -> controls ---

_EVENT_SEMANTIC_CONTROLS: dict[str, tuple[str, ...]] = {
    "identity.user_created": _IDENTITY_ACCOUNT_MANAGEMENT,
    "identity.user_disabled": _IDENTITY_ACCOUNT_MANAGEMENT,
    "identity.admin_role_granted": _IDENTITY_ACCOUNT_MANAGEMENT,
    "identity.mfa_disabled": _IDENTITY_ACCOUNT_MANAGEMENT,
    "network.public_admin_port_opened": _BOUNDARY_NETWORK_FLOW,
    "network.public_database_port_opened": _BOUNDARY_NETWORK_FLOW,
    "network.public_sensitive_service_opened": _BOUNDARY_NETWORK_FLOW,
    "network.firewall_rule_changed": _BOUNDARY_NETWORK_FLOW + _CHANGE_LINKAGE,
    "logging.audit_disabled": _CENTRALIZED_AUDIT_LOGGING,
    "logging.central_ingestion_missing": _CENTRALIZED_AUDIT_LOGGING,
    "compute.untracked_asset_created": _INVENTORY_COMPLETENESS + ("CM-7",),
    "scanner.high_vulnerability_detected": _SCANNER_AND_VULN_SCANNING + ("RA-5(8)",),
    "scanner.asset_missing_from_scope": _SCANNER_AND_VULN_SCANNING,
    "change.no_ticket_linked": _CHANGE_LINKAGE,
    "incident.no_response_evidence": _VULN_EXPLOITATION_REVIEW,
    "unknown": (),
}

# --- Asset / evidence gap categories ---

_ASSET_GAP_CONTROLS: dict[str, tuple[str, ...]] = {
    "inventory_completeness": _INVENTORY_COMPLETENESS,
    "inventory": _INVENTORY_COMPLETENESS,
    "scanner_scope": _SCANNER_AND_VULN_SCANNING,
    "vulnerability_scanning": _SCANNER_AND_VULN_SCANNING,
    "exploitation_review": _VULN_EXPLOITATION_REVIEW,
    "centralized_audit_logging": _CENTRALIZED_AUDIT_LOGGING,
    "central_logging": _CENTRALIZED_AUDIT_LOGGING,
    "alert_instrumentation": _ALERT_INSTRUMENTATION,
    "change_linkage": _CHANGE_LINKAGE,
    "poam": _POAM,
    "boundary_network_flow": _BOUNDARY_NETWORK_FLOW,
    "network_flow": _BOUNDARY_NETWORK_FLOW,
    "identity_account_management": _IDENTITY_ACCOUNT_MANAGEMENT,
    "identity": _IDENTITY_ACCOUNT_MANAGEMENT,
}


def _dedupe_preserve_order(items: tuple[str, ...]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in items:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def get_controls_for_eval(eval_type: str) -> list[str]:
    """
    Map pipeline/eval identifier to NIST 800-53 style control references.

    ``eval_type`` is typically an eval_id such as ``CM8_INVENTORY_RECONCILIATION``.
    Unknown types return an empty list.
    """
    key = eval_type.strip()
    tpl = _EVAL_TYPE_CONTROLS.get(key)
    if tpl is None:
        return []
    return list(tpl)


def get_controls_for_event(semantic_type: str) -> list[str]:
    """
    Map canonical ``SecurityEvent.semantic_type`` to control references.

    Unknown or unmapped semantic types return an empty list.
    """
    key = semantic_type.strip()
    tpl = _EVENT_SEMANTIC_CONTROLS.get(key)
    if tpl is None:
        return []
    return _dedupe_preserve_order(tpl)


def get_controls_for_asset_gap(gap_type: str) -> list[str]:
    """
    Map asset/evidence gap category to control references.

    ``gap_type`` uses lowercase snake keys such as ``inventory_completeness``,
    ``scanner_scope``, ``central_logging``, etc. Unknown types return [].
    """
    key = gap_type.strip().lower().replace(" ", "_")
    tpl = _ASSET_GAP_CONTROLS.get(key)
    if tpl is None:
        return []
    return list(tpl)


def controls_for_eval(eval_id: str) -> list[str]:
    """Backward-compatible alias for :func:`get_controls_for_eval`."""
    return get_controls_for_eval(eval_id)


# Order matches :func:`core.evaluator.run_evaluations` (stable CLI / documentation order).
EVAL_IDS_IN_RUN_ORDER: tuple[str, ...] = (
    "CM8_INVENTORY_RECONCILIATION",
    "RA5_SCANNER_SCOPE_COVERAGE",
    "AU6_CENTRALIZED_LOG_COVERAGE",
    "SI4_ALERT_INSTRUMENTATION",
    "CROSS_DOMAIN_EVENT_CORRELATION",
    "RA5_EXPLOITATION_REVIEW",
    "CM3_CHANGE_EVIDENCE_LINKAGE",
    "AGENT_TOOL_GOVERNANCE",
    "AGENT_PERMISSION_SCOPE",
    "AGENT_MEMORY_CONTEXT_SAFETY",
    "AGENT_APPROVAL_GATES",
    "AGENT_POLICY_VIOLATIONS",
    "AGENT_AUDITABILITY",
    "CA5_POAM_STATUS",
)


def iter_eval_control_mappings() -> list[tuple[str, list[str]]]:
    """Each registered eval id with its mapped control reference strings."""
    return [(eid, get_controls_for_eval(eid)) for eid in EVAL_IDS_IN_RUN_ORDER]
