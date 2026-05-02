"""TRACKER_EVIDENCE_GAP_ANALYSIS — eval that operates directly on EvidenceGap records.

Reads the schema-2.0 ``evidence_gaps.json`` envelope produced by
``core.evidence_gap.write_evidence_gaps_file`` (which itself comes from the assessment
tracker importer) and produces a single canonical :class:`core.models.EvalResult` plus a
group breakdown by control family / functional area.

Result rules:

* ``FAIL`` — at least one open evidence gap has severity ``high`` or ``critical``.
* ``PARTIAL`` — open gaps exist but only at ``moderate`` / ``low`` severity (or only
  ``unknown`` gap_type).
* ``PASS`` — no open evidence gaps remain (all rows became
  :class:`core.models.InformationalTrackerItem`).

Each group surfaces:

* controls_impacted — the union of NIST 800-53 control IDs cited by gaps in the group,
* count_open_gaps,
* max_severity (within the group),
* tracker_rows — the ``source_item_id`` values of contributing rows,
* recommended_closure_artifacts — the union of ``recommended_artifact`` values,
* linked_ksi_ids,
* poam_required — true if any gap in the group requires POA&M,
* gap_types — the distinct gap_type values present in the group.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from core.models import EvalResult, GapSeverity, GapType


__all__ = [
    "EVAL_ID",
    "EVAL_NAME",
    "CONTROL_REFS",
    "TRACKER_GROUPS",
    "GROUP_LABELS",
    "GAP_TYPE_TO_GROUP",
    "GroupSummary",
    "TrackerGapEvalResult",
    "run_tracker_evidence_gap_eval",
]


EVAL_ID = "TRACKER_EVIDENCE_GAP_ANALYSIS"
EVAL_NAME = "Tracker Evidence Gap Analysis"

# Controls referenced by the eval as a whole (used by KSI mapping and reports).
CONTROL_REFS: list[str] = [
    "CM-8",
    "CM-3",
    "CM-10",
    "CM-11",
    "RA-5",
    "RA-5(3)",
    "RA-5(5)",
    "RA-5(8)",
    "AU-2",
    "AU-3",
    "AU-6",
    "AU-12",
    "SI-4",
    "SI-2",
    "CA-5",
    "CA-7",
    "IR-4",
    "IR-6",
    "CP-9",
    "CP-10",
    "AC-2",
    "AC-2(7)",
    "AC-6",
    "IA-5",
    "SC-7",
    "SC-7(11)",
    "SC-12",
    "SC-13",
    "SC-28",
]

# ---------------------------------------------------------------------------
# Group definitions
# ---------------------------------------------------------------------------

TRACKER_GROUPS: tuple[str, ...] = (
    "inventory",
    "scanner_vulnerability",
    "logging",
    "alerting",
    "change_management",
    "incident_response",
    "poam",
    "recovery",
    "identity_access",
    "crypto",
    "network_boundary",
)

GROUP_LABELS: Mapping[str, str] = {
    "inventory": "Inventory reconciliation (CM-8 family)",
    "scanner_vulnerability": "Scanner scope and vulnerability evidence (RA-5 family)",
    "logging": "Centralized logging and local-to-central correlation (AU family)",
    "alerting": "Alert rules, samples, and response actions (SI-4 / IR family)",
    "change_management": "Change evidence chain — SIA, testing, approval, deploy, verify (CM family)",
    "incident_response": "Incident response evidence and US-CERT/CISA notifications (IR family)",
    "poam": "POA&M updates and deviation requests (CA-5)",
    "recovery": "Backup execution and restore-test evidence (CP-9 / CP-10)",
    "identity_access": "Identity listings, MFA, access reviews, password policy (AC / IA)",
    "crypto": "FIPS-140 cryptography and key/cipher evidence (SC-12 / SC-13 / SC-28)",
    "network_boundary": "Traffic flow / boundary / security group evidence (SC-7)",
}

# Which gap_type belongs to which group. Every spec'd GapType value is mapped here.
GAP_TYPE_TO_GROUP: Mapping[GapType, str] = {
    "inventory_mismatch": "inventory",
    "scanner_scope_missing": "scanner_vulnerability",
    "vulnerability_scan_evidence_missing": "scanner_vulnerability",
    "credentialed_scan_evidence_missing": "scanner_vulnerability",
    "exploitation_review_missing": "scanner_vulnerability",
    "centralized_log_missing": "logging",
    "local_to_central_log_correlation_missing": "logging",
    "alert_rule_missing": "alerting",
    "alert_sample_missing": "alerting",
    "response_action_missing": "alerting",
    "change_ticket_missing": "change_management",
    "sia_missing": "change_management",
    "testing_evidence_missing": "change_management",
    "approval_missing": "change_management",
    "deployment_evidence_missing": "change_management",
    "verification_evidence_missing": "change_management",
    # NB: incident_response is also addressed via response_action_missing; the eval
    # surfaces both functional groupings via _AUX_INCIDENT_TYPES below.
    "poam_update_missing": "poam",
    "deviation_request_missing": "poam",
    "backup_evidence_missing": "recovery",
    "restore_test_missing": "recovery",
    "identity_listing_missing": "identity_access",
    "password_policy_evidence_missing": "identity_access",
    "crypto_fips_evidence_missing": "crypto",
    "traffic_flow_policy_missing": "network_boundary",
    "unknown": "inventory",  # surfaced under inventory; assessor must triage
}

# Some gap types belong to MORE than one functional group for reporting purposes
# (e.g. "response_action_missing" should appear under both alerting AND incident_response).
# Listed here as (gap_type, additional_group_to_also_report_under).
_AUXILIARY_GROUPS: tuple[tuple[GapType, str], ...] = (
    ("response_action_missing", "incident_response"),
)


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------

_SEVERITY_RANK: Mapping[GapSeverity, int] = {
    "low": 1,
    "moderate": 2,
    "high": 3,
    "critical": 4,
}

_HIGH_IMPACT_SEVERITIES: frozenset[GapSeverity] = frozenset({"high", "critical"})


def _max_severity(values: Iterable[GapSeverity]) -> GapSeverity:
    best: GapSeverity = "low"
    best_rank = 0
    for v in values:
        r = _SEVERITY_RANK.get(v, 0)
        if r > best_rank:
            best_rank = r
            best = v
    return best


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclass
class GroupSummary:
    """One per functional group (inventory, logging, ...)."""

    group: str
    label: str
    controls_impacted: list[str] = field(default_factory=list)
    count_open_gaps: int = 0
    max_severity: GapSeverity = "low"
    tracker_rows: list[str] = field(default_factory=list)
    recommended_closure_artifacts: list[str] = field(default_factory=list)
    linked_ksi_ids: list[str] = field(default_factory=list)
    poam_required: bool = False
    gap_types: list[GapType] = field(default_factory=list)
    gap_ids: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "label": self.label,
            "controls_impacted": self.controls_impacted,
            "count_open_gaps": self.count_open_gaps,
            "max_severity": self.max_severity,
            "tracker_rows": self.tracker_rows,
            "recommended_closure_artifacts": self.recommended_closure_artifacts,
            "linked_ksi_ids": self.linked_ksi_ids,
            "poam_required": self.poam_required,
            "gap_types": self.gap_types,
            "gap_ids": self.gap_ids,
        }


@dataclass
class TrackerGapEvalResult:
    """Eval output: canonical EvalResult + per-group breakdown."""

    eval_result: EvalResult
    groups: list[GroupSummary]
    total_open_gaps: int
    high_impact_count: int
    poam_required_count: int
    informational_count: int
    source_envelope: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "eval_id": EVAL_ID,
            "eval_name": EVAL_NAME,
            "result": self.eval_result.result,
            "severity": self.eval_result.severity,
            "summary": self.eval_result.summary,
            "totals": {
                "open_gaps": self.total_open_gaps,
                "high_impact_gaps": self.high_impact_count,
                "poam_required_gaps": self.poam_required_count,
                "informational_items": self.informational_count,
            },
            "groups": [g.to_dict() for g in self.groups],
            "eval_result": self.eval_result.model_dump(),
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _add_unique(seq: list[str], value: str | None) -> None:
    if value and value not in seq:
        seq.append(value)


def _normalize_gap_dict(gap: Mapping[str, Any]) -> dict[str, Any]:
    """Coerce missing fields to defaults so the eval is robust against partial input."""
    return {
        "gap_id": str(gap.get("gap_id") or ""),
        "source_item_id": str(gap.get("source_item_id") or ""),
        "controls": list(gap.get("controls") or []),
        "gap_type": str(gap.get("gap_type") or "unknown"),
        "severity": str(gap.get("severity") or "moderate"),
        "linked_ksi_ids": list(gap.get("linked_ksi_ids") or []),
        "recommended_artifact": gap.get("recommended_artifact"),
        "recommended_validation": gap.get("recommended_validation"),
        "poam_required": bool(gap.get("poam_required") or False),
        "title": gap.get("title") or "",
        "description": gap.get("description") or "",
        "owner": gap.get("owner"),
        "status": gap.get("status"),
        "due_date": gap.get("due_date"),
    }


def _groups_for_gap_type(gap_type: str) -> list[str]:
    primary = GAP_TYPE_TO_GROUP.get(gap_type, "inventory")  # type: ignore[arg-type]
    extras = [g for gt, g in _AUXILIARY_GROUPS if gt == gap_type]
    return [primary] + extras


# ---------------------------------------------------------------------------
# Eval entry point
# ---------------------------------------------------------------------------


def run_tracker_evidence_gap_eval(
    *,
    evidence_gaps_envelope: Mapping[str, Any],
) -> TrackerGapEvalResult:
    """Run the eval against a schema-2.0 ``evidence_gaps.json`` envelope.

    ``evidence_gaps_envelope`` must contain ``evidence_gaps`` (list) and may also
    contain ``informational_tracker_items`` (list); both come from
    ``core.evidence_gap.write_evidence_gaps_file``.
    """
    raw_gaps = list(evidence_gaps_envelope.get("evidence_gaps") or evidence_gaps_envelope.get("gaps") or [])
    informational = list(evidence_gaps_envelope.get("informational_tracker_items") or [])

    # Initialize groups in canonical order.
    groups: dict[str, GroupSummary] = {
        g: GroupSummary(group=g, label=GROUP_LABELS[g]) for g in TRACKER_GROUPS
    }

    high_impact_count = 0
    poam_required_count = 0
    severities_seen: list[GapSeverity] = []

    for raw in raw_gaps:
        gap = _normalize_gap_dict(raw)
        sev: GapSeverity = gap["severity"] if gap["severity"] in _SEVERITY_RANK else "moderate"  # type: ignore[assignment]
        severities_seen.append(sev)
        if sev in _HIGH_IMPACT_SEVERITIES:
            high_impact_count += 1
        if gap["poam_required"]:
            poam_required_count += 1

        for group_name in _groups_for_gap_type(gap["gap_type"]):
            grp = groups[group_name]
            grp.count_open_gaps += 1
            grp.max_severity = _max_severity([grp.max_severity, sev])
            for c in gap["controls"]:
                _add_unique(grp.controls_impacted, str(c))
            _add_unique(grp.tracker_rows, gap["source_item_id"])
            _add_unique(grp.recommended_closure_artifacts, gap["recommended_artifact"])
            for k in gap["linked_ksi_ids"]:
                _add_unique(grp.linked_ksi_ids, str(k))
            if gap["poam_required"]:
                grp.poam_required = True
            if gap["gap_type"] not in grp.gap_types:
                grp.gap_types.append(gap["gap_type"])  # type: ignore[arg-type]
            _add_unique(grp.gap_ids, gap["gap_id"])

    total_open_gaps = len(raw_gaps)

    # Result classification.
    if total_open_gaps == 0:
        result = "PASS"
        severity = "info"
        summary = "No open evidence gaps remain — every tracker row is satisfied or informational."
    elif high_impact_count > 0:
        result = "FAIL"
        severity = "high" if "critical" not in severities_seen else "critical"
        summary = (
            f"{high_impact_count} of {total_open_gaps} open evidence gap(s) are high/critical severity. "
            f"{poam_required_count} require POA&M."
        )
    else:
        result = "PARTIAL"
        severity = _max_severity(severities_seen)
        summary = (
            f"{total_open_gaps} open evidence gap(s); none are high/critical. "
            f"{poam_required_count} require POA&M."
        )

    # Build evidence + gap strings for the canonical EvalResult.
    evidence: list[str] = [
        f"evidence_gaps.json: total_open_gaps={total_open_gaps}, high_impact={high_impact_count}, "
        f"poam_required={poam_required_count}, informational_items={len(informational)}"
    ]
    for grp in groups.values():
        if grp.count_open_gaps:
            evidence.append(
                f"group={grp.group} open={grp.count_open_gaps} "
                f"max_severity={grp.max_severity} controls={','.join(grp.controls_impacted) or '(none)'} "
                f"ksi={','.join(grp.linked_ksi_ids) or '(none)'} "
                f"poam={'yes' if grp.poam_required else 'no'}"
            )

    gap_strings: list[str] = []
    affected_assets: list[str] = []
    for raw in raw_gaps:
        gap = _normalize_gap_dict(raw)
        gap_strings.append(
            f"{gap['gap_id']} [{gap['severity']}/{gap['gap_type']}] "
            f"row={gap['source_item_id']} controls={','.join(gap['controls']) or '(none)'} "
            f"poam_required={'yes' if gap['poam_required'] else 'no'} :: {gap['title'][:80]}"
        )
        _add_unique(affected_assets, gap["source_item_id"])

    recommended_actions: list[str] = []
    for grp in groups.values():
        if not grp.count_open_gaps:
            continue
        ctl = ", ".join(grp.controls_impacted) or "(no controls cited)"
        artifacts = "; ".join(grp.recommended_closure_artifacts) or "(no recommended artifact mapped)"
        recommended_actions.append(
            f"{grp.group} ({ctl}): produce {artifacts}; close {grp.count_open_gaps} gap(s); "
            f"linked KSIs: {', '.join(grp.linked_ksi_ids) or '(none)'}."
        )

    eval_result = EvalResult(
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        result=result,  # type: ignore[arg-type]
        controls=CONTROL_REFS,
        severity=severity,
        summary=summary,
        evidence=evidence,
        gaps=gap_strings,
        affected_assets=affected_assets,
        recommended_actions=recommended_actions,
        generated_artifacts=[
            "tracker_gap_eval_results.json",
            "tracker_gap_report.md",
            "tracker_gap_matrix.csv",
        ],
    )

    return TrackerGapEvalResult(
        eval_result=eval_result,
        groups=[groups[g] for g in TRACKER_GROUPS],
        total_open_gaps=total_open_gaps,
        high_impact_count=high_impact_count,
        poam_required_count=poam_required_count,
        informational_count=len(informational),
        source_envelope=dict(evidence_gaps_envelope),
    )
