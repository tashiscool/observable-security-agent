"""Convert FedRAMP assessment-tracker rows into structured evidence-gap records.

This module is the bridge between
:mod:`normalization.assessment_tracker_import` (which does parsing + category routing)
and the canonical :class:`core.models.EvidenceGap` /
:class:`core.models.InformationalTrackerItem` records used downstream by reports,
POA&M generation, and the FedRAMP 20x package builder.

Invariant: **every tracker row is accounted for**. A row becomes either:

* an :class:`EvidenceGap` — open / unsatisfied evidence request,
* an :class:`InformationalTrackerItem` — closed / satisfied / withdrawn / out-of-scope.

No row is silently dropped. The output JSON envelope includes the full count and a
``coverage_invariant_holds`` boolean so downstream tooling can assert this contract.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from classification.classify_tracker_gap import GapClassification, classify_tracker_gap
from core.models import (
    EvidenceGap,
    GapSeverity,
    GapType,
    InformationalTrackerItem,
    model_to_python_dict,
)


__all__ = [
    "EvidenceGapBundle",
    "build_evidence_gaps",
    "write_evidence_gaps_file",
    "GAP_TYPE_TO_KSI",
]


# ---------------------------------------------------------------------------
# GapType → KSI mapping
# ---------------------------------------------------------------------------

GAP_TYPE_TO_KSI: Mapping[GapType, tuple[str, ...]] = {
    "inventory_mismatch": ("KSI-INV-01",),
    "scanner_scope_missing": ("KSI-VULN-01", "KSI-INV-01"),
    "vulnerability_scan_evidence_missing": ("KSI-VULN-01",),
    "credentialed_scan_evidence_missing": ("KSI-VULN-01",),
    "centralized_log_missing": ("KSI-LOG-01",),
    "local_to_central_log_correlation_missing": ("KSI-LOG-01",),
    "alert_rule_missing": ("KSI-LOG-01", "KSI-IR-01"),
    "alert_sample_missing": ("KSI-LOG-01", "KSI-IR-01"),
    "response_action_missing": ("KSI-IR-01",),
    "change_ticket_missing": ("KSI-CM-01",),
    "sia_missing": ("KSI-CM-01",),
    "testing_evidence_missing": ("KSI-CM-01",),
    "approval_missing": ("KSI-CM-01",),
    "deployment_evidence_missing": ("KSI-CM-01",),
    "verification_evidence_missing": ("KSI-CM-01",),
    "exploitation_review_missing": ("KSI-VULN-01", "KSI-IR-01"),
    "poam_update_missing": ("KSI-VULN-01",),
    "deviation_request_missing": ("KSI-VULN-01",),
    "backup_evidence_missing": ("KSI-REC-01",),
    "restore_test_missing": ("KSI-REC-01",),
    "identity_listing_missing": ("KSI-IAM-01",),
    "password_policy_evidence_missing": ("KSI-IAM-01",),
    "crypto_fips_evidence_missing": ("KSI-LOG-01",),  # crypto coverage rolls up under monitoring posture
    "traffic_flow_policy_missing": ("KSI-INV-01",),
    "unknown": (),
}


# Status tokens that mark a tracker row as "no longer an open gap".
_CLOSED_STATUS_TOKENS = frozenset(
    {"closed", "complete", "completed", "satisfied", "accepted", "resolved", "withdrawn", "n/a", "na"}
)


# ---------------------------------------------------------------------------
# Result bundle
# ---------------------------------------------------------------------------


@dataclass
class EvidenceGapBundle:
    """Bundled result of converting a list of tracker rows into structured records."""

    evidence_gaps: list[EvidenceGap]
    informational_items: list[InformationalTrackerItem]
    source_file: str
    coverage_invariant_holds: bool

    @property
    def total_rows(self) -> int:
        return len(self.evidence_gaps) + len(self.informational_items)

    @property
    def by_gap_type(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for g in self.evidence_gaps:
            out[g.gap_type] = out.get(g.gap_type, 0) + 1
        return out

    @property
    def poam_required_count(self) -> int:
        return sum(1 for g in self.evidence_gaps if g.poam_required)

    def to_envelope(self) -> dict[str, Any]:
        return {
            "schema_version": "2.0",
            "generated_at": _now_iso(),
            "source_file": self.source_file,
            "total_row_count": self.total_rows,
            "evidence_gap_count": len(self.evidence_gaps),
            "informational_item_count": len(self.informational_items),
            "coverage_invariant_holds": self.coverage_invariant_holds,
            "summary": {
                "by_gap_type": dict(sorted(self.by_gap_type.items())),
                "poam_required_count": self.poam_required_count,
            },
            "evidence_gaps": [model_to_python_dict(g) for g in self.evidence_gaps],
            "informational_tracker_items": [
                model_to_python_dict(i) for i in self.informational_items
            ],
        }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _row_attr(row: Any, key: str, default: Any = None) -> Any:
    """Get attribute or dict key — accepts TrackerRow, dict, or any duck-typed row."""
    if isinstance(row, dict):
        return row.get(key, default)
    return getattr(row, key, default)


def _row_index(row: Any) -> int | str:
    return _row_attr(row, "row_index", _row_attr(row, "id", 0))


def _row_controls(row: Any) -> list[str]:
    raw = _row_attr(row, "controls", []) or []
    return [str(c) for c in raw]


def _row_status_is_closed(row: Any) -> bool:
    s = (_row_attr(row, "status", "") or "").strip().lower()
    return bool(s) and s in _CLOSED_STATUS_TOKENS


def _row_csp_satisfied(row: Any) -> bool:
    """Heuristic: did the CSP indicate the request was already addressed?"""
    txt = (_row_attr(row, "csp_comment", "") or "").lower()
    if not txt:
        return False
    closed_hints = (
        "no further action",
        "already accepted",
        "previously accepted",
        "previously satisfied",
        "n/a",
    )
    return any(h in txt for h in closed_hints)


def _short_gap_type(gt: GapType) -> str:
    return re.sub(r"_+", "-", gt)


def _build_gap_id(idx: int | str, gap_type: GapType, taken: set[str]) -> str:
    label = f"{int(idx):04d}" if isinstance(idx, int) else str(idx)
    base = f"gap-{label}-{_short_gap_type(gap_type)}"
    if base not in taken:
        taken.add(base)
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    new = f"{base}-{n}"
    taken.add(new)
    return new


def _build_item_id(idx: int | str, taken: set[str]) -> str:
    label = f"{int(idx):04d}" if isinstance(idx, int) else str(idx)
    base = f"info-{label}"
    if base not in taken:
        taken.add(base)
        return base
    n = 2
    while f"{base}-{n}" in taken:
        n += 1
    new = f"{base}-{n}"
    taken.add(new)
    return new


def _ksi_for(gap_type: GapType, controls: list[str]) -> list[str]:
    base = list(GAP_TYPE_TO_KSI.get(gap_type, ()))
    blob = " ".join(controls).upper()
    # Add agent KSIs when any AGENT_* indicator slips in via controls/text.
    if any(tag in blob for tag in ("AC-2(7)", "IA-2", "IA-4")) and "KSI-IAM-01" not in base:
        base.insert(0, "KSI-IAM-01")
    return base


def _short_title_for(gap_type: GapType, request_text: str) -> str:
    pretty = gap_type.replace("_", " ").rstrip()
    snip = (request_text or "").strip().splitlines()[0][:120]
    if snip:
        return f"{pretty.capitalize()}: {snip}"
    return pretty.capitalize()


# ---------------------------------------------------------------------------
# Top-level builder
# ---------------------------------------------------------------------------


def build_evidence_gaps(
    rows: Iterable[Any],
    *,
    source_file: str = "tracker_items.json",
) -> EvidenceGapBundle:
    """Convert tracker rows → :class:`EvidenceGapBundle`. Every row is accounted for."""
    rows_list = list(rows)
    gaps: list[EvidenceGap] = []
    info: list[InformationalTrackerItem] = []
    used_gap_ids: set[str] = set()
    used_item_ids: set[str] = set()

    for row in rows_list:
        idx = _row_index(row)
        controls = _row_controls(row)
        request_text = (_row_attr(row, "request_text", "") or "").strip()
        assessor_comment = _row_attr(row, "assessor_comment")
        csp_comment = _row_attr(row, "csp_comment")
        owner = _row_attr(row, "owner")
        status = _row_attr(row, "status")
        due_date = _row_attr(row, "due_date")

        # Closed / satisfied → informational, no gap.
        if _row_status_is_closed(row) or _row_csp_satisfied(row):
            info.append(
                InformationalTrackerItem(
                    item_id=_build_item_id(idx, used_item_ids),
                    source_item_id=str(idx),
                    source_file=source_file,
                    controls=controls,
                    title=_short_title_for("unknown", request_text) if request_text else f"Tracker row {idx}",
                    status=status,
                    owner=owner,
                    reason_not_a_gap=(
                        f"Closed / satisfied tracker row (status={status!r})"
                        if _row_status_is_closed(row)
                        else "CSP indicated request already satisfied"
                    ),
                    csp_comment=csp_comment,
                    assessor_comment=assessor_comment,
                )
            )
            continue

        # Classify the gap.
        cls: GapClassification = classify_tracker_gap(
            request_text=request_text,
            assessor_comment=assessor_comment,
            csp_comment=csp_comment,
            controls=controls,
        )

        # If we cannot classify AND there is no actionable text, treat it as informational.
        if cls.gap_type == "unknown" and not request_text and not assessor_comment:
            info.append(
                InformationalTrackerItem(
                    item_id=_build_item_id(idx, used_item_ids),
                    source_item_id=str(idx),
                    source_file=source_file,
                    controls=controls,
                    title=f"Tracker row {idx} — no actionable text",
                    status=status,
                    owner=owner,
                    reason_not_a_gap="No request text, assessor comment, or CSP comment",
                    csp_comment=csp_comment,
                    assessor_comment=assessor_comment,
                )
            )
            continue

        # Otherwise: build an EvidenceGap (even for type=unknown — we still want it surfaced).
        gap = EvidenceGap(
            gap_id=_build_gap_id(idx, cls.gap_type, used_gap_ids),
            source_item_id=str(idx),
            source_file=source_file,
            controls=controls,
            gap_type=cls.gap_type,
            title=_short_title_for(cls.gap_type, request_text),
            description=(
                request_text
                if request_text
                else (assessor_comment or "Evidence gap inferred from tracker row.")
            ),
            assessor_comment=assessor_comment,
            owner=owner,
            status=status,
            due_date=due_date,
            severity=cls.severity,
            linked_ksi_ids=_ksi_for(cls.gap_type, controls),
            recommended_artifact=cls.recommended_artifact,
            recommended_validation=cls.recommended_validation,
            poam_required=cls.poam_required,
        )
        gaps.append(gap)

    bundle = EvidenceGapBundle(
        evidence_gaps=gaps,
        informational_items=info,
        source_file=source_file,
        coverage_invariant_holds=(len(gaps) + len(info) == len(rows_list)),
    )
    return bundle


def write_evidence_gaps_file(
    rows: Iterable[Any],
    *,
    output_path: Path,
    source_file: str = "tracker_items.json",
) -> EvidenceGapBundle:
    """Build the bundle and write it to ``output_path`` (JSON, UTF-8, indent=2)."""
    bundle = build_evidence_gaps(rows, source_file=source_file)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(bundle.to_envelope(), indent=2) + "\n", encoding="utf-8")
    return bundle
