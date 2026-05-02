"""FAIL/PARTIAL evaluation rows must support the assessor evidence-chain narrative (README).

No invented facts: validators only require *explicit* structured fields already derivable
from eval output (evidence lines, gaps, controls, remediation hints).
"""

from __future__ import annotations

import re
from typing import Any

FAIL_PARTIAL = frozenset({"FAIL", "PARTIAL"})

# Explicit disposition for POA&M vs risk acceptance (README § failed/partial).
ALLOWED_REMEDIATION_DISPOSITION = frozenset(
    {"poam", "risk_acceptance", "poam_or_risk_acceptance", "none"},
)


def infer_remediation_disposition(
    *,
    recommended_actions: list[str],
    recommended_action: str = "",
) -> str:
    """Infer disposition from remediation text; default requires org choice (not silent pass)."""
    parts = [str(x) for x in recommended_actions if str(x).strip()]
    if recommended_action.strip():
        parts.append(recommended_action.strip())
    blob = " ".join(parts).lower()
    if re.search(r"risk\s+accept", blob):
        if re.search(r"poa\s*&?\s*m|poam", blob):
            return "poam_or_risk_acceptance"
        return "risk_acceptance"
    if re.search(r"poa\s*&?\s*m|\bpoam\b", blob):
        return "poam"
    if not parts:
        return "poam_or_risk_acceptance"
    return "poam_or_risk_acceptance"


def coerce_evaluation_row_to_record(row: dict[str, Any]) -> dict[str, Any]:
    """Normalize a raw ``evaluations[]`` or ``eval_result_records[]`` row for validation."""
    rec = dict(row)
    gaps = rec.get("gaps")
    if gaps is None and rec.get("gap"):
        gaps = [x.strip() for x in str(rec["gap"]).split(";") if x.strip()]
    elif isinstance(gaps, str):
        gaps = [gaps] if gaps.strip() else []
    elif not isinstance(gaps, list):
        gaps = []
    rec["gaps"] = [str(g).strip() for g in gaps if str(g).strip()]

    ctrls = rec.get("controls")
    if ctrls is None:
        ctrls = rec.get("control_refs") or []
    rec["controls"] = [str(c).strip() for c in ctrls if str(c).strip()]

    actions = rec.get("recommended_actions")
    if actions is None:
        ra = rec.get("recommended_action") or ""
        actions = [x.strip() for x in str(ra).split(";") if x.strip()]
    elif isinstance(actions, str):
        actions = [actions] if actions.strip() else []
    elif not isinstance(actions, list):
        actions = []
    rec["recommended_actions"] = [str(a).strip() for a in actions if str(a).strip()]

    ev = rec.get("evidence")
    if isinstance(ev, str) and ev.strip():
        rec["evidence"] = [ev.strip()]
    elif not isinstance(ev, list):
        rec["evidence"] = []
    else:
        rec["evidence"] = [str(x).strip() for x in ev if str(x).strip()]

    ksi = rec.get("linked_ksi_ids")
    if not isinstance(ksi, list):
        ksi = []
    rec["linked_ksi_ids"] = [str(x).strip() for x in ksi if str(x).strip()]

    disp = rec.get("remediation_disposition")
    if not isinstance(disp, str) or disp.strip() not in ALLOWED_REMEDIATION_DISPOSITION:
        rec["remediation_disposition"] = infer_remediation_disposition(
            recommended_actions=list(rec["recommended_actions"]),
            recommended_action=str(rec.get("recommended_action") or ""),
        )
    else:
        rec["remediation_disposition"] = disp.strip()

    if not str(rec.get("summary") or "").strip() and not str(rec.get("name") or "").strip():
        rec["summary"] = str(rec.get("eval_id") or "evaluation")

    return rec


def validate_fail_partial_record(rec: dict[str, Any], *, index: int | None = None) -> list[str]:
    """Return human-readable errors for one FAIL/PARTIAL row; empty if OK or not FAIL/PARTIAL."""
    errs: list[str] = []
    res = str(rec.get("result", "")).upper()
    if res not in FAIL_PARTIAL:
        return errs
    loc = f"eval_result_records[{index}]" if index is not None else "evaluations[?]"
    c = coerce_evaluation_row_to_record(rec)

    if not str(c.get("eval_id") or "").strip():
        errs.append(f"{loc}: missing eval_id")
    if not str(c.get("summary") or "").strip() and not str(c.get("name") or "").strip():
        errs.append(f"{loc} ({c.get('eval_id')}): missing summary/name (what was evaluated)")

    if not c.get("evidence"):
        errs.append(f"{loc} ({c.get('eval_id')}): missing evidence[] (what evidence was used)")
    if not c.get("gaps"):
        errs.append(f"{loc} ({c.get('eval_id')}): missing gaps[] (what evidence was missing)")

    if not c.get("controls") and not c.get("linked_ksi_ids"):
        errs.append(
            f"{loc} ({c.get('eval_id')}): missing controls/control_refs or linked_ksi_ids (impacted control/KSI)",
        )

    if not c.get("recommended_actions"):
        errs.append(
            f"{loc} ({c.get('eval_id')}): missing recommended_actions (artifact/action to close the gap)",
        )

    disp = str(c.get("remediation_disposition") or "")
    if disp not in ALLOWED_REMEDIATION_DISPOSITION:
        errs.append(f"{loc} ({c.get('eval_id')}): invalid remediation_disposition: {disp!r}")

    return errs


def validate_eval_results_fail_partial_contracts(doc: dict[str, Any]) -> list[str]:
    """Validate every FAIL/PARTIAL row in ``eval_results.json`` document."""
    all_errs: list[str] = []
    records = doc.get("eval_result_records")
    if isinstance(records, list) and records:
        for i, rec in enumerate(records):
            if isinstance(rec, dict):
                all_errs.extend(validate_fail_partial_record(rec, index=i))
        return all_errs

    evals = doc.get("evaluations")
    if not isinstance(evals, list):
        return ["eval_results.json: missing evaluations[] for fail/partial contract check"]
    for i, row in enumerate(evals):
        if not isinstance(row, dict):
            continue
        coerced = coerce_evaluation_row_to_record(row)
        all_errs.extend(validate_fail_partial_record(coerced, index=i))
    return all_errs


__all__ = [
    "ALLOWED_REMEDIATION_DISPOSITION",
    "coerce_evaluation_row_to_record",
    "infer_remediation_disposition",
    "validate_eval_results_fail_partial_contracts",
    "validate_fail_partial_record",
]
