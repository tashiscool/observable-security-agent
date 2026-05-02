"""POA&M CSV generation from evaluation gaps (CA-5 / CA-7 / RA-5)."""

from __future__ import annotations

import csv
import io
import re
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from core.models import PoamItem
from core.pipeline_models import (
    EvalStatus,
    PipelineEvalResult as EvalResult,
    PipelineSemanticEvent as SemanticEvent,
)

POAM_CSV_COLUMNS: list[str] = [
    "POA&M ID",
    "Controls",
    "Weakness Name",
    "Weakness Description",
    "Asset Identifier",
    "Original Detection Date",
    "Weakness Source",
    "Raw Severity",
    "Adjusted Risk Rating",
    "Planned Remediation",
    "Milestone",
    "Milestone Due Date",
    "Status",
    "Vendor Dependency",
    "Operational Requirement",
    "Source Eval ID",
]

_POAM_CONTROLS_DISPLAY = "CA-5; CA-7; RA-5"
_WEAKNESS_SOURCE = "Observable Security Agent assessment"

# Default weakness names (override with eval-specific narrative).
_WEAKNESS_NAME_BY_EVAL_ID: dict[str, str] = {
    "CM8_INVENTORY_RECONCILIATION": "Declared inventory does not cover discovered in-boundary production asset",
    "RA5_SCANNER_SCOPE_COVERAGE": "Missing scanner coverage for in-boundary production asset",
    "AU6_CENTRALIZED_LOG_COVERAGE": "No central log ingestion for production compute asset",
    "SI4_ALERT_INSTRUMENTATION": "No enabled alert for public administrative-port exposure",
    "CM3_CHANGE_EVIDENCE_LINKAGE": "No linked change approval for firewall/security rule change",
    "RA5_EXPLOITATION_REVIEW": "No exploitation-review evidence for High vulnerability",
    "CROSS_DOMAIN_EVENT_CORRELATION": "Incomplete cross-domain security event correlation evidence",
}


def severity_bucket_for_eval(r: EvalResult) -> str:
    """Map pipeline eval to POA&M severity bucket: critical | high | moderate | low."""
    raw = (r.machine or {}).get("severity")
    if isinstance(raw, str):
        s = raw.strip().lower()
        if s in ("critical", "high", "moderate", "medium", "low"):
            if s == "medium":
                s = "moderate"
            return s
    if r.result == EvalStatus.FAIL:
        return "high"
    if r.result == EvalStatus.PARTIAL:
        return "moderate"
    return "low"


def milestone_due_date_for_severity(bucket: str, reference: date) -> date:
    """Calendar days after reference: critical 15, high 30, moderate/medium 90, low 180."""
    b = bucket.lower()
    if b == "critical":
        return reference + timedelta(days=15)
    if b == "high":
        return reference + timedelta(days=30)
    if b in ("moderate", "medium"):
        return reference + timedelta(days=90)
    return reference + timedelta(days=180)


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "").strip().lower())


def _weakness_name_for_eval(eval_id: str) -> str:
    return _WEAKNESS_NAME_BY_EVAL_ID.get(eval_id, f"Control gap for {eval_id}")


def _dedupe_key_sets(
    items: list[PoamItem],
    seed_poam_rows: list[dict[str, Any]],
) -> tuple[set[str], set[tuple[str, str]]]:
    by_source: set[str] = set()
    by_weak_asset: set[tuple[str, str]] = set()
    for p in items:
        if p.source_eval_id:
            by_source.add(_norm(p.source_eval_id))
        by_weak_asset.add((_norm(p.weakness_name), _norm(p.asset_identifier)))
    for row in seed_poam_rows:
        if not isinstance(row, dict):
            continue
        se = row.get("source_eval_id")
        if se and str(se).strip():
            by_source.add(_norm(str(se)))
        wn = row.get("weakness_name") or row.get("Weakness Name")
        aid = row.get("asset_identifier") or row.get("Asset ID") or row.get("asset_id")
        if wn and aid:
            by_weak_asset.add((_norm(str(wn)), _norm(str(aid))))
    return by_source, by_weak_asset


def _should_skip_generated(
    eval_id: str,
    weakness_name: str,
    asset_id: str,
    by_source: set[str],
    by_weak_asset: set[tuple[str, str]],
) -> bool:
    if _norm(eval_id) in by_source:
        return True
    if (_norm(weakness_name), _norm(asset_id)) in by_weak_asset:
        return True
    return False


def _register_keys(
    eval_id: str,
    weakness_name: str,
    asset_id: str,
    by_source: set[str],
    by_weak_asset: set[tuple[str, str]],
) -> None:
    by_source.add(_norm(eval_id))
    by_weak_asset.add((_norm(weakness_name), _norm(asset_id)))


def _severity_bucket_from_raw(raw: str) -> str:
    s = (raw or "moderate").strip().lower()
    if s in ("critical", "high", "moderate", "medium", "low"):
        if s == "medium":
            return "moderate"
        return s
    return "moderate"


def _poam_item_to_csv_row(p: PoamItem, reference: date) -> dict[str, str]:
    det = reference.isoformat()
    bucket = _severity_bucket_from_raw(p.raw_severity)
    due_dt = p.milestone_due_date or milestone_due_date_for_severity(bucket, reference)
    due = due_dt.isoformat()
    return {
        "POA&M ID": p.poam_id,
        "Controls": "; ".join(p.controls) if p.controls else _POAM_CONTROLS_DISPLAY,
        "Weakness Name": p.weakness_name,
        "Weakness Description": p.weakness_description,
        "Asset Identifier": p.asset_identifier,
        "Original Detection Date": det,
        "Weakness Source": _WEAKNESS_SOURCE,
        "Raw Severity": p.raw_severity,
        "Adjusted Risk Rating": p.adjusted_risk_rating,
        "Planned Remediation": p.planned_remediation,
        "Milestone": "Initial remediation milestone",
        "Milestone Due Date": due,
        "Status": p.status,
        "Vendor Dependency": "",
        "Operational Requirement": "",
        "Source Eval ID": p.source_eval_id or "",
    }


def _slug_eval_id(eval_id: str) -> str:
    return re.sub(r"[^A-Za-z0-9]+", "-", eval_id).strip("-").upper() or "EVAL"


def _row_from_eval(
    r: EvalResult,
    semantic_event: SemanticEvent,
    reference: date,
    seq: int,
) -> dict[str, str]:
    eval_id = r.eval_id
    bucket = severity_bucket_for_eval(r)
    weakness_name = _weakness_name_for_eval(eval_id)
    aid = semantic_event.asset_id or (
        (r.machine or {}).get("affected_assets", [None])[0]
        if isinstance((r.machine or {}).get("affected_assets"), list) and (r.machine or {}).get("affected_assets")
        else "organization-wide"
    )
    desc = (r.gap or r.recommended_action or r.eval_id)[:2000]
    planned = (r.recommended_action or "Remediate per ISSM / AO-approved plan.")[:2000]
    due = milestone_due_date_for_severity(bucket, reference)
    _disp = {"critical": "Critical", "high": "High", "moderate": "Moderate", "low": "Low"}
    raw_disp = _disp.get(bucket, "Moderate")
    status = "Open"
    if r.result == EvalStatus.PARTIAL and bucket == "moderate":
        status = "Risk Review Required"
    elif r.result == EvalStatus.PARTIAL:
        status = "Open"
    poam_id = f"POAM-AUTO-{_slug_eval_id(eval_id)}-{seq:03d}"
    return {
        "POA&M ID": poam_id,
        "Controls": _POAM_CONTROLS_DISPLAY,
        "Weakness Name": weakness_name,
        "Weakness Description": desc,
        "Asset Identifier": str(aid),
        "Original Detection Date": reference.isoformat(),
        "Weakness Source": _WEAKNESS_SOURCE,
        "Raw Severity": raw_disp,
        "Adjusted Risk Rating": raw_disp,
        "Planned Remediation": planned,
        "Milestone": f"Address gap for {eval_id}",
        "Milestone Due Date": due.isoformat(),
        "Status": status,
        "Vendor Dependency": "",
        "Operational Requirement": "",
        "Source Eval ID": eval_id,
    }


def build_poam_generation(
    prior_eval_results: list[EvalResult],
    semantic_event: SemanticEvent,
    existing_poam_items: list[PoamItem],
    seed_poam_rows: list[dict[str, Any]],
    *,
    reference_date: date | None = None,
) -> tuple[list[dict[str, str]], dict[str, Any]]:
    """
    Build full POA&M CSV row dicts: existing (normalized) plus new rows for FAIL/PARTIAL evals.

    Returns ``(rows, stats)`` where stats includes ``added``, ``skipped_duplicate``, ``failing_eval_count``.
    """
    ref = reference_date or date.today()
    failing = [
        r
        for r in prior_eval_results
        if r.eval_id != "CA5_POAM_STATUS" and r.result in (EvalStatus.FAIL, EvalStatus.PARTIAL)
    ]
    by_source, by_weak_asset = _dedupe_key_sets(existing_poam_items, seed_poam_rows)

    rows: list[dict[str, str]] = [_poam_item_to_csv_row(p, ref) for p in existing_poam_items]
    added = 0
    skipped = 0
    seq = 1
    for r in failing:
        wn = _weakness_name_for_eval(r.eval_id)
        aid = semantic_event.asset_id or (
            (r.machine or {}).get("affected_assets", [None])[0]
            if isinstance((r.machine or {}).get("affected_assets"), list) and (r.machine or {}).get("affected_assets")
            else "organization-wide"
        )
        if _should_skip_generated(r.eval_id, wn, str(aid), by_source, by_weak_asset):
            skipped += 1
            continue
        row = _row_from_eval(r, semantic_event, ref, seq)
        seq += 1
        rows.append(row)
        added += 1
        _register_keys(r.eval_id, wn, str(aid), by_source, by_weak_asset)

    stats = {
        "added": added,
        "skipped_duplicate": skipped,
        "failing_eval_count": len(failing),
        "existing_count": len(existing_poam_items),
    }
    return rows, stats


def write_poam_csv_file(path: Path, rows: list[dict[str, str]]) -> None:
    """Write POA&M rows to UTF-8 CSV with the standard column set."""
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=POAM_CSV_COLUMNS, extrasaction="ignore")
    w.writeheader()
    for row in rows:
        out = {k: row.get(k, "") for k in POAM_CSV_COLUMNS}
        w.writerow(out)
    path.write_text(buf.getvalue(), encoding="utf-8")


def write_poam_csv(
    path: Path,
    bundle: Any,
    *,
    seed_rows: list[dict[str, Any]] | None = None,
    reference_date: date | None = None,
) -> None:
    """
    Regenerate ``poam.csv`` from a :class:`CorrelationBundle` (e.g. ``agent.py report``).

    ``seed_rows`` is optional raw POA&M seed from ``EvidenceBundle.poam_seed_rows`` for dedupe.
    """
    from core.pipeline_models import PipelineCorrelationBundle as CorrelationBundle

    if not isinstance(bundle, CorrelationBundle):
        raise TypeError("bundle must be a CorrelationBundle")
    prior = list(bundle.eval_results)
    sem = bundle.semantic_event
    rows, _stats = build_poam_generation(
        prior,
        sem,
        existing_poam_items=[],
        seed_poam_rows=list(seed_rows or []),
        reference_date=reference_date,
    )
    # Report path has no canonical PoamItems — dedupe using seed_rows only; still emit generated rows.
    write_poam_csv_file(path, rows)


def poam_items_from_written_csv(path: Path) -> list[PoamItem]:
    """Parse merged assessment ``poam.csv`` (display headers or seed-style columns) into PoamItem rows."""
    text = path.read_text(encoding="utf-8")
    reader = csv.DictReader(text.splitlines())
    out: list[PoamItem] = []
    for row in reader:
        if not row:
            continue
        pid = (row.get("POA&M ID") or row.get("poam_id") or "").strip()
        if not pid:
            continue
        ctrl_raw = row.get("Controls") or row.get("controls") or ""
        controls = [c.strip() for c in str(ctrl_raw).replace(";", ",").split(",") if c.strip()]
        wn = str(row.get("Weakness Name") or row.get("weakness_name") or "weakness")
        notes = str(
            row.get("Weakness Description")
            or row.get("weakness_description")
            or row.get("notes")
            or wn
        )
        raw_sev = str(row.get("Raw Severity") or row.get("raw_severity") or "moderate").lower()
        adj = str(row.get("Adjusted Risk Rating") or row.get("adjusted_risk_rating") or raw_sev)
        planned = str(
            row.get("Planned Remediation")
            or row.get("planned_remediation")
            or "Track per ISSO POA&M process."
        )
        asset_id = str(
            row.get("Asset Identifier") or row.get("asset_identifier") or row.get("asset_id") or "unknown"
        )
        status = str(row.get("Status") or row.get("status") or "open")
        mdd = row.get("Milestone Due Date") or row.get("milestone_due_date")
        milestone: date | None = None
        if mdd and str(mdd).strip():
            try:
                milestone = date.fromisoformat(str(mdd).strip()[:10])
            except ValueError:
                milestone = None
        src_eval = row.get("Source Eval ID") or row.get("source_eval_id")
        source_eval_id = str(src_eval).strip() if src_eval and str(src_eval).strip() else None
        try:
            out.append(
                PoamItem(
                    poam_id=pid,
                    controls=controls,
                    weakness_name=wn,
                    weakness_description=notes,
                    asset_identifier=asset_id,
                    raw_severity=raw_sev,
                    adjusted_risk_rating=adj,
                    status=status,
                    planned_remediation=planned,
                    milestone_due_date=milestone,
                    source_eval_id=source_eval_id,
                )
            )
        except ValidationError:
            continue
    return out


# Backward-compatible name used by tests
def poam_rows_from_bundle(bundle: Any, *, reference_date: date | None = None) -> list[dict[str, str]]:
    """Return POA&M CSV row dicts (existing items empty — generation only from eval results)."""
    from core.pipeline_models import PipelineCorrelationBundle as CorrelationBundle

    if not isinstance(bundle, CorrelationBundle):
        raise TypeError("bundle must be a CorrelationBundle")
    rows, _ = build_poam_generation(
        list(bundle.eval_results),
        bundle.semantic_event,
        [],
        [],
        reference_date=reference_date,
    )
    return rows
