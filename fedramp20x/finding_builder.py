"""Build formal Finding records from failed/partial evaluations and KSI rollups.

Severity strings align with scanner import vocabulary (Prowler/OCSF adapters) for consistent reporting.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fedramp20x.eval_ksi_mapping import eval_to_ksi_ids

# Severity order for policy overrides (highest first).
_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


def _norm_severity(s: str) -> str:
    x = (s or "medium").strip().lower()
    return x if x in _SEVERITY_ORDER else "medium"


def _max_severity(a: str, b: str) -> str:
    order = {v: i for i, v in enumerate(_SEVERITY_ORDER)}
    ia, ib = order.get(_norm_severity(a), 99), order.get(_norm_severity(b), 99)
    return a if ia <= ib else b


def _rev5_to_rev4_map(rev4_to_rev5: list[dict[str, Any]]) -> dict[str, list[str]]:
    m: dict[str, set[str]] = {}
    for r in rev4_to_rev5:
        r4 = str(r.get("rev4_control_id") or "").strip()
        r5 = str(r.get("rev5_control_id") or "").strip()
        if not r4 or not r5:
            continue
        m.setdefault(r5, set()).add(r4)
    return {k: sorted(v) for k, v in m.items()}


def _legacy_controls(control_refs: list[str], rev4_to_rev5: list[dict[str, Any]]) -> dict[str, list[str]]:
    rev5 = sorted({str(c).strip() for c in control_refs if str(c).strip()})
    rmap = _rev5_to_rev4_map(rev4_to_rev5)
    rev4: set[str] = set()
    for c5 in rev5:
        rev4.update(rmap.get(c5, ()))
    return {"rev4": sorted(rev4), "rev5": rev5}


def _extract_asset_from_gap(gap_line: str, affected_assets: list[str]) -> str | None:
    """Best-effort asset anchor for deduplication and wording."""
    if affected_assets and len(affected_assets) == 1:
        return affected_assets[0]
    m = re.search(r"`([^`]+)`", gap_line)
    if m:
        return m.group(1).strip()
    for aid in affected_assets or []:
        if aid and aid in gap_line:
            return aid
    # prod-style ids
    m2 = re.search(r"\b(prod-[a-z0-9-]+|rogue-[a-z0-9-]+)\b", gap_line, re.I)
    if m2:
        return m2.group(1)
    return affected_assets[0] if affected_assets else None


def _normalize_core_gap(gap_line: str) -> str:
    return " ".join(gap_line.lower().split())[:400]


def _finding_id_stub(eval_id: str, asset: str | None, gap_norm: str) -> str:
    h = hashlib.sha256(f"{eval_id}|{asset or ''}|{gap_norm}".encode()).hexdigest()[:12].upper()
    safe_eval = re.sub(r"[^A-Za-z0-9]+", "-", eval_id).strip("-").upper() or "EVAL"
    return f"FIND-{safe_eval}-{h}"


def _policy_severity(eval_id: str, base: str, validation_policy: dict[str, Any] | None) -> str:
    if not validation_policy:
        return _norm_severity(base)
    fb = validation_policy.get("finding_builder") or {}
    overrides = fb.get("finding_severity_override") or {}
    if isinstance(overrides, dict) and eval_id in overrides:
        return _max_severity(str(overrides[eval_id]), base)
    return _norm_severity(base)


def _excluded_eval_ids(validation_policy: dict[str, Any] | None) -> set[str]:
    if not validation_policy:
        return {"CA5_POAM_STATUS"}
    fb = validation_policy.get("finding_builder") or {}
    ex = fb.get("exclude_eval_ids")
    if isinstance(ex, list) and ex:
        return {str(x).strip() for x in ex if str(x).strip()}
    return {"CA5_POAM_STATUS"}


def _deficiency_description(eval_id: str, gap_line: str, asset: str | None) -> str:
    """Phrase gaps as evidence deficiencies where appropriate (not bare control failure)."""
    g = gap_line.strip()
    al = asset or "the affected in-scope asset"
    templates: dict[str, str] = {
        "RA5_SCANNER_SCOPE_COVERAGE": (
            f"No evidence was provided showing authorized scanner coverage exists for `{al}` "
            f"within the assessment window (required targets vs. exported scope). "
            f"Observed gap: {g}"
        ),
        "AU6_CENTRALIZED_LOG_COVERAGE": (
            f"No evidence was provided showing `{al}` logs are centrally ingested and current "
            f"within the assessment window. Observed gap: {g}"
        ),
        "SI4_ALERT_INSTRUMENTATION": (
            f"No evidence was provided showing an enabled, accountable alert path exists for the assessed "
            f"risk signal affecting `{al}`. Observed gap: {g}"
        ),
        "CM3_CHANGE_EVIDENCE_LINKAGE": (
            f"No evidence was provided showing a traceable change or incident record is linked for the assessed "
            f"event context involving `{al}`. Observed gap: {g}"
        ),
        "RA5_EXPLOITATION_REVIEW": (
            f"No exploitation-review evidence was provided for the High/Critical vulnerability context on "
            f"`{al}` (ticket linkage and/or documented review within the required window). Observed gap: {g}"
        ),
        "CM8_INVENTORY_RECONCILIATION": (
            f"No reconciled authoritative inventory evidence resolves the assessed gap for `{al}` "
            f"(declared vs. discovered alignment). Observed gap: {g}"
        ),
        "CROSS_DOMAIN_EVENT_CORRELATION": (
            f"No evidence bundle was provided demonstrating required cross-domain observability (logging, "
            f"alerting, and/or ticketing) for `{al}` for the assessed event. Observed gap: {g}"
        ),
    }
    if eval_id in templates:
        return templates[eval_id]
    return (
        f"Evidence deficiency noted for evaluation `{eval_id}` affecting `{al}`: "
        f"the assessment did not receive substantiating artifacts for this gap. Observed gap: {g}"
    )


def _risk_statement(severity: str, rev5: list[str]) -> str:
    fam = ", ".join(sorted({x.split("-")[0] for x in rev5 if "-" in x})) or "in-scope controls"
    return (
        f"At {_norm_severity(severity)} severity, unresolved gaps tied to {fam} increase audit and operational "
        f"risk until evidence of remediation or formal risk acceptance is on record."
    )


def _poam_for_eval(poam_items: list[dict[str, Any]] | None, eval_id: str) -> str | None:
    if not poam_items:
        return None
    for p in poam_items:
        if str(p.get("source_eval_id") or "").strip() == eval_id:
            pid = str(p.get("poam_id") or "").strip()
            return pid or None
    return None


def _iter_gap_lines(ev: dict[str, Any]) -> list[str]:
    gaps = ev.get("gaps")
    if isinstance(gaps, list) and gaps:
        return [str(x).strip() for x in gaps if str(x).strip()]
    gap = str(ev.get("gap") or "").strip()
    if not gap:
        return []
    parts = [p.strip() for p in gap.split(";") if p.strip()]
    return parts or [gap]


def _emit_eval_findings(
    ev: dict[str, Any],
    *,
    rev4_to_rev5: list[dict[str, Any]],
    rev5_to_ksi: list[dict[str, Any]],
    eval_default_ksi: dict[str, str],
    eval_agent_ksi: dict[str, Any] | None,
    validation_policy: dict[str, Any] | None,
    poam_items: list[dict[str, Any]] | None,
    created_at: str,
) -> list[dict[str, Any]]:
    eid = str(ev.get("eval_id") or "unknown")
    res = str(ev.get("result") or "").upper()
    if res not in ("FAIL", "PARTIAL", "OPEN"):
        return []
    if eid in _excluded_eval_ids(validation_policy):
        return []
    # OPEN treated like actionable gap only for explicit policy allowlist
    fb = (validation_policy or {}).get("finding_builder") or {}
    open_ids = {str(x) for x in (fb.get("include_open_result_eval_ids") or [])}
    if res == "OPEN" and eid not in open_ids:
        return []

    control_refs = [str(x).strip() for x in (ev.get("control_refs") or []) if str(x).strip()]
    lc = _legacy_controls(control_refs, rev4_to_rev5)
    ksi_ids = eval_to_ksi_ids(ev, rev5_to_ksi, eval_default_ksi, eval_agent_ksi)
    base_sev = str(ev.get("severity") or "medium")
    severity = _policy_severity(eid, base_sev, validation_policy)
    title = str(ev.get("name") or eid)
    rec = str(ev.get("recommended_action") or "").strip()
    aff = [str(x).strip() for x in (ev.get("affected_assets") or []) if str(x).strip()]
    ev_lines = [str(x).strip() for x in (ev.get("evidence") or []) if str(x).strip()]
    gap_lines = _iter_gap_lines(ev)
    if not gap_lines:
        gap_lines = [str(ev.get("summary") or "Assessment gap recorded without a detailed gap line.")]

    seen: set[tuple[str, str | None, str]] = set()
    out: list[dict[str, Any]] = []
    for gap_line in gap_lines:
        asset = _extract_asset_from_gap(gap_line, aff)
        gn = _normalize_core_gap(gap_line)
        key = (eid, asset, gn)
        if key in seen:
            continue
        seen.add(key)
        fid = _finding_id_stub(eid, asset, gn)
        desc = _deficiency_description(eid, gap_line, asset)
        poam_id = _poam_for_eval(poam_items, eid)
        row: dict[str, Any] = {
            "finding_id": fid,
            "created_at": created_at,
            "source": "eval_result",
            "ksi_ids": list(ksi_ids),
            "legacy_controls": lc,
            "severity": severity,
            "status": "open",
            "title": title,
            "description": desc,
            "affected_assets": aff if aff else ([asset] if asset else []),
            "evidence": ev_lines[:50],
            "risk_statement": _risk_statement(severity, lc.get("rev5") or []),
            "compensating_controls": [],
            "recommended_remediation": rec,
            "risk_acceptance": {
                "required": False,
                "accepted_by": None,
                "expiration_date": None,
                "conditions": [],
            },
            "linked_eval_ids": [eid],
            "linked_ksi_ids": list(ksi_ids),
            "nist_control_refs": lc.get("rev5") or control_refs,
            "source_artifact_refs": (
                [f"agent_eval_results.json#/evaluations/{eid}"]
                if str(eid).startswith("AGENT_")
                else [f"eval_results.json#/evaluations/{eid}"]
            ),
        }
        if poam_id:
            row["poam_id"] = poam_id
        out.append(row)
    return out


def _emit_ksi_rollup_findings(
    ksi_validation_results: list[dict[str, Any]],
    ksi_catalog: list[dict[str, Any]] | None,
    *,
    rev4_to_rev5: list[dict[str, Any]],
    created_at: str,
) -> list[dict[str, Any]]:
    if not ksi_validation_results or not ksi_catalog:
        return []
    by_id = {str(k.get("ksi_id")): k for k in ksi_catalog if k.get("ksi_id")}
    out: list[dict[str, Any]] = []
    for kr in ksi_validation_results:
        st = str(kr.get("status") or "").upper()
        if st not in ("FAIL", "PARTIAL", "OPEN"):
            continue
        kid = str(kr.get("ksi_id") or "").strip()
        if not kid:
            continue
        cat = by_id.get(kid) or {}
        rev4 = [str(x) for x in (cat.get("legacy_controls") or {}).get("rev4") or []]
        rev5 = [str(x) for x in (cat.get("legacy_controls") or {}).get("rev5") or []]
        lc = {"rev4": rev4, "rev5": rev5}
        if not lc["rev5"] and not lc["rev4"]:
            lc = _legacy_controls(rev5, rev4_to_rev5)
        fid = f"FIND-KSIVAL-{re.sub(r'[^A-Za-z0-9]+', '-', kid).strip('-').upper()}-{st}"
        summary = str(kr.get("summary") or "KSI validation did not pass for this assessment run.")
        linked_evals = [str(x) for x in (kr.get("linked_eval_ids") or []) if str(x).strip()]
        desc = (
            f"Evidence deficiency at the KSI rollup: `{kid}` is {st} for this run. "
            f"No complete evidence package was accepted demonstrating all pass/fail criteria for this KSI. "
            f"Summary: {summary}"
        )
        out.append(
            {
                "finding_id": fid,
                "created_at": created_at,
                "source": "ksi_validation",
                "ksi_ids": [kid],
                "legacy_controls": lc,
                "severity": "medium" if st == "OPEN" else "high",
                "status": "open",
                "title": f"KSI validation gap: {kid}",
                "description": desc,
                "affected_assets": [],
                "evidence": linked_evals[:20],
                "risk_statement": _risk_statement("high" if st != "OPEN" else "medium", lc.get("rev5") or []),
                "compensating_controls": [],
                "recommended_remediation": "Close linked evaluation gaps and re-run assessment; attach missing evidence artifacts per KSI criteria.",
                "risk_acceptance": {
                    "required": False,
                    "accepted_by": None,
                    "expiration_date": None,
                    "conditions": [],
                },
                "linked_eval_ids": linked_evals,
                "linked_ksi_ids": [kid],
                "nist_control_refs": lc.get("rev5") or [],
                "source_artifact_refs": ["fedramp20x-package.json#/ksi_validation_results"],
            }
        )
    return out


def build_findings(
    evaluations: list[dict[str, Any]],
    *,
    rev4_to_rev5: list[dict[str, Any]] | None = None,
    rev5_to_ksi: list[dict[str, Any]] | None = None,
    eval_default_ksi: dict[str, str] | None = None,
    eval_agent_ksi: dict[str, Any] | None = None,
    validation_policy: dict[str, Any] | None = None,
    ksi_validation_results: list[dict[str, Any]] | None = None,
    ksi_catalog: list[dict[str, Any]] | None = None,
    poam_items: list[dict[str, Any]] | None = None,
    created_at: str | None = None,
) -> list[dict[str, Any]]:
    """
    Convert FAIL/PARTIAL (and optionally OPEN) evaluations into Finding dicts.

    Dedupes on ``(eval_id, extracted asset, normalized gap text)``. Excludes meta-eval
    rows such as ``CA5_POAM_STATUS`` unless listed in policy ``include_open_result_eval_ids``.
    """
    r45 = list(rev4_to_rev5 or [])
    r5k = list(rev5_to_ksi or [])
    edef = dict(eval_default_ksi or {})
    eagent = dict(eval_agent_ksi or {})
    ts = created_at or datetime.now(timezone.utc).isoformat()
    findings: list[dict[str, Any]] = []
    for ev in evaluations:
        findings.extend(
            _emit_eval_findings(
                ev,
                rev4_to_rev5=r45,
                rev5_to_ksi=r5k,
                eval_default_ksi=edef,
                eval_agent_ksi=eagent,
                validation_policy=validation_policy,
                poam_items=poam_items,
                created_at=ts,
            )
        )
    fb = (validation_policy or {}).get("finding_builder") or {}
    if fb.get("include_failed_ksi_rollup") is True:
        findings.extend(
            _emit_ksi_rollup_findings(
                list(ksi_validation_results or []),
                list(ksi_catalog or []),
                rev4_to_rev5=r45,
                created_at=ts,
            )
        )
    return findings


def findings_from_evaluations(
    evaluations: list[dict[str, Any]],
    **kwargs: Any,
) -> list[dict[str, Any]]:
    """Backward-compatible alias for :func:`build_findings`."""
    return build_findings(evaluations, **kwargs)


def write_findings_json(path: str | Path, findings: list[dict[str, Any]]) -> None:
    """Write ``{"schema_version": "1.0", "findings": [...]}`` for validation-results pipelines."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    doc = {"schema_version": "1.0", "findings": findings}
    p.write_text(json.dumps(doc, indent=2), encoding="utf-8")
