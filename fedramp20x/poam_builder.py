"""FedRAMP 20x-style POA&M items from open findings and legacy CSV ingestion.

Remediation text fields remain assessor-facing prose (not copied from upstream scanner code).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from core.csv_utils import load_csv_rows

_DEFAULT_POLICY: dict[str, Any] = {
    "schema_version": "1.0",
    "poam_id_prefix_auto": "POAM-F20X",
    "default_due_days_by_severity": {"critical": 15, "high": 30, "medium": 90, "low": 180, "info": 180},
    "risk_owner_default": "Customer Chief Risk Officer (delegate)",
    "system_owner_default": "Customer System Owner (ISSO delegate)",
    "validation_required_for_closure_default": True,
    "customer_impact_templates": {
        "critical": "Potential for severe service disruption or data exposure until remediated.",
        "high": "Elevated exposure window with plausible exploitation or audit failure absent timely remediation.",
        "medium": "Moderate residual risk; compensating monitoring may be needed until remediation completes.",
        "low": "Limited exposure; routine remediation tracking applies.",
    },
}


def load_poam_policy(path: Path | None) -> dict[str, Any]:
    """Load ``poam-policy.yaml`` merged over built-in defaults."""
    from fedramp20x.config_normalize import normalize_poam_policy

    policy = dict(_DEFAULT_POLICY)
    if path and path.is_file():
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            policy.update(normalize_poam_policy(raw))
    d = policy.get("default_due_days_by_severity")
    if not isinstance(d, dict) or not d:
        policy["default_due_days_by_severity"] = dict(_DEFAULT_POLICY["default_due_days_by_severity"])
    return policy


def _norm_severity(s: str) -> str:
    x = (s or "medium").strip().lower()
    if x == "moderate":
        x = "medium"
    if x not in ("critical", "high", "medium", "low", "info"):
        x = "medium"
    return x


def _due_days(severity: str, policy: dict[str, Any]) -> int:
    m = policy.get("default_due_days_by_severity") or {}
    sev = _norm_severity(severity)
    v = m.get(sev)
    if v is not None:
        return int(v)
    return int(m.get("medium", 90))


def _parse_created_at(s: str | None) -> datetime:
    if not s:
        return datetime.now(timezone.utc)
    t = str(s).strip().replace("Z", "+00:00")
    try:
        return datetime.fromisoformat(t)
    except ValueError:
        return datetime.now(timezone.utc)


def _classify_finding(finding: dict[str, Any]) -> str:
    lids = [str(x) for x in (finding.get("linked_eval_ids") or []) if str(x).strip()]
    eid = lids[0] if lids else ""
    mapping: dict[str, str] = {
        "CM8_INVENTORY_RECONCILIATION": "inventory",
        "RA5_SCANNER_SCOPE_COVERAGE": "scanner",
        "AU6_CENTRALIZED_LOG_COVERAGE": "logging",
        "SI4_ALERT_INSTRUMENTATION": "alert",
        "CM3_CHANGE_EVIDENCE_LINKAGE": "change",
        "RA5_EXPLOITATION_REVIEW": "exploitation",
        "CROSS_DOMAIN_EVENT_CORRELATION": "correlation",
    }
    if eid in mapping:
        return mapping[eid]
    desc = f"{finding.get('title','')} {finding.get('description','')}".lower()
    if "inventory" in desc or "cm-8" in desc or "declared" in desc:
        return "inventory"
    if "scanner" in desc or ("ra-5" in desc and "scope" in desc):
        return "scanner"
    if "log" in desc or "ingest" in desc or "central" in desc:
        return "logging"
    if "alert" in desc or "siem" in desc or "si-4" in desc:
        return "alert"
    if "change" in desc or "ticket" in desc or "cm-3" in desc:
        return "change"
    if "exploitation" in desc or "ra-5(8)" in desc:
        return "exploitation"
    return "generic"


def _risk_acceptance_block(finding: dict[str, Any]) -> dict[str, Any]:
    ra = finding.get("risk_acceptance")
    if isinstance(ra, dict):
        out = {
            "required": bool(ra.get("required", False)),
            "accepted_by": ra.get("accepted_by"),
            "expiration_date": ra.get("expiration_date"),
            "conditions": [str(x) for x in (ra.get("conditions") or []) if str(x)],
        }
        return out
    return {"required": False, "accepted_by": None, "expiration_date": None, "conditions": []}


def _remediation_plan(kind: str, policy: dict[str, Any], *, risk_owner: str, base: datetime, due_days: int) -> list[dict[str, Any]]:
    """Tailored remediation steps (FedRAMP 20x narrative)."""
    ro = risk_owner
    # Spread step due dates across the remediation window (exclusive of final validation).
    span = max(due_days - 1, 7)

    def step(n: int, desc: str, offset_frac: float) -> dict[str, Any]:
        off = int(span * offset_frac)
        return {
            "step": n,
            "description": desc,
            "owner": ro,
            "due_date": (base + timedelta(days=min(off, due_days - 1))).date().isoformat(),
        }

    if kind == "inventory":
        return [
            step(1, "Investigate affected asset(s); confirm boundary placement and authoritative owner.", 0.0),
            step(2, "Update declared inventory / IIW; resolve duplicate or stale rows.", 0.2),
            step(3, "Assign accountable owner for each in-scope asset row.", 0.4),
            step(4, "Confirm scanner and central logging requirements for updated inventory classes.", 0.65),
            step(5, "Export refreshed inventory evidence and attach to POA&M milestone.", 0.85),
        ]
    if kind == "scanner":
        return [
            step(1, "Add missing scanner targets for in-scope assets; credentialed scan where required.", 0.0),
            step(2, "Run scan cycle; collect raw scanner output with timestamps.", 0.25),
            step(3, "Attach system-generated scanner configuration export to evidence package.", 0.5),
            step(4, "Validate finding closure against scanner scope coverage evaluation.", 0.75),
            step(5, "Record residual risk or schedule re-scan per CA-7 cadence.", 0.9),
        ]
    if kind == "logging":
        return [
            step(1, "Configure central log forwarding for affected assets and required event types.", 0.0),
            step(2, "Produce paired local + central log excerpts for the same event IDs.", 0.3),
            step(3, "Validate last_seen / receipt timestamps meet policy window.", 0.55),
            step(4, "Document retention, integrity, and RBAC for the central store.", 0.75),
            step(5, "Re-run AU-6 style coverage evaluation and attach results.", 0.9),
        ]
    if kind == "alert":
        return [
            step(1, "Implement or enable SIEM detection for the assessed semantic with accountable recipients.", 0.0),
            step(2, "Add on-call / governance distribution lists to the rule.", 0.25),
            step(3, "Generate sample alert payload or saved-search proof with timestamps.", 0.5),
            step(4, "Link alert to incident or change response workflow.", 0.7),
            step(5, "Re-run SI-4 alert instrumentation evaluation.", 0.9),
        ]
    if kind == "change":
        return [
            step(1, "Create or link formal change / incident ticket for the assessed event.", 0.0),
            step(2, "Complete security impact analysis (SIA) and testing evidence per CM-3.", 0.25),
            step(3, "Obtain documented approval aligned to change class.", 0.45),
            step(4, "Attach deployment evidence (automation receipt or timestamped record).", 0.65),
            step(5, "Attach verification evidence (post-change scan or health check).", 0.85),
        ]
    if kind == "exploitation":
        return [
            step(1, "Run generated exploitation-review queries; retain analyst identity and time range.", 0.0),
            step(2, "Export SIEM/log results and attach to vulnerability ticket.", 0.3),
            step(3, "Document analyst or agent conclusion for in-exploitability decision.", 0.55),
            step(4, "Link ticket to scanner finding IDs (`linked_finding_ids`).", 0.75),
            step(5, "Re-run RA-5(8) evaluation with evidence pointers.", 0.9),
        ]
    if kind == "correlation":
        return [
            step(1, "Ensure central logging is active for assets tied to correlated events.", 0.0),
            step(2, "Enable accountable alerting for observed semantic types.", 0.25),
            step(3, "Open and link response ticket with timestamps to the triggering event.", 0.5),
            step(4, "Export correlation bundle (inventory + scan + log + ticket IDs).", 0.75),
            step(5, "Re-run cross-domain correlation evaluation.", 0.9),
        ]
    # generic
    return [
        step(1, "Document root cause and in-scope impact for the finding.", 0.0),
        step(2, "Implement corrective actions per control family guidance.", 0.35),
        step(3, "Collect objective evidence of remediation.", 0.65),
        step(4, "Schedule independent validation for POA&M closure.", 0.85),
    ]


def _assessor_remediation_plan(
    finding: dict[str, Any],
    *,
    risk_owner: str,
    base: datetime,
    due_days: int,
) -> list[dict[str, Any]]:
    steps = finding.get("remediation_steps")
    if not isinstance(steps, list):
        wp = finding.get("assessor_workpaper")
        if isinstance(wp, dict):
            steps = wp.get("remediation_steps")
    if not isinstance(steps, list):
        return []
    clean = [str(x).strip() for x in steps if str(x).strip()]
    if not clean:
        return []
    span = max(due_days - 1, 7)
    total = len(clean)
    out: list[dict[str, Any]] = []
    for i, desc in enumerate(clean, start=1):
        frac = 0.0 if total == 1 else (i - 1) / total
        off = int(span * frac)
        out.append(
            {
                "step": i,
                "description": desc,
                "owner": risk_owner,
                "due_date": (base + timedelta(days=min(off, due_days - 1))).date().isoformat(),
                "source": "assessor_workpaper",
            }
        )
    out.append(
        {
            "step": len(out) + 1,
            "description": "Re-run assessment validation and attach closure evidence for assessor re-test.",
            "owner": risk_owner,
            "due_date": (base + timedelta(days=due_days)).date().isoformat(),
            "source": "assessor_workpaper",
        }
    )
    return out


def _customer_impact(severity: str, policy: dict[str, Any]) -> str:
    tpl = policy.get("customer_impact_templates") or {}
    sev = _norm_severity(severity)
    return str(tpl.get(sev) or tpl.get("medium") or _DEFAULT_POLICY["customer_impact_templates"]["medium"])


def _slug_poam_suffix(finding_id: str) -> str:
    h = re.sub(r"[^A-Za-z0-9]+", "-", finding_id).strip("-").upper()
    return h[-40:] if len(h) > 40 else h


def _should_skip_for_risk_acceptance(finding: dict[str, Any]) -> bool:
    st = str(finding.get("status") or "").lower()
    if st in ("risk_accepted", "closed", "false_positive"):
        return True
    ra = finding.get("risk_acceptance")
    if isinstance(ra, dict) and ra.get("accepted_by"):
        return True
    return False


def build_poam_items_from_findings(
    findings: list[dict[str, Any]],
    policy: dict[str, Any] | None,
    *,
    system_boundary: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """
    One POA&M row per open finding, unless the finding is risk-accepted / closed / false positive.

    ``finding`` dicts are expected to match :func:`fedramp20x.finding_builder.build_findings` output.
    """
    pol = policy or load_poam_policy(None)
    prefix = str(pol.get("poam_id_prefix_auto") or "POAM-F20X").strip() or "POAM-F20X"
    risk_owner = str(pol.get("risk_owner_default") or _DEFAULT_POLICY["risk_owner_default"])
    sys_owner = str(pol.get("system_owner_default") or _DEFAULT_POLICY["system_owner_default"])
    if system_boundary:
        risk_owner = str(system_boundary.get("risk_owner") or risk_owner)
        sys_owner = str(system_boundary.get("system_owner") or sys_owner)
    val_close = bool(pol.get("validation_required_for_closure_default", True))

    out: list[dict[str, Any]] = []
    for f in findings:
        if _should_skip_for_risk_acceptance(f):
            continue
        fid = str(f.get("finding_id") or "").strip()
        if not fid:
            continue
        sev = _norm_severity(str(f.get("severity") or "medium"))
        created = _parse_created_at(str(f.get("created_at") or ""))
        days = _due_days(sev, pol)
        target = (created + timedelta(days=days)).date().isoformat()
        kind = _classify_finding(f)
        plan = _assessor_remediation_plan(f, risk_owner=risk_owner, base=created, due_days=days)
        if not plan:
            plan = _remediation_plan(kind, pol, risk_owner=risk_owner, base=created, due_days=days)
        ra_block = _risk_acceptance_block(f)
        controls = list(f.get("nist_control_refs") or (f.get("legacy_controls") or {}).get("rev5") or [])
        ksi_ids = list(f.get("linked_ksi_ids") or f.get("ksi_ids") or [])
        linked_evals = [str(x) for x in (f.get("linked_eval_ids") or []) if str(x).strip()]
        poam_id = f"{prefix}-{_slug_poam_suffix(fid)}"
        title = str(f.get("title") or "Control weakness")
        desc = str(f.get("description") or f.get("risk_statement") or "")
        assets = [str(x) for x in (f.get("affected_assets") or []) if str(x).strip()]
        wp = f.get("assessor_workpaper") if isinstance(f.get("assessor_workpaper"), dict) else {}
        current_state = str(f.get("current_state") or wp.get("current_state") or desc)
        target_state = str(f.get("target_state") or wp.get("target_state") or "")
        estimated_effort = str(f.get("estimated_effort") or wp.get("estimated_effort") or "")
        priority = str(f.get("priority") or wp.get("priority") or "")
        item: dict[str, Any] = {
            "poam_id": poam_id,
            "finding_id": fid,
            "title": title,
            "severity": sev,
            "priority": priority,
            "estimated_effort": estimated_effort,
            "risk_owner": risk_owner,
            "system_owner": sys_owner,
            "created_at": created.replace(tzinfo=created.tzinfo or timezone.utc).isoformat(),
            "target_completion_date": target,
            "status": str(pol.get("default_status_open") or "Open"),
            "remediation_plan": plan,
            "current_state": current_state,
            "target_state": target_state,
            "validation_required_for_closure": val_close,
            "customer_impact": _customer_impact(sev, pol),
            "risk_acceptance": ra_block,
            "source_ksi_ids": ksi_ids,
            "source_controls": controls,
            "linked_eval_ids": linked_evals,
            # Legacy package / CSV compatibility
            "controls": "; ".join(controls),
            "weakness_name": title[:500],
            "weakness_description": desc[:8000],
            "asset_identifier": "; ".join(assets) if assets else "",
            "source_eval_id": linked_evals[0] if linked_evals else "",
            "raw_row": {},
        }
        out.append(item)
    return out


def merge_poam_items_for_package(
    csv_items: list[dict[str, Any]],
    finding_items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Prefer finding-derived POA&M rows; retain CSV rows whose ``source_eval_id`` is not already
    covered by a generated item (avoids duplicate CM-8 style rows per eval).
    """
    covered_evals = {str(e) for it in finding_items for e in (it.get("linked_eval_ids") or [])}
    merged: list[dict[str, Any]] = list(finding_items)
    for row in csv_items:
        se = str(row.get("source_eval_id") or "").strip()
        if se and se in covered_evals:
            continue
        merged.append(row)
    return merged


def poam_items_from_csv(path: Path) -> list[dict[str, Any]]:
    """Normalize legacy ``poam.csv`` rows into package ``poam_items`` dicts."""
    if not path.is_file():
        return []
    out: list[dict[str, Any]] = []
    for row in load_csv_rows(path):
        raw = {k: (v or "") for k, v in row.items()}
        pid = raw.get("POA&M ID") or raw.get("poam_id") or raw.get("POAM ID") or ""
        if not pid:
            continue
        out.append(
            {
                "poam_id": pid,
                "controls": raw.get("Controls", ""),
                "weakness_name": raw.get("Weakness Name", ""),
                "weakness_description": raw.get("Weakness Description", ""),
                "asset_identifier": raw.get("Asset Identifier", ""),
                "status": raw.get("Status", ""),
                "source_eval_id": raw.get("Source Eval ID", ""),
                "current_state": raw.get("Weakness Description", "") or raw.get("Weakness Name", ""),
                "target_state": raw.get("Target State", "") or "Weakness remediated and validated for closure.",
                "priority": raw.get("Priority", "") or "not specified",
                "estimated_effort": raw.get("Estimated Effort", "") or "not specified",
                "raw_row": raw,
            }
        )
    return out


def write_poam_items_json(path: Path, items: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    doc = {"schema_version": "1.0", "poam_items": items}
    path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")


def write_poam_markdown(path: Path, items: list[dict[str, Any]]) -> None:
    """Human-readable POA&M table for assessor ``poam.md``."""
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# Plan of Action and Milestones (POA&M)",
        "",
        "Generated from open assessment findings (FedRAMP 20x-style machine fields).",
        "",
        "| POA&M ID | Finding (title) | Severity | Target completion | Status |",
        "| --- | --- | --- | --- | --- |",
    ]
    for p in items:
        lines.append(
            f"| `{p.get('poam_id', '')}` | {str(p.get('title', ''))[:80].replace('|', '/')} | "
            f"{p.get('severity', '')} | {p.get('target_completion_date', '')} | {p.get('status', '')} |"
        )
    lines.extend(["", "## Remediation plans", ""])
    for p in items:
        lines.append(f"### `{p.get('poam_id')}` — {p.get('title', '')}")
        lines.append("")
        lines.append(f"- **Finding ID:** `{p.get('finding_id', '')}`")
        lines.append(f"- **Controls:** {', '.join(p.get('source_controls') or [])}")
        lines.append(f"- **KSIs:** {', '.join(p.get('source_ksi_ids') or [])}")
        if p.get("priority") or p.get("estimated_effort"):
            lines.append(f"- **Priority / effort:** {p.get('priority', '')} / {p.get('estimated_effort', '')}")
        if p.get("current_state"):
            lines.append(f"- **Current state:** {p.get('current_state', '')}")
        if p.get("target_state"):
            lines.append(f"- **Target state:** {p.get('target_state', '')}")
        lines.append(f"- **Customer impact:** {p.get('customer_impact', '')}")
        lines.append(f"- **Validation for closure:** {p.get('validation_required_for_closure', '')}")
        lines.append("")
        for s in p.get("remediation_plan") or []:
            if isinstance(s, dict):
                lines.append(
                    f"{s.get('step', '')}. **{s.get('due_date', '')}** ({s.get('owner', '')}): {s.get('description', '')}"
                )
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def attach_poam_ids_to_findings(findings: list[dict[str, Any]], poam_items: list[dict[str, Any]]) -> None:
    """Mutate findings in-place: set ``poam_id`` from generated items when missing."""
    by_fid = {str(p.get("finding_id")): str(p.get("poam_id")) for p in poam_items if p.get("finding_id")}
    for f in findings:
        if f.get("poam_id"):
            continue
        fid = str(f.get("finding_id") or "")
        if fid in by_fid:
            f["poam_id"] = by_fid[fid]
