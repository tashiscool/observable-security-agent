"""Map assessment evaluations to FedRAMP 20x KSI identifiers (control crosswalk + optional agent overrides)."""

from __future__ import annotations

from typing import Any

from core.control_mapper import get_controls_for_eval


def eval_to_ksi_ids(
    ev: dict[str, Any],
    rev5_rows: list[dict[str, Any]],
    eval_default_map: dict[str, str],
    eval_agent_ksi: dict[str, Any] | None = None,
) -> list[str]:
    """
    Resolve KSI ids for one evaluation row.

    ``eval_agent_ksi`` (from ``config/control-crosswalk.yaml`` ``eval_id_agent_ksi``) adds
    agent-program KSIs (e.g. ``KSI-AGENT-01``) on top of control-ref crosswalk hits so agent
    governance evals roll up into dedicated KSIs.
    """
    eid = str(ev.get("eval_id") or "")
    found: set[str] = set()
    for ctrl in ev.get("control_refs") or []:
        c = str(ctrl).strip()
        prim = [r for r in rev5_rows if r.get("rev5_control_id") == c and r.get("mapping_type") == "primary"]
        rows = prim or [r for r in rev5_rows if r.get("rev5_control_id") == c]
        for r in rows:
            kid = r.get("ksi_id") or r.get("ksi_20x_id")
            if kid:
                found.add(str(kid))
    if not found and eid in eval_default_map:
        found.add(eval_default_map[eid])
    if not found:
        for c in get_controls_for_eval(eid):
            rows = [r for r in rev5_rows if r.get("rev5_control_id") == c]
            for r in rows:
                kid = r.get("ksi_id") or r.get("ksi_20x_id")
                if kid:
                    found.add(str(kid))
    if not found and eid in eval_default_map:
        found.add(eval_default_map[eid])

    if eval_agent_ksi:
        raw = eval_agent_ksi.get(eid)
        if isinstance(raw, str) and raw.strip():
            found.add(raw.strip())
        elif isinstance(raw, list):
            for x in raw:
                if x is not None and str(x).strip():
                    found.add(str(x).strip())

    return sorted(found)
