"""Normalize ticket/workflow exports into canonical ``Ticket`` rows."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from core.csv_utils import load_csv_rows
from core.models import Ticket, TicketSystem


def _get(row: dict[str, Any], *keys: str) -> Any:
    lower = {str(k).lower().replace(" ", "_"): v for k, v in row.items()}
    for key in keys:
        norm = key.lower().replace(" ", "_")
        if key in row:
            return row[key]
        val = lower.get(norm)
        if val not in (None, ""):
            return val
    return None


def _truthy(v: Any) -> bool:
    return str(v or "").strip().lower() in {"1", "true", "yes", "y", "done", "complete", "completed", "attached"}


def _list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if str(x).strip()]
    return [x.strip() for x in str(v).replace(";", ",").split(",") if x.strip()]


def _dt(v: Any) -> datetime | None:
    if not v or not str(v).strip():
        return None
    s = str(v).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def _system(v: Any) -> TicketSystem:
    s = str(v or "").lower()
    if "jira" in s:
        return "jira"
    if "service" in s or "snow" in s:
        return "servicenow"
    if "github" in s:
        return "github"
    if "manual" in s or "sheet" in s:
        return "manual"
    return "unknown"


def ticket_row_to_model(row: dict[str, Any], *, default_system: TicketSystem = "unknown") -> Ticket:
    system = _system(_get(row, "system", "source", "tool")) or default_system
    tid = str(_get(row, "ticket_id", "key", "issue_key", "number", "id", "sys_id") or "TICKET-UNKNOWN")
    return Ticket(
        ticket_id=tid,
        system=system if system != "unknown" else default_system,
        title=str(_get(row, "title", "summary", "short_description", "subject") or tid),
        status=str(_get(row, "status", "state", "resolution") or "unknown"),
        linked_asset_ids=_list(_get(row, "linked_asset_ids", "assets", "asset_id", "configuration_item", "cmdb_ci")),
        linked_event_ids=_list(_get(row, "linked_event_ids", "events", "event_id")),
        linked_finding_ids=_list(_get(row, "linked_finding_ids", "findings", "finding_id", "vulnerability_id")),
        has_security_impact_analysis=_truthy(_get(row, "has_security_impact_analysis", "sia", "security_impact_analysis")),
        has_testing_evidence=_truthy(_get(row, "has_testing_evidence", "testing", "test_evidence")),
        has_approval=_truthy(_get(row, "has_approval", "approval", "approved")),
        has_deployment_evidence=_truthy(_get(row, "has_deployment_evidence", "deployment", "deploy_evidence")),
        has_verification_evidence=_truthy(_get(row, "has_verification_evidence", "verification", "post_deploy_verification")),
        created_at=_dt(_get(row, "created_at", "created", "opened_at")),
        updated_at=_dt(_get(row, "updated_at", "updated", "sys_updated_on")),
        closed_at=_dt(_get(row, "closed_at", "resolved_at", "closed")),
    )


def iter_ticket_rows(path: Path) -> list[dict[str, Any]]:
    if path.suffix.lower() == ".csv":
        return load_csv_rows(path)
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("tickets", "issues", "records", "items", "data"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        return [data]
    raise ValueError("Unsupported ticket export shape")


def import_tickets(path: Path, *, default_system: TicketSystem = "unknown") -> list[Ticket]:
    return [ticket_row_to_model(r, default_system=default_system) for r in iter_ticket_rows(path)]


def import_tickets_to_file(input_path: Path, output_path: Path, *, default_system: TicketSystem = "unknown") -> Path:
    tickets = import_tickets(input_path, default_system=default_system)
    dest = output_path if output_path.suffix.lower() == ".json" else output_path / "tickets.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps([t.model_dump(mode="json") for t in tickets], indent=2, default=str), encoding="utf-8")
    return dest


__all__ = ["import_tickets", "import_tickets_to_file", "ticket_row_to_model"]
