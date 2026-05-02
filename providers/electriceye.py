"""Adapter for ElectricEye-style JSON rows (fixture / future API shape), not upstream ElectricEye code."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import FindingSeverity, ScannerFinding, SecurityEvent


from providers.exposure_policy import load_public_exposure_policy, semantic_type_from_public_exposure_policy
from providers.fixture import parse_iso_datetime


def _get(row: dict[str, Any], *keys: str) -> Any:
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        if k in row:
            return row[k]
        v = lower_map.get(k.lower())
        if v is not None:
            return v
    return None


def _stable_id(parts: str) -> str:
    return hashlib.sha256(parts.encode("utf-8")).hexdigest()[:12].upper()


def electric_eye_row_to_scanner_finding(
    row: dict[str, Any],
    *,
    scanner_name: str = "electriceye",
    policy: dict[str, Any] | None = None,
) -> ScannerFinding:
    """Map a simplified ElectricEye-style failure row to :class:`ScannerFinding`."""
    check_id = str(_get(row, "CheckId", "CheckID", "check_id") or "ee-unknown")
    title = str(_get(row, "CheckTitle", "check_title", "title") or check_id)
    resource = str(_get(row, "ResourceArn", "ResourceId", "resource_arn", "resource_id") or "")
    status_raw = str(_get(row, "Status", "status") or "FAIL").upper()
    region = str(_get(row, "Region", "region") or "")
    account = str(_get(row, "AccountId", "account_id") or "")
    ts_raw = _get(row, "UpdatedAt", "updated_at", "Timestamp", "timestamp")
    ts = parse_iso_datetime(str(ts_raw)) if isinstance(ts_raw, str) and ts_raw.strip() else datetime.now(timezone.utc)

    finding_id = f"ee-{check_id}-{_stable_id(f'{resource}|{check_id}')}"
    pol = policy if policy is not None else load_public_exposure_policy()
    sem_hint = semantic_type_from_public_exposure_policy(check_id=check_id, title=title, policy=pol)
    severity: FindingSeverity = "high" if status_raw in ("FAIL", "FAILED") and sem_hint else "medium"

    return ScannerFinding(
        finding_id=finding_id,
        scanner_name=scanner_name,
        asset_id=(resource.split("/")[-1][:120] if resource else None),
        target_id=resource[:512] if resource else None,
        severity=severity,  # type: ignore[arg-type]
        title=title[:500],
        plugin_id=check_id[:200],
        first_seen=ts,
        last_seen=ts,
        status="open" if status_raw in ("FAIL", "FAILED") else "closed",
        evidence=f"ElectricEye-style check `{check_id}` status `{status_raw}`. Resource: {resource or 'n/a'}.",
        raw_ref=resource or None,
        exploitation_review={},
        metadata={
            "source_format": "electriceye_style",
            "electriceye_check_id": check_id,
            "electriceye_region": region or None,
            "electriceye_account_id": account or None,
            "public_exposure_policy_semantic_hint": sem_hint,
        },
    )


def electric_eye_row_to_security_event(row: dict[str, Any], *, index: int, policy: dict[str, Any] | None = None) -> SecurityEvent | None:
    status_raw = str(_get(row, "Status", "status") or "").upper()
    if status_raw not in ("FAIL", "FAILED"):
        return None
    check_id = str(_get(row, "CheckId", "CheckID", "check_id") or "")
    title = str(_get(row, "CheckTitle", "check_title") or "")
    pol = policy if policy is not None else load_public_exposure_policy()
    sem = semantic_type_from_public_exposure_policy(check_id=check_id, title=title, policy=pol)
    if sem is None:
        return None
    resource = str(_get(row, "ResourceArn", "ResourceId", "resource_arn") or f"ee-{index}")
    region = str(_get(row, "Region", "region") or "unknown")
    account = str(_get(row, "AccountId", "account_id") or "unknown")
    ts_raw = _get(row, "UpdatedAt", "updated_at", "Timestamp", "timestamp")
    ts = parse_iso_datetime(str(ts_raw)) if isinstance(ts_raw, str) and ts_raw.strip() else datetime.now(timezone.utc)

    return SecurityEvent(
        event_id=f"ee-ev-{index}-{_stable_id(resource + check_id)}",
        provider="electriceye",
        semantic_type=sem,  # type: ignore[arg-type]
        timestamp=ts,
        asset_id=resource.split("/")[-1][:120] if resource else None,
        resource_id=resource[:512] if resource else None,
        raw_event_name=check_id or "electriceye_check",
        raw_ref=resource or None,
        metadata={
            "source_format": "electriceye_style",
            "check_id": check_id,
            "region": region,
            "account_id": account,
            "status": status_raw,
        },
    )


def iter_electriceye_rows(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict) and isinstance(data.get("findings"), list):
        return [x for x in data["findings"] if isinstance(x, dict)]
    if isinstance(data, dict):
        return [data]
    raise ValueError("Unsupported ElectricEye-style JSON shape")


def import_electriceye(
    path: Path,
    *,
    scanner_name: str = "electriceye",
    emit_security_events: bool = True,
    policy: dict[str, Any] | None = None,
) -> tuple[list[ScannerFinding], list[SecurityEvent]]:
    rows = iter_electriceye_rows(path)
    findings = [electric_eye_row_to_scanner_finding(r, scanner_name=scanner_name, policy=policy) for r in rows]
    events: list[SecurityEvent] = []
    if emit_security_events:
        for i, r in enumerate(rows):
            ev = electric_eye_row_to_security_event(r, index=i, policy=policy)
            if ev:
                events.append(ev)
    return findings, events


__all__ = [
    "electric_eye_row_to_scanner_finding",
    "electric_eye_row_to_security_event",
    "import_electriceye",
    "iter_electriceye_rows",
]
