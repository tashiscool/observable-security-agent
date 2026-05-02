"""Import OCSF Detection Finding-like JSON into ``ScannerFinding`` (+ optional ``SecurityEvent``).

OCSF is an **input adapter** only; the evaluation layer is unchanged.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import FindingSeverity, FindingStatus, ScannerFinding, SecurityEvent, SemanticType

from providers.fixture import parse_iso_datetime
from providers.prowler import write_scanner_findings_json


def _dt(val: Any) -> datetime:
    if val is None:
        return datetime.now(timezone.utc)
    if isinstance(val, str) and val.strip():
        s = val.strip()
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        try:
            return datetime.fromisoformat(s)
        except ValueError:
            return parse_iso_datetime(s) if "T" in s else datetime.now(timezone.utc)
    if isinstance(val, (int, float)):
        sec = float(val)
        if sec > 1e15:
            sec /= 1e9
        elif sec > 1e12:
            sec /= 1000.0
        return datetime.fromtimestamp(sec, tz=timezone.utc)
    return datetime.now(timezone.utc)


def _ocsf_severity(rec: dict[str, Any]) -> FindingSeverity:
    # Numeric OCSF severity_id (common scale)
    sid = rec.get("severity_id")
    if isinstance(sid, int) or (isinstance(sid, str) and str(sid).isdigit()):
        n = int(sid)
        return {1: "info", 2: "info", 3: "low", 4: "medium", 5: "high", 6: "critical"}.get(n, "medium")  # type: ignore[return-value]
    s = str(rec.get("severity") or (rec.get("finding") or {}).get("severity") or "medium").lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s  # type: ignore[return-value]
    return "medium"


def _ocsf_status(rec: dict[str, Any]) -> FindingStatus:
    st = rec.get("status") or rec.get("status_code") or rec.get("state")
    if isinstance(st, str):
        sl = st.lower()
        if sl in ("open", "new", "active"):
            return "open"
        if sl in ("closed", "resolved", "dismissed"):
            return "closed"
        if sl in ("suppressed", "accepted"):
            return "accepted"
    return "open"


def map_ocsf_to_semantic_type(rec: dict[str, Any]) -> SemanticType:
    """Best-effort semantic mapping; unknown OCSF combinations become ``unknown``."""
    act = str(rec.get("activity_name") or "").lower()
    uid = str(rec.get("category_uid") or "")
    cls = str(rec.get("class_uid") or "")
    title = str((rec.get("finding_info") or {}).get("title") or "").lower()
    combined = f"{act} {title} {uid} {cls}".lower()
    if "privilege" in combined or "admin_role" in combined or "role granted" in combined:
        return "identity.admin_role_granted"
    if "mfa" in combined and ("disabl" in combined or "off" in combined):
        return "identity.mfa_disabled"
    if "public" in combined and ("ssh" in combined or "22" in combined or "rdp" in combined or "3389" in combined):
        return "network.public_admin_port_opened"
    if "public" in combined and ("database" in combined or "rds" in combined or "5432" in combined or "3306" in combined):
        return "network.public_database_port_opened"
    if "vulnerab" in combined or "cve" in combined or "scanner" in combined:
        return "scanner.high_vulnerability_detected"
    return "unknown"


def iter_ocsf_detection_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        if isinstance(data.get("findings"), list):
            return [x for x in data["findings"] if isinstance(x, dict)]
        return [data]
    raise ValueError("Unsupported OCSF JSON shape")


def ocsf_detection_to_scanner_finding(rec: dict[str, Any], *, scanner_name: str = "ocsf") -> ScannerFinding:
    meta_block = rec.get("metadata") if isinstance(rec.get("metadata"), dict) else {}
    fi = rec.get("finding_info") if isinstance(rec.get("finding_info"), dict) else {}
    resource = rec.get("resource") if isinstance(rec.get("resource"), dict) else {}
    cloud = rec.get("cloud") if isinstance(rec.get("cloud"), dict) else {}

    sem = map_ocsf_to_semantic_type(rec)

    fid = str(meta_block.get("uid") or fi.get("uid") or rec.get("uuid") or "ocsf-detection")
    title = str(fi.get("title") or fi.get("desc") or "OCSF detection finding")
    desc = str(fi.get("desc") or fi.get("description") or title)

    rid = str(resource.get("uid") or resource.get("id") or resource.get("name") or "")
    region = str(resource.get("region") or resource.get("region_id") or "")
    account = str(cloud.get("account", {}).get("uid") if isinstance(cloud.get("account"), dict) else cloud.get("account_uid") or "")

    remediation = rec.get("remediation") or rec.get("remediations")
    used_keys = {
        "metadata",
        "finding_info",
        "resource",
        "cloud",
        "time",
        "severity_id",
        "severity",
        "status",
        "activity_name",
        "category_uid",
        "class_uid",
        "remediation",
        "remediations",
    }
    extras = {k: v for k, v in rec.items() if k not in used_keys}

    meta: dict[str, Any] = {
        "source_format": "ocsf",
        "semantic_type": sem,
        "ocsf_class_uid": rec.get("class_uid"),
        "ocsf_category_uid": rec.get("category_uid"),
        "ocsf_activity_name": rec.get("activity_name"),
        "ocsf_activity_id": rec.get("activity_id"),
        "ocsf_resource": resource,
        "ocsf_cloud": cloud,
        "ocsf_finding_info": fi,
        "import_extras": extras,
    }
    if remediation is not None:
        meta["remediation"] = remediation

    ts = _dt(rec.get("time") or meta_block.get("create_time") or meta_block.get("start_time"))

    cve_raw = fi.get("cves")
    cve_ids: list[str] = (
        [str(x).strip() for x in cve_raw if str(x).strip()][:20] if isinstance(cve_raw, list) else []
    )
    types_val = fi.get("types") or fi.get("type")
    if isinstance(types_val, list):
        plugin_s = ",".join(str(x) for x in types_val)[:200]
    elif types_val is not None:
        plugin_s = str(types_val)[:200]
    else:
        plugin_s = None

    if region:
        meta["ocsf_region"] = region
    if account:
        meta["ocsf_account_id"] = account

    return ScannerFinding(
        finding_id=f"ocsf-{hashlib.sha256(fid.encode()).hexdigest()[:16]}",
        scanner_name=scanner_name,
        asset_id=(rid[:120] if rid else None),
        target_id=(rid or None),
        severity=_ocsf_severity(rec),
        title=title[:500],
        cve_ids=cve_ids,
        plugin_id=plugin_s,
        first_seen=ts,
        last_seen=ts,
        status=_ocsf_status(rec),
        evidence=desc[:4000] if desc else title,
        raw_ref=rid or None,
        exploitation_review={},
        metadata=meta,
    )


def ocsf_detection_to_security_event(rec: dict[str, Any], *, index: int) -> SecurityEvent:
    sem = map_ocsf_to_semantic_type(rec)
    meta_block = rec.get("metadata") if isinstance(rec.get("metadata"), dict) else {}
    resource = rec.get("resource") if isinstance(rec.get("resource"), dict) else {}
    cloud = rec.get("cloud") if isinstance(rec.get("cloud"), dict) else {}
    fid = str(meta_block.get("uid") or f"ocsf-{index}")
    provider = str(cloud.get("provider") or "unknown").strip() or "unknown"
    rid = str(resource.get("uid") or "")
    ts = _dt(rec.get("time") or meta_block.get("create_time"))

    provider_meta = {
        "source_format": "ocsf",
        "class_uid": rec.get("class_uid"),
        "category_uid": rec.get("category_uid"),
        "activity_name": rec.get("activity_name"),
        "finding_uid": fid,
        "import_raw_subset": {k: rec.get(k) for k in ("message", "type_uid", "category_name", "class_name") if k in rec},
    }
    return SecurityEvent(
        event_id=f"ocsf-ev-{index}-{hashlib.sha256(fid.encode()).hexdigest()[:12]}",
        provider=provider,
        semantic_type=sem,
        timestamp=ts,
        asset_id=(rid.split("/")[-1][:120] if rid else None),
        resource_id=rid or None,
        raw_event_name=str(rec.get("activity_name") or "ocsf_detection"),
        raw_ref=rid or None,
        metadata=provider_meta,
    )


def import_ocsf(
    path: Path,
    *,
    scanner_name: str = "ocsf",
    emit_security_events: bool = True,
) -> tuple[list[ScannerFinding], list[SecurityEvent]]:
    rows = iter_ocsf_detection_records(path)
    findings = [ocsf_detection_to_scanner_finding(r, scanner_name=scanner_name) for r in rows]
    events: list[SecurityEvent] = []
    if emit_security_events:
        for i, r in enumerate(rows):
            events.append(ocsf_detection_to_security_event(r, index=i))
    return findings, events


def import_ocsf_to_file(
    input_path: Path,
    output_path: Path,
    *,
    scanner_name: str = "ocsf",
    emit_security_events: bool = True,
) -> None:
    findings, events = import_ocsf(
        input_path, scanner_name=scanner_name, emit_security_events=emit_security_events
    )
    write_scanner_findings_json(
        output_path,
        scanner=scanner_name,
        findings=findings,
        security_events=events if emit_security_events else None,
    )
