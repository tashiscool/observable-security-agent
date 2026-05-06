"""Universal scanner import router.

The router intentionally normalizes common export shapes into the existing
``scanner_findings.json`` contract instead of reimplementing any scanner.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from core.csv_utils import load_csv_rows
from core.models import FindingSeverity, FindingStatus, ScannerFinding, SecurityEvent
from providers.cloudsploit import import_cloudsploit
from providers.electriceye import import_electriceye
from providers.ocsf import import_ocsf
from providers.prowler import import_prowler, resolve_scanner_findings_output_path, write_scanner_findings_json

ScannerFormat = Literal["auto", "prowler", "cloudsploit", "ocsf", "electriceye", "nessus"]


def detect_scanner_format(path: Path) -> ScannerFormat:
    """Best-effort format detection from extension and header/content hints."""
    name = path.name.lower()
    text = path.read_text(encoding="utf-8-sig", errors="ignore")[:8192].lower()
    if "checkid" in text and ("status" in text or "status_extended" in text):
        return "prowler"
    if "cloudsploit" in text or ("plugin" in text and "status" in text and "resource" in text):
        return "cloudsploit"
    if "class_uid" in text and "finding_info" in text:
        return "ocsf"
    if "checktitle" in text and ("resourcearn" in text or "accountid" in text):
        return "electriceye"
    if "plugin id" in text and "risk" in text and ("host" in text or "asset" in text):
        return "nessus"
    if "nessus" in name:
        return "nessus"
    return "prowler"


def _get(row: dict[str, Any], *keys: str) -> Any:
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for key in keys:
        if key in row:
            return row[key]
        val = lower_map.get(key.lower())
        if val not in (None, ""):
            return val
    return None


def _norm_severity(raw: Any) -> FindingSeverity:
    s = str(raw or "").strip().lower()
    aliases = {
        "critical": "critical",
        "high": "high",
        "medium": "medium",
        "moderate": "medium",
        "low": "low",
        "info": "info",
        "informational": "info",
        "none": "info",
    }
    return aliases.get(s, "medium")  # type: ignore[return-value]


def _norm_status(raw: Any) -> FindingStatus:
    s = str(raw or "").strip().lower()
    if s in ("fixed", "closed", "resolved", "pass", "passed"):
        return "closed"
    if s in ("accepted", "risk accepted", "false_positive", "false positive"):
        return "accepted"
    if s in ("open", "new", "active", "fail", "failed", ""):
        return "open"
    return "unknown"


def _parse_dt(raw: Any) -> datetime | None:
    if raw is None or str(raw).strip() == "":
        return None
    s = str(raw).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


def nessus_row_to_scanner_finding(row: dict[str, Any], *, scanner_name: str = "nessus") -> ScannerFinding:
    plugin = str(_get(row, "Plugin ID", "plugin_id", "Plugin", "plugin") or "unknown-plugin")
    host = str(_get(row, "Host", "host", "Asset", "asset", "IP Address", "ip") or "")
    port = str(_get(row, "Port", "port") or "")
    name = str(_get(row, "Name", "name", "Synopsis", "synopsis") or plugin)
    risk = _get(row, "Risk", "risk", "Severity", "severity")
    status = _get(row, "Status", "status", "State", "state")
    first = _parse_dt(_get(row, "First Discovered", "first_seen", "First Seen"))
    last = _parse_dt(_get(row, "Last Observed", "last_seen", "Last Seen"))
    cve = str(_get(row, "CVE", "cve", "CVEs", "cves") or "")
    cves = [x.strip() for x in cve.replace(";", ",").split(",") if x.strip().upper().startswith("CVE-")][:20]
    desc = str(_get(row, "Description", "description", "Plugin Output", "plugin_output", "Solution", "solution") or name)
    key = hashlib.sha256(f"{plugin}|{host}|{port}|{name}".encode("utf-8")).hexdigest()[:16]
    return ScannerFinding(
        finding_id=f"nessus-{key}",
        scanner_name=scanner_name,
        asset_id=host[:120] if host else None,
        target_id=host or None,
        severity=_norm_severity(risk),
        title=name[:500],
        cve_ids=cves,
        plugin_id=plugin[:200],
        first_seen=first,
        last_seen=last,
        status=_norm_status(status),
        evidence=desc[:4000],
        raw_ref=host or None,
        exploitation_review={},
        metadata={
            "source_format": "nessus_like_csv",
            "host": host or None,
            "port": port or None,
            "risk_raw": risk,
            "status_raw": status,
        },
    )


def import_nessus(path: Path, *, scanner_name: str = "nessus") -> tuple[list[ScannerFinding], list[SecurityEvent]]:
    rows = load_csv_rows(path)
    return [nessus_row_to_scanner_finding(r, scanner_name=scanner_name) for r in rows], []


def import_scanner(
    path: Path,
    *,
    source_format: ScannerFormat = "auto",
    emit_security_events: bool = True,
) -> tuple[str, list[ScannerFinding], list[SecurityEvent]]:
    fmt = detect_scanner_format(path) if source_format == "auto" else source_format
    if fmt == "prowler":
        findings, events = import_prowler(path, emit_security_events=emit_security_events)
    elif fmt == "cloudsploit":
        findings, events = import_cloudsploit(path, emit_security_events=emit_security_events)
    elif fmt == "ocsf":
        findings, events = import_ocsf(path, emit_security_events=emit_security_events)
    elif fmt == "electriceye":
        findings, events = import_electriceye(path, emit_security_events=emit_security_events)
    elif fmt == "nessus":
        findings, events = import_nessus(path)
    else:
        raise ValueError(f"Unsupported scanner format: {fmt}")
    return fmt, findings, events


def import_scanner_to_file(
    input_path: Path,
    output_path: Path,
    *,
    source_format: ScannerFormat = "auto",
    emit_security_events: bool = True,
) -> Path:
    fmt, findings, events = import_scanner(
        input_path,
        source_format=source_format,
        emit_security_events=emit_security_events,
    )
    dest = resolve_scanner_findings_output_path(output_path)
    write_scanner_findings_json(dest, scanner=fmt, findings=findings, security_events=events or None)
    return dest


__all__ = [
    "detect_scanner_format",
    "import_nessus",
    "import_scanner",
    "import_scanner_to_file",
    "nessus_row_to_scanner_finding",
]
