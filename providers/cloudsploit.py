"""Import CloudSploit-style scan rows (JSON/CSV) into ``ScannerFinding`` (+ optional ``SecurityEvent``).

CloudSploit is an **input adapter** only. Status codes follow common plugin semantics: ``0`` OK,
``2`` FAIL, ``3`` unable to query / error. Evaluations and KSI outcomes still come from our
evidence-chain pipeline, not from these rows alone.
"""

from __future__ import annotations

import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import FindingSeverity, FindingStatus, ScannerFinding, SecurityEvent, SemanticType

from providers.exposure_policy import semantic_type_from_public_exposure_policy
from providers.fixture import parse_iso_datetime
from providers.prowler import resolve_scanner_findings_output_path, write_scanner_findings_json


def _get(row: dict[str, Any], *keys: str) -> Any:
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        if k in row:
            return row[k]
        v = lower_map.get(k.lower())
        if v is not None:
            return v
    return None


def _norm_severity(raw: Any, *, status_code: int | None) -> FindingSeverity:
    s = str(raw or "").strip().lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s  # type: ignore[return-value]
    if status_code == 2:
        return "high"
    if status_code == 1:
        return "medium"
    return "info"


def _norm_status_from_code(code: int | None) -> FindingStatus:
    if code == 0:
        return "closed"
    if code == 2:
        return "open"
    if code == 1:
        return "open"
    if code == 3:
        return "unknown"
    return "unknown"


def _parse_status_code(raw: Any) -> int | None:
    if raw is None or raw == "":
        return None
    try:
        return int(str(raw).strip())
    except ValueError:
        return None


def _infer_cloud_provider(row: dict[str, Any], resource: str) -> str:
    p = _get(row, "cloud", "Cloud", "provider", "Provider", "platform", "Platform")
    if p and str(p).strip():
        return str(p).strip().lower()[:32]
    r = resource.lower()
    if r.startswith("arn:aws") or r.startswith("arn:aws-us-gov"):
        return "aws"
    if "azure" in r or "/subscriptions/" in r:
        return "azure"
    if resource.startswith("//") or "googleapis" in r or ".google.com" in r:
        return "gcp"
    return "aws"


def _stable_suffix(resource: str, plugin: str) -> str:
    h = hashlib.sha256(f"{plugin}|{resource}".encode("utf-8")).hexdigest()[:10]
    return h.upper()


def iter_cloudsploit_records(path: Path) -> list[dict[str, Any]]:
    """Load rows from ``.json`` (array or wrapped) or ``.csv`` or ``.ndjson``."""
    suf = path.suffix.lower()
    if suf == ".csv":
        with path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    if suf not in (".json", ".ndjson"):
        raise ValueError(f"Unsupported CloudSploit input extension: {path.suffix}")
    text = path.read_text(encoding="utf-8")
    if suf == ".ndjson":
        out: list[dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
        return out
    data = json.loads(text)
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("results", "data", "findings", "items", "checks"):
            block = data.get(key)
            if isinstance(block, list):
                return [x for x in block if isinstance(x, dict)]
        return [data]
    raise ValueError("Unsupported CloudSploit JSON shape")


def cloudsploit_row_to_scanner_finding(row: dict[str, Any], *, scanner_name: str = "cloudsploit") -> ScannerFinding:
    plugin = str(
        _get(row, "plugin", "Plugin", "check", "Check", "checkId", "check_id", "title", "Title") or "unknown-plugin"
    )
    category = _get(row, "category", "Category")
    status_code = _parse_status_code(_get(row, "status", "Status", "result", "Result"))
    message = str(_get(row, "message", "Message", "Description", "description") or plugin)
    region = _get(row, "region", "Region")
    resource = str(_get(row, "resource", "Resource", "ResourceArn", "resource_arn", "arn", "ARN") or "")
    sev_raw = _get(row, "severity", "Severity")
    remediation = _get(row, "recommended_action", "recommendedAction", "Remediation", "remediation")

    account = None
    if resource.startswith("arn:"):
        parts = resource.split(":")
        if len(parts) > 4 and parts[2] in ("ec2", "s3", "rds", "iam", "lambda", "kms"):
            account = parts[4]

    finding_id = f"cloudsploit-{plugin}-{_stable_suffix(resource or 'none', plugin)}"

    used_lower = {
        "plugin",
        "check",
        "checkid",
        "check_id",
        "category",
        "status",
        "result",
        "message",
        "region",
        "resource",
        "resourcearn",
        "resource_arn",
        "arn",
        "severity",
        "cloud",
        "provider",
        "platform",
        "recommended_action",
        "recommendedaction",
        "remediation",
    }
    extras = {k: v for k, v in row.items() if str(k).lower() not in used_lower}

    cloud = _infer_cloud_provider(row, resource)
    evidence_parts: list[str] = []
    evidence_parts.append(f"CloudSploit plugin `{plugin}` status_code={status_code}.")
    if message:
        evidence_parts.append(message)
    if resource:
        evidence_parts.append(f"Resource: {resource}.")
    if region:
        evidence_parts.append(f"Region: {region}.")
    if remediation:
        evidence_parts.append(f"Remediation: {remediation}.")
    evidence = " ".join(evidence_parts)

    meta: dict[str, Any] = {
        "source_format": "cloudsploit",
        "cloudsploit_plugin": plugin,
        "cloudsploit_category": category,
        "cloudsploit_cloud": cloud,
        "cloudsploit_region": region,
        "cloudsploit_account_id": account,
        "cloudsploit_status_code": status_code,
        "cloudsploit_severity_raw": str(sev_raw) if sev_raw is not None else None,
        "import_extras": extras,
    }
    if remediation is not None and str(remediation).strip():
        meta["remediation"] = str(remediation).strip()

    asset_hint = resource.split("/")[-1][:128] if resource else None

    return ScannerFinding(
        finding_id=finding_id,
        scanner_name=scanner_name,
        asset_id=asset_hint,
        target_id=(resource[:512] if resource else None),
        severity=_norm_severity(sev_raw, status_code=status_code),
        title=message[:500],
        cve_ids=[],
        plugin_id=plugin[:200],
        first_seen=None,
        last_seen=None,
        status=_norm_status_from_code(status_code),
        evidence=evidence,
        raw_ref=resource or None,
        exploitation_review={},
        metadata=meta,
    )


def cloudsploit_row_to_security_event(row: dict[str, Any], *, index: int) -> SecurityEvent | None:
    """Map failed public-exposure-style rows to semantic events (heuristic + YAML policy)."""
    code = _parse_status_code(_get(row, "status", "Status", "result", "Result"))
    if code != 2:
        return None
    plugin = str(_get(row, "plugin", "Plugin", "check", "check_id") or "").lower()
    message = str(_get(row, "message", "Message") or "").lower()
    blob = f"{plugin} {message}"
    sem: SemanticType = "unknown"
    if re.search(r"\bpublic\b.*\b(ip|ssh|rdp|22|3389)\b|0\.0\.0\.0/0", blob):
        sem = "network.public_admin_port_opened"
    elif "public" in blob and ("database" in blob or "rds" in blob):
        sem = "network.public_database_port_opened"
    else:
        from_policy = semantic_type_from_public_exposure_policy(check_id=plugin, title=message)
        if from_policy is not None:
            sem = from_policy
    if sem == "unknown":
        return None

    resource = str(_get(row, "resource", "Resource", "resource_arn") or f"cloudsploit-{index}")
    region = str(_get(row, "region", "Region") or "unknown")
    cloud = _infer_cloud_provider(row, resource)
    ts_raw = _get(row, "timestamp", "Timestamp", "time", "Time")
    ts = parse_iso_datetime(str(ts_raw)) if ts_raw else datetime.now(timezone.utc)

    return SecurityEvent(
        event_id=f"cloudsploit-ev-{index}-{_stable_suffix(resource, plugin or 'x')}",
        provider=cloud,
        semantic_type=sem,
        timestamp=ts,
        actor=None,
        asset_id=resource.split("/")[-1][:120] if resource else None,
        resource_id=resource[:512] if resource else None,
        raw_event_name=plugin or "cloudsploit_check",
        raw_ref=resource or None,
        metadata={
            "source_format": "cloudsploit",
            "plugin": plugin,
            "region": region,
            "status_code": code,
        },
    )


def import_cloudsploit(
    path: Path,
    *,
    scanner_name: str = "cloudsploit",
    emit_security_events: bool = True,
) -> tuple[list[ScannerFinding], list[SecurityEvent]]:
    rows = iter_cloudsploit_records(path)
    findings: list[ScannerFinding] = []
    events: list[SecurityEvent] = []
    for i, row in enumerate(rows):
        findings.append(cloudsploit_row_to_scanner_finding(row, scanner_name=scanner_name))
        if emit_security_events:
            ev = cloudsploit_row_to_security_event(row, index=i)
            if ev:
                events.append(ev)
    return findings, events


def import_cloudsploit_to_file(
    input_path: Path,
    output_path: Path,
    *,
    scanner_name: str = "cloudsploit",
    emit_security_events: bool = True,
) -> Path:
    dest = resolve_scanner_findings_output_path(output_path)
    findings, events = import_cloudsploit(
        input_path,
        scanner_name=scanner_name,
        emit_security_events=emit_security_events,
    )
    write_scanner_findings_json(
        dest,
        scanner=scanner_name,
        findings=findings,
        security_events=events or None,
    )
    return dest
