"""Import Prowler JSON/CSV exports into canonical ``ScannerFinding`` (+ optional ``SecurityEvent`` rows).

Prowler is an **input adapter** only; evaluations still run against the normalized assessment bundle.
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


def _get(row: dict[str, Any], *keys: str) -> Any:
    lower_map = {str(k).lower(): v for k, v in row.items()}
    for k in keys:
        if k in row:
            return row[k]
        v = lower_map.get(k.lower())
        if v is not None:
            return v
    return None


def _norm_severity(raw: Any) -> FindingSeverity:
    s = str(raw or "info").strip().lower()
    if s in ("critical", "high", "medium", "low", "info"):
        return s  # type: ignore[return-value]
    return "info"


def _norm_status(raw: Any) -> FindingStatus:
    st = str(raw or "unknown").strip().upper()
    if st in ("FAIL", "FAILED", "MANUAL"):
        return "open"
    if st in ("PASS", "PASSED", "OK"):
        return "closed"
    if st in ("MUTED", "EXCEPTION"):
        return "accepted"
    s = str(raw or "unknown").strip().lower()
    if s in ("open", "closed", "accepted", "false_positive", "unknown"):
        return s  # type: ignore[return-value]
    return "unknown"


def _looks_like_prowler_compliance_framework_definition(data: dict[str, Any]) -> bool:
    """True for compliance *definitions* (control→check mapping), not executed per-resource results."""
    if data.get("framework") == "GenericCompliance" and (
        isinstance(data.get("Compliance"), list) or isinstance(data.get("requirements"), list)
    ):
        return True
    if data.get("Framework") and isinstance(data.get("Requirements"), list):
        req0 = data["Requirements"][0] if data["Requirements"] else None
        if isinstance(req0, dict) and "Checks" in req0:
            return True
    return False


def _looks_like_prowler_check_metadata_stub(row: dict[str, Any]) -> bool:
    """Prowler *check card* JSON (metadata template) lacks executed-result fields."""
    if row.get("ResourceIdTemplate") is not None:
        return True
    check_id = _get(row, "CheckID", "check_id")
    resource = _get(row, "ResourceId", "resource_id", "ResourceArn", "resource_arn", "resource")
    status = _get(row, "Status", "status")
    if check_id and status is None and not (resource and str(resource).strip().lower().startswith("arn:")):
        return True
    return False


def iter_prowler_records(path: Path) -> list[dict[str, Any]]:
    """Load Prowler rows from ``.json`` (array or wrapped list) or ``.csv``."""
    suf = path.suffix.lower()
    if suf == ".csv":
        with path.open(newline="", encoding="utf-8") as f:
            return list(csv.DictReader(f))
    if suf not in (".json", ".ndjson"):
        raise ValueError(f"Unsupported Prowler input extension: {path.suffix}")
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
        if _looks_like_prowler_compliance_framework_definition(data):
            raise ValueError(
                "Prowler JSON is a compliance framework definition (control→check mapping), "
                "not executed check rows. Use universal JSON/CSV scan output."
            )
        for key in ("results", "checks", "data", "findings", "items", "Findings"):
            block = data.get(key)
            if isinstance(block, list):
                return [x for x in block if isinstance(x, dict)]
        if _looks_like_prowler_check_metadata_stub(data):
            raise ValueError(
                "Prowler JSON looks like check metadata (check card / output template), "
                "not scan result rows. Expected an array or an object with a 'results' list."
            )
        # Single executed-result object (some exporters wrap one row as an object).
        return [data]
    raise ValueError("Unsupported Prowler JSON shape (expected array or object with a list of checks)")


def _stable_suffix(resource: str, check_id: str) -> str:
    h = hashlib.sha256(f"{check_id}|{resource}".encode("utf-8")).hexdigest()[:10]
    return h.upper()


def prowler_row_to_scanner_finding(row: dict[str, Any], *, scanner_name: str = "prowler") -> ScannerFinding:
    check_id = str(_get(row, "CheckID", "check_id", "checkid") or "unknown-check")
    resource = str(
        _get(
            row,
            "ResourceId",
            "resource_id",
            "resource_uid",
            "ResourceArn",
            "resource_arn",
            "ResourceARN",
            "resource",
        )
        or ""
    )
    title = str(_get(row, "CheckTitle", "check_title", "Message", "message", "Description") or check_id)
    status_raw = _get(row, "Status", "status")
    status_extended = _get(row, "StatusExtended", "status_extended", "StatusDetail", "status_detail")
    sev_raw = _get(row, "Severity", "severity", "Risk", "risk")
    region = _get(row, "Region", "region", "RegionName")
    account = _get(row, "AccountId", "account_id", "Account", "account")
    service = _get(row, "ServiceName", "service_name", "Service", "service")
    provider = _get(row, "Provider", "provider", "CloudProvider", "cloud_provider", "Partition", "partition")
    compliance = _get(row, "Compliance", "compliance", "RelatedRequirements", "related_requirements")
    remediation = _get(
        row,
        "Remediation",
        "remediation",
        "RecommendedAction",
        "recommended_action",
        "RemediationText",
        "remediation_text",
        "RemediationRecommendation",
        "remediation_recommendation",
    )
    finding_id = f"prowler-{check_id}-{_stable_suffix(resource or 'none', check_id)}"

    used_lower = {
        "checkid",
        "check_id",
        "resourceid",
        "resource_id",
        "resource_uid",
        "resourcearn",
        "resource_arn",
        "resource",
        "checktitle",
        "check_title",
        "message",
        "description",
        "status",
        "statusextended",
        "status_extended",
        "statusdetail",
        "status_detail",
        "severity",
        "risk",
        "region",
        "regionname",
        "accountid",
        "account_id",
        "account",
        "servicename",
        "service_name",
        "service",
        "compliance",
        "related_requirements",
        "provider",
        "cloudprovider",
        "cloud_provider",
        "partition",
        "remediation",
        "recommendedaction",
        "recommended_action",
        "remediationtext",
        "remediation_text",
    }
    extras = {k: v for k, v in row.items() if str(k).lower() not in used_lower}

    evidence_parts = [f"Prowler check `{check_id}` status `{status_raw}`."]
    if resource:
        evidence_parts.append(f"Resource: {resource}.")
    if region:
        evidence_parts.append(f"Region: {region}.")
    if status_extended and str(status_extended).strip():
        evidence_parts.append(f"Detail: {status_extended}.")
    if remediation and str(remediation).strip():
        evidence_parts.append(f"Remediation: {remediation}.")
    evidence = " ".join(evidence_parts)

    meta: dict[str, Any] = {
        "source_format": "prowler",
        "prowler_check_id": check_id,
        "prowler_service": service,
        "prowler_resource": resource,
        "prowler_region": region,
        "prowler_account_id": account,
        "prowler_provider": str(provider) if provider is not None else None,
        "prowler_status": str(status_raw) if status_raw is not None else None,
        "prowler_status_extended": str(status_extended) if status_extended is not None else None,
        "prowler_severity_raw": str(sev_raw) if sev_raw is not None else None,
        "import_extras": extras,
    }
    if isinstance(compliance, (dict, list)):
        meta["compliance"] = compliance
    elif compliance is not None and str(compliance).strip():
        meta["compliance"] = str(compliance).strip()
    if remediation is not None and str(remediation).strip():
        meta["remediation"] = remediation if isinstance(remediation, (dict, list)) else str(remediation).strip()

    first_seen = None
    last_seen = None
    for ts_key in ("AssessmentDate", "assessment_date", "Timestamp", "timestamp", "UpdatedAt", "updated_at"):
        raw_ts = _get(row, ts_key)
        if raw_ts:
            parsed = parse_iso_datetime(str(raw_ts)) if isinstance(raw_ts, str) else None
            if parsed:
                first_seen = first_seen or parsed
                last_seen = parsed

    cve_raw = _get(row, "CVE", "cve", "cve_ids", "CveIds")
    cve_ids: list[str] = []
    if isinstance(cve_raw, str) and cve_raw.strip():
        cve_ids = [cve_raw.strip()]
    elif isinstance(cve_raw, list):
        cve_ids = [str(x).strip() for x in cve_raw if str(x).strip()]

    asset_hint = None
    if resource:
        parts = resource.split("/")
        asset_hint = parts[-1][:128] if parts else resource[:128]

    return ScannerFinding(
        finding_id=finding_id,
        scanner_name=scanner_name,
        asset_id=asset_hint,
        target_id=(resource[:512] if resource else None),
        severity=_norm_severity(sev_raw if sev_raw is not None else ("high" if str(status_raw).upper() in ("FAIL", "FAILED") else "info")),
        title=title[:500],
        cve_ids=cve_ids,
        plugin_id=check_id[:200],
        first_seen=first_seen,
        last_seen=last_seen,
        status=_norm_status(status_raw),
        evidence=evidence,
        raw_ref=resource or None,
        exploitation_review={},
        metadata=meta,
    )


def prowler_row_to_security_event(row: dict[str, Any], *, index: int) -> SecurityEvent | None:
    """Emit a ``SecurityEvent`` only when a failed check clearly implies public exposure (heuristic)."""
    status_raw = str(_get(row, "Status", "status") or "").upper()
    if status_raw not in ("FAIL", "FAILED"):
        return None
    title = str(_get(row, "CheckTitle", "check_title", "Message", "message") or "").lower()
    check_id = str(_get(row, "CheckID", "check_id") or "").lower()
    blob = f"{title} {check_id}"
    sem: SemanticType = "unknown"
    if re.search(r"\bpublic\b.*\b(admin|ssh|rdp|3389|22)\b|\b0\.0\.0\.0/0\b", blob):
        sem = "network.public_admin_port_opened"
    elif "public" in blob and ("database" in blob or "rds" in blob or "3306" in blob or "5432" in blob):
        sem = "network.public_database_port_opened"
    else:
        from_policy = semantic_type_from_public_exposure_policy(check_id=check_id, title=title)
        if from_policy is not None:
            sem = from_policy
    if sem == "unknown":
        return None

    resource = str(_get(row, "ResourceId", "resource_id", "resource_arn", "resource") or f"prowler-{index}")
    region = str(_get(row, "Region", "region") or "unknown")
    account = str(_get(row, "AccountId", "account_id", "account") or "unknown")
    ts_raw = _get(row, "AssessmentDate", "assessment_date", "Timestamp", "timestamp")
    ts = parse_iso_datetime(str(ts_raw)) if ts_raw else datetime.now(timezone.utc)

    prov_raw = _get(row, "Provider", "provider", "Partition", "partition")
    resource_l = (resource or "").lower()
    if prov_raw and str(prov_raw).strip():
        prov = str(prov_raw).strip().lower()
        if prov in ("aws", "azure", "gcp", "kubernetes", "k8s"):
            provider_name = prov if prov != "kubernetes" else "k8s"
        else:
            provider_name = "aws" if resource_l.startswith("arn:aws") else "prowler"
    elif resource_l.startswith("arn:aws"):
        provider_name = "aws"
    elif resource_l.startswith("arn:aws-us-gov"):
        provider_name = "aws"
    else:
        provider_name = "prowler"

    return SecurityEvent(
        event_id=f"prowler-ev-{index}-{_stable_suffix(resource, check_id or 'x')}",
        provider=provider_name,
        semantic_type=sem,
        timestamp=ts,
        actor=None,
        asset_id=resource.split("/")[-1][:120] if resource else None,
        resource_id=resource[:512] if resource else None,
        raw_event_name=str(_get(row, "CheckID", "check_id") or "prowler_check"),
        raw_ref=resource or None,
        metadata={
            "source_format": "prowler",
            "check_id": check_id,
            "region": region,
            "account_id": account,
            "status": status_raw,
            "check_title": _get(row, "CheckTitle", "check_title"),
        },
    )


def resolve_scanner_findings_output_path(output: Path) -> Path:
    """Return path to ``scanner_findings.json``.

    If ``output`` ends with ``.json`` and is not a directory, use it as the file path
    (legacy single-file mode). Otherwise treat ``output`` as a **scenario directory**
    and return ``output / \"scanner_findings.json\"``.
    """
    output = output.resolve()
    if output.suffix.lower() == ".json" and not output.is_dir():
        output.parent.mkdir(parents=True, exist_ok=True)
        return output
    output.mkdir(parents=True, exist_ok=True)
    return output / "scanner_findings.json"


def import_prowler(
    path: Path,
    *,
    scanner_name: str = "prowler",
    emit_security_events: bool = True,
) -> tuple[list[ScannerFinding], list[SecurityEvent]]:
    rows = iter_prowler_records(path)
    findings: list[ScannerFinding] = []
    events: list[SecurityEvent] = []
    for i, row in enumerate(rows):
        findings.append(prowler_row_to_scanner_finding(row, scanner_name=scanner_name))
        if emit_security_events:
            ev = prowler_row_to_security_event(row, index=i)
            if ev:
                events.append(ev)
    return findings, events


def write_scanner_findings_json(
    out_path: Path,
    *,
    scanner: str,
    findings: list[ScannerFinding],
    security_events: list[SecurityEvent] | None = None,
) -> None:
    """Write the ``scanner_findings.json`` wrapper used by fixture / pipeline bundles."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc: dict[str, Any] = {
        "scanner": scanner,
        "export_time": datetime.now(timezone.utc).isoformat(),
        "findings": [f.model_dump(mode="json") for f in findings],
    }
    if security_events:
        doc["security_events"] = [e.model_dump(mode="json") for e in security_events]
    out_path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")


def import_prowler_to_file(
    input_path: Path,
    output_path: Path,
    *,
    scanner_name: str = "prowler",
    emit_security_events: bool = True,
) -> Path:
    dest = resolve_scanner_findings_output_path(output_path)
    findings, events = import_prowler(
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
