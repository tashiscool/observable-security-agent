"""Normalize scanner, cloud config, and telemetry rows into platform domain models."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import ValidationError

from core.csv_utils import load_csv_rows
from core.domain_models import EvidenceArtifact, NormalizedFinding


SourceAdapter = Literal[
    "vulnerability_scan_json",
    "cloud_config_json",
    "container_scan_csv",
    "scanner_router",
]


@dataclass(frozen=True)
class FreshnessThresholds:
    """Freshness thresholds in days."""

    current_days: int = 7
    stale_days: int = 30


@dataclass(frozen=True)
class NormalizationDiagnostic:
    """Non-fatal warning or fatal row error from normalization."""

    row_index: int
    raw_ref: str
    message: str


@dataclass
class EvidenceNormalizationResult:
    evidence_artifacts: list[EvidenceArtifact] = field(default_factory=list)
    findings: list[NormalizedFinding] = field(default_factory=list)
    errors: list[NormalizationDiagnostic] = field(default_factory=list)
    warnings: list[NormalizationDiagnostic] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def _now() -> datetime:
    return datetime.now(timezone.utc)


def parse_datetime(value: Any) -> datetime | None:
    if value is None or str(value).strip() == "":
        return None
    if isinstance(value, datetime):
        return value
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _get(row: dict[str, Any], *keys: str) -> Any:
    lower = {str(k).lower().replace("_", "").replace(" ", ""): v for k, v in row.items()}
    for key in keys:
        if key in row:
            return row[key]
        norm = key.lower().replace("_", "").replace(" ", "")
        val = lower.get(norm)
        if val not in (None, ""):
            return val
    return None


def _list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip() for x in value if str(x).strip()]
    return [x.strip() for x in str(value).replace(";", ",").split(",") if x.strip()]


def normalize_severity(value: Any) -> str:
    s = str(value or "").strip().lower()
    aliases = {
        "critical": "CRITICAL",
        "crit": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "moderate": "MEDIUM",
        "med": "MEDIUM",
        "low": "LOW",
        "info": "INFORMATIONAL",
        "informational": "INFORMATIONAL",
        "none": "INFORMATIONAL",
        "ok": "INFORMATIONAL",
        "pass": "INFORMATIONAL",
        "passed": "INFORMATIONAL",
    }
    return aliases.get(s, "UNKNOWN")


def normalize_finding_status(value: Any) -> str:
    s = str(value or "").strip().lower()
    aliases = {
        "open": "OPEN",
        "active": "OPEN",
        "new": "OPEN",
        "fail": "OPEN",
        "failed": "OPEN",
        "finding": "OPEN",
        "fixed": "FIXED",
        "closed": "FIXED",
        "resolved": "FIXED",
        "pass": "FIXED",
        "passed": "FIXED",
        "suppressed": "SUPPRESSED",
        "muted": "SUPPRESSED",
        "exception": "SUPPRESSED",
        "false_positive": "FALSE_POSITIVE",
        "false positive": "FALSE_POSITIVE",
        "fp": "FALSE_POSITIVE",
        "accepted": "RISK_ACCEPTED",
        "risk accepted": "RISK_ACCEPTED",
        "risk_accepted": "RISK_ACCEPTED",
    }
    return aliases.get(s, "UNKNOWN")


def freshness_status(
    observed_at: datetime | None,
    collected_at: datetime,
    *,
    thresholds: FreshnessThresholds,
    now: datetime | None = None,
) -> str:
    anchor = observed_at or collected_at
    ref = now or _now()
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=timezone.utc)
    age = ref - anchor
    if age <= timedelta(days=thresholds.current_days):
        return "current"
    if age <= timedelta(days=thresholds.stale_days):
        return "stale"
    return "expired"


def _stable_hash(*parts: Any, length: int = 20) -> str:
    text = "|".join(str(p or "") for p in parts)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:length]


def _resource_from_arn(arn: str | None) -> str | None:
    if not arn:
        return None
    return arn.split("/")[-1].split(":")[-1] or arn


def _identity_key(row: dict[str, Any], *, scanner: str, finding_id: str | None) -> tuple[str, str]:
    if finding_id:
        return ("finding_id", f"{scanner}|{finding_id}")
    vulnerability_id = str(_get(row, "vulnerabilityId", "vulnerability_id", "cve", "cveId", "CVE") or "").strip()
    package_name = str(_get(row, "packageName", "package_name", "package", "pkgName") or "").strip()
    package_version = str(_get(row, "packageVersion", "package_version", "installedVersion", "installed_version") or "").strip()
    resource_id = str(_get(row, "resourceId", "resource_id", "assetId", "asset_id", "host", "Host") or "").strip()
    resource_arn = str(_get(row, "resourceArn", "resource_arn", "arn", "ResourceArn") or "").strip()
    image_digest = str(_get(row, "imageDigest", "image_digest", "digest") or "").strip()
    resource = resource_id or _resource_from_arn(str(resource_arn) if resource_arn else None) or image_digest
    return ("fallback", f"{scanner}|{vulnerability_id}|{package_name}|{package_version}|{resource}")


def _merge_finding(existing: NormalizedFinding, new: NormalizedFinding) -> NormalizedFinding:
    evidence_ids = sorted(set(existing.evidence_ids) | set(new.evidence_ids))
    control_ids = sorted(set(existing.control_ids) | set(new.control_ids))
    firsts = [d for d in (existing.first_observed_at, new.first_observed_at) if d is not None]
    lasts = [d for d in (existing.last_observed_at, new.last_observed_at) if d is not None]
    return existing.model_copy(
        update={
            "evidence_ids": evidence_ids,
            "control_ids": control_ids,
            "first_observed_at": min(firsts) if firsts else None,
            "last_observed_at": max(lasts) if lasts else None,
            "status": new.status if existing.status == "UNKNOWN" else existing.status,
            "severity": new.severity if existing.severity == "UNKNOWN" else existing.severity,
        }
    )


def _normalize_record(
    row: dict[str, Any],
    *,
    row_index: int,
    source_system: str,
    source_type: str,
    default_scanner: str,
    collected_at: datetime,
    thresholds: FreshnessThresholds,
    source_path: Path | None,
) -> tuple[EvidenceArtifact, NormalizedFinding, list[NormalizationDiagnostic]]:
    if not isinstance(row, dict):
        raise ValueError("record must be an object")

    scanner = str(_get(row, "scanner", "scannerName", "scanner_name") or default_scanner or source_system)
    finding_id_raw = _get(row, "findingId", "finding_id", "id", "findingUid", "plugin_id", "checkId", "CheckID")
    finding_id = str(finding_id_raw).strip() if finding_id_raw not in (None, "") else None
    identity_kind, identity = _identity_key(row, scanner=scanner, finding_id=finding_id)
    if identity_kind == "fallback" and not any(identity.split("|")[1:]):
        raise ValueError("record missing findingId and fallback identity fields")

    normalized_finding_id = finding_id or f"nf-{_stable_hash(identity)}"
    account_id = _get(row, "accountId", "account_id", "account", "AccountId")
    region = _get(row, "region", "Region")
    resource_arn = _get(row, "resourceArn", "resource_arn", "arn", "ResourceArn")
    resource_id = (
        _get(row, "resourceId", "resource_id", "assetId", "asset_id", "host", "Host", "resource", "Resource")
        or _resource_from_arn(str(resource_arn) if resource_arn else None)
    )
    resource_type = _get(row, "resourceType", "resource_type", "type", "resourceKind", "service", "Service")
    vulnerability_id = _get(row, "vulnerabilityId", "vulnerability_id", "cve", "cveId", "CVE")
    package_name = _get(row, "packageName", "package_name", "package", "pkgName")
    package_version = _get(row, "packageVersion", "package_version", "installedVersion", "installed_version")
    fixed_version = _get(row, "fixedVersion", "fixed_version", "patchedVersion", "remediationVersion")
    image_digest = _get(row, "imageDigest", "image_digest", "digest")
    image_tag = _get(row, "imageTag", "image_tag", "tag")
    control_ids = _list(_get(row, "controlIds", "control_ids", "controls", "Compliance", "compliance"))

    observed_at = (
        parse_datetime(_get(row, "observedAt", "observed_at", "lastObservedAt", "last_seen", "lastSeen", "updatedAt", "timestamp"))
        or parse_datetime(_get(row, "firstObservedAt", "first_seen", "firstSeen"))
        or collected_at
    )
    first_observed_at = parse_datetime(_get(row, "firstObservedAt", "first_observed_at", "first_seen", "firstSeen")) or observed_at
    last_observed_at = parse_datetime(_get(row, "lastObservedAt", "last_observed_at", "last_seen", "lastSeen", "updatedAt")) or observed_at
    severity = normalize_severity(_get(row, "severity", "Severity", "risk", "Risk"))
    status = normalize_finding_status(_get(row, "status", "Status", "state", "State", "result", "Result"))
    title = str(_get(row, "title", "Title", "name", "Name", "checkTitle", "CheckTitle") or normalized_finding_id)
    description = str(
        _get(row, "description", "Description", "message", "Message", "evidence", "plugin_output", "statusExtended")
        or title
    )

    raw_ref = str(_get(row, "rawRef", "raw_ref") or "")
    if not raw_ref:
        raw_ref = f"{source_path or source_system}#{row_index}"
    evidence_id = f"ev-{_stable_hash(source_system, source_type, raw_ref, identity)}"
    warnings: list[NormalizationDiagnostic] = []
    if image_tag and not image_digest:
        warnings.append(
            NormalizationDiagnostic(
                row_index=row_index,
                raw_ref=raw_ref,
                message="container image tag supplied without imageDigest; digest is preferred for stable evidence identity",
            )
        )

    artifact = EvidenceArtifact(
        evidenceId=evidence_id,
        sourceSystem=source_system,
        sourceType=source_type,
        collectedAt=collected_at,
        observedAt=observed_at,
        accountId=str(account_id) if account_id not in (None, "") else None,
        region=str(region) if region not in (None, "") else None,
        resourceId=str(resource_id) if resource_id not in (None, "") else None,
        resourceArn=str(resource_arn) if resource_arn not in (None, "") else None,
        resourceType=str(resource_type) if resource_type not in (None, "") else None,
        scanner=scanner,
        findingId=normalized_finding_id,
        vulnerabilityId=str(vulnerability_id) if vulnerability_id not in (None, "") else None,
        packageName=str(package_name) if package_name not in (None, "") else None,
        packageVersion=str(package_version) if package_version not in (None, "") else None,
        imageDigest=str(image_digest) if image_digest not in (None, "") else None,
        controlIds=control_ids,
        rawRef=raw_ref,
        normalizedSummary=description[:1000],
        trustLevel="derived",
        freshnessStatus=freshness_status(observed_at, collected_at, thresholds=thresholds),
    )
    finding = NormalizedFinding(
        findingId=normalized_finding_id,
        sourceSystem=source_system,
        scanner=scanner,
        title=title[:500],
        description=description[:4000],
        severity=severity,  # type: ignore[arg-type]
        status=status,  # type: ignore[arg-type]
        vulnerabilityId=str(vulnerability_id) if vulnerability_id not in (None, "") else None,
        packageName=str(package_name) if package_name not in (None, "") else None,
        packageVersion=str(package_version) if package_version not in (None, "") else None,
        fixedVersion=str(fixed_version) if fixed_version not in (None, "") else None,
        accountId=str(account_id) if account_id not in (None, "") else None,
        region=str(region) if region not in (None, "") else None,
        resourceId=str(resource_id) if resource_id not in (None, "") else None,
        imageDigest=str(image_digest) if image_digest not in (None, "") else None,
        firstObservedAt=first_observed_at,
        lastObservedAt=last_observed_at,
        evidenceIds=[evidence_id],
        controlIds=control_ids,
    )
    return artifact, finding, warnings


def normalize_records(
    rows: list[dict[str, Any]],
    *,
    source_system: str,
    source_type: str,
    scanner: str,
    collected_at: datetime | None = None,
    thresholds: FreshnessThresholds | None = None,
    source_path: Path | None = None,
) -> EvidenceNormalizationResult:
    result = EvidenceNormalizationResult()
    collected = collected_at or _now()
    if collected.tzinfo is None:
        collected = collected.replace(tzinfo=timezone.utc)
    fresh = thresholds or FreshnessThresholds()
    by_identity: dict[str, NormalizedFinding] = {}

    for i, row in enumerate(rows):
        raw_ref = f"{source_path or source_system}#{i}"
        try:
            artifact, finding, warnings = _normalize_record(
                row,
                row_index=i,
                source_system=source_system,
                source_type=source_type,
                default_scanner=scanner,
                collected_at=collected,
                thresholds=fresh,
                source_path=source_path,
            )
            identity = _identity_key(row, scanner=finding.scanner or scanner, finding_id=_get(row, "findingId", "finding_id", "id", "plugin_id", "checkId", "CheckID"))[1]
            result.evidence_artifacts.append(artifact)
            by_identity[identity] = _merge_finding(by_identity[identity], finding) if identity in by_identity else finding
            result.warnings.extend(warnings)
        except (ValueError, ValidationError, TypeError) as e:
            result.errors.append(NormalizationDiagnostic(row_index=i, raw_ref=raw_ref, message=str(e)))

    result.findings = list(by_identity.values())
    return result


def _json_records(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        for key in ("findings", "vulnerabilities", "results", "items", "records", "resources", "configurations"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        return [data]
    raise ValueError("JSON input must be an object, array, or object containing a records list")


def normalize_vulnerability_scan_json(
    path: Path,
    *,
    scanner: str = "generic",
    collected_at: datetime | None = None,
    thresholds: FreshnessThresholds | None = None,
) -> EvidenceNormalizationResult:
    return normalize_records(
        _json_records(path),
        source_system=scanner,
        source_type="vulnerability_scan_json",
        scanner=scanner,
        collected_at=collected_at,
        thresholds=thresholds,
        source_path=path,
    )


def normalize_cloud_config_json(
    path: Path,
    *,
    source_system: str = "cloud_config",
    collected_at: datetime | None = None,
    thresholds: FreshnessThresholds | None = None,
) -> EvidenceNormalizationResult:
    return normalize_records(
        _json_records(path),
        source_system=source_system,
        source_type="cloud_config_json",
        scanner=source_system,
        collected_at=collected_at,
        thresholds=thresholds,
        source_path=path,
    )


def normalize_container_scan_csv(
    path: Path,
    *,
    scanner: str = "container_scan",
    collected_at: datetime | None = None,
    thresholds: FreshnessThresholds | None = None,
) -> EvidenceNormalizationResult:
    return normalize_records(
        load_csv_rows(path),
        source_system=scanner,
        source_type="container_scan_csv",
        scanner=scanner,
        collected_at=collected_at,
        thresholds=thresholds,
        source_path=path,
    )


def normalize_existing_scanner_export(
    path: Path,
    *,
    source_format: str = "auto",
    collected_at: datetime | None = None,
    thresholds: FreshnessThresholds | None = None,
) -> EvidenceNormalizationResult:
    """Normalize existing repo scanner formats through ``providers.scanner_router``."""
    from providers.scanner_router import import_scanner

    fmt, findings, _events = import_scanner(path, source_format=source_format)  # type: ignore[arg-type]
    rows: list[dict[str, Any]] = []
    for f in findings:
        meta = dict(f.metadata or {})
        rows.append(
            {
                "findingId": f.finding_id,
                "scanner": f.scanner_name,
                "title": f.title,
                "description": f.evidence,
                "severity": f.severity,
                "status": f.status,
                "vulnerabilityId": (f.cve_ids[0] if f.cve_ids else None),
                "resourceId": f.asset_id or f.target_id,
                "resourceArn": f.target_id if f.target_id and str(f.target_id).startswith("arn:") else None,
                "accountId": meta.get("prowler_account_id") or meta.get("cloudsploit_account_id") or meta.get("electriceye_account_id"),
                "region": meta.get("prowler_region") or meta.get("cloudsploit_region") or meta.get("electriceye_region"),
                "packageName": meta.get("package_name"),
                "packageVersion": meta.get("package_version"),
                "firstObservedAt": f.first_seen,
                "lastObservedAt": f.last_seen,
                "rawRef": f.raw_ref or f.target_id or f.finding_id,
            }
        )
    return normalize_records(
        rows,
        source_system=str(fmt),
        source_type="scanner_router",
        scanner=str(fmt),
        collected_at=collected_at,
        thresholds=thresholds,
        source_path=path,
    )


__all__ = [
    "EvidenceNormalizationResult",
    "FreshnessThresholds",
    "NormalizationDiagnostic",
    "freshness_status",
    "normalize_cloud_config_json",
    "normalize_container_scan_csv",
    "normalize_existing_scanner_export",
    "normalize_finding_status",
    "normalize_records",
    "normalize_severity",
    "normalize_vulnerability_scan_json",
    "parse_datetime",
]
