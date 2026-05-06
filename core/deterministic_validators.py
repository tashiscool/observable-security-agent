"""Deterministic compliance validators for normalized evidence.

This module is intentionally fact-oriented. It checks evidence, findings,
assets, controls, POA&M metadata, exception metadata, and generated package
schemas before any narrative or LLM reasoning layer is allowed to explain the
result.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Sequence

from pydantic import BaseModel, ConfigDict, Field

from core.domain_models import (
    AssessmentResult,
    CloudAsset,
    ControlRequirement,
    DomainModel,
    EvidenceArtifact,
    NormalizedFinding,
)
from fedramp20x.schema_validator import validate_package


ValidatorStatus = Literal["PASS", "FAIL", "WARN", "UNKNOWN"]


class ValidatorResult(DomainModel):
    """Serializable output from a deterministic validator."""

    validator_id: str = Field(..., alias="validatorId", min_length=1)
    status: ValidatorStatus = Field(..., alias="status")
    control_id: str | None = Field(default=None, alias="controlId")
    asset_id: str | None = Field(default=None, alias="assetId")
    evidence_ids: list[str] = Field(default_factory=list, alias="evidenceIds")
    finding_ids: list[str] = Field(default_factory=list, alias="findingIds")
    message: str = Field(..., alias="message", min_length=1)
    remediation_hint: str = Field(..., alias="remediationHint", min_length=1)
    timestamp: datetime = Field(..., alias="timestamp")


class ValidationConfig(BaseModel):
    """Tunable thresholds for deterministic validation."""

    model_config = ConfigDict(extra="forbid")

    freshness_warn_days: int = Field(default=30, ge=0)
    freshness_fail_days: int = Field(default=90, ge=0)
    high_findings_fail: bool = True


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _as_aware(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _ids(items: Sequence[EvidenceArtifact]) -> list[str]:
    return sorted({item.evidence_id for item in items})


def _finding_ids(items: Sequence[NormalizedFinding]) -> list[str]:
    return sorted({item.finding_id for item in items})


def _subject_time(evidence: EvidenceArtifact) -> datetime | None:
    return evidence.observed_at or evidence.collected_at


def _result(
    *,
    validator_id: str,
    status: ValidatorStatus,
    message: str,
    remediation_hint: str,
    timestamp: datetime | None = None,
    control_id: str | None = None,
    asset_id: str | None = None,
    evidence_ids: Sequence[str] = (),
    finding_ids: Sequence[str] = (),
) -> ValidatorResult:
    return ValidatorResult(
        validatorId=validator_id,
        status=status,
        controlId=control_id,
        assetId=asset_id,
        evidenceIds=list(evidence_ids),
        findingIds=list(finding_ids),
        message=message,
        remediationHint=remediation_hint,
        timestamp=timestamp or _now(),
    )


def validate_evidence_presence(
    evidence: Sequence[EvidenceArtifact],
    *,
    required_evidence_ids: Sequence[str] | None = None,
    control_id: str | None = None,
    asset_id: str | None = None,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate that evidence is present, optionally checking explicit IDs."""

    present_ids = set(_ids(evidence))
    if required_evidence_ids:
        missing = sorted(set(required_evidence_ids) - present_ids)
        if missing:
            return _result(
                validator_id="evidence_presence",
                status="FAIL",
                control_id=control_id,
                asset_id=asset_id,
                evidence_ids=sorted(present_ids),
                message="Required evidence is missing: " + ", ".join(missing),
                remediation_hint="Collect the missing evidence artifacts and preserve raw source references.",
                timestamp=timestamp,
            )
    elif not evidence:
        return _result(
            validator_id="evidence_presence",
            status="FAIL",
            control_id=control_id,
            asset_id=asset_id,
            message="No evidence artifacts were provided.",
            remediation_hint="Collect at least one authoritative or corroborated evidence artifact before assessment.",
            timestamp=timestamp,
        )

    return _result(
        validator_id="evidence_presence",
        status="PASS",
        control_id=control_id,
        asset_id=asset_id,
        evidence_ids=sorted(present_ids),
        message="Required evidence artifacts are present.",
        remediation_hint="No remediation required.",
        timestamp=timestamp,
    )


def validate_evidence_freshness(
    evidence: Sequence[EvidenceArtifact],
    *,
    config: ValidationConfig | None = None,
    control_id: str | None = None,
    asset_id: str | None = None,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate that evidence is recent enough for deterministic assessment."""

    ts = timestamp or _now()
    cfg = config or ValidationConfig()
    if not evidence:
        return _result(
            validator_id="evidence_freshness",
            status="UNKNOWN",
            control_id=control_id,
            asset_id=asset_id,
            message="No evidence artifacts were provided for freshness evaluation.",
            remediation_hint="Collect evidence before evaluating freshness.",
            timestamp=ts,
        )

    ages: list[tuple[EvidenceArtifact, int | None]] = []
    for item in evidence:
        item_time = _subject_time(item)
        if item_time is None:
            ages.append((item, None))
            continue
        age_days = max(0, (_as_aware(ts) - _as_aware(item_time)).days)
        ages.append((item, age_days))

    unknown = [item.evidence_id for item, age in ages if age is None or item.freshness_status == "unknown"]
    expired = [
        item.evidence_id
        for item, age in ages
        if item.freshness_status == "expired" or (age is not None and age > cfg.freshness_fail_days)
    ]
    stale = [
        item.evidence_id
        for item, age in ages
        if item.evidence_id not in expired
        and (item.freshness_status == "stale" or (age is not None and age > cfg.freshness_warn_days))
    ]

    if expired:
        return _result(
            validator_id="evidence_freshness",
            status="FAIL",
            control_id=control_id,
            asset_id=asset_id,
            evidence_ids=_ids(evidence),
            message="Evidence is expired or beyond the freshness fail threshold: " + ", ".join(sorted(expired)),
            remediation_hint="Refresh expired evidence from the source system and re-run validation.",
            timestamp=ts,
        )
    if stale:
        return _result(
            validator_id="evidence_freshness",
            status="WARN",
            control_id=control_id,
            asset_id=asset_id,
            evidence_ids=_ids(evidence),
            message="Evidence is stale or beyond the freshness warning threshold: " + ", ".join(sorted(stale)),
            remediation_hint="Refresh stale evidence before relying on it for final assurance.",
            timestamp=ts,
        )
    if unknown:
        return _result(
            validator_id="evidence_freshness",
            status="UNKNOWN",
            control_id=control_id,
            asset_id=asset_id,
            evidence_ids=_ids(evidence),
            message="Evidence freshness could not be determined for: " + ", ".join(sorted(unknown)),
            remediation_hint="Ensure collectedAt or observedAt timestamps are preserved during normalization.",
            timestamp=ts,
        )

    return _result(
        validator_id="evidence_freshness",
        status="PASS",
        control_id=control_id,
        asset_id=asset_id,
        evidence_ids=_ids(evidence),
        message="Evidence is within configured freshness thresholds.",
        remediation_hint="No remediation required.",
        timestamp=ts,
    )


def validate_unresolved_vulnerabilities(
    findings: Sequence[NormalizedFinding],
    *,
    config: ValidationConfig | None = None,
    control_id: str | None = None,
    asset_id: str | None = None,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate that no critical/high vulnerability findings remain open."""

    cfg = config or ValidationConfig()
    open_findings = [f for f in findings if f.status == "OPEN"]
    critical = [f for f in open_findings if f.severity == "CRITICAL"]
    high = [f for f in open_findings if f.severity == "HIGH"]

    if critical:
        return _result(
            validator_id="unresolved_vulnerabilities",
            status="FAIL",
            control_id=control_id,
            asset_id=asset_id,
            finding_ids=_finding_ids(critical),
            message="Open critical vulnerability findings are unresolved.",
            remediation_hint="Remediate or formally disposition critical vulnerabilities with evidence and POA&M linkage.",
            timestamp=timestamp,
        )
    if high:
        return _result(
            validator_id="unresolved_vulnerabilities",
            status="FAIL" if cfg.high_findings_fail else "WARN",
            control_id=control_id,
            asset_id=asset_id,
            finding_ids=_finding_ids(high),
            message="Open high vulnerability findings are unresolved.",
            remediation_hint="Remediate high vulnerabilities or document accepted risk with current approval evidence.",
            timestamp=timestamp,
        )
    if not findings:
        return _result(
            validator_id="unresolved_vulnerabilities",
            status="UNKNOWN",
            control_id=control_id,
            asset_id=asset_id,
            message="No vulnerability findings were provided.",
            remediation_hint="Collect vulnerability scanner output before asserting there are no unresolved findings.",
            timestamp=timestamp,
        )
    return _result(
        validator_id="unresolved_vulnerabilities",
        status="PASS",
        control_id=control_id,
        asset_id=asset_id,
        finding_ids=_finding_ids(findings),
        message="No open critical or high vulnerability findings were detected.",
        remediation_hint="No remediation required.",
        timestamp=timestamp,
    )


def _artifact_matches_asset(evidence: EvidenceArtifact, asset: CloudAsset) -> bool:
    candidates = {
        evidence.resource_id,
        evidence.resource_arn,
        evidence.image_digest,
    }
    subjects = {
        asset.asset_id,
        asset.resource_id,
        asset.resource_arn,
    }
    return bool({str(x) for x in candidates if x} & {str(x) for x in subjects if x})


def _finding_matches_asset(finding: NormalizedFinding, asset: CloudAsset) -> bool:
    candidates = {finding.resource_id, finding.image_digest}
    subjects = {asset.asset_id, asset.resource_id, asset.resource_arn}
    return bool({str(x) for x in candidates if x} & {str(x) for x in subjects if x})


def validate_asset_scan_coverage(
    asset: CloudAsset,
    evidence: Sequence[EvidenceArtifact],
    *,
    findings: Sequence[NormalizedFinding] | None = None,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate that an asset has scanner evidence or scanner findings."""

    matching_evidence = [
        item for item in evidence if item.scanner and _artifact_matches_asset(item, asset)
    ]
    matching_findings = [
        finding for finding in findings or [] if finding.scanner and _finding_matches_asset(finding, asset)
    ]
    if matching_evidence or matching_findings:
        return _result(
            validator_id="asset_scan_coverage",
            status="PASS",
            asset_id=asset.asset_id,
            evidence_ids=_ids(matching_evidence),
            finding_ids=_finding_ids(matching_findings),
            message=f"Asset {asset.asset_id} has scanner coverage evidence.",
            remediation_hint="No remediation required.",
            timestamp=timestamp,
        )
    return _result(
        validator_id="asset_scan_coverage",
        status="FAIL",
        asset_id=asset.asset_id,
        message=f"Asset {asset.asset_id} has no scanner coverage evidence.",
        remediation_hint="Add the asset to scanner scope or collect scanner output proving coverage.",
        timestamp=timestamp,
    )


def validate_required_control_evidence(
    control: ControlRequirement,
    evidence: Sequence[EvidenceArtifact],
    *,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate that at least one artifact maps to a required control."""

    mapped = [item for item in evidence if control.control_id in item.control_ids]
    if not mapped:
        return _result(
            validator_id="required_control_evidence",
            status="FAIL",
            control_id=control.control_id,
            message=f"Control {control.control_id} has no mapped evidence.",
            remediation_hint="Map authoritative evidence artifacts to this control before assessment.",
            timestamp=timestamp,
        )
    return _result(
        validator_id="required_control_evidence",
        status="PASS",
        control_id=control.control_id,
        evidence_ids=_ids(mapped),
        message=f"Control {control.control_id} has mapped evidence.",
        remediation_hint="No remediation required.",
        timestamp=timestamp,
    )


def _value(row: Any, *keys: str) -> Any:
    if isinstance(row, dict):
        for key in keys:
            if key in row:
                return row[key]
    for key in keys:
        if hasattr(row, key):
            return getattr(row, key)
    return None


def validate_poam_owner(
    poam_items: Sequence[Any] | None,
    *,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate POA&M rows have a responsible owner when POA&M data is supplied."""

    if poam_items is None:
        return _result(
            validator_id="poam_owner",
            status="UNKNOWN",
            message="POA&M items were not supplied to the validator.",
            remediation_hint="Provide POA&M rows when validating POA&M ownership.",
            timestamp=timestamp,
        )

    missing: list[str] = []
    for index, item in enumerate(poam_items):
        poam_id = str(_value(item, "poam_id", "poamId", "POA&M ID", "POAM ID") or f"row-{index}")
        owner = _value(item, "owner", "Owner", "responsible_party", "responsibleParty", "assigned_to", "assignedTo")
        if not str(owner or "").strip():
            missing.append(poam_id)

    if missing:
        return _result(
            validator_id="poam_owner",
            status="FAIL",
            message="POA&M rows are missing owners: " + ", ".join(missing),
            remediation_hint="Assign a responsible owner or role to each open POA&M item.",
            timestamp=timestamp,
        )
    return _result(
        validator_id="poam_owner",
        status="PASS",
        message="POA&M rows have responsible owners.",
        remediation_hint="No remediation required.",
        timestamp=timestamp,
    )


def _parse_date(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None


def validate_exception_active(
    exceptions: Sequence[Any] | None,
    *,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate supplied exception/deviation rows are active and unexpired."""

    ts = timestamp or _now()
    if exceptions is None:
        return _result(
            validator_id="exception_active",
            status="UNKNOWN",
            message="Exception records were not supplied to the validator.",
            remediation_hint="Provide exception/deviation records when validating risk acceptance or manual exceptions.",
            timestamp=ts,
        )

    invalid: list[str] = []
    for index, item in enumerate(exceptions):
        exception_id = str(_value(item, "exception_id", "exceptionId", "deviation_id", "deviationId", "id") or f"row-{index}")
        status = str(_value(item, "status", "Status") or "").strip().lower()
        expires = _parse_date(_value(item, "expires_at", "expiresAt", "expiration_date", "expirationDate", "expires"))
        active = status in {"active", "approved", "open", "risk_accepted", "risk accepted"}
        if not active or (expires is not None and _as_aware(expires) < _as_aware(ts)):
            invalid.append(exception_id)

    if invalid:
        return _result(
            validator_id="exception_active",
            status="FAIL",
            message="Exception records are inactive or expired: " + ", ".join(invalid),
            remediation_hint="Renew, close, or replace expired exceptions with current approval evidence.",
            timestamp=ts,
        )
    return _result(
        validator_id="exception_active",
        status="PASS",
        message="Exception records are active and not expired.",
        remediation_hint="No remediation required.",
        timestamp=ts,
    )


def validate_generated_package_schema(
    package_path: Path,
    *,
    schemas_dir: Path | None = None,
    timestamp: datetime | None = None,
) -> ValidatorResult:
    """Validate a generated FedRAMP 20x package with bundled JSON Schema."""

    schemas = schemas_dir or Path(__file__).resolve().parents[1] / "schemas"
    if package_path.is_dir():
        package_file = package_path / "fedramp20x-package.json"
    else:
        package_file = package_path
    if not package_file.is_file():
        return _result(
            validator_id="generated_package_schema",
            status="FAIL",
            message=f"Generated package file is missing: {package_file}",
            remediation_hint="Generate the package before running schema validation.",
            timestamp=timestamp,
        )

    try:
        report = validate_package(package_file, schemas)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        return _result(
            validator_id="generated_package_schema",
            status="FAIL",
            message=f"Generated package could not be validated: {exc}",
            remediation_hint="Write a readable JSON package before running schema validation.",
            timestamp=timestamp,
        )
    if not report.valid:
        return _result(
            validator_id="generated_package_schema",
            status="FAIL",
            message="Generated package schema validation failed: " + "; ".join(report.errors[:5]),
            remediation_hint="Fix package structure and referenced artifact schema errors before release.",
            timestamp=timestamp,
        )
    return _result(
        validator_id="generated_package_schema",
        status="PASS",
        message="Generated package satisfies bundled JSON Schema and assessor contract checks.",
        remediation_hint="No remediation required.",
        timestamp=timestamp,
    )


def aggregate_assessment_result(
    *,
    assessment_id: str,
    control: ControlRequirement,
    validator_results: Sequence[ValidatorResult],
    confidence: float = 1.0,
    created_at: datetime | None = None,
) -> AssessmentResult:
    """Aggregate deterministic validator results into a control assessment."""

    evidence_ids = sorted({eid for result in validator_results for eid in result.evidence_ids})
    finding_ids = sorted({fid for result in validator_results for fid in result.finding_ids})
    failures = [result for result in validator_results if result.status == "FAIL"]
    warnings = [result for result in validator_results if result.status == "WARN"]
    unknowns = [result for result in validator_results if result.status == "UNKNOWN"]
    control_evidence_fail = any(
        result.validator_id == "required_control_evidence" and result.status == "FAIL"
        for result in validator_results
    )

    if control_evidence_fail or not evidence_ids:
        status = "INSUFFICIENT_EVIDENCE"
    elif failures:
        status = "NON_COMPLIANT"
    elif warnings:
        status = "PARTIALLY_COMPLIANT"
    elif unknowns:
        status = "NEEDS_HUMAN_REVIEW"
    else:
        status = "COMPLIANT"

    gaps = [result.message for result in validator_results if result.status in {"FAIL", "WARN", "UNKNOWN"}]
    recommendations = [
        result.remediation_hint
        for result in validator_results
        if result.status in {"FAIL", "WARN", "UNKNOWN"} and result.remediation_hint != "No remediation required."
    ]
    summary = f"{control.control_id} deterministic validation status: {status}."
    return AssessmentResult(
        assessmentId=assessment_id,
        controlId=control.control_id,
        status=status,
        summary=summary,
        evidenceIds=evidence_ids,
        findingIds=finding_ids,
        gaps=gaps,
        recommendations=sorted(set(recommendations)),
        confidence=confidence,
        humanReviewRequired=status != "COMPLIANT",
        createdAt=created_at or _now(),
    )
