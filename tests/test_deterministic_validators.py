"""Tests for deterministic fact validators."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.deterministic_validators import (
    ValidationConfig,
    aggregate_assessment_result,
    validate_asset_scan_coverage,
    validate_evidence_freshness,
    validate_evidence_presence,
    validate_exception_active,
    validate_generated_package_schema,
    validate_poam_owner,
    validate_required_control_evidence,
    validate_unresolved_vulnerabilities,
)
from core.domain_models import CloudAsset, ControlRequirement, EvidenceArtifact, NormalizedFinding, model_from_json, model_to_json


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]


def _evidence(
    evidence_id: str = "ev-001",
    *,
    observed_at: datetime | None = NOW,
    freshness_status: str = "current",
    control_ids: list[str] | None = None,
    scanner: str | None = "nessus",
    resource_id: str | None = "i-001",
) -> EvidenceArtifact:
    return EvidenceArtifact(
        evidenceId=evidence_id,
        sourceSystem="nessus",
        sourceType="vulnerability_scan_json",
        collectedAt=observed_at or NOW,
        observedAt=observed_at,
        accountId="123456789012",
        region="us-east-1",
        resourceId=resource_id,
        resourceArn=f"arn:aws:ec2:us-east-1:123456789012:instance/{resource_id}" if resource_id else None,
        resourceType="ec2.instance",
        scanner=scanner,
        findingId=None,
        vulnerabilityId=None,
        packageName=None,
        packageVersion=None,
        imageDigest=None,
        controlIds=control_ids or ["RA-5"],
        rawRef=f"raw/nessus/report.json#{evidence_id}",
        normalizedSummary="Credentialed vulnerability scan evidence.",
        trustLevel="authoritative",
        freshnessStatus=freshness_status,
    )


def _finding(
    finding_id: str = "nf-001",
    *,
    severity: str = "CRITICAL",
    status: str = "OPEN",
    resource_id: str = "i-001",
) -> NormalizedFinding:
    return NormalizedFinding(
        findingId=finding_id,
        sourceSystem="nessus",
        scanner="nessus",
        title="Outdated package",
        description="Package requires remediation.",
        severity=severity,
        status=status,
        vulnerabilityId="CVE-2026-0001",
        packageName="openssl",
        packageVersion="1.0",
        fixedVersion="1.1",
        accountId="123456789012",
        region="us-east-1",
        resourceId=resource_id,
        imageDigest=None,
        firstObservedAt=NOW,
        lastObservedAt=NOW,
        evidenceIds=["ev-001"],
        controlIds=["RA-5"],
    )


def _control(control_id: str = "RA-5") -> ControlRequirement:
    return ControlRequirement(
        controlId=control_id,
        family=control_id.split("-")[0],
        title="Vulnerability Monitoring and Scanning",
        requirementText="Monitor and scan for vulnerabilities.",
        parameters={"frequency": "monthly"},
        framework="NIST SP 800-53",
        baseline="moderate",
        responsibility="shared",
        sourceRef="fixtures/controls.json#RA-5",
    )


def _asset() -> CloudAsset:
    return CloudAsset(
        assetId="asset-001",
        provider="aws",
        accountId="123456789012",
        region="us-east-1",
        resourceId="i-001",
        resourceArn="arn:aws:ec2:us-east-1:123456789012:instance/i-001",
        resourceType="ec2.instance",
        name="prod-api",
        tags={"Environment": "prod"},
        evidenceIds=[],
        controlIds=["RA-5"],
    )


def test_evidence_present_and_fresh() -> None:
    artifact = _evidence()

    presence = validate_evidence_presence([artifact], required_evidence_ids=["ev-001"], timestamp=NOW)
    freshness = validate_evidence_freshness([artifact], timestamp=NOW)

    assert presence.status == "PASS"
    assert freshness.status == "PASS"
    assert model_from_json(type(presence), model_to_json(presence)) == presence


def test_evidence_missing_fails() -> None:
    result = validate_evidence_presence([], required_evidence_ids=["ev-missing"], timestamp=NOW)

    assert result.status == "FAIL"
    assert "missing" in result.message.lower()


def test_evidence_stale_warns_or_fails_by_threshold() -> None:
    stale = _evidence(observed_at=NOW - timedelta(days=45))
    result = validate_evidence_freshness(
        [stale],
        config=ValidationConfig(freshness_warn_days=30, freshness_fail_days=90),
        timestamp=NOW,
    )

    assert result.status == "WARN"
    assert result.evidence_ids == ["ev-001"]


def test_unresolved_critical_finding_fails() -> None:
    result = validate_unresolved_vulnerabilities([_finding()], timestamp=NOW)

    assert result.status == "FAIL"
    assert result.finding_ids == ["nf-001"]


def test_fixed_vulnerability_finding_passes() -> None:
    result = validate_unresolved_vulnerabilities(
        [_finding(severity="CRITICAL", status="FIXED")],
        timestamp=NOW,
    )

    assert result.status == "PASS"


def test_open_high_finding_can_warn_by_configuration() -> None:
    result = validate_unresolved_vulnerabilities(
        [_finding(finding_id="nf-high", severity="HIGH")],
        config=ValidationConfig(high_findings_fail=False),
        timestamp=NOW,
    )

    assert result.status == "WARN"


def test_asset_has_scan_coverage_and_missing_coverage_fails() -> None:
    asset = _asset()

    covered = validate_asset_scan_coverage(asset, [_evidence()], timestamp=NOW)
    missing = validate_asset_scan_coverage(asset, [_evidence(resource_id="i-other")], timestamp=NOW)

    assert covered.status == "PASS"
    assert missing.status == "FAIL"


def test_control_with_no_evidence_becomes_insufficient_evidence_assessment() -> None:
    control = _control("AC-2")
    validator = validate_required_control_evidence(control, [_evidence(control_ids=["RA-5"])], timestamp=NOW)
    assessment = aggregate_assessment_result(
        assessment_id="assess-001",
        control=control,
        validator_results=[validator],
        created_at=NOW,
    )

    assert validator.status == "FAIL"
    assert assessment.status == "INSUFFICIENT_EVIDENCE"
    assert assessment.human_review_required is True


def test_poam_owner_exists_when_poam_rows_supplied() -> None:
    ok = validate_poam_owner([{"poam_id": "POAM-1", "owner": "ISSO"}], timestamp=NOW)
    bad = validate_poam_owner([{"poam_id": "POAM-2", "owner": ""}], timestamp=NOW)

    assert ok.status == "PASS"
    assert bad.status == "FAIL"


def test_exception_active_and_not_expired() -> None:
    ok = validate_exception_active([{"exceptionId": "EX-1", "status": "approved", "expiresAt": "2026-06-01T00:00:00Z"}], timestamp=NOW)
    bad = validate_exception_active([{"exceptionId": "EX-2", "status": "approved", "expiresAt": "2026-01-01T00:00:00Z"}], timestamp=NOW)

    assert ok.status == "PASS"
    assert bad.status == "FAIL"


def test_malformed_generated_package_fails_schema_validation(tmp_path: Path) -> None:
    package = tmp_path / "fedramp20x-package.json"
    package.write_text(json.dumps({"artifacts": {}}), encoding="utf-8")

    result = validate_generated_package_schema(package, schemas_dir=ROOT / "schemas", timestamp=NOW)

    assert result.status == "FAIL"
    assert "schema" in result.message.lower()


def test_multiple_validators_aggregate_into_assessment_result() -> None:
    control = _control()
    artifact = _evidence()
    results = [
        validate_required_control_evidence(control, [artifact], timestamp=NOW),
        validate_evidence_freshness(
            [artifact],
            config=ValidationConfig(freshness_warn_days=0, freshness_fail_days=90),
            timestamp=NOW + timedelta(days=1),
        ),
        validate_unresolved_vulnerabilities([_finding(status="FIXED")], timestamp=NOW),
    ]
    assessment = aggregate_assessment_result(
        assessment_id="assess-002",
        control=control,
        validator_results=results,
        created_at=NOW,
    )

    assert assessment.status == "PARTIALLY_COMPLIANT"
    assert assessment.evidence_ids == ["ev-001"]
    assert assessment.finding_ids == ["nf-001"]
