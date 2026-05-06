"""Evidence normalization layer tests."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.evidence_normalization import (
    FreshnessThresholds,
    normalize_container_scan_csv,
    normalize_existing_scanner_export,
    normalize_records,
    normalize_vulnerability_scan_json,
)


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def _write_json(path: Path, payload: object) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def test_valid_vulnerability_record(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "scan.json",
        {
            "findings": [
                {
                    "findingId": "F-1",
                    "scanner": "generic-vuln",
                    "title": "Critical OpenSSL CVE",
                    "description": "OpenSSL package is vulnerable.",
                    "severity": "critical",
                    "status": "open",
                    "vulnerabilityId": "CVE-2026-0001",
                    "packageName": "openssl",
                    "packageVersion": "1.0.0",
                    "fixedVersion": "1.0.1",
                    "accountId": "111111111111",
                    "region": "us-east-1",
                    "resourceId": "i-001",
                    "observedAt": NOW.isoformat(),
                    "controlIds": ["RA-5", "SI-2"],
                }
            ]
        },
    )

    result = normalize_vulnerability_scan_json(path, scanner="generic-vuln", collected_at=NOW)

    assert result.ok, result.errors
    assert len(result.evidence_artifacts) == 1
    assert len(result.findings) == 1
    artifact = result.evidence_artifacts[0]
    finding = result.findings[0]
    assert artifact.source_system == "generic-vuln"
    assert artifact.source_type == "vulnerability_scan_json"
    assert artifact.raw_ref.endswith("scan.json#0")
    assert artifact.account_id == "111111111111"
    assert artifact.region == "us-east-1"
    assert finding.severity == "CRITICAL"
    assert finding.status == "OPEN"
    assert finding.vulnerability_id == "CVE-2026-0001"
    assert finding.evidence_ids == [artifact.evidence_id]


def test_missing_finding_id_uses_fallback_identity(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "fallback.json",
        [
            {
                "scanner": "grype",
                "title": "Package CVE",
                "severity": "high",
                "status": "active",
                "vulnerabilityId": "CVE-2026-0002",
                "packageName": "curl",
                "packageVersion": "8.0.0",
                "resourceId": "image-repo/app",
                "imageDigest": "sha256:abc",
                "observedAt": NOW.isoformat(),
            }
        ],
    )

    result = normalize_vulnerability_scan_json(path, scanner="grype", collected_at=NOW)

    assert result.ok, result.errors
    assert result.findings[0].finding_id.startswith("nf-")
    assert result.findings[0].image_digest == "sha256:abc"


def test_duplicate_finding_merge() -> None:
    rows = [
        {
            "scanner": "nessus",
            "findingId": "N-1",
            "title": "Same finding",
            "severity": "medium",
            "status": "open",
            "resourceId": "host-1",
            "observedAt": "2026-05-05T12:00:00+00:00",
            "controlIds": ["RA-5"],
        },
        {
            "scanner": "nessus",
            "findingId": "N-1",
            "title": "Same finding",
            "severity": "medium",
            "status": "open",
            "resourceId": "host-1",
            "observedAt": "2026-05-06T12:00:00+00:00",
            "controlIds": ["SI-2"],
        },
    ]

    result = normalize_records(
        rows,
        source_system="nessus",
        source_type="vulnerability_scan_json",
        scanner="nessus",
        collected_at=NOW,
    )

    assert result.ok, result.errors
    assert len(result.evidence_artifacts) == 2
    assert len(result.findings) == 1
    assert sorted(result.findings[0].control_ids) == ["RA-5", "SI-2"]
    assert len(result.findings[0].evidence_ids) == 2


def test_stale_evidence_classification(tmp_path: Path) -> None:
    old = datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)
    path = _write_json(
        tmp_path / "old.json",
        [
            {
                "findingId": "old-1",
                "title": "Old scan",
                "severity": "low",
                "status": "open",
                "resourceId": "host-old",
                "observedAt": old.isoformat(),
            }
        ],
    )

    result = normalize_vulnerability_scan_json(
        path,
        scanner="generic",
        collected_at=NOW,
        thresholds=FreshnessThresholds(current_days=3, stale_days=60),
    )

    assert result.ok, result.errors
    assert result.evidence_artifacts[0].freshness_status == "stale"


def test_malformed_input_error() -> None:
    result = normalize_records(
        [{"title": "not enough identity"}],
        source_system="generic",
        source_type="vulnerability_scan_json",
        scanner="generic",
        collected_at=NOW,
    )

    assert not result.ok
    assert result.errors
    assert "fallback identity" in result.errors[0].message


def test_image_tag_without_digest_warning(tmp_path: Path) -> None:
    csv_path = tmp_path / "container.csv"
    csv_path.write_text(
        "scanner,vulnerabilityId,packageName,packageVersion,imageTag,severity,status,resourceId,observedAt\n"
        "trivy,CVE-2026-0003,busybox,1.36,repo/app:latest,high,open,repo/app,2026-05-06T12:00:00+00:00\n",
        encoding="utf-8",
    )

    result = normalize_container_scan_csv(csv_path, scanner="trivy", collected_at=NOW)

    assert result.ok, result.errors
    assert result.warnings
    assert "imageDigest" in result.warnings[0].message
    assert result.findings[0].image_digest is None


def test_multiple_accounts_and_regions_preserved(tmp_path: Path) -> None:
    path = _write_json(
        tmp_path / "multi.json",
        [
            {
                "findingId": "F-1",
                "title": "A",
                "severity": "low",
                "status": "open",
                "accountId": "111111111111",
                "region": "us-east-1",
                "resourceId": "r1",
            },
            {
                "findingId": "F-2",
                "title": "B",
                "severity": "medium",
                "status": "open",
                "accountId": "222222222222",
                "region": "us-gov-west-1",
                "resourceId": "r2",
            },
        ],
    )

    result = normalize_vulnerability_scan_json(path, scanner="generic", collected_at=NOW)

    assert result.ok, result.errors
    seen = {(a.account_id, a.region) for a in result.evidence_artifacts}
    assert seen == {("111111111111", "us-east-1"), ("222222222222", "us-gov-west-1")}


def test_existing_prowler_export_adapter_preserves_source_fields() -> None:
    sample = Path("tests/fixtures/prowler/prowler_sample_results.json")

    result = normalize_existing_scanner_export(sample, source_format="prowler", collected_at=NOW)

    assert result.ok, result.errors
    assert result.findings
    assert all(f.scanner == "prowler" for f in result.findings)
    assert all(a.raw_ref for a in result.evidence_artifacts)
