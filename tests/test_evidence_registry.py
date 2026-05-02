"""Tests for ``fedramp20x.evidence_registry`` models and registry YAML."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fedramp20x.evidence_registry import (
    EvidenceRegistry,
    EvidenceRegistryLoadError,
    EvidenceSource,
    evidence_registry_to_package_dict,
    load_evidence_source_registry,
)

ROOT = Path(__file__).resolve().parents[1]
REGISTRY_PATH = ROOT / "config" / "evidence-source-registry.yaml"

REQUIRED_IDS = frozenset(
    {
        "cloud_asset_inventory",
        "declared_system_inventory",
        "scanner_target_export",
        "vulnerability_scan_findings",
        "central_log_source_export",
        "siem_alert_rule_export",
        "cloud_control_plane_events",
        "change_ticket_export",
        "incident_ticket_export",
        "poam_export",
        "identity_provider_users",
        "privileged_group_membership",
        "mfa_status",
        "scim_provisioning_logs",
        "backup_configuration_export",
        "restore_test_records",
        "vendor_inventory",
        "sbom_export",
        "training_records",
        "aws_iam_credential_report",
        "aws_cloudtrail",
        "aws_config",
        "aws_guardduty",
        "aws_securityhub",
        "aws_inspector",
        "aws_s3",
        "aws_rds",
        "aws_backup",
        "aws_vpc",
        "aws_cloudwatch",
    }
)


def test_load_shipped_registry() -> None:
    reg = load_evidence_source_registry(REGISTRY_PATH)
    ids = {s.id for s in reg.sources}
    missing = REQUIRED_IDS - ids
    assert not missing, f"registry missing ids: {sorted(missing)}"
    assert reg.schema_version == "1.0"
    for s in reg.sources:
        assert s.owner.strip()
        assert s.category
        assert 0 <= s.automation_score <= 5
        if s.collection_method in ("api", "hybrid"):
            assert (s.collector or "").strip() or s.limitations


def test_evidence_registry_to_package_dict_json_safe() -> None:
    reg = load_evidence_source_registry(REGISTRY_PATH)
    d = evidence_registry_to_package_dict(reg)
    assert d["schema_version"] == "1.0"
    assert isinstance(d["sources"], list)
    assert d["sources"][0]["id"]


def test_duplicate_source_id_rejected(tmp_path: Path) -> None:
    p = tmp_path / "reg.yaml"
    p.write_text(
        yaml.dump(
            {
                "schema_version": "1.0",
                "sources": [
                    {
                        "id": "dup",
                        "name": "A",
                        "category": "inventory",
                        "collection_method": "manual",
                        "frequency": "annual",
                        "owner": "O",
                        "evidence_format": "json",
                        "automation_score": 0,
                    },
                    {
                        "id": "dup",
                        "name": "B",
                        "category": "inventory",
                        "collection_method": "manual",
                        "frequency": "annual",
                        "owner": "O",
                        "evidence_format": "json",
                        "automation_score": 0,
                    },
                ],
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(EvidenceRegistryLoadError, match="Duplicate"):
        load_evidence_source_registry(p)


def test_api_without_collector_or_limitations_rejected() -> None:
    with pytest.raises(ValueError, match="collector"):
        EvidenceSource.model_validate(
            {
                "id": "x",
                "name": "n",
                "category": "logging",
                "collection_method": "api",
                "frequency": "daily",
                "owner": "O",
                "evidence_format": "json",
                "automation_score": 3,
            }
        )


def test_api_with_limitation_only_ok() -> None:
    s = EvidenceSource.model_validate(
        {
            "id": "x",
            "name": "n",
            "category": "logging",
            "collection_method": "api",
            "frequency": "daily",
            "owner": "O",
            "evidence_format": "json",
            "limitations": ["No collector in environment; assessor pull only."],
            "automation_score": 1,
        }
    )
    assert s.limitations


def test_automation_score_bounds() -> None:
    with pytest.raises(ValueError):
        EvidenceSource.model_validate(
            {
                "id": "x",
                "name": "n",
                "category": "inventory",
                "collection_method": "file",
                "frequency": "annual",
                "owner": "O",
                "evidence_format": "json",
                "automation_score": 6,
            }
        )


def test_load_invalid_yaml(tmp_path: Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text("{ not valid", encoding="utf-8")
    with pytest.raises(EvidenceRegistryLoadError, match="Invalid YAML"):
        load_evidence_source_registry(p)


def test_load_missing_file(tmp_path: Path) -> None:
    p = tmp_path / "nope.yaml"
    with pytest.raises(EvidenceRegistryLoadError, match="not found"):
        load_evidence_source_registry(p)


def test_registry_root_model_accepts_minimal_valid_source() -> None:
    reg = EvidenceRegistry.model_validate(
        {
            "sources": [
                {
                    "id": "minimal",
                    "name": "Minimal Source",
                    "category": "training",
                    "collection_method": "manual",
                    "frequency": "annual",
                    "owner": "Owner Org",
                    "evidence_format": "pdf",
                    "automation_score": 0,
                }
            ]
        }
    )
    assert len(reg.sources) == 1
