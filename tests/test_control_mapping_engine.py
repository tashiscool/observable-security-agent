"""Tests for deterministic control mapping engine."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import yaml

from core.control_mapping_engine import DEFAULT_RULES_PATH, load_mapping_rules, map_controls
from core.domain_models import ControlRequirement, EvidenceArtifact, NormalizedFinding, model_from_json, model_to_json


NOW = datetime(2026, 5, 6, 12, 0, tzinfo=timezone.utc)


def _control(control_id: str, family: str | None = None) -> ControlRequirement:
    fam = family or control_id.split("-")[0]
    return ControlRequirement(
        controlId=control_id,
        family=fam,
        title=f"{control_id} control",
        requirementText=f"{control_id} requirement text.",
        parameters={},
        framework="NIST SP 800-53",
        baseline="moderate",
        responsibility="shared",
        sourceRef=f"controls#{control_id}",
    )


def _controls() -> list[ControlRequirement]:
    return [
        _control("AC-2"),
        _control("AU-2"),
        _control("AU-6"),
        _control("CA-5"),
        _control("CM-6"),
        _control("IA-2"),
        _control("IR-4"),
        _control("RA-5"),
        _control("SC-13"),
        _control("SI-2"),
    ]


def _evidence(
    evidence_id: str = "ev-001",
    *,
    source_type: str = "vulnerability_scan_json",
    scanner: str | None = "nessus",
    resource_type: str | None = "ec2.instance",
    summary: str = "Nessus vulnerability scanner result.",
    control_ids: list[str] | None = None,
) -> EvidenceArtifact:
    return EvidenceArtifact(
        evidenceId=evidence_id,
        sourceSystem=scanner or "aws",
        sourceType=source_type,
        collectedAt=NOW,
        observedAt=NOW,
        accountId="123456789012",
        region="us-east-1",
        resourceId="i-001",
        resourceArn="arn:aws:ec2:us-east-1:123456789012:instance/i-001",
        resourceType=resource_type,
        scanner=scanner,
        findingId=None,
        vulnerabilityId=None,
        packageName=None,
        packageVersion=None,
        imageDigest=None,
        controlIds=control_ids or [],
        rawRef=f"raw/evidence.json#{evidence_id}",
        normalizedSummary=summary,
        trustLevel="authoritative",
        freshnessStatus="current",
    )


def _finding(
    finding_id: str = "nf-001",
    *,
    scanner: str | None = "nessus",
    title: str = "Critical OpenSSL vulnerability",
    description: str = "CVE package patch required.",
    severity: str = "HIGH",
    control_ids: list[str] | None = None,
    evidence_ids: list[str] | None = None,
) -> NormalizedFinding:
    return NormalizedFinding(
        findingId=finding_id,
        sourceSystem=scanner or "scanner",
        scanner=scanner,
        title=title,
        description=description,
        severity=severity,
        status="OPEN",
        vulnerabilityId="CVE-2026-0001",
        packageName="openssl",
        packageVersion="1.0",
        fixedVersion="1.1",
        accountId="123456789012",
        region="us-east-1",
        resourceId="i-001",
        imageDigest=None,
        firstObservedAt=NOW,
        lastObservedAt=NOW,
        evidenceIds=evidence_ids or ["ev-001"],
        controlIds=control_ids or [],
    )


def test_default_rules_file_loads_and_has_comments() -> None:
    text = DEFAULT_RULES_PATH.read_text(encoding="utf-8")
    assert "# Deterministic control mapping rules" in text
    assert yaml.safe_load(text)["rules"]
    assert load_mapping_rules(DEFAULT_RULES_PATH)


def test_direct_source_control_mapping_is_exact() -> None:
    evidence = _evidence(source_type="manual_evidence", scanner=None, summary="Approved control evidence.", control_ids=["AC-2"])

    mappings = map_controls([evidence], [], _controls())

    assert len(mappings) == 1
    mapping = mappings[0]
    assert mapping.target_control_id == "AC-2"
    assert mapping.source_control_id == "AC-2"
    assert mapping.mapping_confidence == "EXACT_SOURCE_CONTROL"
    assert mapping.evidence_ids == ["ev-001"]
    assert mapping.finding_ids == []
    assert model_from_json(type(mapping), model_to_json(mapping)) == mapping


def test_static_mapping_from_vulnerability_finding_maps_ra5_si2() -> None:
    evidence = _evidence()
    finding = _finding()

    mappings = map_controls([evidence], [finding], _controls())
    static_targets = {
        m.target_control_id
        for m in mappings
        if m.mapping_confidence == "STATIC_RULE"
    }

    assert {"RA-5", "SI-2", "CA-5"} <= static_targets
    assert all("ev-001" in m.evidence_ids for m in mappings if m.target_control_id in {"RA-5", "SI-2"})
    assert all("nf-001" in m.finding_ids for m in mappings if m.target_control_id in {"RA-5", "SI-2"})


def test_configurable_mapping_file_is_loaded(tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        """
rules:
  - id: custom_s3_encryption
    resource_type: s3.bucket
    category_keywords: ["encryption"]
    controls: ["SC-13"]
    rationale: Custom S3 encryption evidence maps to SC-13.
""",
        encoding="utf-8",
    )
    evidence = _evidence(
        source_type="cloud_config_json",
        scanner=None,
        resource_type="s3.bucket",
        summary="S3 bucket encryption configuration uses KMS.",
    )

    mappings = map_controls([evidence], [], _controls(), rules_path=rules)

    assert [(m.target_control_id, m.mapping_confidence) for m in mappings] == [("SC-13", "STATIC_RULE")]
    assert "Custom S3 encryption" in mappings[0].rationale


def test_heuristic_mapping_is_not_exact() -> None:
    evidence = _evidence(
        source_type="telemetry_json",
        scanner=None,
        summary="CloudTrail audit log ingestion observed in central SIEM.",
    )

    mappings = map_controls([evidence], [], _controls(), rules_path=Path("/does/not/exist.yaml"))
    heuristic = [m for m in mappings if m.mapping_confidence == "HEURISTIC"]

    assert {m.target_control_id for m in heuristic} == {"AU-2", "AU-6"}
    assert all(m.mapping_confidence != "EXACT_SOURCE_CONTROL" for m in heuristic)


def test_unknown_mapping_needs_review() -> None:
    evidence = _evidence(
        source_type="misc_json",
        scanner=None,
        summary="Unclassified operational signal with no recognizable compliance cue.",
    )

    mappings = map_controls([evidence], [], _controls(), rules_path=Path("/does/not/exist.yaml"))

    assert len(mappings) == 1
    assert mappings[0].target_control_id == "NEEDS_REVIEW"
    assert mappings[0].mapping_confidence == "NEEDS_REVIEW"


def test_conflicting_source_and_static_mapping_is_downgraded_to_review() -> None:
    evidence = _evidence(control_ids=["CM-6"])
    finding = _finding(control_ids=["CM-6"])

    mappings = map_controls([evidence], [finding], _controls())

    exact = [m for m in mappings if m.target_control_id == "CM-6" and m.mapping_confidence == "EXACT_SOURCE_CONTROL"]
    inferred = [m for m in mappings if m.target_control_id in {"RA-5", "SI-2"}]

    assert exact
    assert inferred
    assert all(m.mapping_confidence == "NEEDS_REVIEW" for m in inferred)
    assert all("conflicts with explicit source controls" in m.rationale for m in inferred)
