"""Tests for compact evidence bundle generation."""

from __future__ import annotations

import json

from core.control_mapping_engine import map_controls
from core.deterministic_validators import validate_evidence_freshness, validate_required_control_evidence
from core.domain_models import NormalizedFinding, model_from_json, model_to_json
from core.evidence_compactor import CompactEvidenceBundle, EvidenceCompactor
from tests.test_assurance_package import NOW, _control, _evidence


def _finding(
    finding_id: str,
    *,
    severity: str = "HIGH",
    status: str = "OPEN",
    evidence_ids: list[str] | None = None,
    description: str = "A long vulnerability description " * 40,
) -> NormalizedFinding:
    return NormalizedFinding(
        findingId=finding_id,
        sourceSystem="nessus",
        scanner="nessus",
        title="OpenSSL vulnerability",
        description=description,
        severity=severity,
        status=status,
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
        controlIds=["RA-5"],
    )


def test_duplicate_vulnerabilities_grouped() -> None:
    evidence = [_evidence("ev-001"), _evidence("ev-002")]
    findings = [_finding("nf-001", evidence_ids=["ev-001"]), _finding("nf-002", evidence_ids=["ev-002"])]

    bundle = EvidenceCompactor(max_description_chars=80).compact(evidence=evidence, findings=findings)

    assert len(bundle.vulnerability_groups) == 1
    group = bundle.vulnerability_groups[0]
    assert group.count == 2
    assert group.finding_ids == ["nf-001", "nf-002"]
    assert group.evidence_ids == ["ev-001", "ev-002"]
    assert group.representative_description.endswith("...")


def test_evidence_ids_preserved_across_groups_and_global_index() -> None:
    evidence = [_evidence("ev-001"), _evidence("ev-002", control_ids=["SI-2"])]
    findings = [_finding("nf-001", evidence_ids=["ev-001", "ev-002"])]
    mappings = map_controls(evidence, findings, [_control("RA-5"), _control("SI-2")])

    bundle = EvidenceCompactor().compact(evidence=evidence, findings=findings, control_mappings=mappings)

    grouped_ids = {eid for group in bundle.evidence_groups for eid in group.evidence_ids}
    vuln_ids = {eid for group in bundle.vulnerability_groups for eid in group.evidence_ids}
    assert grouped_ids == {"ev-001", "ev-002"}
    assert vuln_ids == {"ev-001", "ev-002"}
    assert bundle.all_evidence_ids == ["ev-001", "ev-002"]


def test_critical_findings_not_dropped() -> None:
    critical = _finding("nf-critical", severity="CRITICAL")
    low = _finding("nf-low", severity="LOW", evidence_ids=["ev-low"])

    bundle = EvidenceCompactor().compact(evidence=[_evidence("ev-001"), _evidence("ev-low")], findings=[critical, low])

    assert [group.severity for group in bundle.critical_high_findings] == ["CRITICAL"]
    assert bundle.critical_high_findings[0].finding_ids == ["nf-critical"]


def test_missing_and_stale_evidence_retained() -> None:
    control = _control("AC-2")
    stale = _evidence("ev-stale", control_ids=["RA-5"]).model_copy(update={"freshness_status": "stale"})
    validations = [
        validate_required_control_evidence(control, [], timestamp=NOW),
        validate_evidence_freshness([stale], control_id="RA-5", timestamp=NOW),
    ]

    bundle = EvidenceCompactor().compact(evidence=[stale], findings=[], validation_results=validations)

    assert [signal.control_id for signal in bundle.missing_evidence] == ["AC-2"]
    assert any("ev-stale" in signal.evidence_ids for signal in bundle.stale_evidence)
    assert "ev-stale" in bundle.all_evidence_ids


def test_compact_bundle_smaller_than_raw_bundle() -> None:
    evidence = [_evidence(f"ev-{i:03d}") for i in range(1, 8)]
    findings = [_finding(f"nf-{i:03d}", evidence_ids=[f"ev-{i:03d}"]) for i in range(1, 8)]
    raw = {
        "evidence": [item.model_dump(mode="json", by_alias=True) for item in evidence],
        "findings": [item.model_dump(mode="json", by_alias=True) for item in findings],
    }

    bundle = EvidenceCompactor(max_description_chars=80).compact(evidence=evidence, findings=findings)
    compact = bundle.model_dump(mode="json", by_alias=True)

    assert len(json.dumps(compact, sort_keys=True)) < len(json.dumps(raw, sort_keys=True))
    assert bundle.compact_estimated_tokens < bundle.raw_estimated_tokens


def test_deterministic_output_ordering_and_round_trip() -> None:
    evidence = [_evidence("ev-b"), _evidence("ev-a")]
    findings = [_finding("nf-b", evidence_ids=["ev-b"]), _finding("nf-a", evidence_ids=["ev-a"])]
    compactor = EvidenceCompactor()

    first = compactor.compact(evidence=evidence, findings=findings)
    second = compactor.compact(evidence=list(reversed(evidence)), findings=list(reversed(findings)))

    assert first.model_dump(mode="json", by_alias=True) == second.model_dump(mode="json", by_alias=True)
    assert model_from_json(CompactEvidenceBundle, model_to_json(first)) == first
