"""Tests for the assessment-tracker → EvidenceGap pipeline.

Covers:

* The 24 phrase-driven :class:`GapType` rules (≥20 representative classifications).
* The "every tracker row is accounted for" invariant.
* The :class:`EvidenceGap` model gets controls + recommended_artifact + linked_ksi_ids.
* Closed / satisfied rows become :class:`InformationalTrackerItem` records.
* The new ``evidence_gaps.json`` schema-2.0 envelope is written by the importer.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from classification.classify_tracker_gap import GapClassification, classify_tracker_gap
from core.evidence_gap import (
    GAP_TYPE_TO_KSI,
    EvidenceGapBundle,
    build_evidence_gaps,
    write_evidence_gaps_file,
)
from core.models import EvidenceGap, GapType, InformationalTrackerItem
from normalization.assessment_tracker_import import (
    TrackerRow,
    import_assessment_tracker_to_dir,
    parse_tracker_text,
)
from providers.assessment_tracker import AssessmentTrackerProvider

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CSV = REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv"


# ---------------------------------------------------------------------------
# 1. Classifier — ≥20 representative row classifications
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "request_text,expected_gap_type",
    [
        # 1. inventory
        (
            "Provide the latest Integrated Inventory Workbook (IIW) and AWS dump for EC2/RDS/ALB",
            "inventory_mismatch",
        ),
        # 2. inventory — drift wording
        (
            "Inventory appears to be evolving — please reconcile declared vs. discovered and address discrepancies",
            "inventory_mismatch",
        ),
        # 3. scanner scope
        (
            "Provide evidence to display all system components that are scanned in the boundary",
            "scanner_scope_missing",
        ),
        # 4. scan plugins / signatures
        (
            "Confirm Nessus plugins and Burp signatures are updated prior to each new scan",
            "vulnerability_scan_evidence_missing",
        ),
        # 5. credentialed scans
        (
            "Provide evidence of credentialed checks for all in-boundary assets (privileged access used)",
            "credentialed_scan_evidence_missing",
        ),
        # 6. central log aggregation
        (
            "Demonstrate centralized audit log aggregation in Splunk for CloudTrail and CloudWatch Logs",
            "centralized_log_missing",
        ),
        # 7. local-vs-central correlation
        (
            "Provide a local audit log example that matches the same audit log contained within Splunk",
            "local_to_central_log_correlation_missing",
        ),
        # 8. alert rule
        (
            "Provide enabled alerts and the recipient list for SOC and IR mailbox",
            "alert_rule_missing",
        ),
        # 9. alert sample
        (
            "Provide example alerts that fired in the last 30 days with sample alert export",
            "alert_sample_missing",
        ),
        # 10. response action
        (
            "Document the actions taken in response to the most recent suspicious-activity alert",
            "response_action_missing",
        ),
        # 11. change ticket
        (
            "Provide change tickets in JIRA for the last quarter's production changes",
            "change_ticket_missing",
        ),
        # 12. SIA
        (
            "Confirm the Security Impact Analysis (SIA) was performed before deployment",
            "sia_missing",
        ),
        # 13. testing evidence
        (
            "Provide test documentation for the change including unit and integration test artifacts",
            "testing_evidence_missing",
        ),
        # 14. approval
        (
            "Provide CAB approval evidence for the change ticket",
            "approval_missing",
        ),
        # 15. deployment evidence
        (
            "Provide deployment evidence (deploy log) showing successful rollout",
            "deployment_evidence_missing",
        ),
        # 16. verification evidence
        (
            "Provide post-deploy verification evidence — was a verification test executed?",
            "verification_evidence_missing",
        ),
        # 17. exploitation review
        (
            "Provide historic audit logs and IoC search showing no evidence of exploitation",
            "exploitation_review_missing",
        ),
        # 18. POA&M update
        (
            "POA&M updated as of this cycle? Please provide the current plan of action",
            "poam_update_missing",
        ),
        # 19. deviation request
        (
            "Provide the Deviation Request and any vendor dependency justifications",
            "deviation_request_missing",
        ),
        # 20. backup evidence
        (
            "Provide backup evidence including AMI snapshot and RDS snapshot exports",
            "backup_evidence_missing",
        ),
        # 21. restore test
        (
            "Provide the most recent restore test with measured RTO/RPO",
            "restore_test_missing",
        ),
        # 22. identity listing
        (
            "Provide the IAM user listing including privileged account flag and MFA report",
            "identity_listing_missing",
        ),
        # 23. crypto FIPS
        (
            "Provide FIPS 140-2 evidence for KMS key rotation and TLS cipher list",
            "crypto_fips_evidence_missing",
        ),
        # 24. traffic flow
        (
            "Provide the traffic flow / data flow diagram and security group inventory",
            "traffic_flow_policy_missing",
        ),
        # 25. password policy (extra)
        (
            "Provide the password policy export with minimum password length and complexity requirements",
            "password_policy_evidence_missing",
        ),
    ],
)
def test_classify_tracker_gap_phrase_rules(request_text: str, expected_gap_type: GapType) -> None:
    cls = classify_tracker_gap(request_text=request_text)
    assert cls.gap_type == expected_gap_type, (
        f"text={request_text!r} → got {cls.gap_type} (matched={cls.matched_phrases}); "
        f"expected {expected_gap_type}"
    )
    assert cls.matched_phrases, "non-unknown classification must record at least one matched phrase"


def test_classify_tracker_gap_unknown_when_no_match() -> None:
    cls = classify_tracker_gap(request_text="totally unrelated request without any keywords")
    assert cls.gap_type == "unknown"
    assert cls.matched_phrases == []
    assert cls.poam_required is False


def test_classify_tracker_gap_uses_assessor_and_csp_text() -> None:
    cls = classify_tracker_gap(
        request_text="Sample change tickets evidence",
        assessor_comment="Confirm the Security Impact Analysis (SIA) was performed before deployment",
    )
    assert cls.gap_type == "sia_missing", cls.matched_phrases


def test_classify_tracker_gap_specificity_order() -> None:
    cls_specific = classify_tracker_gap(
        request_text="Provide evidence of credentialed checks for vulnerability scan reports"
    )
    assert cls_specific.gap_type == "credentialed_scan_evidence_missing"
    cls_inv = classify_tracker_gap(
        request_text="Provide system component inventory with EC2 inventory and RDS inventory"
    )
    assert cls_inv.gap_type == "inventory_mismatch"


def test_high_risk_controls_bump_severity() -> None:
    base = classify_tracker_gap(
        request_text="Provide testing evidence for change ticket CHG-1234",
    )
    bumped = classify_tracker_gap(
        request_text="Provide testing evidence for change ticket CHG-1234",
        controls=["AU-12"],
    )
    assert base.severity == "moderate"
    assert bumped.severity == "high"


def test_poam_required_flag() -> None:
    must_poam = classify_tracker_gap(
        request_text="Historic audit logs and IoC search for HIGH/CRITICAL vulnerabilities"
    )
    assert must_poam.gap_type == "exploitation_review_missing"
    assert must_poam.poam_required is True

    no_poam = classify_tracker_gap(
        request_text="Provide AMI snapshot and RDS snapshot for backup evidence"
    )
    assert no_poam.gap_type == "backup_evidence_missing"
    assert no_poam.poam_required is False


# ---------------------------------------------------------------------------
# 2. EvidenceGap model + GAP_TYPE_TO_KSI mapping
# ---------------------------------------------------------------------------


def test_evidence_gap_model_round_trip() -> None:
    gap = EvidenceGap(
        gap_id="gap-0001-credentialed-scan-evidence-missing",
        source_item_id="1",
        source_file="tracker_items.json",
        controls=["RA-5", "RA-5(5)"],
        gap_type="credentialed_scan_evidence_missing",
        title="Credentialed scan evidence missing: provide credentialed scan",
        description="Provide credentialed scan evidence",
        owner="Vuln Mgmt",
        status="Open",
        due_date="2026-04-26",
        severity="high",
        linked_ksi_ids=["KSI-VULN-01"],
        recommended_artifact="scanner_targets.csv with credentialed=true",
        recommended_validation="Run RA5_SCANNER_SCOPE_COVERAGE",
        poam_required=True,
    )
    parsed = EvidenceGap.model_validate_json(gap.model_dump_json())
    assert parsed == gap


def test_gap_type_to_ksi_mapping_covers_every_gap_type() -> None:
    # Every concrete (non-unknown) GapType must map to at least one KSI.
    expected = {gt for gt in GAP_TYPE_TO_KSI if gt != "unknown"}
    for gt in expected:
        assert GAP_TYPE_TO_KSI[gt], f"{gt} has no linked KSI ids"


# ---------------------------------------------------------------------------
# 3. Coverage invariant — every tracker row is accounted for
# ---------------------------------------------------------------------------


def test_every_row_accounted_for_on_real_sample() -> None:
    rows = parse_tracker_text(SAMPLE_CSV.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(SAMPLE_CSV))
    assert bundle.coverage_invariant_holds is True
    assert bundle.total_rows == len(rows) == 16
    assert len(bundle.evidence_gaps) == 15
    assert len(bundle.informational_items) == 1
    # The closed AC-2 row from the sample becomes informational.
    info = bundle.informational_items[0]
    assert info.controls == ["AC-2"]
    assert "Closed" in info.reason_not_a_gap or "satisfied" in info.reason_not_a_gap


def test_closed_status_becomes_informational(tmp_path: Path) -> None:
    rows = [
        TrackerRow(
            row_index=1,
            controls=["AC-2"],
            request_text="Provide IAM listing",
            request_date=None,
            due_date=None,
            status="Closed",
            owner="IAM Gov",
            assessor_comment=None,
            csp_comment="Accepted from prior cycle.",
            category="iam",
            classification_signals=["account listing"],
            raw={},
        )
    ]
    bundle = build_evidence_gaps(rows, source_file="test.csv")
    assert len(bundle.evidence_gaps) == 0
    assert len(bundle.informational_items) == 1
    assert bundle.informational_items[0].status == "Closed"


def test_csp_already_satisfied_becomes_informational(tmp_path: Path) -> None:
    rows = [
        TrackerRow(
            row_index=1,
            controls=["AC-2"],
            request_text="Provide IAM listing",
            request_date=None,
            due_date=None,
            status="Open",  # status NOT closed
            owner="IAM Gov",
            assessor_comment=None,
            csp_comment="Already accepted from prior cycle. No further action.",
            category="iam",
            classification_signals=["account listing"],
            raw={},
        )
    ]
    bundle = build_evidence_gaps(rows, source_file="test.csv")
    assert len(bundle.evidence_gaps) == 0, "CSP-satisfied open row should be informational"
    assert len(bundle.informational_items) == 1
    assert "satisfied" in bundle.informational_items[0].reason_not_a_gap.lower()


def test_unknown_classification_with_text_still_becomes_gap() -> None:
    rows = [
        TrackerRow(
            row_index=42,
            controls=["XX-99"],
            request_text="some genuinely unrelated thing the assessor asked for",
            request_date=None,
            due_date=None,
            status="Open",
            owner=None,
            assessor_comment=None,
            csp_comment=None,
            category="other",
            classification_signals=[],
            raw={},
        )
    ]
    bundle = build_evidence_gaps(rows)
    assert bundle.coverage_invariant_holds is True
    assert len(bundle.evidence_gaps) == 1
    assert bundle.evidence_gaps[0].gap_type == "unknown"
    assert bundle.evidence_gaps[0].linked_ksi_ids == []


# ---------------------------------------------------------------------------
# 4. Field richness on the real sample
# ---------------------------------------------------------------------------


def test_real_sample_gaps_carry_controls_artifacts_and_ksi() -> None:
    rows = parse_tracker_text(SAMPLE_CSV.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(SAMPLE_CSV))
    for g in bundle.evidence_gaps:
        # Every gap surfaces the controls parsed from the tracker row.
        assert g.controls, f"{g.gap_id} has no controls"
        # Non-unknown gap types must record a recommended artifact + validation step + KSI.
        if g.gap_type != "unknown":
            assert g.recommended_artifact, f"{g.gap_id} ({g.gap_type}) missing recommended_artifact"
            assert g.recommended_validation, f"{g.gap_id} ({g.gap_type}) missing recommended_validation"
            assert g.linked_ksi_ids, f"{g.gap_id} ({g.gap_type}) missing linked_ksi_ids"
        # Source traceability fields are always set.
        assert g.gap_id.startswith("gap-")
        assert g.source_item_id
        assert g.source_file


def test_real_sample_includes_critical_gap_types() -> None:
    rows = parse_tracker_text(SAMPLE_CSV.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(SAMPLE_CSV))
    types = bundle.by_gap_type
    # The sample exercises a broad spread of gap types — at least these should be present.
    # Note: the sample's wording naturally bumps several rows to the more-specific gap
    # type (e.g. local_to_central rather than centralized_log_missing; sia_missing
    # rather than the generic change_ticket_missing). Both are correct.
    for must in (
        "inventory_mismatch",
        "credentialed_scan_evidence_missing",
        "vulnerability_scan_evidence_missing",
        "exploitation_review_missing",
        "local_to_central_log_correlation_missing",
        "alert_sample_missing",
        "response_action_missing",
        "sia_missing",
        "deviation_request_missing",
        "crypto_fips_evidence_missing",
        "restore_test_missing",
        "identity_listing_missing",
        "traffic_flow_policy_missing",
    ):
        assert types.get(must, 0) >= 1, f"sample expected at least one {must} gap; got {types}"
    # No row in the sample should be 'unknown' — every one of the 16 rows is a real
    # FedRAMP evidence request that should map to a concrete gap type or be informational.
    assert types.get("unknown", 0) == 0, f"sample produced unknown gaps: {types}"


# ---------------------------------------------------------------------------
# 5. JSON envelope writer
# ---------------------------------------------------------------------------


def test_write_evidence_gaps_file_envelope_shape(tmp_path: Path) -> None:
    rows = parse_tracker_text(SAMPLE_CSV.read_text(encoding="utf-8"))
    out = tmp_path / "evidence_gaps.json"
    bundle = write_evidence_gaps_file(rows, output_path=out, source_file="tracker_items.json")
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["schema_version"] == "2.0"
    assert doc["coverage_invariant_holds"] is True
    assert doc["total_row_count"] == 16
    assert doc["evidence_gap_count"] == 15
    assert doc["informational_item_count"] == 1
    assert doc["source_file"] == "tracker_items.json"
    # Each evidence gap must conform to the EvidenceGap pydantic model.
    for g in doc["evidence_gaps"]:
        EvidenceGap.model_validate(g)
    for i in doc["informational_tracker_items"]:
        InformationalTrackerItem.model_validate(i)
    # Summary block.
    assert "by_gap_type" in doc["summary"]
    assert doc["summary"]["poam_required_count"] == bundle.poam_required_count


# ---------------------------------------------------------------------------
# 6. End-to-end: importer writes evidence_gaps.json in new schema
# ---------------------------------------------------------------------------


def test_importer_writes_new_evidence_gaps_schema(tmp_path: Path) -> None:
    out = tmp_path / "scen"
    import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
    doc = json.loads((out / "evidence_gaps.json").read_text(encoding="utf-8"))
    assert doc["schema_version"] == "2.0"
    assert doc["coverage_invariant_holds"] is True
    assert doc["evidence_gap_count"] + doc["informational_item_count"] == 16


def test_provider_loads_new_schema_via_evidence_gaps_key(tmp_path: Path) -> None:
    out = tmp_path / "scen"
    import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
    prov = AssessmentTrackerProvider(out)
    gaps = prov.evidence_gaps()
    assert len(gaps) == 15
    sample = gaps[0]
    # Every loaded gap dict matches the EvidenceGap pydantic model schema.
    EvidenceGap.model_validate(sample)


def test_provider_back_compat_with_legacy_gaps_key(tmp_path: Path) -> None:
    out = tmp_path / "scen"
    out.mkdir()
    (out / "tracker_items.json").write_text(
        json.dumps({"row_count": 0, "rows": []}), encoding="utf-8"
    )
    # Legacy schema 1.0 with `gaps` key.
    (out / "evidence_gaps.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "open_gap_count": 1,
                "gaps": [{"row_index": 1, "category": "iam", "request_text": "Provide IAM listing"}],
            }
        ),
        encoding="utf-8",
    )
    prov = AssessmentTrackerProvider(out)
    legacy = prov.evidence_gaps()
    assert len(legacy) == 1
    assert legacy[0]["category"] == "iam"
