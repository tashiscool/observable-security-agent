"""Sanitized 3PAO-style tracker batches: evidence *spirit* → gaps → virtual 3PAO reasoning.

Each batch is 3–5 synthetic rows patterned on real SAP / assessment-tracker language
(no production IPs, people, or tenant names). Tests assert:

1. Parser + :func:`core.evidence_gap.build_evidence_gaps` account for every row.
2. Classified ``gap_type`` matches what practitioners expect for that row archetype.
3. :func:`ai.reasoning.evaluate_3pao_remediation_for_gap` output stays traceable to the
   gap (type + recommended artifact) so the agent app captures the collection intent.

Add new CSVs under ``fixtures/assessment_tracker/3pao_spirit_batch_NN.csv`` and update
``fixtures/assessment_tracker/3pao_spirit_manifest.yaml`` as you expand coverage.
"""

from __future__ import annotations

from pathlib import Path
from typing import get_args

import pytest
import yaml

from ai.reasoning import evaluate_3pao_remediation_for_gap
from core.evidence_gap import build_evidence_gaps
from core.models import GapType, model_to_python_dict
from normalization.assessment_tracker_import import parse_tracker_text

REPO_ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = REPO_ROOT / "fixtures" / "assessment_tracker"

MANIFEST_PATH = FIXTURE_DIR / "3pao_spirit_manifest.yaml"


def _load_batch_expectations() -> dict[str, tuple[list[str], list[int]]]:
    doc = yaml.safe_load(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(doc, dict), "3PAO spirit manifest must be a mapping"
    batches = doc.get("batches")
    assert isinstance(batches, list) and batches, "3PAO spirit manifest must list batches"

    expectations: dict[str, tuple[list[str], list[int]]] = {}
    for entry in batches:
        assert isinstance(entry, dict), "Each manifest batch must be a mapping"
        filename = str(entry.get("file") or "")
        expected_types = [str(x) for x in (entry.get("expected_gap_types") or [])]
        min_ksi_counts = [int(x) for x in (entry.get("min_ksi_counts") or [])]
        assert filename.endswith(".csv"), f"Invalid batch filename: {filename!r}"
        assert expected_types, f"{filename}: missing expected_gap_types"
        assert len(expected_types) == len(min_ksi_counts), f"{filename}: expectations/min KSI length mismatch"
        assert filename not in expectations, f"Duplicate manifest batch: {filename}"
        expectations[filename] = (expected_types, min_ksi_counts)
    return expectations


BATCH_EXPECTATIONS = _load_batch_expectations()


def _combined_3pao_text(ev: object) -> str:
    r = getattr(ev, "recommendation", "") or ""
    m = getattr(ev, "remediation_plan_md", "") or ""
    return f"{r}\n{m}".lower()


def test_manifest_covers_every_spirit_batch_file() -> None:
    """New sanitized batches must be discoverable without editing Python expectations."""
    fixture_files = {p.name for p in FIXTURE_DIR.glob("3pao_spirit_batch_*.csv")}
    manifest_files = set(BATCH_EXPECTATIONS)

    assert fixture_files, "No 3PAO spirit batch CSV fixtures found"
    assert manifest_files == fixture_files


def test_manifest_uses_canonical_gap_types_and_covers_taxonomy() -> None:
    """The spirit corpus should exercise every canonical non-unknown gap type."""
    allowed = set(get_args(GapType))
    expected = {t for types, _ in BATCH_EXPECTATIONS.values() for t in types}

    assert expected <= allowed
    assert (allowed - {"unknown"}) <= expected


@pytest.mark.parametrize("filename", sorted(BATCH_EXPECTATIONS.keys()))
def test_batch_rows_parse_and_classify(filename: str) -> None:
    expected_types, min_ksi_counts = BATCH_EXPECTATIONS[filename]
    path = FIXTURE_DIR / filename
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    assert len(rows) == len(expected_types), f"{filename}: row count"

    bundle = build_evidence_gaps(rows, source_file=str(path))
    assert bundle.coverage_invariant_holds, bundle.to_envelope().get("summary")
    assert len(bundle.evidence_gaps) == len(expected_types)
    assert not bundle.informational_items

    for gap, exp_type, min_ksi in zip(
        bundle.evidence_gaps, expected_types, min_ksi_counts, strict=True
    ):
        assert gap.gap_type == exp_type, f"{filename} row {gap.source_item_id}: {gap.title}"
        assert len(gap.linked_ksi_ids) >= min_ksi, (
            f"{gap.gap_id} expected >= {min_ksi} KSIs, got {gap.linked_ksi_ids}"
        )
        assert gap.recommended_artifact, f"{gap.gap_id} should recommend a concrete artifact class"


@pytest.mark.parametrize("filename", sorted(BATCH_EXPECTATIONS.keys()))
def test_batch_3pao_output_traces_gap_and_artifacts(filename: str) -> None:
    expected_types, _ = BATCH_EXPECTATIONS[filename]
    path = FIXTURE_DIR / filename
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))

    for gap, exp_type in zip(bundle.evidence_gaps, expected_types, strict=True):
        assert gap.gap_type == exp_type
        ev = evaluate_3pao_remediation_for_gap(evidence_gap=model_to_python_dict(gap))
        blob = _combined_3pao_text(ev)

        assert gap.gap_type in ev.remediation_plan_md, (
            "Fallback/LLM plan should echo gap_type for reviewer traceability"
        )
        assert gap.gap_id in ev.remediation_plan_md

        if gap.recommended_artifact:
            head = gap.recommended_artifact.split()[0].strip("`,*").lower()
            if len(head) > 2:
                assert head in blob, (
                    f"3PAO output should cite recommended artifact head {head!r} for {gap.gap_id}"
                )

        if gap.linked_ksi_ids:
            assert "ksi" in blob, f"Expected KSI context in 3PAO output for {gap.gap_id}"

        # Spirit: multi-turn / SAR language for practitioner rows (deterministic path includes these cues).
        assert "assessor" in blob
        assert "reasonable" in blob or "closure" in blob or "sub-requirement" in blob


def test_batch_01_request_text_preserved_in_gap_description() -> None:
    """Ensure description carries the assessor request (not only comments)."""
    path = FIXTURE_DIR / "3pao_spirit_batch_01.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g = bundle.evidence_gaps[3]
    assert g.gap_type == "exploitation_review_missing"
    assert "audit log" in g.description.lower()
    assert "critical" in g.description.lower() or "high" in g.description.lower()


def test_batch_03_leveraged_service_row_keeps_request_narrative() -> None:
    """CA-3 / CRM style rows should surface interconnection + data-location language."""
    path = FIXTURE_DIR / "3pao_spirit_batch_03.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g = bundle.evidence_gaps[1]
    assert g.gap_type == "traffic_flow_policy_missing"
    blob = g.description.lower()
    assert "interconnection" in blob or "leveraged" in blob
    assert "fedramp" in blob or "responsibility" in blob


def test_batch_04_audit_correlation_row_description() -> None:
    """AU rows should preserve local-vs-central pairing language."""
    path = FIXTURE_DIR / "3pao_spirit_batch_04.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "local_to_central_log_correlation_missing"
    d = g0.description.lower()
    assert "local" in d and ("central" in d or "siem" in d)


def test_batch_05_restore_before_change_cm_chain() -> None:
    """CP restore rows must not be classified as generic CM testing gaps."""
    path = FIXTURE_DIR / "3pao_spirit_batch_05.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    assert bundle.evidence_gaps[0].gap_type == "restore_test_missing"
    desc = bundle.evidence_gaps[0].description.lower()
    assert "rto" in desc or "rpo" in desc


def test_batch_06_incident_thread_row() -> None:
    """IR listing rows should keep suspected/confirmed and closure language."""
    path = FIXTURE_DIR / "3pao_spirit_batch_06.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "response_action_missing"
    d = g0.description.lower()
    assert "incident" in d
    assert "suspected" in d or "confirmed" in d


def test_batch_07_public_content_review_row() -> None:
    """AC-22 style rows should retain posting-review and public-surface language."""
    path = FIXTURE_DIR / "3pao_spirit_batch_07.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "approval_missing"
    t = g2.description.lower()
    assert "public" in t or "posting" in t


def test_batch_08_supply_chain_and_sbom_spirit() -> None:
    """SR/SA-9 supply packet and SBOM rows keep distinct evidence language."""
    path = FIXTURE_DIR / "3pao_spirit_batch_08.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    assert bundle.evidence_gaps[0].gap_type == "deviation_request_missing"
    assert "supply" in bundle.evidence_gaps[0].description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "inventory_mismatch"
    d2 = g2.description.lower()
    assert "sbom" in d2 or "spdx" in d2 or "cyclonedx" in d2


def test_batch_09_contingency_sr2_pedigree_and_sar_poam_crossfoot() -> None:
    """CP excerpt, SR-2 supplier auth pedigree, SAR–POA&M cross-foot, CP-9 backup scope, AU sign-off."""
    path = FIXTURE_DIR / "3pao_spirit_batch_09.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "alternate processing" in d0 or "contingency plan excerpt" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "deviation_request_missing"
    d1 = g1.description.lower()
    assert "fedramp" in d1 and ("authorization" in d1 or "inheritance" in d1)
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "poam_update_missing"
    assert "sar" in g2.description.lower() and "poa&m" in g2.description.lower()


def test_batch_10_pe_sc_ra_boundary_malware_spirit() -> None:
    """PE escorted access, SC-13 key mgmt, RA-3 assessment, SC-7 segmentation, SI malware + alert linkage."""
    path = FIXTURE_DIR / "3pao_spirit_batch_10.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "identity_listing_missing"
    assert "escort" in g0.description.lower() or "visitor" in g0.description.lower()
    assert bundle.evidence_gaps[1].gap_type == "crypto_fips_evidence_missing"
    assert "key" in bundle.evidence_gaps[1].description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    assert "risk assessment" in g2.description.lower()
    assert bundle.evidence_gaps[3].gap_type == "traffic_flow_policy_missing"
    d3 = bundle.evidence_gaps[3].description.lower()
    assert "segmentation" in d3 or "boundary" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "alert_rule_missing"
    d4 = g4.description.lower()
    assert "malware" in d4 or "alert rule" in d4


def test_batch_11_pl4_ir_ca_pl8_conmon_spirit() -> None:
    """PL-4 acknowledgements, IR-4 hunt, CA-2 assessment, PL-8 architecture, CA-7 ConMon."""
    path = FIXTURE_DIR / "3pao_spirit_batch_11.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "identity_listing_missing"
    d0 = g0.description.lower()
    assert "rules of behavior" in d0 or "acceptable use" in d0 or "pl-4" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "response_action_missing"
    assert "hunt" in g1.description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    assert "ca-2" in g2.description.lower() or "control assessment" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "traffic_flow_policy_missing"
    d3 = g3.description.lower()
    assert "pl-8" in d3 or "architecture" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "testing_evidence_missing"
    assert "continuous monitoring" in g4.description.lower() or "ca-7" in g4.description.lower()


def test_batch_12_ac3_mp5_si10_ac6_au3_spirit() -> None:
    """AC-3 enforcement, MP-5 media chain, SI-10 validation tests, AC-6 least privilege, AU-3 log content."""
    path = FIXTURE_DIR / "3pao_spirit_batch_12.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    assert bundle.evidence_gaps[0].gap_type == "identity_listing_missing"
    d0 = bundle.evidence_gaps[0].description.lower()
    assert "ac-3" in d0 or "access enforcement" in d0 or "enforcement" in d0
    assert bundle.evidence_gaps[1].gap_type == "testing_evidence_missing"
    d1 = bundle.evidence_gaps[1].description.lower()
    assert "media" in d1 or "mp-5" in d1 or "custody" in d1 or "handoff" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    assert "input validation" in g2.description.lower() or "si-10" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "identity_listing_missing"
    d3 = g3.description.lower()
    assert "least" in d3 and "priv" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "centralized_log_missing"
    assert "au-3" in g4.description.lower() or "audit record" in g4.description.lower()


def test_batch_13_cm6_ac17_au9_cp6_sc28_spirit() -> None:
    """CM-6 baseline, AC-17 remote access, AU-9 audit protection, CP-6 alternate site, SC-28 encryption at rest."""
    path = FIXTURE_DIR / "3pao_spirit_batch_13.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    assert "cm-6" in g0.description.lower() or "baseline" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "traffic_flow_policy_missing"
    d1 = g1.description.lower()
    assert "remote access" in d1 or "vpn" in d1 or "ac-17" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "centralized_log_missing"
    assert "au-9" in g2.description.lower() or "audit" in g2.description.lower()
    assert bundle.evidence_gaps[3].gap_type == "backup_evidence_missing"
    d3 = bundle.evidence_gaps[3].description.lower()
    assert "cp-6" in d3 or "alternate" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "crypto_fips_evidence_missing"
    d4 = g4.description.lower()
    assert "sc-28" in d4 or "encryption" in d4


def test_batch_14_si11_ac20_sa21_sc39_ir8_spirit() -> None:
    """SI-11 fault handling, AC-20 distributed processing, SA-21 dev separation, SC-39 isolation, IR-8 tabletop."""
    path = FIXTURE_DIR / "3pao_spirit_batch_14.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "si-11" in d0 or "fault" in d0 or "error handling" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "traffic_flow_policy_missing"
    d1 = g1.description.lower()
    assert "ac-20" in d1 or "distributed processing" in d1 or "broker" in d1
    assert bundle.evidence_gaps[2].gap_type == "testing_evidence_missing"
    d2 = bundle.evidence_gaps[2].description.lower()
    assert "sa-21" in d2 or "developer" in d2 or "development environment" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    assert "sc-39" in g3.description.lower() or "process isolation" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "testing_evidence_missing"
    d4 = g4.description.lower()
    assert "ir-8" in d4 or "tabletop" in d4


def test_batch_15_si12_ac21_sa4_si7_au11_spirit() -> None:
    """SI-12 SDLC gates, AC-21 collab devices, SA-4 acquisition trace, SI-7 integrity monitoring, AU-11 retention."""
    path = FIXTURE_DIR / "3pao_spirit_batch_15.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "si-12" in d0 or "sdlc" in d0 or "development lifecycle" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "identity_listing_missing"
    d1 = g1.description.lower()
    assert "ac-21" in d1 or "collaborative" in d1 or "conference" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    assert "sa-4" in g2.description.lower() or "acquisition" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "alert_rule_missing"
    d3 = g3.description.lower()
    assert "si-7" in d3 or "integrity" in d3 or "tamper" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "centralized_log_missing"
    assert "au-11" in g4.description.lower() or "retention" in g4.description.lower()


def test_batch_16_si16_sc12_au4_ia8_sc23_spirit() -> None:
    """SI-16 memory protection, SC-12 PIV establishment, AU-4 event generation, IA-8 reuse, SC-23 fail-secure."""
    path = FIXTURE_DIR / "3pao_spirit_batch_16.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "si-16" in d0 or "memory" in d0 or "aslr" in d0
    assert bundle.evidence_gaps[1].gap_type == "crypto_fips_evidence_missing"
    d1 = bundle.evidence_gaps[1].description.lower()
    assert "sc-12" in d1 or "piv" in d1 or "credential" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "centralized_log_missing"
    assert "au-4" in g2.description.lower() or "audit event" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "identity_listing_missing"
    assert "ia-8" in g3.description.lower() or "reuse" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "testing_evidence_missing"
    d4 = g4.description.lower()
    assert "sc-23" in d4 or "fail" in d4 and "secure" in d4


def test_batch_17_si2_si15_ra5_cm3_ac4_spirit() -> None:
    """SI-2 flaw remediation tickets, SI-15 guarded exchange, RA-5(2) scans, CM-3(2) parity test, AC-4 flows."""
    path = FIXTURE_DIR / "3pao_spirit_batch_17.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "change_ticket_missing"
    d0 = g0.description.lower()
    assert "si-2" in d0 or "remediation" in d0 or "patch" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "traffic_flow_policy_missing"
    assert "si-15" in g1.description.lower() or "information exchange" in g1.description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "vulnerability_scan_evidence_missing"
    assert "ra-5" in g2.description.lower() or "vulnerability scan" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    d3 = g3.description.lower()
    assert "cm-3(2)" in d3 or "non-production" in d3 or "parity" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "traffic_flow_policy_missing"
    d4 = g4.description.lower()
    assert "ac-4" in d4 or "information flow" in d4 or "approved" in d4


def test_batch_18_si14_sc34_ac19_sc51_au2_spirit() -> None:
    """SI-14 non-persistence, SC-34 DoS monitoring, AC-19 device roster, SC-51 TPM integrity, AU-2 auditable events."""
    path = FIXTURE_DIR / "3pao_spirit_batch_18.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "si-14" in d0 or "non-persistence" in d0 or "transient" in d0 or "ephemeral" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "alert_rule_missing"
    d1 = g1.description.lower()
    assert "sc-34" in d1 or "denial" in d1 or "dos" in d1 or "syn" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "identity_listing_missing"
    d2 = g2.description.lower()
    assert "ac-19" in d2 or "mdm" in d2 or "device" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    assert "sc-51" in g3.description.lower() or "tpm" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "centralized_log_missing"
    assert "au-2" in g4.description.lower() or "auditable" in g4.description.lower()


def test_batch_19_si18_sc36_si17_ac7_au13_spirit() -> None:
    """SI-18 mobile code, SC-36 processing site, SI-17 fail-safe, AC-7 lockout, AU-13 audit disclosure monitoring."""
    path = FIXTURE_DIR / "3pao_spirit_batch_19.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "si-18" in d0 or "mobile code" in d0 or "content-security" in d0 or "script origins" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "traffic_flow_policy_missing"
    d1 = g1.description.lower()
    assert "sc-36" in d1 or "processing site" in d1 or "distributed processing" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    assert "si-17" in g2.description.lower() or "fail" in g2.description.lower() and "safe" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "password_policy_evidence_missing"
    d3 = g3.description.lower()
    assert "ac-7" in d3 or "lockout" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "centralized_log_missing"
    assert "au-13" in g4.description.lower() or "unauthorized" in g4.description.lower() or "audit information" in g4.description.lower()


def test_batch_20_si19_ac5_pm9_au8_sc5_spirit() -> None:
    """SI-19 voice/video media, AC-5 SoD matrix, PM-9 risk executive, AU-8 time sync, SC-5 resource limits."""
    path = FIXTURE_DIR / "3pao_spirit_batch_20.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "si-19" in d0 or "voice" in d0 or "video" in d0 or "media encryption" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "identity_listing_missing"
    d1 = g1.description.lower()
    assert "ac-5" in d1 or "separation" in d1 or "segregation" in d1 or "sod" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    assert "pm-9" in g2.description.lower() or "risk executive" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "centralized_log_missing"
    assert "au-8" in g3.description.lower() or "ntp" in g3.description.lower() or "time synchronization" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "traffic_flow_policy_missing"
    d4 = g4.description.lower()
    assert "sc-5" in d4 or "rate limit" in d4 or "quota" in d4


def test_batch_21_ac3_4_si3_at2_cp10_ir9_spirit() -> None:
    """AC-3(4) dual auth, SI-3 malware + alerts, AT-2 phishing metrics, CP-10 alt comms drill, IR-9 spillage."""
    path = FIXTURE_DIR / "3pao_spirit_batch_21.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "approval_missing"
    d0 = g0.description.lower()
    assert "ac-3(4)" in d0 or "dual authorization" in d0 or "approver" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "alert_rule_missing"
    d1 = g1.description.lower()
    assert "si-3" in d1 or "malicious code" in d1 or "alert rule" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "identity_listing_missing"
    assert "at-2" in g2.description.lower() or "phishing" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    assert "cp-10" in g3.description.lower() or "alternate communications" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "response_action_missing"
    d4 = g4.description.lower()
    assert "ir-9" in d4 or "spillage" in d4


def test_batch_22_sa11_si423_ra55_cm7_sa15_spirit() -> None:
    """SA-11 app sec testing gates, SI-4(23) HIDS + alerts, RA-5(5) priv scans, CM-7 least function, SA-15 processor addendum."""
    path = FIXTURE_DIR / "3pao_spirit_batch_22.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "sa-11" in d0 or "application security" in d0 or "static" in d0 or "dynamic" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "alert_rule_missing"
    d1 = g1.description.lower()
    assert "si-4(23)" in d1 or "host" in d1 and "intrusion" in d1 or "alert rule" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "credentialed_scan_evidence_missing"
    assert "ra-5(5)" in g2.description.lower() or "authenticated" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    assert "cm-7" in g3.description.lower() or "least functionality" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "deviation_request_missing"
    d4 = g4.description.lower()
    assert "sa-15" in d4 or "subprocessor" in d4 or "flow-down" in d4


def test_batch_23_sc8_si5_ac10_ra9_cp8_spirit() -> None:
    """SC-8 TLS confidentiality, SI-5 warning banner, AC-10 session limits, RA-9 criticality, CP-8 alt telecom."""
    path = FIXTURE_DIR / "3pao_spirit_batch_23.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "crypto_fips_evidence_missing"
    d0 = g0.description.lower()
    assert "sc-8" in d0 or "transmission" in d0 or "tls" in d0 or "cipher" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "alert_rule_missing"
    d1 = g1.description.lower()
    assert "si-5" in d1 or "security warning" in d1 or "banner" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "password_policy_evidence_missing"
    d2 = g2.description.lower()
    assert "ac-10" in d2 or "concurrent session" in d2 or "session limit" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    assert "ra-9" in g3.description.lower() or "criticality" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "testing_evidence_missing"
    d4 = g4.description.lower()
    assert "cp-8" in d4 or "telecommunications" in d4 or "failover" in d4


def test_batch_24_ac4_ra51_exploit_au12_ca5_spirit() -> None:
    """AC-4 flows, RA-5(1) scan scope, exploitation review, AU-12 logging, CA-5 POA&M refresh."""
    path = FIXTURE_DIR / "3pao_spirit_batch_24.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "traffic_flow_policy_missing"
    d0 = g0.description.lower()
    assert "ac-4" in d0 or "information flow" in d0 or "approved information" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "scanner_scope_missing"
    assert "ra-5(1)" in g1.description.lower() or "scanned" in g1.description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "exploitation_review_missing"
    d2 = g2.description.lower()
    assert "exploitation" in d2 or "compromise" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "centralized_log_missing"
    assert g3.severity == "high"  # AU-12 control family bumps moderate → high
    d3 = g3.description.lower()
    assert "au-12" in d3 or "cloudwatch" in d3 or "vpc flow" in d3 or "immutable" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "poam_update_missing"
    assert "poa" in g4.description.lower() or "poam" in g4.description.lower()


def test_batch_25_sia_deploy_vuln_ir_au6_spirit() -> None:
    """SIA, deploy log, Nessus scan export, IR response pack, local-to-central audit pairing."""
    path = FIXTURE_DIR / "3pao_spirit_batch_25.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "sia_missing"
    d0 = g0.description.lower()
    assert "security impact analysis" in d0 or "sia" in d0 or "cm-3" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "deployment_evidence_missing"
    d1 = g1.description.lower()
    assert "deployment" in d1 or "artifact digest" in d1 or "digest" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "vulnerability_scan_evidence_missing"
    d2 = g2.description.lower()
    assert "nessus" in d2 or "vulnerability scan" in d2 or "scan frequency" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "response_action_missing"
    d3 = g3.description.lower()
    assert "incident response" in d3 or "response action" in d3 or "ir-4" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "local_to_central_log_correlation_missing"
    d4 = g4.description.lower()
    assert "local audit log" in d4 or "matches centralized" in d4 or "au-6" in d4


def test_batch_26_approval_verify_change_backup_identity_spirit() -> None:
    """CAB approval, post-deploy verification, change record, RDS backup evidence, IAM inventory."""
    path = FIXTURE_DIR / "3pao_spirit_batch_26.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "approval_missing"
    d0 = g0.description.lower()
    assert "approval" in d0 or "cab" in d0 or "advisory board" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "verification_evidence_missing"
    d1 = g1.description.lower()
    assert "verification" in d1 or "post-deploy" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "change_ticket_missing"
    d2 = g2.description.lower()
    assert "change request" in d2 or "jira" in d2 or "cm-3" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "backup_evidence_missing"
    d3 = g3.description.lower()
    assert "rds snapshot" in d3 or "snapshot" in d3 or "cp-9" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "identity_listing_missing"
    d4 = g4.description.lower()
    assert "iam role" in d4 or "privileged" in d4 or "ac-2" in d4


def test_batch_27_deviation_restore_sample_cred_inv_spirit() -> None:
    """Deviation memo, DR restore metrics, SIEM sample alert, credentialed scan, inventory reconcile."""
    path = FIXTURE_DIR / "3pao_spirit_batch_27.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "deviation_request_missing"
    d0 = g0.description.lower()
    assert "deviation" in d0 or "vendor dependency" in d0 or "fedramp deviation" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "restore_test_missing"
    d1 = g1.description.lower()
    assert "rto" in d1 or "rpo" in d1 or "restore" in d1 or "dr exercise" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "alert_sample_missing"
    d2 = g2.description.lower()
    assert "sample alert" in d2 or "example alert" in d2 or "saved search" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "credentialed_scan_evidence_missing"
    d3 = g3.description.lower()
    assert "credentialed" in d3 or "authenticated vulnerability" in d3 or "ra-5(5)" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "inventory_mismatch"
    d4 = g4.description.lower()
    assert "reconcile" in d4 or "discrepancies" in d4 or "duplicate" in d4 or "cm-8" in d4


def test_batch_28_ca2_sc7_scope_exploit_alarm_spirit() -> None:
    """CA-2 assessment artifacts, SC-7 SG inventory, scan scope, exploitation review, CloudWatch alarms."""
    path = FIXTURE_DIR / "3pao_spirit_batch_28.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    d0 = g0.description.lower()
    assert "ca-2" in d0 or "control assessment" in d0 or "security control assessment" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "traffic_flow_policy_missing"
    d1 = g1.description.lower()
    assert "sc-7" in d1 or "ingress rule" in d1 or "security group" in d1 or "egress rule" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "scanner_scope_missing"
    d2 = g2.description.lower()
    assert "in-boundary" in d2 or "scanner_targets" in d2 or "ra-5(1)" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "exploitation_review_missing"
    d3 = g3.description.lower()
    assert "exploitation" in d3 or "compromise assessment" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "alert_rule_missing"
    d4 = g4.description.lower()
    assert "cloudwatch alarm" in d4 or "recipient list" in d4 or "si-4" in d4


def test_batch_29_poam_dualauth_ir8_burp_au11_spirit() -> None:
    """POA&M SAR export, dual authorization, IR-8 tabletop CM strategy, Burp scan pack, AU-11 retention."""
    path = FIXTURE_DIR / "3pao_spirit_batch_29.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "poam_update_missing"
    assert "poa" in g0.description.lower() or "poam" in g0.description.lower() or "sar appendix" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "approval_missing"
    d1 = g1.description.lower()
    assert "dual authorization" in d1 or "two-person" in d1 or "maker-checker" in d1 or "ac-3(4)" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    d2 = g2.description.lower()
    assert "ir-8" in d2 or "tabletop" in d2 or "lessons learned" in d2 or "continuous monitoring" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "vulnerability_scan_evidence_missing"
    d3 = g3.description.lower()
    assert "burp" in d3 or "recurring vulnerability scan" in d3 or "scan tool version" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "centralized_log_missing"
    d4 = g4.description.lower()
    assert "au-11" in d4 or "audit retention" in d4 or "log retention" in d4 or "worm-style" in d4


def test_batch_30_sia_deploy_verify_change_backup_spirit() -> None:
    """SIA narrative, deploy digest log, post-deploy verification, patch change export, RDS snapshot chain."""
    path = FIXTURE_DIR / "3pao_spirit_batch_30.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "sia_missing"
    d0 = g0.description.lower()
    assert "security impact analysis" in d0 or "sia" in d0 or "cm-3" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "deployment_evidence_missing"
    d1 = g1.description.lower()
    assert "deployment" in d1 or "artifact digest" in d1 or "digest" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "verification_evidence_missing"
    d2 = g2.description.lower()
    assert "verification" in d2 or "post-deploy" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "change_ticket_missing"
    d3 = g3.description.lower()
    assert "jira" in d3 or "change request" in d3 or "security patch" in d3 or "change control board" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "backup_evidence_missing"
    d4 = g4.description.lower()
    assert "rds snapshot" in d4 or "snapshot evidence" in d4 or "cp-9" in d4 or "kms" in d4


def test_batch_31_inv_hunt_crypto_pw_vpn_spirit() -> None:
    """Inventory reconcile, threat hunt response, KMS FIPS policy, password lockout export, VPN traffic matrix."""
    path = FIXTURE_DIR / "3pao_spirit_batch_31.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "inventory_mismatch"
    d0 = g0.description.lower()
    assert "reconcile declared" in d0 or "discrepancies" in d0 or "stale cmdb" in d0 or "cm-8" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "response_action_missing"
    d1 = g1.description.lower()
    assert "threat hunt" in d1 or "response action" in d1 or "ir-4" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "crypto_fips_evidence_missing"
    d2 = g2.description.lower()
    assert "fips" in d2 or "kms" in d2 or "cryptographic key" in d2 or "sc-13" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "password_policy_evidence_missing"
    d3 = g3.description.lower()
    assert "failed logon" in d3 or "password policy" in d3 or "ia-5" in d3 or "ac-7" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "traffic_flow_policy_missing"
    d4 = g4.description.lower()
    assert "vpn" in d4 or "ingress rule" in d4 or "split-tunnel" in d4 or "ac-17" in d4


def test_batch_32_local_central_exploit_scope_cred_spirit() -> None:
    """Local-to-central pairing, AU-2 log baseline, exploitation review, scan scope, credentialed RA-5(5)."""
    path = FIXTURE_DIR / "3pao_spirit_batch_32.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "local_to_central_log_correlation_missing"
    d0 = g0.description.lower()
    assert "local audit log" in d0 or "matches centralized" in d0 or "au-6" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "centralized_log_missing"
    d1 = g1.description.lower()
    assert "au-2" in d1 or "auditable events" in d1 or "log aggregation" in d1 or "log forwarding" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "exploitation_review_missing"
    d2 = g2.description.lower()
    assert "exploitation" in d2 or "compromise assessment" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "scanner_scope_missing"
    d3 = g3.description.lower()
    assert "scanner_targets" in d3 or "in-boundary" in d3 or "ra-5(1)" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "credentialed_scan_evidence_missing"
    d4 = g4.description.lower()
    assert "credentialed" in d4 or "authenticated vulnerability" in d4 or "ra-5(5)" in d4


def test_batch_33_deviation_restore_sample_identity_fim_spirit() -> None:
    """Subprocessor deviation, DR RTO/RPO, SIEM sample alert, access review plus MFA, FIM SI-7 policy."""
    path = FIXTURE_DIR / "3pao_spirit_batch_33.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "deviation_request_missing"
    d0 = g0.description.lower()
    assert "deviation" in d0 or "flow-down" in d0 or "vendor dependency" in d0 or "subprocessor" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "restore_test_missing"
    d1 = g1.description.lower()
    assert "rto" in d1 or "rpo" in d1 or "recovery test" in d1 or "dr exercise" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "alert_sample_missing"
    d2 = g2.description.lower()
    assert "sample alert" in d2 or "example alert" in d2 or "soc email notification" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "identity_listing_missing"
    d3 = g3.description.lower()
    assert "access review" in d3 or "mfa report" in d3 or "privileged account" in d3 or "ac-2" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "alert_rule_missing"
    d4 = g4.description.lower()
    assert "fim" in d4 or "file integrity" in d4 or "monitored paths" in d4 or "malware protection" in d4 or "si-7" in d4


def test_batch_34_poam_logreview_sast_nessus_dfd_spirit() -> None:
    """POA&M SAR refresh, log review sign-off, SA-11 pipeline SAST gate, Nessus cadence, SC-7 DFD matrix."""
    path = FIXTURE_DIR / "3pao_spirit_batch_34.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "poam_update_missing"
    assert "poa" in g0.description.lower() or "poam" in g0.description.lower() or "sar appendix" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "approval_missing"
    d1 = g1.description.lower()
    assert "log review" in d1 or "periodic log review" in d1 or "sign-off" in d1 or "au-6" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "testing_evidence_missing"
    d2 = g2.description.lower()
    assert "sa-11" in d2 or "application security testing" in d2 or "static application security" in d2 or "pipeline security" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "vulnerability_scan_evidence_missing"
    d3 = g3.description.lower()
    assert "nessus" in d3 or "vulnerability scan" in d3 or "recurring vulnerability scan" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "traffic_flow_policy_missing"
    d4 = g4.description.lower()
    assert "data flow diagram" in d4 or "ports and protocols" in d4 or "security group" in d4 or "sc-7" in d4


def test_batch_35_inv_exploit_scope_cred_sia_spirit() -> None:
    """ENI inventory drift, exploitation IOC addendum, scan scope export, credentialed runbook, mesh SIA checklist."""
    path = FIXTURE_DIR / "3pao_spirit_batch_35.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "inventory_mismatch"
    d0 = g0.description.lower()
    assert "reconcile inventory" in d0 or "orphan" in d0 or "duplicate entries" in d0 or "cm-8" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "exploitation_review_missing"
    d1 = g1.description.lower()
    assert "exploitation" in d1 or "compromise assessment" in d1 or "ioc" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "scanner_scope_missing"
    d2 = g2.description.lower()
    assert "scanner_targets" in d2 or "in-boundary" in d2 or "ra-5(1)" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "credentialed_scan_evidence_missing"
    d3 = g3.description.lower()
    assert "credentialed" in d3 or "authenticated vulnerability" in d3 or "ra-5(5)" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "sia_missing"
    d4 = g4.description.lower()
    assert "security impact analysis" in d4 or "sia" in d4 or "cm-3" in d4


def test_batch_36_local_central_ir_guardduty_idam_spirit() -> None:
    """Local-central pairing, immutable audit landing zone, IR closure, GuardDuty routing, least-privilege review."""
    path = FIXTURE_DIR / "3pao_spirit_batch_36.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "local_to_central_log_correlation_missing"
    d0 = g0.description.lower()
    assert "local auth" in d0 or "matches centralized" in d0 or "au-6" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "centralized_log_missing"
    d1 = g1.description.lower()
    assert "immutable bucket" in d1 or "centralized audit log aggregation" in d1 or "append-only" in d1 or "au-9" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "response_action_missing"
    d2 = g2.description.lower()
    assert "documented response action" in d2 or "cisa report" in d2 or "incident closure" in d2 or "ir-8" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "alert_rule_missing"
    d3 = g3.description.lower()
    assert "guardduty" in d3 or "recipient list" in d3 or "syn flood" in d3 or "denial-of-service" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "identity_listing_missing"
    d4 = g4.description.lower()
    assert "least privilege review" in d4 or "privilege recertification" in d4 or "separation-of-duties" in d4 or "ac-6" in d4


def test_batch_37_poam_cab_inv_ioc_scope_spirit() -> None:
    """POA&M refresh workbook, CAB approval export, declared-vs-live inventory drift, IOC exploitation addendum, scan scope memo."""
    path = FIXTURE_DIR / "3pao_spirit_batch_37.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "poam_update_missing"
    assert "poa" in g0.description.lower() or "poam" in g0.description.lower() or "sar appendix" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "approval_missing"
    d1 = g1.description.lower()
    assert "cab approval" in d1 or "change advisory board" in d1 or "evidence of review and approval" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "inventory_mismatch"
    d2 = g2.description.lower()
    assert "reconcile declared" in d2 or "unique identifier" in d2 or "duplicate entries" in d2 or "cm-8" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "exploitation_review_missing"
    d3 = g3.description.lower()
    assert "exploitation" in d3 or "indicator of compromise" in d3 or "ioc" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "scanner_scope_missing"
    d4 = g4.description.lower()
    assert "scanner_targets" in d4 or "in-boundary" in d4 or "ra-5(1)" in d4


def test_batch_38_cred_burp_sia_deploy_verify_spirit() -> None:
    """Credentialed RA-5(5) pack, Burp cadence folder, gateway SIA narrative, deploy digest log, post-deploy verification."""
    path = FIXTURE_DIR / "3pao_spirit_batch_38.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "credentialed_scan_evidence_missing"
    d0 = g0.description.lower()
    assert "credentialed" in d0 or "authenticated vulnerability" in d0 or "ra-5(5)" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "vulnerability_scan_evidence_missing"
    d1 = g1.description.lower()
    assert "burp" in d1 or "recurring vulnerability scan" in d1 or "scan tool version" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "sia_missing"
    d2 = g2.description.lower()
    assert "security impact analysis" in d2 or "sia" in d2 or "cm-3" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "deployment_evidence_missing"
    d3 = g3.description.lower()
    assert "deployment" in d3 or "artifact digest" in d3 or "prior to production deployment" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "verification_evidence_missing"
    d4 = g4.description.lower()
    assert "verification evidence" in d4 or "post-deploy" in d4 or "post-deploy verification" in d4


def test_batch_39_deviation_restore_sample_seg_fips_spirit() -> None:
    """Supply-chain deviation memo, DR RTO/RPO packet, SIEM sample alert bundle, SC-7 segmentation, FIPS KMS inventory."""
    path = FIXTURE_DIR / "3pao_spirit_batch_39.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "deviation_request_missing"
    d0 = g0.description.lower()
    assert "supply chain" in d0 or "fedramp deviation" in d0 or "vendor dependency" in d0 or "sa-15" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "restore_test_missing"
    d1 = g1.description.lower()
    assert "measured rto" in d1 or "measured rpo" in d1 or "recovery test" in d1 or "dr exercise" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "alert_sample_missing"
    d2 = g2.description.lower()
    assert "sample alert" in d2 or "saved search export" in d2 or "example alert" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "traffic_flow_policy_missing"
    d3 = g3.description.lower()
    assert "network segmentation" in d3 or "ports and protocols" in d3 or "security group" in d3 or "sc-7" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "crypto_fips_evidence_missing"
    d4 = g4.description.lower()
    assert "fips" in d4 or "kms key rotation" in d4 or "encryption at rest" in d4 or "sc-13" in d4


def test_batch_40_patch_backup_pw_alarm_ir_spirit() -> None:
    """Patch change export, RDS snapshot workbook, lockout password policy, CloudWatch alarm routing, IR evidence pack."""
    path = FIXTURE_DIR / "3pao_spirit_batch_40.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "change_ticket_missing"
    d0 = g0.description.lower()
    assert "jira" in d0 or "change request" in d0 or "security patch" in d0 or "ccb meeting" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "backup_evidence_missing"
    d1 = g1.description.lower()
    assert "rds snapshot" in d1 or "snapshot evidence" in d1 or "backup scope" in d1 or "cp-9" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "password_policy_evidence_missing"
    d2 = g2.description.lower()
    assert "failed logon" in d2 or "password policy" in d2 or "lockout" in d2 or "ia-5" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "alert_rule_missing"
    d3 = g3.description.lower()
    assert "cloudwatch alarm" in d3 or "recipient list" in d3 or "si-4" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "response_action_missing"
    d4 = g4.description.lower()
    assert "incident response" in d4 or "threat hunt" in d4 or "documented response action" in d4 or "ir-4" in d4


def test_batch_41_local_central_id_ca7_webapprove_spirit() -> None:
    """Log pairing, AU-3/AU-2 aggregation map, IAM access review export, CA-7 CM strategy, public web content approvals."""
    path = FIXTURE_DIR / "3pao_spirit_batch_41.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "local_to_central_log_correlation_missing"
    d0 = g0.description.lower()
    assert "local log" in d0 or "matches centralized" in d0 or "forwarder healthcheck" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "centralized_log_missing"
    d1 = g1.description.lower()
    assert "vpc flow logs" in d1 or "central log aggregation" in d1 or "audit record content" in d1 or "au-3" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "identity_listing_missing"
    d2 = g2.description.lower()
    assert "access review" in d2 or "mfa report" in d2 or "service account inventory" in d2 or "ac-2" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "testing_evidence_missing"
    d3 = g3.description.lower()
    assert "continuous monitoring" in d3 or "security control assessment" in d3 or "security risk assessment" in d3 or "ca-7" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "approval_missing"
    d4 = g4.description.lower()
    assert "publicly accessible" in d4 or "web content review" in d4 or "reviewed before posting" in d4 or "ac-3" in d4


def test_batch_42_poam_inv_scope_cred_burp_spirit() -> None:
    """POA&M post-import refresh, CM-8 reconcile drift, RA-5(1) targets worksheet, credentialed RA-5(5) binder, Burp cadence."""
    path = FIXTURE_DIR / "3pao_spirit_batch_42.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "poam_update_missing"
    assert "poa" in g0.description.lower() or "poam" in g0.description.lower() or "sar appendix" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "inventory_mismatch"
    d1 = g1.description.lower()
    assert "reconcile declared" in d1 or "discrepancies" in d1 or "duplicate entries" in d1 or "stale cmdb" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "scanner_scope_missing"
    d2 = g2.description.lower()
    assert "scanner_targets" in d2 or "in-boundary" in d2 or "ra-5(1)" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "credentialed_scan_evidence_missing"
    d3 = g3.description.lower()
    assert "credentialed" in d3 or "authenticated vulnerability" in d3 or "ra-5(5)" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "vulnerability_scan_evidence_missing"
    d4 = g4.description.lower()
    assert "burp" in d4 or "recurring vulnerability scan" in d4 or "scan frequency" in d4


def test_batch_43_restore_backup_chg_pw_cm7_spirit() -> None:
    """DR RTO/RPO runbook, RDS snapshot contingency excerpt, patch change export, AC-7 password JSON, CM-7 least functionality."""
    path = FIXTURE_DIR / "3pao_spirit_batch_43.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "restore_test_missing"
    d0 = g0.description.lower()
    assert "measured rto" in d0 or "measured rpo" in d0 or "recovery test" in d0 or "dr exercise" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "backup_evidence_missing"
    d1 = g1.description.lower()
    assert "snapshot evidence" in d1 or "alternate storage" in d1 or "backup scope" in d1 or "cp-9" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "change_ticket_missing"
    d2 = g2.description.lower()
    assert "jira" in d2 or "change request" in d2 or "security patch" in d2 or "change control board" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "password_policy_evidence_missing"
    d3 = g3.description.lower()
    assert "failed logon" in d3 or "password policy" in d3 or "lockout" in d3 or "ia-5" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "testing_evidence_missing"
    d4 = g4.description.lower()
    assert "cm-7" in d4 or "least functionality" in d4 or "disabled services" in d4 or "baseline configuration" in d4


def test_batch_44_exploit_nessus_cred_fips_seg_spirit() -> None:
    """Exploitation IOC workbook, Nessus cadence binder, credentialed RA-5(5) binder, FIPS KMS excerpt, SC-7 segmentation."""
    path = FIXTURE_DIR / "3pao_spirit_batch_44.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "exploitation_review_missing"
    d0 = g0.description.lower()
    assert "exploitation" in d0 or "compromise assessment" in d0 or "indicator of compromise" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "vulnerability_scan_evidence_missing"
    d1 = g1.description.lower()
    assert "nessus" in d1 or "recurring vulnerability scan" in d1 or "vulnerability scan" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "credentialed_scan_evidence_missing"
    d2 = g2.description.lower()
    assert "credentialed" in d2 or "authenticated vulnerability" in d2 or "ra-5(5)" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "crypto_fips_evidence_missing"
    d3 = g3.description.lower()
    assert "fips" in d3 or "kms key rotation" in d3 or "encryption at rest" in d3 or "sc-13" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "traffic_flow_policy_missing"
    d4 = g4.description.lower()
    assert "network segmentation" in d4 or "ports and protocols" in d4 or "security group" in d4 or "sc-7" in d4


def test_batch_45_logreview_inv_scope_alarm_sample_spirit() -> None:
    """Privileged log review sign-off, CM-8 drift, RA-5(1) scope memo, CloudWatch alarm routing, SIEM sample alert bundle."""
    path = FIXTURE_DIR / "3pao_spirit_batch_45.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "approval_missing"
    d0 = g0.description.lower()
    assert "log review" in d0 or "periodic log review" in d0 or "sign-off" in d0 or "au-6" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "inventory_mismatch"
    d1 = g1.description.lower()
    assert "reconcile declared" in d1 or "discrepancies" in d1 or "duplicate entries" in d1 or "stale cmdb" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "scanner_scope_missing"
    d2 = g2.description.lower()
    assert "scanner_targets" in d2 or "in-boundary" in d2 or "ra-5(1)" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "alert_rule_missing"
    d3 = g3.description.lower()
    assert "cloudwatch alarm" in d3 or "recipient list" in d3 or "si-4" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "alert_sample_missing"
    d4 = g4.description.lower()
    assert "sample alert" in d4 or "saved search export" in d4 or "example alert" in d4


def test_batch_46_deviation_restore_local_central_ir_spirit() -> None:
    """Risk adjustment deviation, DR RTO/RPO summary, local-central audit pairing, AU-2/AU-3 log baseline, IR threat hunt."""
    path = FIXTURE_DIR / "3pao_spirit_batch_46.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "deviation_request_missing"
    d0 = g0.description.lower()
    assert "risk adjustment" in d0 or "fedramp deviation" in d0 or "vendor dependency" in d0 or "operational requirement" in d0
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "restore_test_missing"
    d1 = g1.description.lower()
    assert "measured rto" in d1 or "measured rpo" in d1 or "recovery test" in d1 or "dr exercise" in d1
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "local_to_central_log_correlation_missing"
    d2 = g2.description.lower()
    assert "local audit log" in d2 or "matches centralized" in d2 or "forwarder healthcheck" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "centralized_log_missing"
    d3 = g3.description.lower()
    assert "vpc flow logs" in d3 or "central log aggregation" in d3 or "auditable events" in d3 or "au-2" in d3
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "response_action_missing"
    d4 = g4.description.lower()
    assert "threat hunt" in d4 or "documented response action" in d4 or "ir-4" in d4


def test_batch_47_sia_deploy_verify_poam_traffic_spirit() -> None:
    """CM-3 SIA, CP-10 deployment, CM-3 verification, CA-5 POA&M updates, AC-17 traffic flows."""
    path = FIXTURE_DIR / "3pao_spirit_batch_47.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "sia_missing"
    d0 = g0.description.lower()
    assert "security impact analysis" in d0 or "sia" in d0
    assert bundle.evidence_gaps[1].gap_type == "deployment_evidence_missing"
    assert "deploy" in bundle.evidence_gaps[1].description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "verification_evidence_missing"
    assert "verification" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "poam_update_missing"
    assert "poa&m" in g3.description.lower() or "poam" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "traffic_flow_policy_missing"
    assert "remote access" in g4.description.lower() or "vpn" in g4.description.lower()


def test_batch_48_change_backup_log_deviation_identity_spirit() -> None:
    """CM-3 change ticket, CP-9 backup, AU-4 centralized log, SA-9 deviation, AC-2 privileged account."""
    path = FIXTURE_DIR / "3pao_spirit_batch_48.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "change_ticket_missing"
    assert "change ticket" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "backup_evidence_missing"
    assert "backup" in g1.description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "centralized_log_missing"
    assert "centralized log" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "deviation_request_missing"
    assert "deviation request" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "identity_listing_missing"
    assert "privileged account" in g4.description.lower()


def test_batch_49_sast_scan_approval_exploit_fim_spirit() -> None:
    """SA-11 testing, RA-5 vuln scan, AC-3 approval, RA-5 exploit review, SI-7 alert rule."""
    path = FIXTURE_DIR / "3pao_spirit_batch_49.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "testing_evidence_missing"
    assert "sast" in g0.description.lower() or "dynamic application security" in g0.description.lower()
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "vulnerability_scan_evidence_missing"
    assert "vulnerability scan" in g1.description.lower()
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "approval_missing"
    assert "two-person" in g2.description.lower()
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "exploitation_review_missing"
    assert "exploitation review" in g3.description.lower()
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "alert_rule_missing"
    assert "file integrity monitoring" in g4.description.lower()


def test_batch_50_sap_scanner_pentest_phish_scr_spirit() -> None:
    """SAP package, scanner version/update evidence, pentest access packet, phishing mail log, SCR/SIA register."""
    path = FIXTURE_DIR / "3pao_spirit_batch_50.csv"
    rows = parse_tracker_text(path.read_text(encoding="utf-8"))
    bundle = build_evidence_gaps(rows, source_file=str(path))
    g0 = bundle.evidence_gaps[0]
    assert g0.gap_type == "approval_missing"
    d0 = g0.description.lower()
    assert "sap" in d0 and ("approval" in d0 or "locked" in d0 or "kickoff" in d0)
    g1 = bundle.evidence_gaps[1]
    assert g1.gap_type == "vulnerability_scan_evidence_missing"
    d1 = g1.description.lower()
    assert ("scanner" in d1 or "scanning" in d1) and (
        "version" in d1 or "plugin" in d1 or "signature" in d1
    )
    g2 = bundle.evidence_gaps[2]
    assert g2.gap_type == "identity_listing_missing"
    d2 = g2.description.lower()
    assert "test accounts" in d2 or "temporary account" in d2 or "rules of behavior" in d2
    g3 = bundle.evidence_gaps[3]
    assert g3.gap_type == "alert_sample_missing"
    d3 = g3.description.lower()
    assert "phishing" in d3 and ("mail gateway" in d3 or "spam filter" in d3 or "mail security log" in d3)
    g4 = bundle.evidence_gaps[4]
    assert g4.gap_type == "sia_missing"
    d4 = g4.description.lower()
    assert "significant change" in d4 or "scr" in d4 or "security impact determination" in d4
