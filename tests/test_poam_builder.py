"""Tests for :mod:`fedramp20x.poam_builder`."""

from __future__ import annotations

from pathlib import Path

from fedramp20x.poam_builder import (
    build_poam_items_from_findings,
    load_poam_policy,
    merge_poam_items_for_package,
)

CONFIG = Path(__file__).resolve().parents[1] / "config"


def _policy() -> dict:
    return load_poam_policy(CONFIG / "poam-policy.yaml")


def test_all_open_findings_get_poam_unless_risk_accepted() -> None:
    findings = [
        {
            "finding_id": "F1",
            "status": "open",
            "severity": "high",
            "created_at": "2026-01-01T00:00:00+00:00",
            "title": "Gap A",
            "description": "d",
            "linked_eval_ids": ["CM8_INVENTORY_RECONCILIATION"],
            "linked_ksi_ids": ["KSI-INV-01"],
            "nist_control_refs": ["CM-8"],
            "affected_assets": ["a1"],
            "risk_acceptance": {"required": False, "accepted_by": None, "expiration_date": None, "conditions": []},
        },
        {
            "finding_id": "F2",
            "status": "risk_accepted",
            "severity": "high",
            "created_at": "2026-01-01T00:00:00+00:00",
            "title": "Accepted",
            "description": "d",
            "linked_eval_ids": ["RA5_SCANNER_SCOPE_COVERAGE"],
            "linked_ksi_ids": ["KSI-VULN-01"],
            "nist_control_refs": ["RA-5"],
            "affected_assets": [],
        },
    ]
    items = build_poam_items_from_findings(findings, _policy())
    assert len(items) == 1
    assert items[0]["finding_id"] == "F1"


def test_due_dates_match_policy() -> None:
    pol = _policy()
    days = pol["default_due_days_by_severity"]
    base = {
        "finding_id": "FX",
        "status": "open",
        "severity": "critical",
        "created_at": "2026-06-01T12:00:00+00:00",
        "title": "t",
        "description": "d",
        "linked_eval_ids": ["AU6_CENTRALIZED_LOG_COVERAGE"],
        "linked_ksi_ids": ["KSI-LOG-01"],
        "nist_control_refs": ["AU-6"],
        "affected_assets": [],
    }
    item = build_poam_items_from_findings([base], pol)[0]
    from datetime import date, timedelta

    exp = date(2026, 6, 1) + timedelta(days=int(days["critical"]))
    assert item["target_completion_date"] == exp.isoformat()


def test_remediation_plan_specific_to_inventory() -> None:
    f = {
        "finding_id": "FINV",
        "status": "open",
        "severity": "medium",
        "created_at": "2026-01-15T00:00:00+00:00",
        "title": "CM-8",
        "description": "inventory gap",
        "linked_eval_ids": ["CM8_INVENTORY_RECONCILIATION"],
        "linked_ksi_ids": ["KSI-INV-01"],
        "nist_control_refs": ["CM-8"],
        "affected_assets": ["x"],
    }
    plan = build_poam_items_from_findings([f], _policy())[0]["remediation_plan"]
    blob = " ".join(str(s.get("description", "")) for s in plan).lower()
    assert "inventory" in blob or "iiw" in blob or "declared" in blob


def test_remediation_plan_specific_to_scanner() -> None:
    f = {
        "finding_id": "FSC",
        "status": "open",
        "severity": "high",
        "created_at": "2026-01-15T00:00:00+00:00",
        "title": "RA-5",
        "description": "scanner",
        "linked_eval_ids": ["RA5_SCANNER_SCOPE_COVERAGE"],
        "linked_ksi_ids": ["KSI-VULN-01"],
        "nist_control_refs": ["RA-5"],
        "affected_assets": ["p1"],
    }
    plan = build_poam_items_from_findings([f], _policy())[0]["remediation_plan"]
    blob = " ".join(str(s.get("description", "")) for s in plan).lower()
    assert "scanner" in blob


def test_remediation_logging_alert_change_exploitation_keywords() -> None:
    pol = _policy()
    cases = [
        ("AU6_CENTRALIZED_LOG_COVERAGE", "forwarding"),
        ("SI4_ALERT_INSTRUMENTATION", "siem"),
        ("CM3_CHANGE_EVIDENCE_LINKAGE", "ticket"),
        ("RA5_EXPLOITATION_REVIEW", "exploitation"),
        ("CROSS_DOMAIN_EVENT_CORRELATION", "cross-domain"),
    ]
    for eid, needle in cases:
        f = {
            "finding_id": f"F-{eid}",
            "status": "open",
            "severity": "medium",
            "created_at": "2026-01-15T00:00:00+00:00",
            "title": eid,
            "description": "x",
            "linked_eval_ids": [eid],
            "linked_ksi_ids": ["KSI-X"],
            "nist_control_refs": ["X-0"],
            "affected_assets": [],
        }
        plan = build_poam_items_from_findings([f], pol)[0]["remediation_plan"]
        blob = " ".join(str(s.get("description", "")) for s in plan).lower()
        assert needle in blob, (eid, blob)


def test_merge_skips_csv_when_eval_covered_by_generated() -> None:
    gen = [
        {
            "poam_id": "POAM-G1",
            "finding_id": "F1",
            "linked_eval_ids": ["CM8_INVENTORY_RECONCILIATION"],
            "title": "t",
            "severity": "high",
            "remediation_plan": [],
            "risk_acceptance": {},
            "source_controls": [],
            "source_ksi_ids": [],
        }
    ]
    csv_rows = [{"poam_id": "POAM-OLD", "source_eval_id": "CM8_INVENTORY_RECONCILIATION", "weakness_name": "w"}]
    merged = merge_poam_items_for_package(csv_rows, gen)
    assert len(merged) == 1
    assert merged[0]["poam_id"] == "POAM-G1"


def test_risk_acceptance_accepted_by_skips() -> None:
    f = {
        "finding_id": "FR",
        "status": "open",
        "severity": "low",
        "created_at": "2026-01-01T00:00:00+00:00",
        "title": "t",
        "description": "d",
        "linked_eval_ids": ["CM8_INVENTORY_RECONCILIATION"],
        "linked_ksi_ids": [],
        "nist_control_refs": [],
        "affected_assets": [],
        "risk_acceptance": {"required": True, "accepted_by": "AO", "expiration_date": None, "conditions": []},
    }
    assert build_poam_items_from_findings([f], _policy()) == []
