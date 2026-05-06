"""Tests for :mod:`fedramp20x.finding_builder`."""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from fedramp20x.crosswalk_normalize import normalize_rev4_rev5_table, normalize_rev5_ksi_table
from fedramp20x.finding_builder import build_findings, findings_from_evaluations
from fedramp20x.ksi_catalog import ksi_catalog_to_package_payload, load_ksi_catalog
from fedramp20x.eval_ksi_mapping import eval_to_ksi_ids
from fedramp20x.package_builder import _load_csv

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_EVAL = ROOT / "web" / "sample-data" / "eval_results.json"
MAPPINGS = ROOT / "mappings"
CONFIG = ROOT / "config"


def _crosswalks() -> tuple[list[dict], list[dict], dict[str, str]]:
    rev4 = normalize_rev4_rev5_table(_load_csv(MAPPINGS / "rev4-to-rev5-crosswalk.csv"))
    rev5 = normalize_rev5_ksi_table(_load_csv(MAPPINGS / "rev5-to-20x-ksi-crosswalk.csv"))
    cfg = yaml.safe_load((CONFIG / "control-crosswalk.yaml").read_text(encoding="utf-8"))
    edef = {str(k): str(v) for k, v in (cfg.get("eval_id_default_ksi") or {}).items()}
    return rev4, rev5, edef


def _evaluations() -> list[dict]:
    doc = json.loads(SAMPLE_EVAL.read_text(encoding="utf-8"))
    return list(doc.get("evaluations") or [])


def test_each_failed_eval_produces_at_least_one_finding() -> None:
    evs = _evaluations()
    rev4, rev5, edef = _crosswalks()
    policy = yaml.safe_load((CONFIG / "validation-policy.yaml").read_text(encoding="utf-8"))
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef, validation_policy=policy)
    failed_evals = {
        str(e.get("eval_id"))
        for e in evs
        if str(e.get("result") or "").upper() in ("FAIL", "PARTIAL")
        and str(e.get("eval_id")) not in (policy.get("finding_builder") or {}).get("exclude_eval_ids", [])
    }
    linked = {lid for f in findings for lid in (f.get("linked_eval_ids") or [])}
    missing = failed_evals - linked
    assert not missing, f"no findings for eval ids: {sorted(missing)}"


def test_findings_link_to_ksi_and_controls() -> None:
    evs = _evaluations()
    rev4, rev5, edef = _crosswalks()
    policy = yaml.safe_load((CONFIG / "validation-policy.yaml").read_text(encoding="utf-8"))
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef, validation_policy=policy)
    assert findings
    for f in findings:
        assert f.get("linked_ksi_ids") or f.get("ksi_ids")
        lc = f.get("legacy_controls") or {}
        assert isinstance(lc.get("rev5"), list) and lc["rev5"]
        assert isinstance(lc.get("rev4"), list)
        nist = f.get("nist_control_refs") or []
        assert nist


def test_evidence_deficiency_phrasing_not_bare_logging_failed() -> None:
    evs = _evaluations()
    rev4, rev5, edef = _crosswalks()
    policy = yaml.safe_load((CONFIG / "validation-policy.yaml").read_text(encoding="utf-8"))
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef, validation_policy=policy)
    joined = " ".join(str(f.get("description") or "") for f in findings).lower()
    assert "no evidence" in joined or "evidence deficiency" in joined
    assert "logging failed" not in joined


def test_fixture_examples_covered_in_descriptions() -> None:
    """Six canonical gap themes from the public-admin scenario appear in finding text."""
    evs = _evaluations()
    rev4, rev5, edef = _crosswalks()
    policy = yaml.safe_load((CONFIG / "validation-policy.yaml").read_text(encoding="utf-8"))
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef, validation_policy=policy)
    blob = " ".join(f"{f.get('title','')} {f.get('description','')}" for f in findings).lower()
    assert "scanner" in blob and "prod-api-01" in blob
    assert "centrally ingested" in blob or "central" in blob
    assert "alert" in blob
    assert "change" in blob or "ticket" in blob
    assert "exploitation" in blob or "high/critical" in blob
    assert "inventory" in blob or "reconcil" in blob or "rogue" in blob


def test_dedupe_identical_gap_lines() -> None:
    evs = [
        {
            "eval_id": "DEDUP_TEST",
            "result": "FAIL",
            "severity": "high",
            "name": "Dedup test eval",
            "control_refs": ["CM-8"],
            "gaps": ["same gap text", "same gap text"],
            "affected_assets": ["asset-a"],
            "evidence": ["e1"],
            "recommended_action": "fix",
        }
    ]
    rev4, rev5, edef = _crosswalks()
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef)
    assert len(findings) == 1


def test_policy_severity_override() -> None:
    evs = [
        {
            "eval_id": "OV",
            "result": "FAIL",
            "severity": "low",
            "name": "override",
            "control_refs": ["AU-6"],
            "gaps": ["x"],
            "affected_assets": ["a1"],
            "evidence": [],
            "recommended_action": "",
        }
    ]
    rev4, rev5, edef = _crosswalks()
    policy = {"finding_builder": {"finding_severity_override": {"OV": "critical"}, "exclude_eval_ids": ["CA5_POAM_STATUS"]}}
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef, validation_policy=policy)
    assert findings[0]["severity"] == "critical"


def test_findings_from_evaluations_backward_compat() -> None:
    evs = [{"eval_id": "X", "result": "FAIL", "severity": "medium", "name": "n", "gaps": ["g"], "affected_assets": []}]
    f = findings_from_evaluations(evs)
    assert f and f[0]["finding_id"]


def test_assessor_workpaper_fields_survive_into_formal_findings() -> None:
    evs = [
        {
            "eval_id": "WORKPAPER_TEST",
            "result": "PARTIAL",
            "severity": "medium",
            "name": "workpaper",
            "control_refs": ["RA-5"],
            "gaps": ["scanner target export missing for asset-a"],
            "affected_assets": ["asset-a"],
            "evidence": ["asset evidence loaded"],
            "recommended_action": "Export scanner target inventory; link target to asset-a",
            "assessor_findings": [
                {
                    "finding_id": "WORKPAPER_TEST-GAP-001",
                    "control_refs": ["RA-5"],
                    "current_state": "scanner target export missing for asset-a",
                    "target_state": "Scanner coverage is exported and matched to asset-a.",
                    "remediation_steps": ["Export scanner target inventory", "Re-run assessment"],
                    "estimated_effort": "0.5 day",
                    "priority": "moderate",
                    "affected_subjects": ["asset-a"],
                }
            ],
        }
    ]
    findings = build_findings(evs)
    assert findings
    wp = findings[0]["assessor_workpaper"]
    assert wp["source_assessor_finding_id"] == "WORKPAPER_TEST-GAP-001"
    assert findings[0]["current_state"] == "scanner target export missing for asset-a"
    assert findings[0]["target_state"] == "Scanner coverage is exported and matched to asset-a."
    assert findings[0]["remediation_steps"] == ["Export scanner target inventory", "Re-run assessment"]
    assert findings[0]["estimated_effort"] == "0.5 day"
    assert findings[0]["priority"] == "moderate"


def test_ksi_rollup_findings_when_enabled() -> None:
    evs = _evaluations()
    rev4, rev5, edef = _crosswalks()
    cat = ksi_catalog_to_package_payload(load_ksi_catalog(CONFIG / "ksi-catalog.yaml"))
    ksi_results = [
        {
            "ksi_id": "KSI-LOG-01",
            "status": "FAIL",
            "summary": "rolled up fail",
            "linked_eval_ids": ["AU6_CENTRALIZED_LOG_COVERAGE"],
            "linked_nist_control_refs": [],
            "evidence_refs": [],
        }
    ]
    policy = {"finding_builder": {"include_failed_ksi_rollup": True, "exclude_eval_ids": ["CA5_POAM_STATUS"]}}
    findings = build_findings(
        evs,
        rev4_to_rev5=rev4,
        rev5_to_ksi=rev5,
        eval_default_ksi=edef,
        validation_policy=policy,
        ksi_validation_results=ksi_results,
        ksi_catalog=cat,
    )
    rollup = [f for f in findings if f.get("source") == "ksi_validation"]
    assert any("KSI-LOG-01" in (x.get("linked_ksi_ids") or []) for x in rollup)


def test_linked_ksi_matches_package_builder_logic() -> None:
    evs = _evaluations()
    rev4, rev5, edef = _crosswalks()
    policy = yaml.safe_load((CONFIG / "validation-policy.yaml").read_text(encoding="utf-8"))
    findings = build_findings(evs, rev4_to_rev5=rev4, rev5_to_ksi=rev5, eval_default_ksi=edef, validation_policy=policy)
    by_eval: dict[str, list[str]] = {}
    for f in findings:
        for eid in f.get("linked_eval_ids") or []:
            by_eval.setdefault(str(eid), []).append(f)
    ev = next(e for e in evs if e.get("eval_id") == "AU6_CENTRALIZED_LOG_COVERAGE")
    expected = eval_to_ksi_ids(ev, rev5, edef, None)
    got = by_eval.get("AU6_CENTRALIZED_LOG_COVERAGE", [{}])[0].get("linked_ksi_ids")
    assert got == expected
