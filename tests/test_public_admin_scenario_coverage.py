"""
End-to-end coverage for ``fixtures/scenario_public_admin_vuln_event`` and AWS normalizers.

Uses real fixture files and production eval / provider code (no mocks of core logic).
"""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path

import pytest

from core.evaluator import run_evaluations
from core.evidence_graph import (
    REL_EVENT_TARGETS_ASSET,
    REL_HAS_FINDING,
    REL_MAPS_TO_KSI,
    REL_TRACKED_BY_POAM,
    evidence_graph_from_assessment_bundle,
    node_key,
)
from core.normalizer import load_normalized_primary_event
from core.pipeline_models import EvalStatus, PipelineCorrelationBundle, PipelineEvalResult
from core.utils import build_asset_evidence
from providers.aws import extract_security_group_exposures, semantic_type_from_cloudtrail_event
from providers.fixture import FixtureProvider

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"
VALIDATE_SCRIPT = ROOT / "scripts" / "validate_outputs.py"

SCENARIO = "scenario_public_admin_vuln_event"


def _scenario_root() -> Path:
    return ROOT / "fixtures" / SCENARIO


def _load_bundle():
    return FixtureProvider(_scenario_root()).load()


def _run_correlation_bundle(tmp_path: Path | None = None) -> PipelineCorrelationBundle:
    bundle = _load_bundle()
    sem, _ = load_normalized_primary_event(bundle)
    asset_evidence = build_asset_evidence(bundle, sem.asset_id)
    out = tmp_path if tmp_path is not None else None
    return run_evaluations(bundle, sem, asset_evidence, output_dir=out)


def _eval(cb: PipelineCorrelationBundle, eval_id: str) -> PipelineEvalResult:
    for r in cb.eval_results:
        if r.eval_id == eval_id:
            return r
    raise AssertionError(f"No eval result for {eval_id!r}")


def _eval_text(r: PipelineEvalResult) -> str:
    parts = [r.gap or "", r.recommended_action or "", *(r.evidence or [])]
    if r.machine:
        parts.append(json.dumps(r.machine, default=str))
    return "\n".join(parts)


# --- 1 ---


def test_fixture_provider_loads_complete_bundle() -> None:
    root = _scenario_root()
    prov = FixtureProvider(root)
    prov.validate_layout()
    bundle = prov.load()

    ev = bundle.cloud_events if isinstance(bundle.cloud_events, list) else bundle.cloud_events.get("events", [])
    findings = bundle.scanner_findings.get("findings", [])
    rules = bundle.alert_rules.get("rules", [])
    tix = bundle.tickets.get("tickets", [])
    logs = bundle.central_log_sources.get("sources", [])

    assert bundle.source_root == root.resolve()
    assert len(bundle.declared_inventory_rows) == 6
    assert len(bundle.discovered_assets.get("assets", [])) == 5
    assert len(ev) == 7
    assert len(findings) == 3
    assert len(bundle.scanner_target_rows) == 3
    assert len(logs) == 4
    assert len(rules) == 4
    assert len(tix) == 3


# --- 2 ---


def test_inventory_eval_detects_rogue_asset() -> None:
    cb = _run_correlation_bundle()
    r = _eval(cb, "CM8_INVENTORY_RECONCILIATION")
    assert r.result == EvalStatus.FAIL
    blob = _eval_text(r).lower()
    assert "rogue-prod-worker-99" in blob


# --- 3 ---


def test_scanner_scope_detects_missing_prod_api() -> None:
    cb = _run_correlation_bundle()
    r = _eval(cb, "RA5_SCANNER_SCOPE_COVERAGE")
    assert r.result == EvalStatus.FAIL
    blob = _eval_text(r).lower()
    assert "prod-api-01" in blob
    assert "scanner" in blob or "target" in blob


# --- 4 ---


def test_log_coverage_detects_stale_prod_api_logs() -> None:
    cb = _run_correlation_bundle()
    r = _eval(cb, "AU6_CENTRALIZED_LOG_COVERAGE")
    assert r.result in (EvalStatus.FAIL, EvalStatus.PARTIAL)
    blob = _eval_text(r).lower()
    assert "prod-api-01" in blob


# --- 5 ---


def test_alert_instrumentation_detects_missing_public_admin_alert() -> None:
    cb = _run_correlation_bundle()
    r = _eval(cb, "SI4_ALERT_INSTRUMENTATION")
    assert r.result == EvalStatus.FAIL
    blob = _eval_text(r)
    assert "network.public_admin_port_opened" in blob


# --- 6 ---


def test_event_correlation_detects_missing_chain() -> None:
    cb = _run_correlation_bundle()
    r = _eval(cb, "CROSS_DOMAIN_EVENT_CORRELATION")
    assert r.result == EvalStatus.FAIL
    blob = _eval_text(r).lower()
    # Correlation rows and gaps reference observability / ticket gaps.
    assert "scanner" in blob or "scanner_covered" in blob or "scanner_scope" in blob
    assert "log" in blob or "central_logging" in blob
    assert "alert" in blob or "alert_rule" in blob
    assert "ticket" in blob or "linked_ticket" in blob


# --- 7 ---


def test_exploitation_review_required_for_high_vuln(tmp_path: Path) -> None:
    cb = _run_correlation_bundle(tmp_path)
    r = _eval(cb, "RA5_EXPLOITATION_REVIEW")
    assert r.result == EvalStatus.FAIL
    blob = _eval_text(r)
    assert "prod-api-01" in blob
    assert "CVE-2026-00001" in blob or "cve" in blob.lower()

    qpath = tmp_path / "exploitation_review_queries.md"
    assert qpath.is_file()
    qtext = qpath.read_text(encoding="utf-8")
    assert "prod-api-01" in qtext
    assert "CVE-2026-00001" in qtext or "CVE-" in qtext


# --- 8 ---


def test_change_linkage_detects_missing_sia_testing_deployment_verification() -> None:
    cb = _run_correlation_bundle()
    r = _eval(cb, "CM3_CHANGE_EVIDENCE_LINKAGE")
    assert r.result in (EvalStatus.FAIL, EvalStatus.PARTIAL)
    blob = _eval_text(r).lower()
    for needle in ("sia", "testing", "deployment", "verification"):
        assert needle in blob, f"expected {needle!r} in CM3 narrative"


# --- 9 ---


def test_poam_generation(tmp_path: Path) -> None:
    cb = _run_correlation_bundle(tmp_path)
    r = _eval(cb, "CA5_POAM_STATUS")
    assert r.result in (EvalStatus.OPEN, EvalStatus.PASS)

    poam_path = tmp_path / "poam.csv"
    assert poam_path.is_file()
    text = poam_path.read_text(encoding="utf-8")
    assert "CA-5" in text or "CA_5" in text
    assert "RA-5" in text or "RA_5" in text

    reader = csv.DictReader(text.splitlines())
    headers = reader.fieldnames or ()
    control_col = next((h for h in headers if "control" in h.lower()), "")
    assert control_col, "expected a Controls column in poam.csv"
    rows = list(reader)
    assert rows, "expected at least one POA&M row"


# --- 10 ---


def test_evidence_graph_public_admin_chains_to_asset_finding_ksi_poam(tmp_path: Path) -> None:
    """Graph links public-admin primary event → asset → scanner finding → KSI → POA&M (SI4 path)."""
    import agent as agent_main

    root = _scenario_root()
    prov = FixtureProvider(root)
    eb = prov.load()
    sem, _e = load_normalized_primary_event(eb)
    ae = build_asset_evidence(eb, sem.asset_id)
    cb2 = run_evaluations(eb, sem, ae, output_dir=tmp_path)
    assessment = agent_main._assessment_for_evidence_graph(eb, tmp_path)
    cev = [agent_main._pipeline_eval_to_canonical(p) for p in cb2.eval_results]
    g = evidence_graph_from_assessment_bundle(assessment, eval_results=cev, source_root=root)

    primary_ref = str(root / "cloud_events.json") + "#0"
    ev_k = node_key("event", primary_ref)
    assert g.find_edges(from_id=ev_k, relationship=REL_EVENT_TARGETS_ASSET), "event → asset"
    assert any(
        x["to"] == node_key("asset", "prod-api-01") for x in g.find_edges(from_id=ev_k, relationship=REL_EVENT_TARGETS_ASSET)
    )
    hs = g.find_edges(from_id=node_key("asset", "prod-api-01"), relationship=REL_HAS_FINDING)
    assert hs, "asset → HAS_FINDING"
    assert any("nessus-2026-0501-prod-api-01" in x["to"] for x in hs)
    ksi_edges = g.find_edges(
        from_id=node_key("evaluation", "SI4_ALERT_INSTRUMENTATION"),
        relationship=REL_MAPS_TO_KSI,
        to_id=node_key("ksi", "KSI-LOG-01"),
    )
    assert ksi_edges, "SI4 eval should MAPS_TO_KSI KSI-LOG-01"
    poam_path = tmp_path / "poam.csv"
    assert poam_path.is_file()
    poam_text = poam_path.read_text(encoding="utf-8")
    assert "POAM-AUTO" in poam_text
    assert "SI4_ALERT_INSTRUMENTATION" in poam_text or "SI4-ALERT-INSTRUMENTATION" in poam_text
    tracked = g.find_edges(from_id=node_key("evaluation", "SI4_ALERT_INSTRUMENTATION"), relationship=REL_TRACKED_BY_POAM)
    assert tracked, "evaluation TRACKED_BY_POAM → poam_item"


def test_report_outputs_created(tmp_path: Path) -> None:
    assess = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            SCENARIO,
            "--output-dir",
            str(tmp_path),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert assess.returncode == 0, assess.stderr + assess.stdout

    required = (
        "evidence_graph.json",
        "eval_results.json",
        "correlation_report.md",
        "auditor_questions.md",
        "instrumentation_plan.md",
        "agent_instrumentation_plan.md",
        "poam.csv",
        "evidence_gap_matrix.csv",
        "assessment_summary.json",
    )
    for name in required:
        assert (tmp_path / name).is_file(), f"missing {name}"

    val = subprocess.run(
        [sys.executable, str(VALIDATE_SCRIPT), "--output-dir", str(tmp_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert val.returncode == 0, val.stderr + val.stdout
    assert "VALIDATION PASSED" in val.stdout


# --- 11 ---


def test_aws_normalizer_security_group_public_ssh() -> None:
    """``describe_security_groups`` shape: public SSH exposure maps to admin-port semantic."""
    sg = {
        "GroupId": "sg-test123",
        "VpcId": "vpc-test",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    rows = extract_security_group_exposures(sg)
    assert len(rows) == 1
    assert rows[0]["semantic_type"] == "network.public_admin_port_opened"
    assert rows[0]["port"] == 22


# --- 12 ---


def test_aws_normalizer_cloudtrail_stoplogging() -> None:
    record = {
        "eventName": "StopLogging",
        "requestParameters": {"name": "org-trail-main"},
    }
    st, meta = semantic_type_from_cloudtrail_event(record)
    assert st == "logging.audit_disabled"
    assert meta.get("eventName") == "StopLogging"
