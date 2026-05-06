from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def _run_agent(argv: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(AGENT), *argv],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )


def test_assess_fixture_cli_public_admin_scenario(tmp_path: Path) -> None:
    r = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Multi-Cloud Security Evidence Agent" in r.stdout
    assert "Scenario: scenario_public_admin_vuln_event" in r.stdout
    assert "[FAIL] CM-8 Inventory Reconciliation" in r.stdout
    assert "[OPEN] CA-5 POA&M rows generated" in r.stdout
    assert (tmp_path / "eval_results.json").is_file()
    assert (tmp_path / "evidence_graph.json").is_file()
    assert (tmp_path / "correlation_report.md").is_file()
    assert (tmp_path / "instrumentation_plan.md").is_file()
    assert (tmp_path / "agent_instrumentation_plan.md").is_file()
    assert (tmp_path / "poam.csv").is_file()
    assert (tmp_path / "evidence_gap_matrix.csv").is_file()
    assert (tmp_path / "assessment_summary.json").is_file()
    assert "assessment_summary.json" in r.stdout


def test_assess_fixture_uses_fixture_dir_instead_of_scenario_name(tmp_path: Path) -> None:
    fixture = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--fixture-dir",
            str(fixture),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Scenario: scenario_public_admin_vuln_event" in r.stdout
    assert (tmp_path / "eval_results.json").is_file()


def test_assess_default_scenario_when_omitted(tmp_path: Path) -> None:
    r = _run_agent(
        ["assess", "--provider", "fixture", "--output-dir", str(tmp_path)],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert "Scenario: scenario_public_admin_vuln_event" in r.stdout


def test_validate_after_assess(tmp_path: Path) -> None:
    a = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert a.returncode == 0, a.stderr
    v = _run_agent(["validate", "--output-dir", str(tmp_path)], cwd=ROOT)
    assert v.returncode == 0, v.stderr + v.stdout
    assert "VALIDATION PASSED" in v.stdout


def test_assess_eval_results_include_assessor_style_findings(tmp_path: Path) -> None:
    r = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    doc = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    records = doc.get("evaluations") or []
    finding_sets = [
        rec.get("assessor_findings")
        for rec in records
        if rec.get("result") in ("FAIL", "PARTIAL")
    ]
    findings = [item for block in finding_sets if isinstance(block, list) for item in block]
    assert findings
    assert {"control_refs", "current_state", "target_state", "remediation_steps", "estimated_effort"} <= set(findings[0])
    normalized_records = doc.get("eval_result_records") or []
    normalized_sets = [
        rec.get("assessor_findings")
        for rec in normalized_records
        if rec.get("result") in ("FAIL", "PARTIAL")
    ]
    normalized_findings = [item for block in normalized_sets if isinstance(block, list) for item in block]
    assert normalized_findings
    assert {"control_refs", "current_state", "target_state", "remediation_steps", "estimated_effort"} <= set(
        normalized_findings[0]
    )


def test_list_evals_cli() -> None:
    r = _run_agent(["list-evals"], cwd=ROOT)
    assert r.returncode == 0, r.stderr + r.stdout
    assert "CM8_INVENTORY_RECONCILIATION" in r.stdout
    assert "RA5_SCANNER_SCOPE_COVERAGE" in r.stdout
    assert "Controls:" in r.stdout


def test_report_rerender_from_eval_results(tmp_path: Path) -> None:
    a = _run_agent(
        [
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            "scenario_public_admin_vuln_event",
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert a.returncode == 0, a.stderr
    out2 = tmp_path / "report_out"
    r = _run_agent(
        ["report", "--input", str(tmp_path / "eval_results.json"), "--output-dir", str(out2)],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert (out2 / "correlation_report.md").is_file()
    assert (out2 / "eval_results.json").is_file()


def test_report_missing_input_returns_nonzero() -> None:
    r = _run_agent(
        ["report", "--input", str(ROOT / "nonexistent_eval_results.json"), "--output-dir", "output"],
        cwd=ROOT,
    )
    assert r.returncode == 2


def test_assess_aws_requires_raw_evidence_dir() -> None:
    r = _run_agent(["assess", "--provider", "aws", "--output-dir", "out"], cwd=ROOT)
    assert r.returncode == 2
    assert "raw-evidence-dir" in r.stderr.lower() or "evidence-dir" in r.stderr.lower()


def test_assess_aws_with_raw_evidence_dir_fixture_layout(tmp_path: Path) -> None:
    raw = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "aws",
            "--raw-evidence-dir",
            str(raw),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert (tmp_path / "eval_results.json").is_file()


def test_assess_aws_deprecated_evidence_dir_alias(tmp_path: Path) -> None:
    raw = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "aws",
            "--evidence-dir",
            str(raw),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
    )
    assert r.returncode == 0, r.stderr + r.stdout


def test_assess_aws_live_with_asset_but_zero_cloud_events(tmp_path: Path) -> None:
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "manifest.json").write_text(
        json.dumps(
            {
                "collected_at": "2026-05-01T00:00:00Z",
                "region": "us-gov-west-1",
                "permission_coverage": {
                    "successful_call_count": 3,
                    "failed_call_count": 1,
                    "access_denied_call_count": 1,
                    "assessment_confidence": "partial",
                },
            }
        ),
        encoding="utf-8",
    )
    (raw / "discovered_assets.json").write_text(
        json.dumps(
            {
                "assets": [
                    {
                        "asset_id": "i-clean",
                        "provider": "aws",
                        "resource_type": "EC2",
                        "resource_id": "i-clean",
                        "region": "us-gov-west-1",
                        "criticality": "moderate",
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (raw / "cloud_events.json").write_text("[]", encoding="utf-8")
    (raw / "scanner_findings.json").write_text('{"findings":[]}', encoding="utf-8")
    (raw / "scanner_targets.csv").write_text("asset_id,scanner,target_type,hostname,ip\n", encoding="utf-8")
    (raw / "central_log_sources.json").write_text('{"sources":[]}', encoding="utf-8")
    (raw / "alert_rules.json").write_text('{"rules":[]}', encoding="utf-8")
    (raw / "tickets.json").write_text('{"tickets":[]}', encoding="utf-8")
    (raw / "declared_inventory.csv").write_text(
        "inventory_id,asset_id,name,asset_type,in_boundary,scanner_required,log_required\n",
        encoding="utf-8",
    )
    (raw / "poam.csv").write_text(
        "poam_id,weakness_name,controls,raw_severity,status,asset_identifier,notes\n",
        encoding="utf-8",
    )

    out = tmp_path / "out"
    r = _run_agent(
        [
            "assess",
            "--provider",
            "aws",
            "--raw-evidence-dir",
            str(raw),
            "--output-dir",
            str(out),
            "--mode",
            "live",
        ],
        cwd=ROOT,
    )

    assert r.returncode == 0, r.stderr + r.stdout
    eval_doc = json.loads((out / "eval_results.json").read_text(encoding="utf-8"))
    assert eval_doc["semantic_event"]["event_type"] == "assessment.no_cloud_event_evidence"
    summary = json.loads((out / "assessment_summary.json").read_text(encoding="utf-8"))
    assert summary["assessment_mode"] == "live"
    assert summary["permission_coverage"]["assessment_confidence"] == "partial"
