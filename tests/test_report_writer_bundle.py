"""Assessment report bundle (Markdown, CSV, JSON)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from core.evaluator import run_evaluations
from core.normalizer import load_normalized_primary_event
from core.report_writer import write_output_bundle
from providers.fixture import FixtureProvider, assessment_bundle_from_evidence_bundle


def test_report_files_created_with_expected_auditor_content(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1] / "fixtures" / "scenario_public_admin_vuln_event"
    ev = FixtureProvider(root).load()
    sem, _ = load_normalized_primary_event(ev)
    cb = run_evaluations(ev, sem, output_dir=tmp_path)
    assessment = assessment_bundle_from_evidence_bundle(ev)
    graph = {"nodes": [{"id": "n1"}], "edges": []}
    corr_path = tmp_path / "correlations.json"
    correlations_data = json.loads(corr_path.read_text(encoding="utf-8")) if corr_path.is_file() else None

    write_output_bundle(
        tmp_path,
        cb,
        assessment=assessment,
        evidence_graph=graph,
        correlations_data=correlations_data,
    )

    assert (tmp_path / "eval_results.json").is_file()
    assert (tmp_path / "correlation_report.md").is_file()
    assert (tmp_path / "auditor_questions.md").is_file()
    assert (tmp_path / "evidence_gap_matrix.csv").is_file()
    assert (tmp_path / "assessment_summary.json").is_file()

    auditor = (tmp_path / "auditor_questions.md").read_text(encoding="utf-8")
    assert "CM-8" in auditor
    assert "RA-5" in auditor
    assert "AU-6/AU-12" in auditor
    assert "SI-4" in auditor
    assert "CM-3" in auditor
    assert "RA-5(8)" in auditor
    assert "CA-5" in auditor
    assert "prod-api-01" in auditor
    assert "Assessor workpaper prompts" in auditor

    report = (tmp_path / "correlation_report.md").read_text(encoding="utf-8")
    assert "Current state" in report
    assert "Target state" in report
    for heading in (
        "Executive summary",
        "What was assessed",
        "Evidence chain summary",
        "Failed evaluations",
        "Partial evaluations",
        "Correlated risky events",
        "Control impact",
        "Recommended remediation sequence",
        "Assessor finding workpapers",
        "Generated artifacts",
        "Detailed evaluation results",
    ):
        marker = f"## {heading}"
        assert marker in report
        start = report.index(marker)
        if heading == "Detailed evaluation results":
            chunk = report[start:]
        else:
            nxt = report.find("## ", start + len(marker))
            chunk = report[start : nxt if nxt > start else len(report)]
        assert len(chunk.strip()) > len(marker) + 5

    rows = list(csv.DictReader((tmp_path / "evidence_gap_matrix.csv").read_text(encoding="utf-8").splitlines()))
    assert rows and "eval_id" in rows[0]
    for col in ("current_state", "target_state", "priority", "estimated_effort", "remediation_steps"):
        assert col in rows[0]
    gap_rows = [r for r in rows if r.get("result") in ("FAIL", "PARTIAL")]
    assert gap_rows
    assert all(r.get("current_state") for r in gap_rows)
    assert all(r.get("target_state") for r in gap_rows)
    assert all(r.get("remediation_steps") for r in gap_rows)

    summary = json.loads((tmp_path / "assessment_summary.json").read_text(encoding="utf-8"))
    assert summary["assessment_bundle"] == "present"
    assert summary["assets"] >= 1

    eval_doc = json.loads((tmp_path / "eval_results.json").read_text(encoding="utf-8"))
    pop = eval_doc["assessment_population_summary"]
    assert pop["assets_total"] >= 1
    assert pop["sample_readiness"]["asset_population_available"] is True
    assert "scanner_population_available" in pop["sample_readiness"]
