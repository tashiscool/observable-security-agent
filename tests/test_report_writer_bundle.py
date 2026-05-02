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

    report = (tmp_path / "correlation_report.md").read_text(encoding="utf-8")
    for heading in (
        "Executive summary",
        "What was assessed",
        "Evidence chain summary",
        "Failed evaluations",
        "Partial evaluations",
        "Correlated risky events",
        "Control impact",
        "Recommended remediation sequence",
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

    summary = json.loads((tmp_path / "assessment_summary.json").read_text(encoding="utf-8"))
    assert summary["assessment_bundle"] == "present"
    assert summary["assets"] >= 1
