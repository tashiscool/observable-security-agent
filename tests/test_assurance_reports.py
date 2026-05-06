"""Tests for human-readable assurance reports."""

from __future__ import annotations

from pathlib import Path

from core.assurance_package import write_assurance_package
from core.assurance_reports import build_human_readable_reports, write_human_readable_reports, write_human_readable_reports_from_package
from tests.test_assurance_package import _build_package, _fixture_package_inputs


EXPECTED_FILES = {
    "executive-summary.md",
    "control-assessment-report.md",
    "open-risks.md",
    "evidence-table.md",
    "reviewer-decisions.md",
}


def test_human_readable_reports_written_from_fixture_package(tmp_path: Path) -> None:
    package = _build_package()
    written = write_human_readable_reports(tmp_path, package)

    assert set(written) == EXPECTED_FILES
    for path in written.values():
        assert path.is_file()
        assert path.read_text(encoding="utf-8").startswith("# ")


def test_executive_summary_contains_required_counts_and_review_status() -> None:
    report = build_human_readable_reports(_build_package())["executive-summary.md"]

    assert "**System:** Fixture System" in report
    assert "**Framework / baseline:** NIST SP 800-53 / moderate" in report
    assert "**Package status:** READY_FOR_REVIEW" in report
    assert "**Controls assessed:** 3" in report
    assert "**Controls with insufficient evidence:** 1 (AC-2)" in report
    assert "**Open critical/high findings:** 1" in report
    assert "review decision(s) recorded" in report
    assert "`ev-001`" in report


def test_control_assessment_report_states_missing_evidence_plainly() -> None:
    report = build_human_readable_reports(_build_package())["control-assessment-report.md"]

    assert "## AC-2 - AC-2 control" in report
    assert "Evidence is missing for this control in the package." in report
    assert "## RA-5 - RA-5 control" in report
    assert "`ev-001`" in report
    assert "Credentialed vulnerability scan evidence." in report
    assert "Package patch required." in report


def test_open_risks_contains_required_fields() -> None:
    report = build_human_readable_reports(_build_package())["open-risks.md"]

    assert "| Severity | Finding | Affected assets | Related controls | Evidence IDs | Recommendation | Owner | Due date |" in report
    assert "HIGH" in report
    assert "`nf-001`" in report
    assert "`ev-001`" in report
    assert "Not recorded" in report


def test_evidence_table_contains_source_metadata_and_controls() -> None:
    report = build_human_readable_reports(_build_package())["evidence-table.md"]

    assert "| Evidence ID | Source system | Source type | Account | Region | Resource | Observed at | Freshness | Controls |" in report
    assert "`ev-001`" in report
    assert "nessus" in report
    assert "vulnerability_scan_json" in report
    assert "123456789012" in report
    assert "us-east-1" in report
    assert "RA-5" in report


def test_reviewer_decisions_report_and_pending_state() -> None:
    reviewed = build_human_readable_reports(_build_package())["reviewer-decisions.md"]
    pending_package = _build_package(**_fixture_package_inputs(with_human_review=False))
    pending = build_human_readable_reports(pending_package)["reviewer-decisions.md"]

    assert "| Recommendation ID | Reviewer | Decision | Justification | Timestamp | Evidence IDs |" in reviewed
    assert "ISSO" in reviewed
    assert "ACCEPTED" in reviewed
    assert "`ev-001`" in reviewed
    assert "Human review pending" in pending
    assert "No reviewer decision has been recorded." in pending


def test_reports_can_be_generated_from_assurance_package_file(tmp_path: Path) -> None:
    package = _build_package()
    package_path = write_assurance_package(tmp_path, package=package)

    written = write_human_readable_reports_from_package(package_path)

    assert set(written) == EXPECTED_FILES
    assert (tmp_path / "executive-summary.md").is_file()
