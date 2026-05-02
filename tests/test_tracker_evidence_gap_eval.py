"""Tests for TRACKER_EVIDENCE_GAP_ANALYSIS (evals/tracker_evidence_gap_eval.py)."""

from __future__ import annotations

import csv
import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from core.evidence_gap import build_evidence_gaps
from evals.tracker_evidence_gap_eval import (
    EVAL_ID,
    EVAL_NAME,
    GAP_TYPE_TO_GROUP,
    GROUP_LABELS,
    TRACKER_GROUPS,
    run_tracker_evidence_gap_eval,
)
from evals.tracker_evidence_gap_report import (
    write_all_tracker_gap_outputs,
    write_tracker_gap_eval_results_json,
    write_tracker_gap_instrumentation_plan_md,
    write_tracker_gap_matrix_csv,
    write_tracker_gap_poam_csv,
    write_tracker_gap_report_md,
)
from normalization.assessment_tracker_import import (
    TrackerRow,
    import_assessment_tracker_to_dir,
)


REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_TRACKER = REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    idx: int,
    controls: list[str],
    request_text: str,
    assessor_comment: str = "",
    csp_comment: str = "",
    status: str = "Open",
    owner: str = "Owner",
    due_date: str | None = "2026-05-01",
    request_date: str | None = "2026-04-12",
    category: str = "uncategorized",
) -> TrackerRow:
    return TrackerRow(
        row_index=idx,
        controls=controls,
        request_text=request_text,
        request_date=request_date,
        due_date=due_date,
        status=status,
        owner=owner,
        assessor_comment=assessor_comment or None,
        csp_comment=csp_comment or None,
        category=category,
        classification_signals=[],
        raw={},
    )


def _envelope_from_rows(rows: list[TrackerRow]) -> dict[str, Any]:
    bundle = build_evidence_gaps(rows, source_file="test_tracker.json")
    return bundle.to_envelope()


# ---------------------------------------------------------------------------
# Group mapping coverage
# ---------------------------------------------------------------------------


class TestGroupMapping:
    def test_every_canonical_gap_type_maps_to_known_group(self) -> None:
        for gap_type, group in GAP_TYPE_TO_GROUP.items():
            assert group in TRACKER_GROUPS, f"{gap_type} -> {group} not in TRACKER_GROUPS"

    def test_every_group_has_label(self) -> None:
        for g in TRACKER_GROUPS:
            assert GROUP_LABELS.get(g)

    def test_eval_id_and_name_constants(self) -> None:
        assert EVAL_ID == "TRACKER_EVIDENCE_GAP_ANALYSIS"
        assert "Tracker" in EVAL_NAME


# ---------------------------------------------------------------------------
# Eval result classification (PASS / PARTIAL / FAIL)
# ---------------------------------------------------------------------------


class TestEvalResultClassification:
    def test_pass_when_no_open_gaps(self) -> None:
        envelope = {
            "evidence_gaps": [],
            "informational_tracker_items": [
                {"item_id": "info-0001", "source_item_id": "1"},
            ],
        }
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        assert out.eval_result.result == "PASS"
        assert out.total_open_gaps == 0
        assert out.high_impact_count == 0
        assert out.informational_count == 1

    def test_partial_when_only_low_or_moderate_gaps(self) -> None:
        # testing_evidence_missing has 'moderate' severity by default and CM-3 is
        # not in the high-risk control bump list, so the eval should land on PARTIAL.
        rows = [
            _row(
                idx=1,
                controls=["CM-3"],
                request_text="Provide test documentation for change CHG-1234.",
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        assert out.eval_result.result == "PARTIAL", (
            f"expected PARTIAL, got {out.eval_result.result}; "
            f"groups={[g.gap_types for g in out.groups if g.count_open_gaps]}"
        )
        assert out.high_impact_count == 0
        assert out.total_open_gaps >= 1

    def test_fail_when_any_high_impact_open_gap(self) -> None:
        rows = [
            _row(
                idx=1,
                controls=["RA-5(8)"],
                request_text=(
                    "Exploitation review for all High/Critical vulnerabilities open >30 days. "
                    "Show IoC search and historical audit log review."
                ),
                assessor_comment=(
                    "Per FedRAMP guidance, HIGH/CRITICAL >30 days require a documented exploitation review."
                ),
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        assert out.eval_result.result == "FAIL"
        assert out.high_impact_count >= 1


# ---------------------------------------------------------------------------
# Per-group field correctness
# ---------------------------------------------------------------------------


class TestGroupSummaries:
    def test_logging_group_collects_au_si_controls(self) -> None:
        rows = [
            _row(
                idx=1,
                controls=["AU-2", "AU-3", "AU-6", "AU-12"],
                request_text=(
                    "Demonstrate centralized audit log aggregation: provide Splunk dashboards "
                    "showing CloudTrail, VPC Flow Logs, CloudWatch Logs, and OS auth.log "
                    "are reaching the SIEM."
                ),
                assessor_comment=(
                    "Need both centralized view AND a local log example from a production host."
                ),
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        logging = next(g for g in out.groups if g.group == "logging")
        assert logging.count_open_gaps >= 1
        assert any(c.startswith("AU-") for c in logging.controls_impacted)
        assert "KSI-LOG-01" in logging.linked_ksi_ids

    def test_change_management_group_includes_cm_controls(self) -> None:
        rows = [
            _row(
                idx=1,
                controls=["CM-3", "SI-2"],
                request_text=(
                    "Sample change tickets in JIRA with full evidence chain: Security Impact "
                    "Analysis, testing artifacts, CAB approval, deployment evidence, "
                    "post-deploy verification."
                ),
                assessor_comment=(
                    "verify SIA was performed BEFORE deployment; include test, approval, deploy, verify."
                ),
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        cm = next(g for g in out.groups if g.group == "change_management")
        assert cm.count_open_gaps >= 1
        assert any(c.startswith("CM-") for c in cm.controls_impacted)
        # SIA / testing / approval / deployment / verification → CM gap types.
        assert any(
            t
            in {
                "sia_missing",
                "testing_evidence_missing",
                "approval_missing",
                "deployment_evidence_missing",
                "verification_evidence_missing",
                "change_ticket_missing",
            }
            for t in cm.gap_types
        )

    def test_scanner_group_carries_ra5_for_high_vuln_exploit_review(self) -> None:
        rows = [
            _row(
                idx=1,
                controls=["RA-5(8)"],
                request_text=(
                    "Exploitation review for all High/Critical vulnerabilities open >30 days. "
                    "Show IoC search and historical audit log review for each finding."
                ),
                assessor_comment=(
                    "Per FedRAMP guidance, HIGH/CRITICAL >30 days require a documented "
                    "exploitation review with IoC matches and historical log queries."
                ),
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        scanner = next(g for g in out.groups if g.group == "scanner_vulnerability")
        assert scanner.count_open_gaps >= 1
        assert "RA-5(8)" in scanner.controls_impacted
        assert "exploitation_review_missing" in scanner.gap_types
        # And the eval as a whole must FAIL on this row.
        assert out.eval_result.result == "FAIL"

    def test_response_action_appears_in_both_alerting_and_incident_response(self) -> None:
        rows = [
            _row(
                idx=1,
                controls=["SI-4(1)", "SI-4(4)"],
                request_text=(
                    "List CloudWatch alarms and GuardDuty findings considered "
                    "\"suspicious activity\"; map each to a documented response action."
                ),
                assessor_comment="actions taken in response must be evidenced.",
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        alerting = next(g for g in out.groups if g.group == "alerting")
        ir = next(g for g in out.groups if g.group == "incident_response")
        assert alerting.count_open_gaps >= 1
        assert ir.count_open_gaps >= 1
        # The same gap_id appears in both groups (auxiliary mapping).
        assert set(alerting.gap_ids) & set(ir.gap_ids)

    def test_poam_group_aggregates_poam_required(self) -> None:
        rows = [
            _row(
                idx=1,
                controls=["CA-5"],
                request_text=(
                    "POA&M updates: Provide the current POA&M with deviation requests, "
                    "vendor dependencies, and operational requirements clearly noted."
                ),
            ),
        ]
        envelope = _envelope_from_rows(rows)
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        poam = next(g for g in out.groups if g.group == "poam")
        assert poam.count_open_gaps >= 1
        assert poam.poam_required is True


# ---------------------------------------------------------------------------
# Output writers
# ---------------------------------------------------------------------------


class TestWriters:
    @pytest.fixture()
    def sample_result(self, tmp_path: Path) -> Any:
        # Build a small but multi-group sample.
        rows = [
            _row(
                idx=1,
                controls=["AU-2", "AU-3"],
                request_text="Demonstrate centralized audit log aggregation via Splunk.",
                assessor_comment="Need local log sample from prod-api-01 to prove forwarder.",
            ),
            _row(
                idx=2,
                controls=["RA-5(8)"],
                request_text="Exploitation review for High/Critical vulnerabilities open >30 days.",
                assessor_comment="Need IoC and historical log review.",
            ),
            _row(
                idx=3,
                controls=["CA-5"],
                request_text="POA&M updates with deviation requests and vendor dependencies.",
            ),
            _row(
                idx=4,
                controls=["CM-3"],
                request_text="Change tickets with SIA, testing, approval, deployment, verification.",
            ),
        ]
        envelope = _envelope_from_rows(rows)
        return run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)

    def test_report_md_contains_all_groups(self, sample_result: Any, tmp_path: Path) -> None:
        dest = tmp_path / "tracker_gap_report.md"
        write_tracker_gap_report_md(sample_result, dest)
        text = dest.read_text(encoding="utf-8")
        assert "Tracker Evidence Gap Analysis" in text
        for group in TRACKER_GROUPS:
            assert GROUP_LABELS[group] in text
        assert "FAIL" in text  # has a high-impact RA-5(8) row

    def test_matrix_csv_has_header_and_rows(self, sample_result: Any, tmp_path: Path) -> None:
        dest = tmp_path / "tracker_gap_matrix.csv"
        write_tracker_gap_matrix_csv(sample_result, dest)
        with dest.open(encoding="utf-8") as f:
            reader = list(csv.reader(f))
        assert reader[0][0] == "gap_id"
        assert "group" in reader[0]
        assert "controls" in reader[0]
        assert len(reader) > 1

    def test_eval_results_json_is_valid_envelope(self, sample_result: Any, tmp_path: Path) -> None:
        dest = tmp_path / "tracker_gap_eval_results.json"
        write_tracker_gap_eval_results_json(sample_result, dest)
        env = json.loads(dest.read_text(encoding="utf-8"))
        assert env["eval_id"] == EVAL_ID
        assert env["result"] in {"PASS", "FAIL", "PARTIAL", "NOT_APPLICABLE"}
        assert "groups" in env and isinstance(env["groups"], list)
        assert "totals" in env

    def test_poam_csv_only_has_poam_required_rows(self, sample_result: Any, tmp_path: Path) -> None:
        dest = tmp_path / "poam.csv"
        write_tracker_gap_poam_csv(sample_result, dest)
        with dest.open(encoding="utf-8") as f:
            reader = list(csv.DictReader(f))
        # Should have at least one POA&M-required entry from the RA-5(8) and CA-5 rows.
        assert len(reader) >= 1
        for row in reader:
            assert row["poam_id"].startswith("POAM-TRK-")
            assert row["controls"]

    def test_instrumentation_plan_written_when_logging_or_alerting_open(
        self, sample_result: Any, tmp_path: Path
    ) -> None:
        dest = tmp_path / "instrumentation_plan.md"
        out = write_tracker_gap_instrumentation_plan_md(sample_result, dest)
        assert out is not None and out.exists()
        text = dest.read_text(encoding="utf-8")
        assert "Instrumentation Plan" in text
        assert "Centralized logging" in text or "logging" in text.lower()

    def test_instrumentation_plan_skipped_when_no_logging_or_alerting_gaps(
        self, tmp_path: Path
    ) -> None:
        rows = [
            _row(
                idx=1,
                controls=["CP-9", "CP-10"],
                request_text="Backup/restore evidence: most recent restore test (RTO/RPO).",
            ),
        ]
        envelope = _envelope_from_rows(rows)
        result = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)
        dest = tmp_path / "instrumentation_plan.md"
        out = write_tracker_gap_instrumentation_plan_md(result, dest)
        assert out is None
        assert not dest.exists()

    def test_write_all_outputs_writes_every_required_file(
        self, sample_result: Any, tmp_path: Path
    ) -> None:
        # Provide a fake auditor_questions.md from the importer to be re-used.
        src_qs = tmp_path / "src_auditor_questions.md"
        src_qs.write_text("# Auditor Questions\n\n- (existing) ask about scanner scope.\n")
        out_dir = tmp_path / "outputs"
        written = write_all_tracker_gap_outputs(
            sample_result, output_dir=out_dir, source_questions_md=src_qs
        )
        for name in (
            "tracker_gap_report.md",
            "tracker_gap_matrix.csv",
            "tracker_gap_eval_results.json",
            "poam.csv",
            "auditor_questions.md",
        ):
            assert name in written
            assert written[name].exists()
        # auditor_questions reused source content
        assert "(existing)" in (out_dir / "auditor_questions.md").read_text()
        # Sample includes logging+alerting+IR work, so plan must be present.
        assert "instrumentation_plan.md" in written


# ---------------------------------------------------------------------------
# End-to-end against the real sample tracker
# ---------------------------------------------------------------------------


class TestSampleTrackerEndToEnd:
    def test_real_sample_produces_logging_change_and_exploitation_gaps(
        self, tmp_path: Path
    ) -> None:
        scenario = tmp_path / "scenario_from_tracker"
        result = import_assessment_tracker_to_dir(
            input_path=SAMPLE_TRACKER, output_dir=scenario
        )
        envelope = json.loads((scenario / "evidence_gaps.json").read_text(encoding="utf-8"))
        out = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)

        # Splunk / local-vs-central logging row → AU/SI logging group has gaps with AU-* controls.
        logging = next(g for g in out.groups if g.group == "logging")
        assert logging.count_open_gaps >= 1
        assert any(c.startswith("AU-") for c in logging.controls_impacted), (
            f"expected AU-* controls in logging group, got {logging.controls_impacted}"
        )
        assert "KSI-LOG-01" in logging.linked_ksi_ids

        # SIA / testing / approval / deployment / verification row → CM group with CM-* controls.
        cm = next(g for g in out.groups if g.group == "change_management")
        assert cm.count_open_gaps >= 1
        assert any(c.startswith("CM-") for c in cm.controls_impacted), (
            f"expected CM-* controls in change_management group, got {cm.controls_impacted}"
        )

        # High vulnerability exploitation review → scanner_vulnerability group with RA-5(8).
        scanner = next(g for g in out.groups if g.group == "scanner_vulnerability")
        assert "RA-5(8)" in scanner.controls_impacted, (
            f"expected RA-5(8) in scanner_vulnerability group, got {scanner.controls_impacted}"
        )
        assert "exploitation_review_missing" in scanner.gap_types

        # And the overall result must be FAIL because the High vuln exploit review is high impact.
        assert out.eval_result.result == "FAIL"


# ---------------------------------------------------------------------------
# CLI: assess-tracker
# ---------------------------------------------------------------------------


class TestAssessTrackerCli:
    def test_cli_produces_required_outputs(self, tmp_path: Path) -> None:
        out_dir = tmp_path / "output_tracker"
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "agent.py"),
                "assess-tracker",
                "--input",
                str(SAMPLE_TRACKER),
                "--output-dir",
                str(out_dir),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, (
            f"agent.py assess-tracker exited {result.returncode}\n"
            f"stdout=\n{result.stdout}\nstderr=\n{result.stderr}"
        )
        for name in (
            "tracker_gap_report.md",
            "tracker_gap_matrix.csv",
            "tracker_gap_eval_results.json",
            "poam.csv",
            "auditor_questions.md",
            "instrumentation_plan.md",
        ):
            assert (out_dir / name).exists(), f"missing {name} in {out_dir}"

        env = json.loads((out_dir / "tracker_gap_eval_results.json").read_text())
        assert env["eval_id"] == EVAL_ID
        # Sample contains a HIGH RA-5(8) exploitation row, so should be FAIL.
        assert env["result"] == "FAIL"
