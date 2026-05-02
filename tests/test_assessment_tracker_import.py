"""Tests for the FedRAMP assessment-tracker importer."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from normalization.assessment_tracker_import import (
    CATEGORY_TO_FILES,
    classify_row,
    extract_controls,
    import_assessment_tracker_to_dir,
    parse_tracker_text,
)
from providers.assessment_tracker import AssessmentTrackerProvider, TrackerLoadError

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_CSV = REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv"


# ---------------------------------------------------------------------------
# Control extraction
# ---------------------------------------------------------------------------


class TestExtractControls:
    def test_simple_comma_list(self) -> None:
        assert extract_controls("AC-2, AC-2(7), AU-6") == ["AC-2", "AC-2(7)", "AU-6"]

    def test_semicolon_and_newline_mixed(self) -> None:
        assert extract_controls("RA-5;RA-5(3)\nSI-2") == ["RA-5", "RA-5(3)", "SI-2"]

    def test_nested_enhancement_letters(self) -> None:
        # AU-6(1)(c) is a valid enhancement notation; SC-7(11) is single-arg.
        assert extract_controls("AU-6(1)(c) and SC-7(11)") == ["AU-6(1)(c)", "SC-7(11)"]

    def test_dedupe_preserves_first_occurrence(self) -> None:
        assert extract_controls("AC-2, AU-6, AC-2") == ["AC-2", "AU-6"]

    def test_handles_empty_and_garbage(self) -> None:
        assert extract_controls("") == []
        assert extract_controls("no controls here") == []
        assert extract_controls(None) == []  # type: ignore[arg-type]

    def test_lowercase_input_is_normalized(self) -> None:
        assert extract_controls("ac-2(7)") == ["AC-2(7)"]

    def test_two_digit_family_number(self) -> None:
        assert extract_controls("CM-12, CM-8(3)") == ["CM-12", "CM-8(3)"]


# ---------------------------------------------------------------------------
# Classifier
# ---------------------------------------------------------------------------


class TestClassifier:
    @pytest.mark.parametrize(
        "text,expected_category",
        [
            ("Provide the latest Integrated Inventory Workbook (IIW) plus AWS dump", "inventory"),
            ("Inventory of Load Balancers (ALB/NLB) and S3 buckets", "inventory"),
            ("Provide TrendMicro inventory and EC2 instance listing", "inventory"),
            ("Nessus scan target list and credentialed scan profile", "scanner"),
            ("Latest Nessus vulnerability scan reports plus Burp signatures", "scanner"),
            ("Demonstrate centralized audit log aggregation in Splunk", "logging"),
            ("VPC Flow Logs reaching the SIEM and a local audit log example", "logging"),
            ("Provide alert rules with recipient lists and notification routing", "alerting"),
            ("CloudWatch alarms and GuardDuty findings considered suspicious activity", "alerting"),
            ("Sample change tickets in JIRA with SIA, testing, approval, deployment, verification", "change_ticket"),
            ("POA&M updates with deviation requests and vendor dependencies", "poam"),
            ("Incident response evidence and US-CERT notifications", "incident"),
            ("Exploitation review for High/Critical vulnerabilities; provide IoC search", "exploitation_review"),
            ("FIPS 140-2 evidence: KMS key rotation and TLS cipher list", "crypto"),
            ("Backup evidence and restore test with RTO/RPO measurements", "backup"),
            ("Account listing of all IAM users with MFA report and access review", "iam"),
            ("Traffic flow / data flow diagram and security group inventory", "traffic_flow"),
            ("Random unrelated request that does not match anything", "other"),
        ],
    )
    def test_category_matches(self, text: str, expected_category: str) -> None:
        cat, signals = classify_row(text)
        assert cat == expected_category, f"text={text!r} → {cat} (signals={signals})"
        if expected_category != "other":
            assert signals, "category match should record at least one signal keyword"

    def test_specific_categories_win_over_generic(self) -> None:
        # Row mentioning both "vulnerability" and "exploitation review" → exploitation wins.
        cat, _ = classify_row("Exploitation review of HIGH vulnerabilities — provide IoC")
        assert cat == "exploitation_review"

    def test_alerting_wins_over_logging_when_both_mentioned(self) -> None:
        cat, _ = classify_row("Provide alert rule plus Splunk SIEM dashboard")
        assert cat == "alerting"


# ---------------------------------------------------------------------------
# Parser shapes (CSV / TSV / pipe / pasted-text)
# ---------------------------------------------------------------------------


class TestParseShapes:
    def test_parses_real_sample_csv(self) -> None:
        rows = parse_tracker_text(SAMPLE_CSV.read_text(encoding="utf-8"))
        # 16 evidence rows in the sample (excluding header).
        assert len(rows) == 16
        # Every row carries at least one parsed control.
        assert all(r.controls for r in rows), [r.row_index for r in rows if not r.controls]
        # Every row classified into a known category (none "other" in the curated sample).
        cats = {r.category for r in rows}
        assert "other" not in cats, f"unexpected 'other' rows: {cats}"

    def test_tsv_input(self) -> None:
        text = (
            "Controls\tEvidence/Request Item\tStatus\tOwner\n"
            "AC-2(7)\tProvide IAM access review\tOpen\tIAM Gov\n"
        )
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        r = rows[0]
        assert r.controls == ["AC-2(7)"]
        assert r.category == "iam"
        assert r.owner == "IAM Gov"
        assert r.status == "Open"

    def test_semicolon_input(self) -> None:
        text = "Controls;Evidence Request;Owner\nRA-5;Provide Nessus credentialed scan report;Vuln Mgmt\n"
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        assert rows[0].category == "scanner"
        assert rows[0].owner == "Vuln Mgmt"

    def test_pasted_text_no_header(self) -> None:
        # Two columns, no recognizable header row → assume controls + request_text.
        text = "AC-2,Provide IAM access review for privileged users\nAU-6,Provide centralized log aggregation evidence\n"
        rows = parse_tracker_text(text)
        assert len(rows) == 2
        assert rows[0].controls == ["AC-2"]
        assert rows[0].category == "iam"
        assert rows[1].category == "logging"

    def test_handles_bom_prefix(self) -> None:
        text = "\ufeffControls,Evidence/Request Item\nAC-2,Provide IAM listing\n"
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        assert rows[0].controls == ["AC-2"]

    def test_blank_input_returns_empty(self) -> None:
        assert parse_tracker_text("") == []
        assert parse_tracker_text("   \n  \n") == []


# ---------------------------------------------------------------------------
# Messy multiline comments + missing-field handling
# ---------------------------------------------------------------------------


class TestMessyInputs:
    def test_multiline_quoted_assessor_comment(self) -> None:
        text = (
            'Controls,Evidence/Request Item,Assessor Comments\n'
            '"AC-2, AC-2(7), AU-6","Provide IAM listing and access review",'
            '"Line 1 of assessor comment.\nLine 2 with extra detail.\nLine 3."\n'
        )
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        r = rows[0]
        assert r.controls == ["AC-2", "AC-2(7)", "AU-6"]
        assert "Line 2 with extra detail." in (r.assessor_comment or "")
        assert "\n" in (r.assessor_comment or "")
        assert r.category == "iam"

    def test_multiline_csp_comment_and_request(self) -> None:
        text = (
            'Controls,Evidence/Request Item,CSP Comments\n'
            '"AU-2, AU-6","Provide centralized log aggregation in Splunk:\n'
            '- CloudTrail\n- VPC Flow Logs\n- OS auth.log","Will deliver dashboards by EOD.\n'
            'Forwarder healthchecks attached."\n'
        )
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        r = rows[0]
        assert r.category == "logging"
        assert "VPC Flow Logs" in r.request_text
        assert "Forwarder healthchecks" in (r.csp_comment or "")

    def test_missing_dates_and_owners(self) -> None:
        text = (
            "Controls,Evidence/Request Item,Request Date,Due Date,Status,Owner,Assessor Comments\n"
            "RA-5,Provide Nessus scan target list,,,,,Need confirmation of scope\n"
        )
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        r = rows[0]
        assert r.controls == ["RA-5"]
        assert r.request_date is None
        assert r.due_date is None
        assert r.status is None
        assert r.owner is None
        assert r.assessor_comment == "Need confirmation of scope"
        assert r.category == "scanner"

    def test_row_with_only_controls_and_request(self) -> None:
        text = "Controls,Evidence Request\nCM-3,Sample change ticket evidence\n"
        rows = parse_tracker_text(text)
        assert len(rows) == 1
        assert rows[0].category == "change_ticket"
        assert rows[0].owner is None
        assert rows[0].csp_comment is None


# ---------------------------------------------------------------------------
# Importer end-to-end (writes scenario)
# ---------------------------------------------------------------------------


class TestImportToDir:
    def test_emits_all_canonical_files(self, tmp_path: Path) -> None:
        out = tmp_path / "scenario_from_tracker"
        result = import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        # All 8 fixture-shaped files + tracker_items + evidence_gaps + auditor_questions.
        for name in (
            "declared_inventory.csv",
            "scanner_targets.csv",
            "scanner_findings.json",
            "central_log_sources.json",
            "alert_rules.json",
            "tickets.json",
            "poam.csv",
            "discovered_assets.json",
            "cloud_events.json",
            "tracker_items.json",
            "evidence_gaps.json",
            "auditor_questions.md",
        ):
            assert (out / name).is_file(), f"missing output file: {name}"
        assert result.output_dir == out.resolve()
        assert result.rows, "expected non-empty rows"

    def test_canonical_fixture_files_are_empty_payloads(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        # Header-only CSVs.
        for name in ("declared_inventory.csv", "scanner_targets.csv", "poam.csv"):
            lines = [ln for ln in (out / name).read_text("utf-8").splitlines() if ln.strip()]
            assert len(lines) == 1, f"{name} should be header-only, got {lines!r}"
        # Empty JSON envelopes.
        assert json.loads((out / "scanner_findings.json").read_text())["findings"] == []
        assert json.loads((out / "central_log_sources.json").read_text())["sources"] == []
        assert json.loads((out / "alert_rules.json").read_text())["rules"] == []
        assert json.loads((out / "tickets.json").read_text())["tickets"] == []
        assert json.loads((out / "discovered_assets.json").read_text())["assets"] == []

    def test_cloud_events_empty_by_default(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        assert json.loads((out / "cloud_events.json").read_text())["events"] == []

    def test_with_meta_event_emits_synthetic_event(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out, with_meta_event=True)
        events = json.loads((out / "cloud_events.json").read_text())["events"]
        assert len(events) == 1
        ev = events[0]
        assert ev["event_type"] == "assessment.tracker_loaded"
        assert ev["synthesized_from"] == "assessment_tracker"
        assert "NOT an observed cloud event" in ev["narrative"]

    def test_tracker_items_and_evidence_gaps_shape(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        result = import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        items_doc = json.loads((out / "tracker_items.json").read_text())
        gaps_doc = json.loads((out / "evidence_gaps.json").read_text())
        assert items_doc["row_count"] == len(result.rows)
        assert items_doc["row_count"] == 16
        assert all("controls" in r and "category" in r for r in items_doc["rows"])
        # Schema 2.0: every row → either an evidence_gap or an informational_tracker_item.
        assert gaps_doc["schema_version"] == "2.0"
        assert gaps_doc["coverage_invariant_holds"] is True
        assert (
            gaps_doc["evidence_gap_count"] + gaps_doc["informational_item_count"]
            == items_doc["row_count"]
        )
        # The closed row at the end of the sample becomes informational, not a gap.
        assert gaps_doc["evidence_gap_count"] == 15
        assert gaps_doc["informational_item_count"] == 1
        assert gaps_doc["evidence_gap_count"] == len(result.evidence_gaps)
        # Each gap row references the right canonical evidence file(s) via the legacy alias.
        for gap in result.evidence_gaps:
            cat = gap["category"]
            assert gap["expected_evidence_files"] == list(CATEGORY_TO_FILES.get(cat, ()))

    def test_auditor_questions_has_per_category_grouping(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        md = (out / "auditor_questions.md").read_text(encoding="utf-8")
        assert "# Auditor follow-up questions" in md
        # At least one of the categories surfaced as a header.
        assert any(f"## {cat}" in md for cat in ("scanner", "logging", "change_ticket", "iam"))

    def test_idempotent_overwrite(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        first = import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        second = import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        assert first.counts_by_category == second.counts_by_category


# ---------------------------------------------------------------------------
# AssessmentTrackerProvider
# ---------------------------------------------------------------------------


class TestAssessmentTrackerProvider:
    def test_loads_imported_scenario(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        prov = AssessmentTrackerProvider(out)
        prov.validate_layout()
        assert prov.provider_name() == "assessment_tracker"
        items = prov.tracker_items()
        assert len(items) == 16
        assert "AC-2" in prov.requested_controls()
        cc = prov.category_counts()
        assert cc.get("inventory", 0) >= 2
        assert cc.get("scanner", 0) >= 2
        # Open vs closed.
        assert len(prov.open_items()) == 15

    def test_missing_directory_raises(self, tmp_path: Path) -> None:
        prov = AssessmentTrackerProvider(tmp_path / "does-not-exist")
        with pytest.raises(TrackerLoadError):
            prov.validate_layout()

    def test_summary_dict(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out, with_meta_event=True)
        prov = AssessmentTrackerProvider(out)
        summary = prov.to_summary_dict()
        assert summary["provider"] == "assessment_tracker"
        assert summary["row_count"] == 16
        assert summary["open_gap_count"] == 15
        assert summary["has_meta_event"] is True

    def test_items_by_category_filter(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out)
        prov = AssessmentTrackerProvider(out)
        for cat in ("inventory", "scanner", "logging", "alerting", "change_ticket", "poam"):
            items = prov.items_by_category(cat)
            assert items, f"no rows classified as {cat} in sample"
            assert all((r.get("category") or "other") == cat for r in items)


# ---------------------------------------------------------------------------
# FixtureProvider compatibility (only with --with-meta-event)
# ---------------------------------------------------------------------------


class TestFixtureProviderCompatibility:
    def test_with_meta_event_loads_through_fixture_provider(self, tmp_path: Path) -> None:
        from providers.fixture import FixtureProvider

        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out, with_meta_event=True)
        prov = FixtureProvider(out)
        prov.validate_layout()
        bundle = prov.load_bundle()
        # Empty-payload scenario: zero assets / events / etc., but provider loads cleanly.
        assert bundle.assets == []
        assert bundle.scanner_findings == []
        assert bundle.alert_rules == []
        # Meta-event present (single synthesized).
        assert len(bundle.events) == 1
        ev = bundle.events[0]
        # `assessment.tracker_loaded` is not in the SemanticType literal → coerced to 'unknown'.
        assert ev.semantic_type == "unknown"
        assert ev.provider == "assessment_tracker"
        assert ev.metadata.get("synthesized_from") == "assessment_tracker"
        assert "NOT an observed cloud event" in ev.metadata.get("narrative", "")

    def test_without_meta_event_fixture_provider_rejects(self, tmp_path: Path) -> None:
        from providers.fixture import FixtureProvider

        out = tmp_path / "scen"
        import_assessment_tracker_to_dir(input_path=SAMPLE_CSV, output_dir=out, with_meta_event=False)
        prov = FixtureProvider(out)
        prov.validate_layout()  # files exist
        # …but minimum-bundle gate refuses (no cloud events) — by design.
        with pytest.raises(Exception):
            prov.load_bundle()


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestCli:
    def test_import_assessment_tracker_subcommand(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "agent.py"),
                "import-assessment-tracker",
                "--input",
                str(SAMPLE_CSV),
                "--output",
                str(out),
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert "Parsed 16 tracker rows" in proc.stdout
        assert "Open evidence gaps: 15" in proc.stdout
        assert (out / "tracker_items.json").is_file()
        assert (out / "evidence_gaps.json").is_file()
        assert (out / "auditor_questions.md").is_file()

    def test_with_meta_event_flag(self, tmp_path: Path) -> None:
        out = tmp_path / "scen"
        proc = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "agent.py"),
                "import-assessment-tracker",
                "--input",
                str(SAMPLE_CSV),
                "--output",
                str(out),
                "--with-meta-event",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        events = json.loads((out / "cloud_events.json").read_text("utf-8"))["events"]
        assert events and events[0]["event_type"] == "assessment.tracker_loaded"
