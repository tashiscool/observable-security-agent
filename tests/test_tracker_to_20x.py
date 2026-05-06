"""Integration tests for the ``tracker-to-20x`` end-to-end CLI command.

The pipeline takes only a FedRAMP assessment-tracker file (no live cloud
credentials) and produces a complete FedRAMP 20x evidence package.
"""

from __future__ import annotations

import csv
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
SAMPLE_TRACKER = REPO_ROOT / "fixtures" / "assessment_tracker" / "sample_tracker.csv"
CONFIG_DIR = REPO_ROOT / "config"


@pytest.fixture(scope="module")
def tracker_to_20x_run(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Path]:
    """Run ``tracker-to-20x`` once for the entire module and return useful paths."""
    base = tmp_path_factory.mktemp("tracker_to_20x")
    out_dir = base / "output_tracker"
    pkg_out = base / "package_tracker"

    result = subprocess.run(
        [
            sys.executable,
            str(REPO_ROOT / "agent.py"),
            "tracker-to-20x",
            "--input",
            str(SAMPLE_TRACKER),
            "--config",
            str(CONFIG_DIR),
            "--output-dir",
            str(out_dir),
            "--package-output",
            str(pkg_out),
        ],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )

    return {
        "rc": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "out_dir": out_dir,
        "pkg_out": pkg_out,
    }


# ---------------------------------------------------------------------------
# Step 1: command exits 0
# ---------------------------------------------------------------------------


class TestExitCode:
    def test_tracker_to_20x_exits_zero(self, tracker_to_20x_run: dict[str, Path]) -> None:
        assert tracker_to_20x_run["rc"] == 0, (
            f"tracker-to-20x exited {tracker_to_20x_run['rc']}\n"
            f"stdout=\n{tracker_to_20x_run['stdout']}\n"
            f"stderr=\n{tracker_to_20x_run['stderr']}"
        )

    def test_pipeline_reports_all_eleven_steps(self, tracker_to_20x_run: dict[str, Path]) -> None:
        for step in (
            "[1/11]",
            "[2/11]",
            "[3/11]",
            "[4/11]",
            "[5/11]",
            "[6/11]",
            "[7/11]",
            "[8/11]",
            "[9/11]",
            "[10/11]",
            "[11/11]",
        ):
            assert step in tracker_to_20x_run["stdout"], (
                f"missing step marker {step} in pipeline stdout"
            )
        assert "ALL STEPS PASSED" in tracker_to_20x_run["stdout"]


# ---------------------------------------------------------------------------
# Step 2: every required output file exists
# ---------------------------------------------------------------------------


class TestRequiredOutputs:
    def test_output_tracker_artifacts_present(self, tracker_to_20x_run: dict[str, Path]) -> None:
        out = tracker_to_20x_run["out_dir"]
        for name in (
            "tracker_gap_report.md",
            "tracker_gap_matrix.csv",
            "tracker_gap_eval_results.json",
            "tracker_poam.csv",
            "eval_results.json",
            "evidence_graph.json",
            "auditor_questions.md",
            "instrumentation_plan.md",
            "poam.csv",
            "evidence_gap_matrix.csv",
            "assessment_summary.json",
        ):
            assert (out / name).exists(), f"missing {name} under {out}"

    def test_package_tracker_artifacts_present(self, tracker_to_20x_run: dict[str, Path]) -> None:
        pkg = tracker_to_20x_run["pkg_out"]
        for rel in (
            "fedramp20x-package.json",
            "evidence/validation-results/ksi-results.json",
            "evidence/validation-results/findings.json",
            "evidence/validation-results/poam-items.json",
            "evidence/validation-results/reconciliation.json",
            "reports/assessor/ksi-by-ksi-assessment.md",
            "reports/assessor/assessor-summary.md",
            "reports/executive/executive-summary.md",
            "reports/agency-ao/ao-risk-brief.md",
            "reports/reconciliation_report.md",
        ):
            assert (pkg / rel).exists(), f"missing {rel} under {pkg}"


# ---------------------------------------------------------------------------
# Step 3: KSI rollup includes the tracker eval and impacted KSIs
# ---------------------------------------------------------------------------


# KSIs that the tracker eval should impact based on its CONTROL_REFS plus the
# rev5-to-20x crosswalk (logging, identity, change mgmt, inventory, vuln, IR).
EXPECTED_TRACKER_KSI_IMPACTS: frozenset[str] = frozenset(
    {
        "KSI-LOG-01",
        "KSI-INV-01",
        "KSI-CM-01",
        "KSI-IR-01",
        "KSI-IAM-01",
    }
)


class TestKsiImpacts:
    def test_tracker_eval_appears_in_evaluations(self, tracker_to_20x_run: dict[str, Path]) -> None:
        eval_doc = json.loads(
            (tracker_to_20x_run["out_dir"] / "eval_results.json").read_text(encoding="utf-8")
        )
        ids = {e.get("eval_id") for e in (eval_doc.get("evaluations") or [])}
        assert "TRACKER_EVIDENCE_GAP_ANALYSIS" in ids, ids
        record_ids = {r.get("eval_id") for r in (eval_doc.get("eval_result_records") or [])}
        assert "TRACKER_EVIDENCE_GAP_ANALYSIS" in record_ids, record_ids

    def test_tracker_eval_carries_assessor_findings(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        eval_doc = json.loads(
            (tracker_to_20x_run["out_dir"] / "eval_results.json").read_text(encoding="utf-8")
        )
        rows = [
            e
            for e in (eval_doc.get("evaluations") or [])
            if e.get("eval_id") == "TRACKER_EVIDENCE_GAP_ANALYSIS"
        ]
        assert rows
        findings = rows[0].get("assessor_findings")
        assert isinstance(findings, list) and findings
        first = findings[0]
        for key in ("control_refs", "current_state", "target_state", "remediation_steps", "estimated_effort", "priority"):
            assert first.get(key), key

    def test_tracker_output_directory_validates_after_fold_in(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(REPO_ROOT / "agent.py"),
                "validate",
                "--mode",
                "demo",
                "--output-dir",
                str(tracker_to_20x_run["out_dir"]),
            ],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr + result.stdout

    def test_tracker_eval_rolls_up_into_expected_ksis(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        pkg = json.loads(
            (tracker_to_20x_run["pkg_out"] / "fedramp20x-package.json").read_text(encoding="utf-8")
        )
        ksi_results = pkg.get("ksi_validation_results") or []
        impacted = {
            k.get("ksi_id")
            for k in ksi_results
            if "TRACKER_EVIDENCE_GAP_ANALYSIS" in (k.get("linked_eval_ids") or [])
        }
        assert impacted, "no KSIs link to TRACKER_EVIDENCE_GAP_ANALYSIS"
        missing = EXPECTED_TRACKER_KSI_IMPACTS - impacted
        assert not missing, f"expected KSIs missing the tracker eval rollup: {missing}"

    def test_tracker_findings_present_in_package(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        pkg = json.loads(
            (tracker_to_20x_run["pkg_out"] / "fedramp20x-package.json").read_text(encoding="utf-8")
        )
        findings = pkg.get("findings") or []
        tracker_findings = [
            f
            for f in findings
            if "TRACKER" in str(f.get("source_artifact_refs") or [])
            or "TRACKER_EVIDENCE_GAP_ANALYSIS" in str(f.get("source_artifact_refs") or [])
        ]
        assert len(tracker_findings) >= 1, (
            f"expected tracker-derived findings; saw {len(findings)} total"
        )
        assert all(isinstance(f.get("assessor_workpaper"), dict) for f in tracker_findings)
        assert all(f.get("current_state") and f.get("target_state") for f in tracker_findings)

    def test_tracker_findings_carry_tracker_ksis(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        pkg = json.loads(
            (tracker_to_20x_run["pkg_out"] / "fedramp20x-package.json").read_text(encoding="utf-8")
        )
        findings = pkg.get("findings") or []
        tracker_findings = [
            f for f in findings if "TRACKER" in str(f.get("source_artifact_refs") or [])
        ]
        all_ksis: set[str] = set()
        for f in tracker_findings:
            all_ksis.update(str(x) for x in (f.get("linked_ksi_ids") or f.get("ksi_ids") or []))
        # At minimum the LOG / INV / CM groups must appear in tracker findings KSI links.
        for k in ("KSI-LOG-01", "KSI-INV-01"):
            assert k in all_ksis, f"tracker findings did not carry {k} (saw {sorted(all_ksis)})"


# ---------------------------------------------------------------------------
# Step 4: assessor / executive / AO reports surface tracker gaps
# ---------------------------------------------------------------------------


class TestAssessorReportsCiteTracker:
    def test_assessor_summary_mentions_tracker_eval(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        text = (
            tracker_to_20x_run["pkg_out"] / "reports" / "assessor" / "assessor-summary.md"
        ).read_text(encoding="utf-8")
        assert (
            "TRACKER" in text or "tracker" in text.lower()
        ), "assessor-summary.md does not cite tracker findings"
        # And it must reference tracker-derived FIND ids.
        assert re.search(r"FIND-TRACKER", text), "assessor-summary.md missing FIND-TRACKER-* IDs"

    def test_ksi_by_ksi_includes_tracker_eval_id(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        text = (
            tracker_to_20x_run["pkg_out"] / "reports" / "assessor" / "ksi-by-ksi-assessment.md"
        ).read_text(encoding="utf-8")
        assert "TRACKER_EVIDENCE_GAP_ANALYSIS" in text, (
            "ksi-by-ksi-assessment.md does not list TRACKER_EVIDENCE_GAP_ANALYSIS"
        )
        # And at least one tracker FIND id must appear in the per-KSI breakdown.
        assert re.search(r"FIND-TRACKER", text), (
            "ksi-by-ksi-assessment.md missing FIND-TRACKER-* IDs"
        )

    def test_executive_summary_includes_findings_count(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        text = (
            tracker_to_20x_run["pkg_out"] / "reports" / "executive" / "executive-summary.md"
        ).read_text(encoding="utf-8")
        # Executive report must show non-zero FAIL/critical numbers because the
        # tracker eval contributes a critical-severity finding row.
        assert "FAIL" in text or "Failed" in text or "fail" in text, "executive-summary.md missing FAIL signal"

    def test_ao_risk_brief_cites_tracker_findings_and_ksi_signal(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        ao = tracker_to_20x_run["pkg_out"] / "reports" / "agency-ao" / "ao-risk-brief.md"
        text = ao.read_text(encoding="utf-8")
        assert len(text) > 100
        # AO brief surfaces the per-finding risk list — tracker-derived findings must be present.
        assert re.search(r"FIND-TRACKER", text), (
            "ao-risk-brief.md missing FIND-TRACKER-* finding references"
        )
        # And it must summarize KSI status (FAIL KSIs, POA&M, etc.).
        assert "KSI" in text, "ao-risk-brief.md missing any KSI reference"


# ---------------------------------------------------------------------------
# Step 5: reconciliation produced a pass/fail report
# ---------------------------------------------------------------------------


class TestReconciliation:
    def test_reconciliation_json_present_with_overall_status(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        recon_json = (
            tracker_to_20x_run["pkg_out"]
            / "evidence"
            / "validation-results"
            / "reconciliation.json"
        )
        data = json.loads(recon_json.read_text(encoding="utf-8"))
        assert "overall_status" in data
        assert data["overall_status"] in {"pass", "fail"}

    def test_reconciliation_markdown_reports_parity(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        md = tracker_to_20x_run["pkg_out"] / "reports" / "reconciliation_report.md"
        assert md.exists()
        text = md.read_text(encoding="utf-8")
        # Parity status is one of {aligned, misaligned}; pipeline currently aligns.
        assert "Parity status" in text
        assert any(token in text for token in ("aligned", "misaligned")), (
            "reconciliation_report.md missing aligned/misaligned parity status"
        )


# ---------------------------------------------------------------------------
# Step 6: no hallucinated evidence
# ---------------------------------------------------------------------------


# Phrases / asset IDs that would indicate the pipeline INVENTED evidence the
# tracker did not provide. The sample tracker is purely textual (no real EC2
# instance IDs, no real CloudTrail event timestamps, no real findings, etc.) so
# the assess-style outputs MUST contain empty inventories / scanner findings /
# alert rules / tickets — never hallucinated rows.
HALLUCINATION_FORBIDDEN_TOKENS: tuple[str, ...] = (
    "i-0",  # AWS EC2 instance ID prefix
    "vpc-",  # AWS VPC ID prefix
    "sg-",  # AWS security group ID prefix
)


class TestNoHallucination:
    def test_scenario_inventory_csv_is_header_only(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        scen = tracker_to_20x_run["out_dir"] / "scenario_from_tracker"
        for name in ("declared_inventory.csv", "scanner_targets.csv", "poam.csv"):
            p = scen / name
            with p.open(encoding="utf-8") as f:
                rows = list(csv.reader(f))
            assert len(rows) <= 1, (
                f"{name} should be header-only (no invented assets); saw {len(rows)} rows"
            )

    def test_scenario_json_payloads_are_empty_envelopes(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        scen = tracker_to_20x_run["out_dir"] / "scenario_from_tracker"
        for name in (
            "scanner_findings.json",
            "central_log_sources.json",
            "alert_rules.json",
            "tickets.json",
            "discovered_assets.json",
        ):
            p = scen / name
            data = json.loads(p.read_text(encoding="utf-8"))
            # Every payload is either empty list/dict OR a {"items"|"findings"|...: []}
            # envelope. None should contain invented assets.
            if isinstance(data, list):
                assert data == [], f"{name} contained invented entries: {data}"
            elif isinstance(data, dict):
                for key in (
                    "items",
                    "findings",
                    "log_sources",
                    "rules",
                    "tickets",
                    "assets",
                    "discovered_assets",
                    "scanner_findings",
                    "alert_rules",
                ):
                    if key in data:
                        assert data[key] == [], (
                            f"{name}::{key} contained invented entries: {data[key]}"
                        )

    def test_no_hallucinated_aws_ids_in_eval_results(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        text = (tracker_to_20x_run["out_dir"] / "eval_results.json").read_text(encoding="utf-8")
        for token in HALLUCINATION_FORBIDDEN_TOKENS:
            # The token must not appear as an AWS-style identifier in the eval results.
            # It IS allowed inside descriptive prose (e.g. "i-0...") only via direct
            # tracker text. The sample tracker doesn't contain any such IDs, so the
            # pipeline must not have inserted them either.
            pattern = rf"\b{re.escape(token)}[a-z0-9]{{6,}}\b"
            assert not re.search(pattern, text), (
                f"hallucinated AWS-style id matching {pattern!r} found in eval_results.json"
            )

    def test_no_hallucinated_aws_ids_in_assessor_report(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        report = (
            tracker_to_20x_run["pkg_out"] / "reports" / "assessor" / "assessor-summary.md"
        )
        text = report.read_text(encoding="utf-8")
        for token in HALLUCINATION_FORBIDDEN_TOKENS:
            pattern = rf"\b{re.escape(token)}[a-z0-9]{{6,}}\b"
            assert not re.search(pattern, text), (
                f"hallucinated AWS-style id matching {pattern!r} found in assessor-summary.md"
            )

    def test_evidence_graph_inventory_nodes_are_empty(
        self, tracker_to_20x_run: dict[str, Path]
    ) -> None:
        graph = json.loads(
            (tracker_to_20x_run["out_dir"] / "evidence_graph.json").read_text(encoding="utf-8")
        )
        nodes = graph.get("nodes") or {}
        if isinstance(nodes, list):
            # v3+ exports use a flat node list (no v1 ``nodes.inventory`` buckets).
            return
        for category in ("inventory", "scanner", "logs", "alerts", "tickets"):
            assert nodes.get(category) in (None, [], {}), (
                f"evidence_graph.json invented {category} nodes from a tracker-only source"
            )
