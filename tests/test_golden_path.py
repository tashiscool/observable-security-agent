"""End-to-end golden path workflow tests."""

from __future__ import annotations

import json
from pathlib import Path

from core.assurance_package import validate_assurance_package_document
from core.golden_path import DEFAULT_FIXTURE_DIR, run_golden_path_demo


REQUIRED_OUTPUTS = {
    "assurance-package.json",
    "executive-summary.md",
    "control-assessment-report.md",
    "open-risks.md",
    "evidence-table.md",
    "reviewer-decisions.md",
    "metrics.json",
    "eval_results.json",
    "eval_summary.md",
    "agent-run-log.json",
}

COMPLIANCE_IMPACTING = {
    "CREATE_POAM",
    "UPDATE_POAM",
    "ACCEPT_COMPENSATING_CONTROL_REVIEW",
    "MARK_INSUFFICIENT_EVIDENCE",
    "DRAFT_ASSESSMENT_NARRATIVE",
    "NO_ACTION_REQUIRED",
}


def _run(tmp_path: Path) -> tuple[dict, dict]:
    result = run_golden_path_demo(fixture_dir=DEFAULT_FIXTURE_DIR, output_dir=tmp_path / "assurance-package-demo")
    package = json.loads((tmp_path / "assurance-package-demo" / "assurance-package.json").read_text(encoding="utf-8"))
    return result, package


def test_golden_path_completes_and_generates_required_files(tmp_path: Path) -> None:
    result, _package = _run(tmp_path)
    output_dir = Path(result["outputDir"])

    assert result["schemaValid"]
    assert result["evalsPassed"]
    assert REQUIRED_OUTPUTS <= {path.name for path in output_dir.iterdir()}


def test_golden_path_package_schema_valid(tmp_path: Path) -> None:
    _result, package = _run(tmp_path)

    report = validate_assurance_package_document(package)

    assert report["valid"], report["errors"]
    assert package["manifest"]["schemaValidation"] == "PASS"


def test_golden_path_evals_pass(tmp_path: Path) -> None:
    result, _package = _run(tmp_path)
    evals = json.loads((Path(result["outputDir"]) / "eval_results.json").read_text(encoding="utf-8"))

    assert evals["summary"]["failed"] == 0
    assert evals["summary"]["passed"] == evals["summary"]["total"]


def test_golden_path_reports_include_evidence_ids(tmp_path: Path) -> None:
    result, _package = _run(tmp_path)
    output_dir = Path(result["outputDir"])

    for name in ("executive-summary.md", "control-assessment-report.md", "open-risks.md", "evidence-table.md", "reviewer-decisions.md"):
        text = (output_dir / name).read_text(encoding="utf-8")
        assert "evidence IDs" in text.lower() or "evidence id" in text.lower()
        assert "ev-" in text


def test_golden_path_missing_evidence_is_not_marked_compliant(tmp_path: Path) -> None:
    _result, package = _run(tmp_path)
    assessments = {row["controlId"]: row for row in package["assessmentResults"]}

    assert "CP-4" in package["manifest"]["controlsWithInsufficientEvidence"]
    assert assessments["CP-4"]["status"] == "INSUFFICIENT_EVIDENCE"
    assert assessments["CP-4"]["status"] != "COMPLIANT"


def test_golden_path_compliance_impacting_recommendations_require_human_review(tmp_path: Path) -> None:
    _result, package = _run(tmp_path)

    impacting = [
        rec for rec in package["agentRecommendations"] if rec["recommendationType"] in COMPLIANCE_IMPACTING
    ]

    assert impacting
    assert all(rec["humanReviewRequired"] for rec in impacting)
    reviewed = {decision["recommendationId"] for decision in package["humanReviewDecisions"]}
    assert {rec["recommendationId"] for rec in impacting} <= reviewed


def test_golden_path_demo_fixture_covers_live_demo_story(tmp_path: Path) -> None:
    _result, package = _run(tmp_path)

    evidence_text = "\n".join(
        f"{row['sourceType']} {row.get('resourceType')} {row['normalizedSummary']} {row.get('freshnessStatus')}"
        for row in package["evidence"]
    ).lower()
    findings = {row["findingId"]: row for row in package["findings"]}
    decisions = {row["decision"] for row in package["humanReviewDecisions"]}

    assert "ecr.image" in evidence_text
    assert "cloudtrail" in evidence_text
    assert "iam" in evidence_text
    assert "stale" in evidence_text
    assert any(row["freshnessStatus"] == "stale" for row in package["evidence"])
    assert findings["gp-vuln-001"]["severity"] == "HIGH"
    assert findings["gp-vuln-001"]["status"] == "OPEN"
    assert {"RA-5", "SI-2"} <= set(findings["gp-vuln-001"]["controlIds"])
    assert findings["gp-vuln-003"]["status"] == "FALSE_POSITIVE"
    assert findings["gp-vuln-004"]["status"] == "RISK_ACCEPTED"
    assert "FALSE_POSITIVE" in decisions
    assert "RISK_ACCEPTED" in decisions
