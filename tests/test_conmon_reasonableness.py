"""ConMon catalog and 3PAO reasonableness contracts."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.conmon_reasonableness import (
    assess_conmon_reasonableness,
    load_conmon_catalog,
    load_tracker_rows,
    render_reasonableness_markdown,
)

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "config" / "conmon-catalog.yaml"
CONMON_TRACKER = ROOT / "fixtures" / "assessment_tracker" / "conmon_19_tracker.csv"


def test_catalog_covers_full_cadence_and_ecosystem_story() -> None:
    catalog = load_conmon_catalog(CATALOG)
    obligations = catalog["obligations"]
    cadences = {o["cadence"] for o in obligations}
    for cadence in {
        "continuous",
        "every_10_days",
        "weekly",
        "monthly",
        "every_60_days",
        "quarterly",
        "annual",
        "annual_assessment",
        "event_driven",
    }:
        assert cadence in cadences

    ecosystems = catalog["evidence_ecosystems"]
    ticketing = " ".join(ecosystems["ticketing"]["systems"])
    assert "Smartsheet" in ticketing and "Jira" in ticketing and "ServiceNow" in ticketing
    assert "AWS CloudTrail" in ecosystems["aws"]["systems"]
    assert "Splunk" in ecosystems["siem"]["systems"]
    assert "Wazuh" in ecosystems["os_and_endpoint"]["systems"]


def test_reasonableness_tests_include_3pao_core_questions() -> None:
    tests = load_conmon_catalog(CATALOG)["reasonableness_tests"]
    for key in {
        "source_authority",
        "population_completeness",
        "freshness_and_cadence",
        "traceability",
        "independent_observability",
        "exception_governance",
    }:
        assert key in tests
        assert tests[key]["question"]


def test_conmon_tracker_maps_to_annual_policy_obligation_but_not_full_platform() -> None:
    catalog = load_conmon_catalog(CATALOG)
    rows = load_tracker_rows(CONMON_TRACKER)
    result = assess_conmon_reasonableness(catalog=catalog, tracker_rows=rows)

    assert result["summary"]["tracker_rows"] == 19
    annual_policy = next(
        r for r in result["obligation_assessments"] if r["obligation_id"] == "CONMON-ANNUAL-001"
    )
    assert annual_policy["matched_tracker_rows"]
    assert annual_policy["coverage"] in {"partial", "reasonable"}

    # The annual policy fixture should not falsely claim full ConMon coverage.
    assert result["summary"]["missing"] > 0
    continuous = next(
        r for r in result["obligation_assessments"] if r["obligation_id"] == "CONMON-CONT-001"
    )
    assert continuous["coverage"] == "missing"


def test_markdown_names_ai_system_evidence_and_reasonableness() -> None:
    catalog = load_conmon_catalog(CATALOG)
    result = assess_conmon_reasonableness(catalog=catalog, tracker_rows=load_tracker_rows(CONMON_TRACKER))
    md = render_reasonableness_markdown(result)

    for needle in ("AWS CloudTrail", "Splunk", "Wazuh", "Smartsheet", "Jira", "ServiceNow", "3PAO"):
        assert needle in md
    assert "workflow evidence, not as proof by themselves" in md


def test_cli_writes_reasonableness_outputs(tmp_path: Path) -> None:
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "conmon-reasonableness",
            "--tracker",
            str(CONMON_TRACKER),
            "--output-dir",
            str(tmp_path),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    assert proc.returncode == 0, proc.stderr + proc.stdout
    assert "CONMON REASONABLENESS" in proc.stdout
    data = json.loads((tmp_path / "conmon_reasonableness.json").read_text(encoding="utf-8"))
    assert data["summary"]["tracker_rows"] == 19
    assert (tmp_path / "conmon_reasonableness.md").is_file()
