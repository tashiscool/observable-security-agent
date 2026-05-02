"""FedRAMP 20x readiness fixture — KSI rollup expectations."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCENARIO = "scenario_20x_readiness"


@pytest.fixture(scope="module")
def readiness_run(tmp_path_factory: pytest.TempPathFactory) -> tuple[dict, Path]:
    base = tmp_path_factory.mktemp("20x-readiness")
    out = base / "assess"
    pkg = base / "package"
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "assess",
            "--provider",
            "fixture",
            "--scenario",
            SCENARIO,
            "--output-dir",
            str(out),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "build-20x-package",
            "--assessment-output",
            str(out),
            "--config",
            str(ROOT / "config"),
            "--package-output",
            str(pkg),
        ],
        cwd=str(ROOT),
        check=True,
        capture_output=True,
        text=True,
    )
    doc = json.loads((pkg / "fedramp20x-package.json").read_text(encoding="utf-8"))
    return doc, out


def test_ksi_rollups_match_readiness_narrative(readiness_run: tuple[dict, Path]) -> None:
    package_doc, _out = readiness_run
    rows = {r["ksi_id"]: r["status"] for r in package_doc.get("ksi_validation_results", []) if r.get("ksi_id")}
    assert rows.get("KSI-IAM-01") == "PARTIAL"
    assert rows.get("KSI-LOG-01") == "PARTIAL"
    assert rows.get("KSI-VULN-01") == "FAIL"
    assert rows.get("KSI-CM-01") == "PARTIAL"
    assert rows.get("KSI-INV-01") == "FAIL"
    assert rows.get("KSI-REC-01") == "PASS"
    assert rows.get("KSI-SCRM-01") == "PARTIAL"
    assert rows.get("KSI-IR-01") == "PARTIAL"


def test_eval_mixed_outcomes(readiness_run: tuple[dict, Path]) -> None:
    """Spot-check that automation produced mixed PASS/PARTIAL/FAIL eval results."""
    _package_doc, out = readiness_run
    raw = json.loads((out / "eval_results.json").read_text(encoding="utf-8"))
    evs = raw.get("evaluations") or raw.get("eval_results") or []
    ev = {e["eval_id"]: str(e.get("result", "")).upper() for e in evs}
    assert ev.get("CM8_INVENTORY_RECONCILIATION") == "FAIL"
    assert ev.get("RA5_EXPLOITATION_REVIEW") == "FAIL"
    assert ev.get("AU6_CENTRALIZED_LOG_COVERAGE") == "PARTIAL"
    assert ev.get("CROSS_DOMAIN_EVENT_CORRELATION") == "PARTIAL"
    assert ev.get("CM3_CHANGE_EVIDENCE_LINKAGE") == "PARTIAL"
    assert ev.get("RA5_SCANNER_SCOPE_COVERAGE") == "PASS"
    assert ev.get("SI4_ALERT_INSTRUMENTATION") == "PASS"
    assert ev.get("CA5_POAM_STATUS") == "PASS"
