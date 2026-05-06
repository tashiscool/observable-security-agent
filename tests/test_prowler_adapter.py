"""Prowler scanner import adapter — JSON/CSV → ``ScannerFinding`` / optional ``SecurityEvent``."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.models import ScannerFinding
from providers.prowler import (
    import_prowler,
    import_prowler_to_file,
    iter_prowler_records,
    prowler_row_to_scanner_finding,
    resolve_scanner_findings_output_path,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_JSON = ROOT / "reference_samples" / "prowler" / "outputs" / "scan_result_sample.json"
SAMPLE_CSV = ROOT / "reference_samples" / "prowler" / "outputs" / "scan_result_sample.csv"


def test_reference_sample_json_exists():
    assert SAMPLE_JSON.is_file()


def test_iter_prowler_records_json_returns_rows():
    rows = iter_prowler_records(SAMPLE_JSON)
    assert len(rows) == 2


def test_prowler_preserves_remediation_compliance_provider_metadata():
    rows = iter_prowler_records(SAMPLE_JSON)
    f = prowler_row_to_scanner_finding(rows[0])
    assert isinstance(f, ScannerFinding)
    assert f.metadata.get("prowler_check_id") == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    assert f.metadata.get("prowler_account_id") == "111122223333"
    assert f.metadata.get("prowler_region") == "us-east-1"
    assert f.metadata.get("prowler_provider") == "aws"
    assert "Remediation" in f.evidence or "Restrict SSH" in f.evidence
    assert f.metadata.get("remediation")
    comp = f.metadata.get("compliance")
    assert comp is not None
    assert isinstance(comp, dict)
    assert "NIST-800-53" in comp


def test_prowler_csv_matches_json_row_count():
    assert SAMPLE_CSV.is_file()
    assert len(iter_prowler_records(SAMPLE_CSV)) == len(iter_prowler_records(SAMPLE_JSON))


def test_iter_prowler_records_handles_semicolon_csv(tmp_path: Path):
    p = tmp_path / "prowler_semicolon.csv"
    p.write_text(
        "CheckID;Status;Severity;ResourceId;Region;AccountId\n"
        "ec2_public_admin;FAIL;high;arn:aws:ec2:us-east-1:111122223333:security-group/sg-1;us-east-1;111122223333\n",
        encoding="utf-8",
    )

    rows = iter_prowler_records(p)
    finding = prowler_row_to_scanner_finding(rows[0])

    assert rows[0]["CheckID"] == "ec2_public_admin"
    assert finding.status == "open"
    assert finding.severity == "high"


def test_import_prowler_emits_public_exposure_event_for_failed_ssh_check():
    findings, events = import_prowler(SAMPLE_JSON, emit_security_events=True)
    assert len(findings) == 2
    assert any(e.semantic_type == "network.public_admin_port_opened" for e in events)


def test_import_prowler_no_events_when_disabled():
    _, events = import_prowler(SAMPLE_JSON, emit_security_events=False)
    assert events == []


def test_resolve_output_scenario_dir_vs_file(tmp_path: Path):
    d = tmp_path / "scenario"
    p = resolve_scanner_findings_output_path(d)
    assert p == d / "scanner_findings.json"
    f = tmp_path / "out.json"
    p2 = resolve_scanner_findings_output_path(f)
    assert p2 == f


def test_import_prowler_to_file_writes_under_scenario_dir(tmp_path: Path):
    dest = import_prowler_to_file(SAMPLE_JSON, tmp_path / "scen", emit_security_events=True)
    assert dest.name == "scanner_findings.json"
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert doc["scanner"] == "prowler"
    assert len(doc["findings"]) == 2
    assert "security_events" in doc


def test_fixture_provider_loads_scenario_after_prowler_import(tmp_path: Path):
    """Imported ``scanner_findings.json`` replaces the fixture file while keeping a valid scenario layout."""
    import shutil

    from providers.fixture import FixtureProvider
    from providers.prowler import import_prowler_to_file

    src = ROOT / "fixtures" / "scenario_20x_readiness"
    dst = tmp_path / "scenario"
    shutil.copytree(src, dst)
    import_prowler_to_file(SAMPLE_JSON, dst, emit_security_events=False)
    fp = FixtureProvider(dst)
    fp.validate_layout()
    bundle = fp.load_bundle()
    assert any(f.scanner_name == "prowler" for f in bundle.scanner_findings)
    assert len(bundle.scanner_findings) >= 2


    out_dir = tmp_path / "out"
    rc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "import-findings",
            "--format",
            "prowler",
            "--input",
            str(SAMPLE_JSON),
            "--output",
            str(out_dir),
            "--no-security-events",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0, rc.stderr
    loaded = json.loads((out_dir / "scanner_findings.json").read_text(encoding="utf-8"))
    assert loaded["scanner"] == "prowler"
    assert len(loaded["findings"]) == 2
    assert "security_events" not in loaded or loaded.get("security_events") is None
