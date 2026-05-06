"""CloudSploit-style scan import adapter — JSON/CSV → ``ScannerFinding`` / optional ``SecurityEvent``."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.models import ScannerFinding
from providers.cloudsploit import (
    cloudsploit_row_to_scanner_finding,
    import_cloudsploit,
    import_cloudsploit_to_file,
    iter_cloudsploit_records,
)

ROOT = Path(__file__).resolve().parents[1]
SAMPLE_JSON = ROOT / "reference_samples" / "cloudsploit" / "outputs" / "scan_result_sample.json"
SAMPLE_CSV = ROOT / "reference_samples" / "cloudsploit" / "outputs" / "scan_result_sample.csv"


def test_reference_sample_json_exists():
    assert SAMPLE_JSON.is_file()


def test_iter_cloudsploit_records():
    rows = iter_cloudsploit_records(SAMPLE_JSON)
    assert len(rows) == 2
    assert rows[0]["plugin"] == "publicIpAddress"


def test_cloudsploit_finding_preserves_plugin_cloud_resource_status():
    rows = iter_cloudsploit_records(SAMPLE_JSON)
    f = cloudsploit_row_to_scanner_finding(rows[0])
    assert isinstance(f, ScannerFinding)
    assert f.scanner_name == "cloudsploit"
    assert f.metadata.get("cloudsploit_plugin") == "publicIpAddress"
    assert f.metadata.get("cloudsploit_cloud") == "aws"
    assert f.metadata.get("cloudsploit_status_code") == 2
    assert f.status == "open"
    assert "arn:aws:ec2" in (f.raw_ref or "")


def test_cloudsploit_pass_row_is_closed():
    rows = iter_cloudsploit_records(SAMPLE_JSON)
    f = cloudsploit_row_to_scanner_finding(rows[1])
    assert f.status == "closed"


def test_cloudsploit_csv_row_count():
    assert SAMPLE_CSV.is_file()
    assert len(iter_cloudsploit_records(SAMPLE_CSV)) == 2


def test_iter_cloudsploit_records_handles_semicolon_csv(tmp_path: Path):
    p = tmp_path / "cloudsploit_semicolon.csv"
    p.write_text(
        "plugin;status;severity;resource;region\n"
        "open_ssh;2;high;arn:aws:ec2:us-east-1:111122223333:security-group/sg-1;us-east-1\n",
        encoding="utf-8",
    )

    rows = iter_cloudsploit_records(p)
    finding = cloudsploit_row_to_scanner_finding(rows[0])

    assert rows[0]["plugin"] == "open_ssh"
    assert finding.status == "open"
    assert finding.severity == "high"


def test_import_cloudsploit_public_ip_failure_emits_semantic_event():
    findings, events = import_cloudsploit(SAMPLE_JSON, emit_security_events=True)
    assert len(findings) == 2
    assert any(e.semantic_type == "network.public_admin_port_opened" for e in events)


def test_import_cloudsploit_to_scenario_dir(tmp_path: Path):
    dest = import_cloudsploit_to_file(SAMPLE_JSON, tmp_path / "s", emit_security_events=True)
    doc = json.loads(dest.read_text(encoding="utf-8"))
    assert doc["scanner"] == "cloudsploit"
    assert len(doc["findings"]) == 2


def test_fixture_provider_loads_scenario_after_cloudsploit_import(tmp_path: Path):
    import shutil

    from providers.cloudsploit import import_cloudsploit_to_file
    from providers.fixture import FixtureProvider

    src = ROOT / "fixtures" / "scenario_20x_readiness"
    dst = tmp_path / "scenario"
    shutil.copytree(src, dst)
    import_cloudsploit_to_file(SAMPLE_JSON, dst, emit_security_events=False)
    fp = FixtureProvider(dst)
    fp.validate_layout()
    bundle = fp.load_bundle()
    assert any(f.scanner_name == "cloudsploit" for f in bundle.scanner_findings)


def test_cli_import_findings_cloudsploit(tmp_path: Path):
    out_dir = tmp_path / "out"
    rc = subprocess.run(
        [
            sys.executable,
            str(ROOT / "agent.py"),
            "import-findings",
            "--format",
            "cloudsploit",
            "--input",
            str(SAMPLE_CSV),
            "--output",
            str(out_dir),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0, rc.stderr
    doc = json.loads((out_dir / "scanner_findings.json").read_text(encoding="utf-8"))
    assert doc["scanner"] == "cloudsploit"
    assert len(doc["findings"]) == 2
