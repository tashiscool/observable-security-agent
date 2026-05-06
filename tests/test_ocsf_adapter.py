"""OCSF-like import/export adapters (not strict OCSF schema validation)."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from core.models import ScannerFinding, SecurityEvent
from normalization.ocsf_export import (
    FORMAT_LABEL,
    build_ocsf_like_bundle,
    export_ocsf_like_json,
    read_semantic_type_from_ocsf_like_export,
    read_severity_and_status_from_finding_export,
    scanner_finding_to_ocsf_like_export,
    security_event_to_ocsf_like_export,
)
from providers.ocsf import import_ocsf, ocsf_detection_to_scanner_finding

ROOT = Path(__file__).resolve().parents[1]
FIX_OCSF = ROOT / "tests" / "fixtures" / "ocsf"
SCENARIO = ROOT / "fixtures" / "scenario_public_admin_vuln_event"
AGENT = ROOT / "agent.py"


def test_ocsf_sample_imports_scanner_finding_with_semantic_and_raw_extras() -> None:
    path = FIX_OCSF / "sample_detection.json"
    findings, events = import_ocsf(path)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, ScannerFinding)
    assert f.metadata.get("source_format") == "ocsf"
    assert f.metadata.get("semantic_type") == "network.public_admin_port_opened"
    assert f.metadata.get("import_extras") == {}
    assert len(events) == 1


def test_ocsf_import_preserves_unmapped_top_level_in_import_extras() -> None:
    raw = json.loads((FIX_OCSF / "sample_detection.json").read_text(encoding="utf-8"))
    raw["vendor_specific_hint"] = {"tool": "fixture"}
    finding = ocsf_detection_to_scanner_finding(raw)
    extras = finding.metadata.get("import_extras") or {}
    assert extras.get("vendor_specific_hint") == {"tool": "fixture"}


def test_ocsf_mapping_covers_api_auth_network_storage_and_compute_classes() -> None:
    samples = [
        ({"activity_name": "CreateUser", "class_name": "API Activity", "api": {"operation": "CreateUser"}}, "identity.user_created"),
        (
            {"activity_name": "AuthorizeSecurityGroupIngress", "class_name": "API Activity", "api": {"operation": "AuthorizeSecurityGroupIngress"}},
            "network.firewall_rule_changed",
        ),
        (
            {"activity_name": "PutBucketPolicy", "finding_info": {"title": "Public bucket policy changed"}, "resource": {"type": "bucket"}},
            "storage.policy_changed",
        ),
        ({"activity_name": "RunInstances", "class_name": "Cloud Resource Activity"}, "compute.untracked_asset_created"),
        ({"activity_name": "StopLogging", "api": {"operation": "StopLogging", "service_name": "cloudtrail"}}, "logging.audit_disabled"),
    ]
    from providers.ocsf import map_ocsf_to_semantic_type

    for rec, expected in samples:
        assert map_ocsf_to_semantic_type(rec) == expected


def test_security_event_export_preserves_semantic_type() -> None:
    _, events = import_ocsf(FIX_OCSF / "sample_detection.json")
    sem = events[0].semantic_type
    exported = security_event_to_ocsf_like_export(events[0])
    assert exported.get("format_label") is None  # envelope optional on single object
    assert read_semantic_type_from_ocsf_like_export(exported) == sem
    assert exported.get("class_uid") == 2004
    assert exported.get("compliance_claim") is None
    ext = exported["metadata"]["extensions"]["observable_security_agent"]
    assert ext.get("provider_raw_metadata", {}).get("source_format") == "ocsf"


def test_scanner_finding_export_preserves_severity_and_status() -> None:
    findings, _ = import_ocsf(FIX_OCSF / "sample_detection.json")
    ex = scanner_finding_to_ocsf_like_export(findings[0])
    sev, st = read_severity_and_status_from_finding_export(ex)
    assert sev == findings[0].severity
    assert st == findings[0].status
    sem = read_semantic_type_from_ocsf_like_export(ex)
    assert sem == findings[0].metadata.get("semantic_type")
    bag = ex["metadata"]["extensions"]["observable_security_agent"].get("provider_agent_metadata") or {}
    assert bag.get("ocsf_cloud") is not None


def test_ocsf_like_bundle_envelope_is_labeled_not_compliant() -> None:
    doc = build_ocsf_like_bundle(events=[], detection_findings=[], source_assessment_dir="/tmp/x")
    assert doc["format_label"] == FORMAT_LABEL
    assert doc["compliance_claim"] is False
    assert "not" in doc["format_note"].lower()


def test_export_ocsf_from_scenario_writes_file(tmp_path: Path) -> None:
    out = tmp_path / "evidence" / "validation-results" / "ocsf-like-events.json"
    path = export_ocsf_like_json(SCENARIO, out)
    assert path.is_file()
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["format_label"] == FORMAT_LABEL
    assert data["compliance_claim"] is False
    assert isinstance(data["events"], list) and len(data["events"]) >= 1
    assert isinstance(data["detection_findings"], list) and len(data["detection_findings"]) >= 1
    sem0 = read_semantic_type_from_ocsf_like_export(data["events"][0])
    assert sem0 is not None


def test_import_findings_cli_ocsf_writes_scanner_findings_json(tmp_path: Path) -> None:
    scen = tmp_path / "scenario_dir"
    r = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "import-findings",
            "--format",
            "ocsf",
            "--input",
            str(FIX_OCSF / "sample_detection.json"),
            "--output",
            str(scen),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    out = scen / "scanner_findings.json"
    assert out.is_file()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc.get("scanner") == "ocsf"
    assert len(doc.get("findings") or []) == 1
    assert doc["findings"][0].get("metadata", {}).get("semantic_type") == "network.public_admin_port_opened"


def test_export_ocsf_cli(tmp_path: Path) -> None:
    out = tmp_path / "ocsf-like-events.json"
    r = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "export-ocsf",
            "--assessment-output",
            str(SCENARIO),
            "--output",
            str(out),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    assert out.is_file()
    assert json.loads(out.read_text(encoding="utf-8"))["format_label"] == FORMAT_LABEL
