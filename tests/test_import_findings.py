"""Tests for Prowler / OCSF ``import-findings`` adapters."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from core.models import ScannerFinding
from providers.ocsf import import_ocsf, map_ocsf_to_semantic_type
from providers.prowler import import_prowler

ROOT = Path(__file__).resolve().parents[1]


def test_prowler_failed_check_becomes_scanner_finding(tmp_path: Path) -> None:
    prowler_doc = [
        {
            "CheckID": "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22",
            "CheckTitle": "Ensure no security groups allow SSH from 0.0.0.0/0",
            "Status": "FAIL",
            "Severity": "high",
            "ServiceName": "ec2",
            "ResourceId": "arn:aws:ec2:us-east-1:111122223333:security-group/sg-abc123",
            "Region": "us-east-1",
            "AccountId": "111122223333",
            "Compliance": {"NIST-800-53": ["AC-4", "SC-7"]},
            "CustomFieldOnlyInProwler": {"nested": True},
        }
    ]
    p = tmp_path / "prowler.json"
    p.write_text(json.dumps(prowler_doc), encoding="utf-8")
    findings, events = import_prowler(p)
    assert len(findings) == 1
    f = findings[0]
    assert isinstance(f, ScannerFinding)
    assert f.scanner_name == "prowler"
    assert f.plugin_id == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    assert f.status == "open"
    assert f.severity == "high"
    assert f.metadata.get("prowler_check_id") == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    assert f.metadata.get("prowler_region") == "us-east-1"
    assert f.metadata.get("prowler_account_id") == "111122223333"
    assert f.metadata.get("compliance") == {"NIST-800-53": ["AC-4", "SC-7"]}
    assert f.metadata.get("import_extras", {}).get("CustomFieldOnlyInProwler") == {"nested": True}
    assert any(e.semantic_type == "network.public_admin_port_opened" for e in events)


def test_ocsf_detection_becomes_scanner_finding(tmp_path: Path) -> None:
    ocsf = {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_name": "Create",
        "metadata": {"uid": "550e8400-e29b-41d4-a716-446655440000", "product": {"name": "Test"}},
        "time": 1_704_000_000_000,
        "severity_id": 5,
        "status": "Open",
        "finding_info": {
            "title": "Suspicious login pattern",
            "desc": "Multiple failed authentications followed by success",
            "uid": "sub-finding-1",
        },
        "resource": {"uid": "arn:aws:iam::123456789012:user/alice", "region": "us-west-2"},
        "cloud": {"provider": "aws", "account": {"uid": "123456789012"}},
        "remediation": {"kb_articles": ["https://example.invalid/guidance"]},
        "unmapped_vendor_extension": 42,
    }
    p = tmp_path / "ocsf.json"
    p.write_text(json.dumps(ocsf), encoding="utf-8")
    findings, events = import_ocsf(p)
    assert len(findings) == 1
    f = findings[0]
    assert f.scanner_name == "ocsf"
    assert f.severity == "high"
    assert f.status == "open"
    assert "Suspicious login" in f.title
    assert f.metadata.get("remediation") == ocsf["remediation"]
    assert f.metadata.get("import_extras", {}).get("unmapped_vendor_extension") == 42
    assert events[0].semantic_type == map_ocsf_to_semantic_type(ocsf)


def test_ocsf_unknown_semantic_preserved(tmp_path: Path) -> None:
    rec = {
        "metadata": {"uid": "u-1"},
        "time": 1_700_000_000,
        "severity_id": 2,
        "status": "Open",
        "finding_info": {"title": "Generic signal", "desc": "No strong mapping cues"},
        "resource": {},
        "cloud": {"provider": "aws"},
        "activity_name": "Other",
    }
    assert map_ocsf_to_semantic_type(rec) == "unknown"


def test_cli_import_findings_prowler(tmp_path: Path) -> None:
    src = tmp_path / "in.json"
    src.write_text(
        json.dumps(
            [
                {
                    "CheckID": "s3_bucket_public_read",
                    "CheckTitle": "S3 public read",
                    "Status": "FAIL",
                    "Severity": "medium",
                    "ResourceId": "arn:aws:s3:::my-bucket",
                    "Region": "eu-west-1",
                    "AccountId": "999",
                }
            ]
        ),
        encoding="utf-8",
    )
    dst = tmp_path / "scanner_findings.json"
    r = subprocess.run(
        [sys.executable, str(ROOT / "agent.py"), "import-findings", "--format", "prowler", "--input", str(src), "--output", str(dst)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    doc = json.loads(dst.read_text(encoding="utf-8"))
    assert doc["scanner"] == "prowler"
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["metadata"]["prowler_check_id"] == "s3_bucket_public_read"
