"""Architecture guarantees: evals stay canonical, AWS collection stays in providers/scripts."""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from core.evaluator import run_evaluations
from core.normalizer import load_normalized_primary_event, normalize_cloud_event
from core.utils import build_asset_evidence
from providers.aws import semantic_type_from_cloudtrail_event
from providers.fixture import FixtureProvider


ROOT = Path(__file__).resolve().parents[1]
SCENARIO = ROOT / "fixtures" / "scenario_public_admin_vuln_event"


def _eval_py_files_do_not_import_aws_sdks() -> None:
    banned_roots = ("boto3", "botocore")
    for sub in ("evals", "core"):
        base = ROOT / sub
        if not base.is_dir():
            continue
        paths = list(base.rglob("*.py")) if sub == "evals" else [p for p in base.rglob("*.py") if p.name != "__init__.py"]
        for path in paths:
            if "__pycache__" in path.parts:
                continue
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = alias.name.split(".", 1)[0]
                        assert mod not in banned_roots, f"{path}: imports {mod}"
                elif isinstance(node, ast.ImportFrom) and node.module:
                    mod = node.module.split(".", 1)[0]
                    assert mod not in banned_roots, f"{path}: from-import {node.module}"


def test_eval_modules_do_not_import_boto3_or_botocore() -> None:
    _eval_py_files_do_not_import_aws_sdks()


def test_core_modules_do_not_import_boto3_or_botocore() -> None:
    _eval_py_files_do_not_import_aws_sdks()


def test_fixture_provider_runs_all_evals_without_aws_credentials() -> None:
    """Full pipeline on fixture data: no live AWS calls (evals use AssessmentBundle only)."""
    bundle = FixtureProvider(SCENARIO).load()
    sem, _ = load_normalized_primary_event(bundle)
    cb = run_evaluations(bundle, sem, build_asset_evidence(bundle, sem.asset_id), output_dir=None)
    assert len(cb.eval_results) == 14
    assert cb.overall_result == "FAIL"


def test_normalize_azure_fixture_primary_runs_eval_pipeline(tmp_path: Path) -> None:
    shutil.copytree(SCENARIO, tmp_path / "s", dirs_exist_ok=True)
    scen = tmp_path / "s"
    azure_primary = {
        "_primary": True,
        "_format": "azure_activity",
        "_asset_id": "prod-api-01",
        "caller": "ops@example.com",
        "time": "2026-05-01T10:42:00Z",
        "resourceId": "/subscriptions/x/resourceGroups/rg/providers/Microsoft.Network/networkSecurityGroups/nsg1",
        "operationName": "Microsoft.Network/networkSecurityGroups/securityRules/write",
        "_port": 22,
        "_source": "0.0.0.0/0",
    }
    events_path = scen / "cloud_events.json"
    events = json.loads(events_path.read_text(encoding="utf-8"))
    for e in events:
        e.pop("_primary", None)
    events.insert(0, azure_primary)
    events_path.write_text(json.dumps(events, indent=2), encoding="utf-8")

    bundle = FixtureProvider(scen).load()
    sem, _ = load_normalized_primary_event(bundle)
    assert sem.provider == "azure"
    assert sem.event_type == "network.public_admin_port_opened"
    cb = run_evaluations(bundle, sem, build_asset_evidence(bundle, sem.asset_id), output_dir=None)
    assert len(cb.eval_results) == 14


def test_normalize_gcp_fixture_primary_runs_eval_pipeline(tmp_path: Path) -> None:
    shutil.copytree(SCENARIO, tmp_path / "g", dirs_exist_ok=True)
    scen = tmp_path / "g"
    gcp_primary = {
        "_primary": True,
        "_format": "gcp_audit",
        "_asset_id": "prod-api-01",
        "timestamp": "2026-05-01T10:42:00Z",
        "resource": {"labels": {"name": "fw-edge"}},
        "protoPayload": {
            "methodName": "google.cloud.compute.v1.Firewalls.Insert",
            "authenticationInfo": {"principalEmail": "builder@example.com"},
        },
    }
    events_path = scen / "cloud_events.json"
    events = json.loads(events_path.read_text(encoding="utf-8"))
    for e in events:
        e.pop("_primary", None)
    events.insert(0, gcp_primary)
    events_path.write_text(json.dumps(events, indent=2), encoding="utf-8")

    bundle = FixtureProvider(scen).load()
    sem, _ = load_normalized_primary_event(bundle)
    assert sem.provider == "gcp"
    assert sem.event_type == "network.public_admin_port_opened"
    cb = run_evaluations(bundle, sem, build_asset_evidence(bundle, sem.asset_id), output_dir=None)
    assert len(cb.eval_results) == 14


def test_aws_cloudtrail_record_maps_to_same_semantic_type_as_fixture_admin_port() -> None:
    """AWS API-shaped CloudTrail record uses the same canonical semantic as fixture primary story."""
    record = {
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 22,
                        "toPort": 22,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }
                ]
            }
        },
    }
    st, _ = semantic_type_from_cloudtrail_event(record)
    assert st == "network.public_admin_port_opened"

    ref = "fixture#0"
    raw_row = {
        "_format": "aws_cloudtrail",
        "_asset_id": "prod-api-01",
        "detail": {
            "eventName": "AuthorizeSecurityGroupIngress",
            "eventTime": "2026-05-01T10:42:00Z",
            "userIdentity": {"type": "IAMUser", "userName": "alice"},
            "requestParameters": record["requestParameters"]
            | {"groupId": "sg-test"},
        },
    }
    sem = normalize_cloud_event(raw_row, ref)
    assert sem.event_type == "network.public_admin_port_opened"


def test_subprocess_can_import_evals_without_providers_aws_preloaded() -> None:
    """Sanity: fresh interpreter can load eval stack (no hard dependency on boto3 at import time for evals)."""
    code = (
        "import evals.inventory_coverage, evals.scanner_scope, evals.central_log_coverage; "
        "import evals.alert_instrumentation, evals.event_correlation; "
        "import evals.vulnerability_exploitation_review, evals.change_ticket_linkage, evals.poam_status"
    )
    r = subprocess.run([sys.executable, "-c", code], cwd=str(ROOT), capture_output=True, text=True, check=False)
    assert r.returncode == 0, r.stderr
