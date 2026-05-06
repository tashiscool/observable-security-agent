"""Unit tests for AWS raw evidence helpers (no live AWS calls)."""

from __future__ import annotations

import json
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from botocore.exceptions import ClientError

from providers.aws_evidence_raw import (
    CallFailure,
    CollectionManifest,
    build_alert_rules_from_cloudwatch,
    build_central_log_sources_payload,
    build_discovered_assets_payload,
    collect_aws_raw_evidence,
    guardduty_finding_to_semantic_event,
    paginate_all,
    safe_client_call,
    to_jsonable,
    write_json_file,
)


def test_to_jsonable_primitives_and_collections() -> None:
    assert to_jsonable(Decimal("1.5")) == 1.5
    assert to_jsonable(datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)) == "2026-01-02T03:04:05+00:00"
    assert to_jsonable(date(2026, 1, 2)) == "2026-01-02"
    assert to_jsonable(b"hello\xff") == "hello\ufffd"
    nested = {"N": [{"M": Decimal("2")}]}
    assert to_jsonable(nested) == {"N": [{"M": 2.0}]}


def test_write_json_file_roundtrip(tmp_path: Path) -> None:
    p = tmp_path / "a" / "b.json"
    write_json_file(p, {"x": True, "y": [1, 2]})
    assert json.loads(p.read_text(encoding="utf-8")) == {"x": True, "y": [1, 2]}


def test_safe_client_call_access_denied() -> None:
    m = CollectionManifest(
        collected_at="2026-01-01T00:00:00Z",
        account_id="1",
        region="us-east-1",
        account_label=None,
    )

    def boom() -> None:
        raise ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}},
            "TestOp",
        )

    assert safe_client_call(m, "test:Denied", boom) is None
    assert m.successful_calls == []
    assert len(m.failed_calls) == 1
    assert m.failed_calls[0].error_code == "AccessDenied"


def test_build_discovered_assets_payload_ec2_rds() -> None:
    pages = [
        {
            "Reservations": [
                {
                    "Instances": [
                        {
                            "InstanceId": "i-abc",
                            "OwnerId": "111",
                            "Tags": [{"Key": "Name", "Value": "web-1"}],
                            "State": {"Name": "running"},
                            "VpcId": "vpc-1",
                            "SecurityGroups": [{"GroupId": "sg-1"}],
                            "PrivateIpAddress": "10.0.0.1",
                            "PublicIpAddress": "",
                        }
                    ]
                }
            ]
        }
    ]
    rds = {"DBInstances": [{"DBInstanceIdentifier": "db1", "DBInstanceArn": "arn:aws:rds:us-east-1:111:db:db1", "TagList": []}]}
    out = build_discovered_assets_payload(
        account_id="111",
        region="us-east-1",
        as_of="2026-05-01T00:00:00Z",
        describe_instances_pages=pages,
        describe_db_instances_response=rds,
        describe_load_balancers_response=None,
        list_buckets_response=None,
    )
    assert len(out["assets"]) == 2
    assert out["assets"][0]["resource_type"] == "EC2"
    assert out["assets"][0]["asset_id"] == "web-1"
    assert out["assets"][1]["resource_type"] == "RDS"


def test_build_central_log_sources_from_trails_and_flows() -> None:
    trails = {
        "trailList": [
            {
                "Name": "t1",
                "TrailARN": "arn:aws:cloudtrail:us-east-1:111:trail/t1",
                "HomeRegion": "us-east-1",
                "S3BucketName": "logs",
                "IsMultiRegionTrail": False,
            }
        ]
    }
    flow_pages = [{"FlowLogs": [{"FlowLogId": "fl-1", "ResourceId": "vpc-9", "TrafficType": "ALL"}]}]
    out = build_central_log_sources_payload(
        account_id="111",
        region="us-east-1",
        describe_trails_response=trails,
        describe_flow_logs_pages=flow_pages,
    )
    assert len(out["sources"]) == 2
    assert out["sources"][0]["source_type"] == "cloud_control_plane"


def test_build_alert_rules_from_cloudwatch() -> None:
    pages = [
        {
            "MetricAlarms": [
                {"AlarmName": "A1", "StateValue": "ALARM", "MetricName": "Errors"},
            ]
        }
    ]
    out = build_alert_rules_from_cloudwatch(pages)
    assert out["platform"] == "cloudwatch"
    assert len(out["rules"]) == 1
    assert out["rules"][0]["enabled"] is True


def test_guardduty_finding_to_semantic_event() -> None:
    f = {
        "Id": "fid1",
        "Severity": 8.5,
        "Type": "Recon:EC2/PortProbe",
        "CreatedAt": "2026-01-01T00:00:00Z",
        "Resource": {"InstanceId": "i-xyz", "InstanceDetails": {}},
        "Service": {"Count": 3},
    }
    ev = guardduty_finding_to_semantic_event(f, region="us-east-1", account_id="111")
    assert ev["event_type"] == "guardduty.threat_detected"
    assert ev["asset_id"] == "i-xyz"
    assert ev["resource_id"] == "i-xyz"


def test_paginate_all_records_denied() -> None:
    manifest = CollectionManifest(
        collected_at="t",
        account_id="1",
        region="r",
        account_label=None,
    )
    bad = MagicMock()
    bad.get_paginator.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "x"}},
        "GetPaginator",
    )
    assert paginate_all("describe_instances", bad, manifest, "ec2") == []
    assert any(f.error_code == "AccessDenied" for f in manifest.failed_calls)


def _minimal_aws_clients() -> dict[str, MagicMock]:
    clients: dict[str, MagicMock] = {k: MagicMock() for k in (
        "sts",
        "iam",
        "ec2",
        "elbv2",
        "s3",
        "rds",
        "cloudtrail",
        "guardduty",
        "config",
        "cloudwatch",
    )}

    clients["sts"].get_caller_identity.return_value = {
        "Account": "123456789012",
        "Arn": "arn:aws:iam::123456789012:root",
        "UserId": "AIDACKCEVSQ6C2EXAMPLE",
    }

    iam = clients["iam"]
    iam.get_account_summary.return_value = {"SummaryMap": {"Users": 1}}
    iam.get_account_password_policy.side_effect = ClientError(
        {"Error": {"Code": "NoSuchEntityException", "Message": "none"}},
        "GetAccountPasswordPolicy",
    )
    iam.generate_credential_report.return_value = {}
    iam.get_credential_report.return_value = {
        "Content": b"user,arn\nalice,arn:aws:iam::1:user/alice\n",
        "GeneratedTime": datetime(2026, 1, 1, tzinfo=timezone.utc),
    }

    def _iam_pag(_name: str):
        p = MagicMock()
        p.paginate.return_value = iter(())
        return p

    iam.get_paginator.side_effect = _iam_pag
    iam.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}

    ec2 = clients["ec2"]

    def ec2_pag_side(n: str, **_kw: object) -> MagicMock:
        pg = MagicMock()
        if n == "describe_instances":
            pg.paginate.return_value = iter([{"Reservations": []}])
        elif n == "describe_flow_logs":
            pg.paginate.return_value = iter([{"FlowLogs": []}])
        else:
            pg.paginate.return_value = iter([{}])
        return pg

    ec2.get_paginator.side_effect = ec2_pag_side

    clients["elbv2"].describe_load_balancers.return_value = {"LoadBalancers": []}
    clients["s3"].list_buckets.return_value = {"Buckets": []}
    clients["rds"].describe_db_instances.return_value = {"DBInstances": []}
    clients["rds"].describe_db_snapshots.side_effect = [
        {"DBSnapshots": [], "Marker": None},
        {"DBSnapshots": [], "Marker": None},
    ]
    clients["cloudtrail"].describe_trails.return_value = {"trailList": []}
    clients["cloudtrail"].lookup_events.return_value = {"Events": []}
    clients["guardduty"].list_detectors.return_value = {"DetectorIds": []}
    clients["config"].describe_config_rules.return_value = {"ConfigRules": []}

    cw = clients["cloudwatch"]
    cwp = MagicMock()
    cwp.paginate.return_value = iter([{"MetricAlarms": []}])
    cw.get_paginator.return_value = cwp

    return clients


def test_collect_aws_raw_evidence_fixture_compatible_writes_files(tmp_path: Path) -> None:
    clients = _minimal_aws_clients()
    session = MagicMock()
    session.client = MagicMock(side_effect=lambda name, region_name=None: clients[name])

    manifest_path = collect_aws_raw_evidence(
        session,
        region="us-east-1",
        output_dir=tmp_path,
        account_label="dev",
        fixture_compatible=True,
        collected_at_iso="2026-05-01T12:00:00Z",
    )

    assert manifest_path.name == "manifest.json"
    man = json.loads(manifest_path.read_text(encoding="utf-8"))
    assert man["account_id"] == "123456789012"
    assert man["region"] == "us-east-1"
    assert man["account_label"] == "dev"
    assert "sts:GetCallerIdentity" in man["successful_calls"]

    disc = json.loads((tmp_path / "discovered_assets.json").read_text(encoding="utf-8"))
    assert disc["collection"]["account"] == "123456789012"
    assert disc["assets"] == []

    events = json.loads((tmp_path / "cloud_events.json").read_text(encoding="utf-8"))
    assert len(events) == 1
    assert events[0]["event_type"] == "audit.collection_placeholder"

    region_root = tmp_path / "raw" / "aws" / "123456789012" / "us-east-1"
    assert json.loads((region_root / "cloud_events.json").read_text(encoding="utf-8")) == events
    assert (region_root / "discovered_assets.json").is_file()
    assert (region_root / "central_log_sources.json").is_file()
    assert (region_root / "alert_rules.json").is_file()

    raw_identity = region_root / "identity"
    assert (raw_identity / "sts_get_caller_identity.json").is_file()
    pp = json.loads((raw_identity / "iam_get_account_password_policy.json").read_text(encoding="utf-8"))
    assert pp.get("NoSuchEntityException") is True


def test_manifest_to_dict_errors_list() -> None:
    m = CollectionManifest(
        collected_at="t",
        account_id="1",
        region="r",
        account_label=None,
        failed_calls=[CallFailure(call="x", error_code="AccessDenied", message="no")],
    )
    d = m.to_dict()
    assert d["errors"] == ["x: [AccessDenied] no"]
    assert d["permission_coverage"]["access_denied_call_count"] == 1
    assert d["permission_coverage"]["assessment_confidence"] == "partial"
    assert d["permission_coverage"]["impact"][0]["assessment_impact"]
