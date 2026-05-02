"""Tests for :class:`AWSProvider` and AWS raw normalization helpers."""

from __future__ import annotations

import json
from pathlib import Path

from providers.aws import (
    AWSProvider,
    extract_security_group_exposures,
    semantic_type_from_cloudtrail_event,
)


def test_extract_sg_public_ssh_maps_public_admin() -> None:
    sg = {
        "GroupId": "sg-prodapi",
        "VpcId": "vpc-1",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    rows = extract_security_group_exposures(sg)
    assert len(rows) == 1
    assert rows[0]["semantic_type"] == "network.public_admin_port_opened"
    assert rows[0]["port"] == 22


def test_extract_sg_private_cidr_yields_no_exposure() -> None:
    sg = {
        "GroupId": "sg-internal",
        "VpcId": "vpc-1",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
            }
        ],
    }
    assert extract_security_group_exposures(sg) == []


def test_extract_sg_public_mysql_maps_database_port() -> None:
    sg = {
        "GroupId": "sg-db",
        "VpcId": "vpc-1",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    rows = extract_security_group_exposures(sg)
    assert len(rows) == 1
    assert rows[0]["semantic_type"] == "network.public_database_port_opened"


def test_stop_logging_maps_audit_disabled() -> None:
    st, _ = semantic_type_from_cloudtrail_event({"eventName": "StopLogging", "requestParameters": {"name": "t1"}})
    assert st == "logging.audit_disabled"


def test_run_instances_maps_untracked_compute() -> None:
    st, _ = semantic_type_from_cloudtrail_event({"eventName": "RunInstances", "requestParameters": {}})
    assert st == "compute.untracked_asset_created"


def test_aws_provider_rds_and_s3_asset_types(tmp_path: Path) -> None:
    root = tmp_path / "raw" / "aws" / "111111111111" / "us-east-1"
    (root / "identity").mkdir(parents=True)
    (root / "storage").mkdir(parents=True)
    (root / "logging").mkdir(parents=True)
    (root / "compute").mkdir(parents=True)
    (root / "load_balancers").mkdir(parents=True)

    (root / "identity" / "sts_get_caller_identity.json").write_text(
        json.dumps({"Account": "111111111111", "Arn": "arn:aws:iam::111111111111:root"}),
        encoding="utf-8",
    )
    (root / "storage" / "rds_describe_db_instances.json").write_text(
        json.dumps(
            {
                "DBInstances": [
                    {
                        "DBInstanceIdentifier": "appdb",
                        "DBInstanceArn": "arn:aws:rds:us-east-1:111111111111:db:appdb",
                        "TagList": [],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    (root / "storage" / "s3_list_buckets.json").write_text(
        json.dumps({"Buckets": [{"Name": "artifacts-bucket"}]}),
        encoding="utf-8",
    )
    (root / "manifest.json").write_text(
        json.dumps({"collected_at": "2026-05-01T12:00:00Z", "account_id": "111111111111", "region": "us-east-1"}),
        encoding="utf-8",
    )

    p = AWSProvider(tmp_path)
    bundle = p.load_bundle()
    by_name = {a.name: a for a in bundle.assets}
    assert by_name["appdb"].asset_type == "database"
    assert by_name["artifacts-bucket"].asset_type == "storage"


def test_aws_provider_cloudtrail_authorize_sg_event(tmp_path: Path) -> None:
    root = tmp_path / "raw" / "aws" / "222222222222" / "us-west-2"
    (root / "identity").mkdir(parents=True)
    (root / "logging").mkdir(parents=True)
    (root / "compute").mkdir(parents=True)
    (root / "storage").mkdir(parents=True)
    (root / "load_balancers").mkdir(parents=True)

    (root / "identity" / "sts_get_caller_identity.json").write_text(
        json.dumps({"Account": "222222222222"}), encoding="utf-8"
    )
    ct = {
        "Records": [
            {
                "eventName": "AuthorizeSecurityGroupIngress",
                "eventTime": "2026-05-01T10:00:00Z",
                "userIdentity": {"type": "IAMUser", "userName": "alice"},
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
                    },
                    "groupId": "sg-abc",
                },
            }
        ]
    }
    (root / "logging" / "cloudtrail_export.json").write_text(json.dumps(ct), encoding="utf-8")
    (root / "manifest.json").write_text(
        json.dumps({"collected_at": "2026-05-01T12:00:00Z"}), encoding="utf-8"
    )

    bundle = AWSProvider(tmp_path).load_bundle()
    assert any(e.semantic_type == "network.public_admin_port_opened" for e in bundle.events)
