"""Tests for ``config/public-exposure-policy.yaml`` and ``providers.exposure_policy``."""

from __future__ import annotations

from pathlib import Path

import yaml

from instrumentation.aws_cloudtrail import aws_cloudtrail_instrumentation
from instrumentation.context import InstrumentationInput
from instrumentation.gcp_logging import gcp_logging_instrumentation
from instrumentation.sentinel import sentinel_instrumentation
from instrumentation.splunk import splunk_instrumentation
from providers.exposure_policy import (
    merged_query_keywords_for_semantic,
    semantic_type_for_exposed_port,
    semantic_type_from_public_exposure_policy,
)
from providers.aws import extract_security_group_exposures, semantic_type_from_cloudtrail_event

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "config" / "public-exposure-policy.yaml"


def test_policy_entries_have_ports_and_severity() -> None:
    raw = yaml.safe_load(POLICY_PATH.read_text(encoding="utf-8"))
    services = raw.get("services")
    assert isinstance(services, list) and services
    for svc in services:
        assert isinstance(svc, dict)
        ports = svc.get("ports")
        assert isinstance(ports, list) and ports, svc.get("service_name")
        assert str(svc.get("severity") or "").strip(), svc.get("service_name")


def test_public_postgresql_maps_to_database_semantic() -> None:
    assert semantic_type_for_exposed_port(5432, "tcp") == "network.public_database_port_opened"


def test_public_kubernetes_api_maps_to_sensitive_semantic() -> None:
    assert semantic_type_for_exposed_port(6443, "tcp") == "network.public_sensitive_service_opened"


def test_extract_sg_reflects_policy_semantics() -> None:
    pg = {
        "GroupId": "sg-pg",
        "VpcId": "vpc-1",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 5432,
                "ToPort": 5432,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    assert extract_security_group_exposures(pg)[0]["semantic_type"] == "network.public_database_port_opened"
    k8s = {
        "GroupId": "sg-k8s",
        "VpcId": "vpc-1",
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 6443,
                "ToPort": 6443,
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
            }
        ],
    }
    assert extract_security_group_exposures(k8s)[0]["semantic_type"] == "network.public_sensitive_service_opened"


def test_cloudtrail_authorize_sg_uses_policy_ranks() -> None:
    rec = {
        "eventName": "AuthorizeSecurityGroupIngress",
        "requestParameters": {
            "ipPermissions": {
                "items": [
                    {
                        "ipProtocol": "tcp",
                        "fromPort": 6443,
                        "toPort": 6443,
                        "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                    }
                ]
            }
        },
    }
    st, _ = semantic_type_from_cloudtrail_event(rec)
    assert st == "network.public_sensitive_service_opened"


def test_electric_eye_substring_maps_sensitive_rule() -> None:
    sem = semantic_type_from_public_exposure_policy(
        check_id="security-group-kafka-open-check",
        title="Kafka streams open",
    )
    assert sem == "network.public_sensitive_service_opened"


def test_instrumentation_includes_merged_policy_keywords() -> None:
    kws = merged_query_keywords_for_semantic("network.public_database_port_opened")
    assert kws
    inp = InstrumentationInput(
        semantic_type="network.public_database_port_opened",
        asset_id="db-01",
        controls=(),
    )
    spl = splunk_instrumentation(inp).query_text
    sen = sentinel_instrumentation(inp).query_text
    gcp = gcp_logging_instrumentation(inp).query_text
    aws = aws_cloudtrail_instrumentation(inp).query_text
    assert any(k in spl for k in kws)
    assert any(k in sen for k in kws)
    assert any(k in gcp for k in kws)
    assert any(k in aws for k in kws)
