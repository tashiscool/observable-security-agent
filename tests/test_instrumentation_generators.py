"""Instrumentation generators: SPL, KQL, GCP, AWS."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AE,
    PipelineCorrelationBundle as CB,
    PipelineEvalResult as PER,
    PipelineSemanticEvent as Sem,
)
from core.report_writer import write_agent_instrumentation_plan, write_instrumentation_plan
from instrumentation.context import SUPPORTED_SEMANTIC_TYPES, InstrumentationInput
from instrumentation.aws_cloudtrail import aws_cloudtrail_instrumentation
from instrumentation.gcp_logging import gcp_logging_instrumentation
from instrumentation.sentinel import sentinel_instrumentation
from instrumentation.splunk import splunk_instrumentation


def _inp(semantic: str, asset_id: str = "prod-api-01") -> InstrumentationInput:
    return InstrumentationInput(
        semantic_type=semantic,
        asset_id=asset_id,
        asset_name="prod-api-01",
        provider="aws",
        raw_event_ref="evt-1",
        timestamp="2026-05-01T12:00:00Z",
        controls=("SI-4", "SC-7", "AU-6"),
    )


@pytest.mark.parametrize("semantic", sorted(SUPPORTED_SEMANTIC_TYPES))
def test_each_semantic_non_empty_queries(semantic: str) -> None:
    inp = _inp(semantic)
    assert splunk_instrumentation(inp).query_text.strip()
    assert sentinel_instrumentation(inp).query_text.strip()
    assert gcp_logging_instrumentation(inp).query_text.strip()
    assert aws_cloudtrail_instrumentation(inp).query_text.strip()
    assert splunk_instrumentation(inp).alert_rule_name.strip()
    assert splunk_instrumentation(inp).suggested_schedule.strip()
    assert splunk_instrumentation(inp).suggested_recipients_placeholder


def test_public_admin_port_multicloud_coverage() -> None:
    inp = _inp("network.public_admin_port_opened")
    spl = splunk_instrumentation(inp).query_text
    assert "AuthorizeSecurityGroupIngress" in spl
    assert "OperationNameValue" in spl or "networkSecurityGroups" in spl
    assert "protoPayload.methodName" in spl
    assert "0.0.0.0/0" in spl

    kql = sentinel_instrumentation(inp).query_text
    assert "AzureActivity" in kql
    assert "networkSecurityGroups" in kql

    gcp = gcp_logging_instrumentation(inp).query_text
    assert "protoPayload.methodName" in gcp
    assert "compute.firewalls" in gcp

    aws = aws_cloudtrail_instrumentation(inp).query_text
    assert "AuthorizeSecurityGroupIngress" in aws
    assert "CreateSecurityGroup" in aws
    assert "ModifyNetworkInterfaceAttribute" in aws


def test_instrumentation_plan_md_written(tmp_path: Path) -> None:
    sem = Sem(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r1",
    )
    bundle = CB(
        correlation_id="C1",
        semantic_event=sem,
        asset_evidence=AE(
            declared_inventory=True,
            discovered_cloud_asset=True,
            scanner_scope=True,
            central_log_seen_last_24h=True,
            criticality="high",
        ),
        eval_results=[
            PER(
                eval_id="SI4_ALERT_INSTRUMENTATION",
                control_refs=["SI-4"],
                result=EvalStatus.FAIL,
                evidence=["x"],
                gap="g",
            )
        ],
        overall_result="FAIL",
        evidence_chain={},
    )
    path = tmp_path / "instrumentation_plan.md"
    write_instrumentation_plan(path, bundle)
    text = path.read_text(encoding="utf-8")
    assert "# Instrumentation plan" in text
    assert "Splunk" in text
    assert "Azure Sentinel" in text
    assert "GCP Cloud Logging" in text
    assert "AWS CloudTrail" in text


def test_agent_instrumentation_plan_includes_multicloud_prompt_injection_queries(tmp_path: Path) -> None:
    sem = Sem(
        event_type="network.public_admin_port_opened",
        provider="aws",
        asset_id="a",
        timestamp="2026-05-01T12:00:00Z",
        raw_event_ref="r1",
    )
    bundle = CB(
        correlation_id="C1",
        semantic_event=sem,
        asset_evidence=AE(
            declared_inventory=True,
            discovered_cloud_asset=True,
            scanner_scope=True,
            central_log_seen_last_24h=True,
            criticality="high",
        ),
        eval_results=[
            PER(
                eval_id="AGENT_POLICY_VIOLATIONS",
                control_refs=["SI-4"],
                result=EvalStatus.FAIL,
                evidence=["x"],
                gap="g",
            )
        ],
        overall_result="FAIL",
        evidence_chain={},
    )
    path = tmp_path / "agent_instrumentation_plan.md"
    write_agent_instrumentation_plan(path, bundle=bundle, evidence_bundle=None)
    text = path.read_text(encoding="utf-8")
    assert "# Agent telemetry instrumentation plan" in text
    assert "SIEM gap: prompt injection" in text
    assert "Splunk SPL (prompt injection suspected)" in text
    assert "Microsoft Sentinel KQL" in text
    assert "Google Cloud Logging query" in text
    assert "EventBridge" in text or "CloudTrail Lake" in text
    assert "### 1. Prompt injection suspected" in text
    assert "agent.tool_call" in text
