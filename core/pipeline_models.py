"""
Runtime / pipeline types for fixture-on-disk loading and correlation runs.

Canonical domain models live in `core.models`.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EvalStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    PARTIAL = "PARTIAL"
    GENERATED = "GENERATED"
    OPEN = "OPEN"


class PipelineSemanticEvent(BaseModel):
    """Legacy normalized event used by current normalizer and eval loop."""

    model_config = ConfigDict(extra="allow")

    event_type: str
    provider: str
    actor: str | None = None
    asset_id: str
    resource_id: str | None = None
    timestamp: str = ""
    raw_event_ref: str = ""
    port: int | None = None
    source_cidr: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


class PipelineAssetEvidence(BaseModel):
    declared_inventory: bool
    discovered_cloud_asset: bool
    scanner_scope: bool
    central_log_seen_last_24h: bool
    criticality: str


class PipelineEvalResult(BaseModel):
    model_config = ConfigDict(extra="allow")

    eval_id: str
    control_refs: list[str]
    result: EvalStatus
    evidence: list[str]
    gap: str = ""
    recommended_action: str = ""
    machine: dict[str, Any] = Field(default_factory=dict)


class PipelineCorrelationBundle(BaseModel):
    correlation_id: str
    semantic_event: PipelineSemanticEvent
    asset_evidence: PipelineAssetEvidence
    eval_results: list[PipelineEvalResult]
    overall_result: str
    evidence_chain: dict[str, str]


class PipelineEvidenceBundle(BaseModel):
    """Raw evidence package loaded from fixture or AWS export directories."""

    model_config = ConfigDict(arbitrary_types_allowed=True)

    source_root: Path
    declared_inventory_rows: list[dict[str, Any]]
    discovered_assets: dict[str, Any]
    cloud_events: Any
    scanner_findings: dict[str, Any]
    scanner_target_rows: list[dict[str, Any]]
    central_log_sources: dict[str, Any]
    alert_rules: dict[str, Any]
    tickets: dict[str, Any]
    poam_seed_rows: list[dict[str, Any]] = Field(default_factory=list)


def eval_status_from_str(value: str) -> EvalStatus:
    return EvalStatus(value)


def parse_iso_datetime(ts: str):
    from datetime import datetime

    if ts.endswith("Z"):
        ts = ts[:-1] + "+00:00"
    return datetime.fromisoformat(ts)
