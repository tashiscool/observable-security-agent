"""Shared types for instrumentation generators (SPL, KQL, GCP, AWS)."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SUPPORTED_SEMANTIC_TYPES: frozenset[str] = frozenset(
    {
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
        "identity.admin_role_granted",
        "identity.mfa_disabled",
        "logging.audit_disabled",
        "compute.untracked_asset_created",
        "scanner.high_vulnerability_detected",
    }
)


@dataclass
class InstrumentationInput:
    """Inputs shared across platform instrumentation generators."""

    semantic_type: str
    asset_id: str
    asset_name: str | None = None
    provider: str = "aws"
    raw_event_ref: str = ""
    timestamp: str = ""
    controls: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InstrumentationArtifact:
    """Single-platform instrumentation recommendation."""

    platform: str
    query_text: str
    alert_rule_name: str
    suggested_schedule: str
    suggested_severity: str
    suggested_recipients_placeholder: str
    evidence_required: str


def instrumentation_input_from_pipeline_event(
    *,
    semantic_type: str,
    asset_id: str,
    asset_name: str | None = None,
    provider: str = "aws",
    raw_event_ref: str = "",
    timestamp: str = "",
    controls: tuple[str, ...] = (),
    metadata: dict[str, Any] | None = None,
) -> InstrumentationInput:
    return InstrumentationInput(
        semantic_type=semantic_type,
        asset_id=asset_id,
        asset_name=asset_name,
        provider=provider,
        raw_event_ref=raw_event_ref,
        timestamp=timestamp,
        controls=controls,
        metadata=dict(metadata or {}),
    )
