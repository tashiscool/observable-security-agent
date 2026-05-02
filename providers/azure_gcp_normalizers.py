"""Azure / GCP audit-shaped dicts → pipeline semantic events (no cloud SDKs)."""

from __future__ import annotations

from typing import Any

from core.pipeline_models import PipelineSemanticEvent as SemanticEvent


def azure_activity_to_semantic(raw: dict[str, Any], ref_path: str) -> SemanticEvent:
    """Map ``_format == "azure_activity"`` bundle rows to a semantic event."""
    return SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="azure",
        actor=raw.get("caller", "unknown@example.com"),
        asset_id=raw.get("_asset_id", "unknown-asset"),
        resource_id=raw.get("resourceId", "nsg-unknown"),
        timestamp=raw.get("time", ""),
        raw_event_ref=ref_path,
        port=int(raw.get("_port", 22)),
        source_cidr=raw.get("_source", "0.0.0.0/0"),
        metadata={"operation": raw.get("operationName")},
    )


def gcp_audit_to_semantic(raw: dict[str, Any], ref_path: str) -> SemanticEvent:
    """Map ``_format == "gcp_audit"`` bundle rows to a semantic event."""
    payload = raw.get("protoPayload", {})
    return SemanticEvent(
        event_type="network.public_admin_port_opened",
        provider="gcp",
        actor=payload.get("authenticationInfo", {}).get("principalEmail", "unknown@example.com"),
        asset_id=raw.get("_asset_id", "unknown-asset"),
        resource_id=raw.get("resource", {}).get("labels", {}).get("name", "fw-unknown"),
        timestamp=raw.get("timestamp", ""),
        raw_event_ref=ref_path,
        port=22,
        source_cidr="0.0.0.0/0",
        metadata={"method": payload.get("methodName")},
    )
