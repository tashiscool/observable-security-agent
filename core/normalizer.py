"""Normalize provider-native events into SemanticEvent records (provider logic delegated to ``providers``)."""

from __future__ import annotations

from typing import Any

from core.pipeline_models import PipelineEvidenceBundle as EvidenceBundle
from core.pipeline_models import PipelineSemanticEvent as SemanticEvent


def normalize_cloud_event(obj: dict[str, Any], ref_path: str) -> SemanticEvent:
    """
    Normalize a single ``cloud_events.json`` row to :class:`PipelineSemanticEvent`.

    Vendor-shaped rows (``_format``) are handled in ``providers.*`` so this module stays cloud-neutral.
    """
    fmt = obj.get("_format")
    if fmt == "aws_cloudtrail":
        from providers.aws import aws_cloudtrail_bundle_event_to_semantic

        return aws_cloudtrail_bundle_event_to_semantic(obj, ref_path)
    if fmt == "azure_activity":
        from providers.azure_gcp_normalizers import azure_activity_to_semantic

        return azure_activity_to_semantic(obj, ref_path)
    if fmt == "gcp_audit":
        from providers.azure_gcp_normalizers import gcp_audit_to_semantic

        return gcp_audit_to_semantic(obj, ref_path)
    if obj.get("event_type"):
        meta = {k: v for k, v in obj.items() if k not in {"event_type", "asset_id"}}
        return SemanticEvent(
            event_type=obj["event_type"],
            provider=obj.get("provider", "fixture"),
            actor=obj.get("actor"),
            asset_id=obj["asset_id"],
            resource_id=obj.get("resource_id"),
            timestamp=obj["timestamp"],
            raw_event_ref=ref_path,
            port=obj.get("port"),
            source_cidr=obj.get("source"),
            metadata=meta,
        )
    raise ValueError(f"Cannot normalize event in {ref_path}: missing _format or event_type")


def load_normalized_primary_event(bundle: EvidenceBundle) -> tuple[SemanticEvent, list[dict[str, Any]]]:
    data = bundle.cloud_events
    events = data if isinstance(data, list) else data.get("events", [])
    if not events:
        raise FileNotFoundError("No events in evidence bundle cloud_events")
    primary_idx = next((i for i, e in enumerate(events) if e.get("_primary")), 0)
    primary = events[primary_idx]
    ref = str(bundle.source_root / "cloud_events.json") + f"#{primary_idx}"
    return normalize_cloud_event(primary, ref), events
