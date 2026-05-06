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
        asset_id = "org-wide-aws"
        assets = bundle.discovered_assets
        items = assets.get("assets", assets.get("items", [])) if isinstance(assets, dict) else assets
        if isinstance(items, list) and items:
            first = items[0] if isinstance(items[0], dict) else {}
            asset_id = str(first.get("asset_id") or first.get("id") or asset_id)
        elif bundle.declared_inventory_rows:
            first_inv = bundle.declared_inventory_rows[0]
            asset_id = str(first_inv.get("asset_id") or first_inv.get("inventory_id") or asset_id)
        synthetic = {
            "event_type": "assessment.no_cloud_event_evidence",
            "provider": "aws",
            "actor": "observable-security-agent",
            "asset_id": asset_id,
            "resource_id": "missing-cloud-events",
            "timestamp": "",
            "raw_event_ref": "cloud_events.json#missing",
            "metadata": {
                "gap": "No cloud events were loaded; live assessment continues with inventory/log/scanner evidence only."
            },
        }
        return normalize_cloud_event(synthetic, str(bundle.source_root / "cloud_events.json") + "#missing"), [synthetic]
    primary_idx = next((i for i, e in enumerate(events) if e.get("_primary")), 0)
    primary = events[primary_idx]
    ref = str(bundle.source_root / "cloud_events.json") + f"#{primary_idx}"
    return normalize_cloud_event(primary, ref), events
