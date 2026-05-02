"""Shared helpers: paths, CSV/JSON IO, evidence bundle derivation."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from core.pipeline_models import PipelineAssetEvidence as AssetEvidence
from core.pipeline_models import PipelineEvidenceBundle as EvidenceBundle


def load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def load_csv_rows(path: Path) -> list[dict[str, Any]]:
    text = path.read_text(encoding="utf-8")
    lines = text.strip().splitlines()
    if not lines:
        return []
    reader = csv.DictReader(lines)
    return [dict(row) for row in reader]


def inventory_ids(bundle: EvidenceBundle) -> set[str]:
    return {
        str(r.get("asset_id") or r.get("Asset ID") or "").strip()
        for r in bundle.declared_inventory_rows
        if (r.get("asset_id") or r.get("Asset ID"))
    }


def discovered_ids(bundle: EvidenceBundle) -> set[str]:
    assets = bundle.discovered_assets
    if isinstance(assets, dict):
        items = assets.get("assets", assets.get("items", []))
    else:
        items = assets
    return {str(a.get("asset_id") or a.get("id")) for a in items if a}


def scanner_target_ids(bundle: EvidenceBundle) -> set[str]:
    return {
        str(r.get("asset_id") or r.get("target") or "").strip()
        for r in bundle.scanner_target_rows
        if (r.get("asset_id") or r.get("target"))
    }


def central_log_recent(bundle: EvidenceBundle, asset_id: str) -> bool:
    src = bundle.central_log_sources
    items = src.get("sources", src) if isinstance(src, dict) else src
    if not isinstance(items, list):
        return False
    for s in items:
        if s.get("asset_id") != asset_id:
            continue
        if s.get("seen_last_24h") is True:
            return True
    return False


def asset_criticality(bundle: EvidenceBundle, asset_id: str) -> str:
    findings = bundle.scanner_findings
    items = findings.get("findings", findings) if isinstance(findings, dict) else findings
    if not isinstance(items, list):
        return "unknown"
    for f in items:
        if f.get("asset_id") != asset_id:
            continue
        sev = str(f.get("severity", "")).lower()
        if sev in ("critical", "high"):
            return "high"
    return "medium"


def build_asset_evidence(bundle: EvidenceBundle, asset_id: str) -> AssetEvidence:
    return AssetEvidence(
        declared_inventory=asset_id in inventory_ids(bundle),
        discovered_cloud_asset=asset_id in discovered_ids(bundle),
        scanner_scope=asset_id in scanner_target_ids(bundle),
        central_log_seen_last_24h=central_log_recent(bundle, asset_id),
        criticality=asset_criticality(bundle, asset_id),
    )


def load_evidence_bundle_from_directory(source_root: Path) -> EvidenceBundle:
    """Load canonical evidence from a directory (fixture layout or AWS export layout)."""
    inv = source_root / "declared_inventory.csv"
    disc = source_root / "discovered_assets.json"
    events = source_root / "cloud_events.json"
    findings = source_root / "scanner_findings.json"
    targets = source_root / "scanner_targets.csv"
    logs = source_root / "central_log_sources.json"
    alerts = source_root / "alert_rules.json"
    tix = source_root / "tickets.json"
    poam = source_root / "poam.csv"

    declared_rows: list[dict[str, Any]] = load_csv_rows(inv) if inv.is_file() else []
    discovered: dict[str, Any] = load_json(disc) if disc.is_file() else {"assets": []}
    cloud_events: Any = load_json(events) if events.is_file() else []
    scanner_findings: dict[str, Any] = (
        load_json(findings) if findings.is_file() else {"findings": []}
    )
    scanner_rows = load_csv_rows(targets) if targets.is_file() else []
    central = load_json(logs) if logs.is_file() else {"sources": []}
    alert_data = load_json(alerts) if alerts.is_file() else {"rules": []}
    tickets_data = load_json(tix) if tix.is_file() else {"tickets": []}
    poam_seed = load_csv_rows(poam) if poam.is_file() else []

    return EvidenceBundle(
        source_root=source_root.resolve(),
        declared_inventory_rows=declared_rows,
        discovered_assets=discovered,
        cloud_events=cloud_events,
        scanner_findings=scanner_findings,
        scanner_target_rows=scanner_rows,
        central_log_sources=central,
        alert_rules=alert_data,
        tickets=tickets_data,
        poam_seed_rows=poam_seed,
    )


def validate_evidence_bundle_minimum(bundle: EvidenceBundle) -> None:
    """Raise ValueError if cloud_events missing or empty (cannot normalize primary event)."""
    ev = bundle.cloud_events
    events = ev if isinstance(ev, list) else (ev.get("events", []) if isinstance(ev, dict) else [])
    if not events:
        raise ValueError(
            "Evidence bundle has no cloud events. Add cloud_events.json or use a complete fixture."
        )
