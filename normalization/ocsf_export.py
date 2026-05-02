"""OCSF-*like* JSON envelope for ``SecurityEvent`` and ``ScannerFinding`` (interop aid).

This module does **not** implement strict OCSF JSON Schema validation. All emitted documents
include ``format_label``: ``"OCSF-like"`` and an explicit ``compliance_claim`` of ``false``.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.models import ScannerFinding, SecurityEvent

_EXTENSION_KEY = "observable_security_agent"
_EXTENSION_NS = "https://observable-security-agent.local/extensions/v1"

FORMAT_LABEL = "OCSF-like"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def canonical_severity_to_severity_id(severity: str | None) -> int:
    """Map canonical finding/event severity string to an OCSF-style numeric scale (informative)."""
    s = str(severity or "medium").lower()
    return {"info": 2, "low": 3, "medium": 4, "high": 5, "critical": 6}.get(s, 4)


def _dumpable_metadata(meta: dict[str, Any] | None) -> dict[str, Any]:
    return dict(meta) if meta else {}


def security_event_to_ocsf_like_export(event: SecurityEvent | dict[str, Any]) -> dict[str, Any]:
    """Minimal Detection Finding-shaped document; ``semantic_type`` lives under ``metadata.extensions``."""
    if isinstance(event, dict):
        d = dict(event)
    else:
        d = event.model_dump(mode="json")
    sem = d.get("semantic_type")
    ts = d.get("timestamp")
    raw_meta = _dumpable_metadata(d.get("metadata") if isinstance(d.get("metadata"), dict) else None)
    net_hints = {k: d.get(k) for k in ("source_ip", "destination_ip", "port", "protocol", "actor") if d.get(k) is not None}
    return {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_name": d.get("raw_event_name") or "Detection",
        "time": ts,
        "severity_id": canonical_severity_to_severity_id("medium"),
        "metadata": {
            "uid": d.get("event_id"),
            "extensions": {
                _EXTENSION_KEY: {
                    "semantic_type": sem,
                    "extension_ns": _EXTENSION_NS,
                    "provider_raw_metadata": raw_meta,
                    "network_hints": net_hints,
                },
            },
        },
        "finding_info": {
            "title": f"Observable semantic: {sem}",
            "desc": f"Exported from SecurityEvent {d.get('event_id')}",
            "uid": d.get("event_id"),
        },
        "resource": {"uid": d.get("resource_id") or d.get("asset_id") or ""},
        "cloud": {"provider": d.get("provider") or "unknown"},
        "observable_source_model": "SecurityEvent",
    }


def scanner_finding_to_ocsf_like_export(finding: ScannerFinding | dict[str, Any]) -> dict[str, Any]:
    """OCSF-like Detection Finding shaped row from ``ScannerFinding`` (extensions hold semantic + agent metadata)."""
    if isinstance(finding, dict):
        d = dict(finding)
    else:
        d = finding.model_dump(mode="json")
    sem = d.get("metadata", {}).get("semantic_type") if isinstance(d.get("metadata"), dict) else None
    agent_meta = _dumpable_metadata(d.get("metadata") if isinstance(d.get("metadata"), dict) else None)
    ts = d.get("last_seen") or d.get("first_seen")
    title = str(d.get("title") or "Scanner finding")
    evidence = str(d.get("evidence") or title)
    return {
        "class_uid": 2004,
        "category_uid": 2,
        "activity_name": "Detection",
        "time": ts,
        "severity_id": canonical_severity_to_severity_id(str(d.get("severity"))),
        "status": str(d.get("status") or "open"),
        "metadata": {
            "uid": d.get("finding_id"),
            "extensions": {
                _EXTENSION_KEY: {
                    "semantic_type": sem,
                    "extension_ns": _EXTENSION_NS,
                    "provider_agent_metadata": agent_meta,
                },
            },
        },
        "finding_info": {
            "title": title[:500],
            "desc": evidence[:4000],
            "uid": d.get("finding_id"),
            "types": [str(x) for x in (d.get("cve_ids") or [])][:20],
        },
        "resource": {"uid": d.get("target_id") or d.get("asset_id") or ""},
        "cloud": {"provider": "unknown"},
        "observable_source_model": "ScannerFinding",
    }


def read_semantic_type_from_ocsf_like_export(doc: dict[str, Any]) -> str | None:
    """Read ``semantic_type`` from an OCSF-like export (event or finding shape)."""
    meta = doc.get("metadata")
    if not isinstance(meta, dict):
        return None
    ext = meta.get("extensions")
    if not isinstance(ext, dict):
        return None
    inner = ext.get(_EXTENSION_KEY)
    if not isinstance(inner, dict):
        return None
    st = inner.get("semantic_type")
    return str(st) if st is not None else None


def read_severity_and_status_from_finding_export(doc: dict[str, Any]) -> tuple[str | None, str | None]:
    """Inverse helpers for tests: OCSF-like severity_id and status string."""
    sid = doc.get("severity_id")
    sev = None
    if isinstance(sid, int):
        inv = {2: "info", 3: "low", 4: "medium", 5: "high", 6: "critical"}
        sev = inv.get(sid)
    st = doc.get("status")
    return sev, str(st).lower() if st is not None else None


def build_ocsf_like_bundle(
    *,
    events: list[dict[str, Any]],
    detection_findings: list[dict[str, Any]],
    source_assessment_dir: str | None = None,
) -> dict[str, Any]:
    """Top-level envelope for CLI / file export."""
    return {
        "format_label": FORMAT_LABEL,
        "format_note": "Observable Security Agent export; not OCSF-schema-validated. Do not claim OCSF compliance.",
        "compliance_claim": False,
        "ocsf_reference": "https://schema.ocsf.io/ (informative only)",
        "exported_at": _now_iso(),
        "source_assessment_dir": source_assessment_dir,
        "events": events,
        "detection_findings": detection_findings,
    }


def export_ocsf_like_json(assessment_dir: Path, output_path: Path) -> Path:
    """
    Load an assessment directory (fixture / assess output), emit one OCSF-like JSON file.

    Uses :func:`providers.fixture.assessment_bundle_from_evidence_bundle` so cloud events and
    scanner findings match the same normalization as the Fixture provider.
    """
    from core.utils import load_evidence_bundle_from_directory
    from providers.fixture import assessment_bundle_from_evidence_bundle

    root = assessment_dir.resolve()
    pb = load_evidence_bundle_from_directory(root)
    bundle = assessment_bundle_from_evidence_bundle(pb)

    event_docs = [security_event_to_ocsf_like_export(e) for e in bundle.events]
    finding_docs = [scanner_finding_to_ocsf_like_export(f) for f in bundle.scanner_findings]

    doc = build_ocsf_like_bundle(
        events=event_docs,
        detection_findings=finding_docs,
        source_assessment_dir=str(root),
    )
    output_path = output_path.resolve()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return output_path


__all__ = [
    "FORMAT_LABEL",
    "build_ocsf_like_bundle",
    "canonical_severity_to_severity_id",
    "export_ocsf_like_json",
    "read_semantic_type_from_ocsf_like_export",
    "read_severity_and_status_from_finding_export",
    "scanner_finding_to_ocsf_like_export",
    "security_event_to_ocsf_like_export",
]
