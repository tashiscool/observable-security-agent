"""Normalize FedRAMP crosswalk CSV rows for package emission and eval linkage."""

from __future__ import annotations

from typing import Any


def normalize_rev4_to_rev5_row(row: dict[str, Any]) -> dict[str, Any]:
    """
    Accept legacy headers (``rev4_control_id``) or newer ``rev4_control`` /
    ``rev5_control`` plus ``relationship`` and ``notes``.
    """
    r4 = str(row.get("rev4_control_id") or row.get("rev4_control") or "").strip()
    r5 = str(row.get("rev5_control_id") or row.get("rev5_control") or "").strip()
    out: dict[str, Any] = {"rev4_control_id": r4, "rev5_control_id": r5}
    notes = row.get("notes")
    if notes is not None and str(notes).strip():
        out["notes"] = str(notes).strip()
    rel = row.get("relationship")
    if rel is not None and str(rel).strip():
        out["relationship"] = str(rel).strip()
    return out


def normalize_rev5_to_ksi_row(row: dict[str, Any]) -> dict[str, Any]:
    """
    Accept ``rev5_control`` or ``rev5_control_id``; optional descriptive columns
    are passed through for documentation and package embedding.
    """
    r5 = str(row.get("rev5_control_id") or row.get("rev5_control") or "").strip()
    ksi = str(row.get("ksi_id") or "").strip()
    mt = str(row.get("mapping_type") or "secondary").strip().lower()
    if mt not in ("primary", "secondary"):
        mt = "secondary"
    out: dict[str, Any] = {"rev5_control_id": r5, "ksi_id": ksi, "mapping_type": mt}
    for k in ("theme", "capability", "validation_focus", "trace_note"):
        v = row.get(k)
        if v is not None and str(v).strip():
            out[k] = str(v).strip()
    return out


def normalize_rev4_rev5_table(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        n = normalize_rev4_to_rev5_row(r)
        if n["rev4_control_id"] and n["rev5_control_id"]:
            out.append(n)
    return out


def normalize_rev5_ksi_table(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for r in rows:
        n = normalize_rev5_to_ksi_row(r)
        if n["rev5_control_id"] and n["ksi_id"]:
            out.append(n)
    return out
