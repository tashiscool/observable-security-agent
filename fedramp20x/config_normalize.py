"""Normalize newer structured YAML configs to legacy keys expected by package/report builders."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _providers_to_cloud_provider(providers: Any) -> str:
    if isinstance(providers, str) and providers.strip():
        return providers.strip()
    if isinstance(providers, list) and providers:
        return "/".join(str(p).strip() for p in providers if str(p).strip()) or "multi-cloud"
    return "multi-cloud"


def normalize_system_boundary(doc: dict[str, Any]) -> dict[str, Any]:
    """
    Accept nested ``system:`` / ``authorization_scope`` / ``data_types`` / ``external_services`` plus
    legacy flat keys. Ensures ``system_id``, ``short_name``, ``description``, ``regions``, etc. exist.
    """
    if not isinstance(doc, dict):
        return {}
    out = dict(doc)
    sys = doc.get("system")
    if isinstance(sys, dict):
        out.setdefault("system_id", str(sys.get("id") or "").strip() or out.get("system_id", ""))
        out.setdefault("short_name", str(sys.get("name") or "").strip() or out.get("short_name", ""))
        desc = str(sys.get("description") or out.get("description", "")).strip()
        if desc:
            out.setdefault("description", desc)
        elif not out.get("description"):
            out["description"] = (
                "Logical security program boundary for observability evidence under this assessment configuration."
            )
        out.setdefault("boundary_type", str(sys.get("boundary_type") or out.get("boundary_type", "logical")))
        out.setdefault("notes", str(sys.get("notes") or out.get("notes", "")).strip())
        out.setdefault("authorization_path", str(sys.get("authorization_path") or out.get("authorization_path", "")))
        out.setdefault("deployment_model", str(sys.get("deployment_model") or out.get("deployment_model", "")))
        out.setdefault("impact_level", str(sys.get("impact_level") or out.get("impact_level", "")))
        r = sys.get("regions")
        if isinstance(r, list) and r:
            out.setdefault("regions", [str(x) for x in r])
        out.setdefault("cloud_provider", _providers_to_cloud_provider(sys.get("cloud_providers")))
    return out


def normalize_authorization_scope(doc: dict[str, Any]) -> dict[str, Any]:
    """
    Map ``included_components`` / ``excluded_components`` to ``in_scope_services`` / ``out_of_scope``
    when legacy lists are absent.
    """
    if not isinstance(doc, dict):
        return {}
    out = dict(doc)
    if not out.get("in_scope_services") and isinstance(doc.get("included_components"), list):
        rows: list[dict[str, Any]] = []
        for c in doc["included_components"]:
            if not isinstance(c, dict):
                continue
            cat = str(c.get("type") or c.get("environment") or c.get("id") or "component").strip()
            row = dict(c)
            row["category"] = cat
            rows.append(row)
        out["in_scope_services"] = rows
    if not out.get("out_of_scope") and isinstance(doc.get("excluded_components"), list):
        rows_o: list[dict[str, Any]] = []
        for c in doc["excluded_components"]:
            if not isinstance(c, dict):
                continue
            rows_o.append(
                {
                    "category": str(c.get("name") or c.get("id") or "excluded").strip(),
                    "rationale": str(c.get("rationale") or "").strip(),
                }
            )
        out["out_of_scope"] = rows_o
    if "minimum_assessment_scope_applied" in doc:
        out["minimum_assessment_scope_applied"] = bool(doc.get("minimum_assessment_scope_applied"))
    return out


def normalize_validation_policy(doc: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(doc, dict):
        return {}
    out = dict(doc)
    # severity_rules: optional map for future evaluators; keep as-is
    return out


def normalize_poam_policy(doc: dict[str, Any]) -> dict[str, Any]:
    """Map newer POA&M policy field names onto keys :func:`load_poam_policy` consumers expect."""
    if not isinstance(doc, dict):
        return {}
    out = dict(doc)
    if "due_days_by_severity" in doc and "default_due_days_by_severity" not in out:
        d = doc.get("due_days_by_severity")
        if isinstance(d, dict):
            out["default_due_days_by_severity"] = d
    owners = doc.get("default_owners")
    if isinstance(owners, dict):
        if owners.get("risk") and "risk_owner_default" not in out:
            out["risk_owner_default"] = str(owners["risk"])
        if owners.get("system") and "system_owner_default" not in out:
            out["system_owner_default"] = str(owners["system"])
    if "closure_evidence_required" in doc and "validation_required_for_closure_default" not in out:
        out["validation_required_for_closure_default"] = bool(doc.get("closure_evidence_required"))
    return out


def normalize_reporting_policy(doc: dict[str, Any]) -> dict[str, Any]:
    """Preserve legacy ``reports`` / ``reconciliation`` / ``machine_readable``; pass through extensions."""
    if not isinstance(doc, dict):
        return {}
    return dict(doc)


def validate_against_schema(instance: Any, schema_path: Path) -> None:
    """Raise ``jsonschema.ValidationError`` if the instance does not match the schema file."""
    if not schema_path.is_file():
        return
    import jsonschema

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    jsonschema.validate(instance=instance, schema=schema)
