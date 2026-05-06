"""Validate FedRAMP 20x JSON artifacts against bundled JSON Schema (draft 2020-12)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012


@dataclass(frozen=True)
class ValidationReport:
    """Outcome of validating a JSON document against a schema."""

    valid: bool
    errors: list[str]
    schema_path: Path
    json_path: Path


def _build_registry(schemas_dir: Path) -> Registry:
    reg: Registry = Registry()
    for path in sorted(schemas_dir.glob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        rid = doc.get("$id")
        if not rid:
            raise ValueError(f"Schema file {path} must declare a top-level $id")
        resource = Resource.from_contents(doc, default_specification=DRAFT202012)
        reg = reg.with_resource(rid, resource)
    return reg


def _format_errors(validator: Draft202012Validator, instance: Any) -> list[str]:
    lines: list[str] = []
    for err in sorted(validator.iter_errors(instance), key=lambda e: (list(e.absolute_path), e.message)):
        loc = "/".join(str(p) for p in err.absolute_path) if err.absolute_path else "$"
        lines.append(f"{loc}: {err.message}")
    return lines


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _extract_object_array(
    raw: Any, array_keys: tuple[str, ...]
) -> tuple[list[dict[str, Any]], str | None]:
    """Return list of dict rows from a JSON wrapper or top-level array."""
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)], None
    if isinstance(raw, dict):
        for k in array_keys:
            v = raw.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)], k
    return [], None


def _is_top_level_package(doc: dict[str, Any]) -> bool:
    return (
        isinstance(doc, dict)
        and "package_id" in doc
        and "artifacts" in doc
        and isinstance(doc.get("artifacts"), dict)
        and "package_metadata" not in doc
    )


def _has_text(row: dict[str, Any], key: str) -> bool:
    return bool(str(row.get(key) or "").strip())


def _has_nonempty_list(row: dict[str, Any], key: str) -> bool:
    value = row.get(key)
    return isinstance(value, list) and any(str(x).strip() for x in value)


def _generated_finding_requires_workpaper(row: dict[str, Any]) -> bool:
    if str(row.get("source") or "") == "eval_result":
        return True
    refs = row.get("source_artifact_refs")
    if isinstance(refs, list) and any("eval_results.json" in str(x) for x in refs):
        return True
    return False


def _assessor_contract_errors(document: dict[str, Any]) -> list[str]:
    """Business-rule checks for generated nested packages.

    JSON Schema stays broad for compatibility with imported/top-level artifacts. Generated
    nested packages, however, must preserve the assessor workpaper chain from eval finding
    through POA&M closure tracking.
    """
    if _is_top_level_package(document):
        return []
    errors: list[str] = []
    findings = document.get("findings") or []
    if isinstance(findings, list):
        for i, row in enumerate(findings):
            if not isinstance(row, dict) or not _generated_finding_requires_workpaper(row):
                continue
            wp = row.get("assessor_workpaper")
            if not isinstance(wp, dict):
                errors.append(f"findings[{i}]: generated eval finding missing assessor_workpaper")
            for key in ("current_state", "target_state", "estimated_effort", "priority"):
                if not _has_text(row, key):
                    errors.append(f"findings[{i}]: missing {key}")
                if isinstance(wp, dict) and not _has_text(wp, key):
                    errors.append(f"findings[{i}].assessor_workpaper: missing {key}")
            if not _has_nonempty_list(row, "remediation_steps"):
                errors.append(f"findings[{i}]: missing remediation_steps")
            if isinstance(wp, dict) and not _has_nonempty_list(wp, "remediation_steps"):
                errors.append(f"findings[{i}].assessor_workpaper: missing remediation_steps")

    poam_items = document.get("poam_items") or []
    if isinstance(poam_items, list):
        for i, row in enumerate(poam_items):
            if not isinstance(row, dict) or not str(row.get("finding_id") or "").strip():
                continue
            for key in ("current_state", "target_state", "estimated_effort", "priority"):
                if not _has_text(row, key):
                    errors.append(f"poam_items[{i}]: generated finding-linked POA&M missing {key}")
            plan = row.get("remediation_plan")
            if not isinstance(plan, list) or not plan:
                errors.append(f"poam_items[{i}]: generated finding-linked POA&M missing remediation_plan")
            elif not any(isinstance(step, dict) and str(step.get("description") or "").strip() for step in plan):
                errors.append(f"poam_items[{i}]: remediation_plan has no described milestones")
    return errors


def _validate_item_rows(
    *,
    label: str,
    rows: list[dict[str, Any]],
    item_schema_path: Path,
    registry: Registry,
    errors: list[str],
) -> None:
    if not item_schema_path.is_file():
        errors.append(f"{label}: missing schema file {item_schema_path}")
        return
    item_schema = json.loads(item_schema_path.read_text(encoding="utf-8"))
    v = Draft202012Validator(item_schema, registry=registry)
    for i, row in enumerate(rows):
        row_errs = _format_errors(v, row)
        for line in row_errs:
            errors.append(f"{label}[{i}] {line}")


def _validate_top_level_artifacts(
    package_json_path: Path,
    doc: dict[str, Any],
    schemas_dir: Path,
    registry: Registry,
) -> list[str]:
    errors: list[str] = []
    base = package_json_path.parent
    art = doc.get("artifacts")
    if not isinstance(art, dict):
        return errors

    pairs: list[tuple[str, Path, Path, tuple[str, ...]]] = [
        ("artifacts/ksi_results", schemas_dir / "ksi-result.schema.json", base / str(art["ksi_results"]), ("ksi_results", "ksi_validation_results", "results")),
        ("artifacts/findings", schemas_dir / "finding.schema.json", base / str(art["findings"]), ("findings", "results")),
        ("artifacts/poam_items", schemas_dir / "poam-item.schema.json", base / str(art["poam_items"]), ("poam_items", "items")),
        ("reports/machine-readable/evidence_links", schemas_dir / "evidence-link.schema.json", base / str(art["evidence_links"]), ("evidence_links", "links")),
        ("reports/machine-readable/reconciliation", schemas_dir / "reconciliation.schema.json", base / str(art["reconciliation"]), ()),
    ]

    for label, schema_path, file_path, keys in pairs:
        if not file_path.is_file():
            errors.append(f"{label}: referenced file missing: {file_path}")
            continue
        raw = _load_json(file_path)
        if label.endswith("reconciliation"):
            rec_schema = json.loads(schema_path.read_text(encoding="utf-8"))
            v = Draft202012Validator(rec_schema, registry=registry)
            errors.extend(f"{label} {line}" for line in _format_errors(v, raw))
            continue
        rows, _k = _extract_object_array(raw, keys)
        _validate_item_rows(
            label=label,
            rows=rows,
            item_schema_path=schema_path,
            registry=registry,
            errors=errors,
        )
    return errors


def validate_json_file(schema_path: Path, json_path: Path) -> ValidationReport:
    """
    Validate ``json_path`` against the root schema at ``schema_path`` (sibling ``*.schema.json``
    in the same directory are registered for ``$ref`` resolution).
    """
    schema_path = schema_path.resolve()
    json_path = json_path.resolve()
    schemas_dir = schema_path.parent
    registry = _build_registry(schemas_dir)
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    instance = _load_json(json_path)
    validator = Draft202012Validator(schema, registry=registry)
    errors = _format_errors(validator, instance)
    if not errors and isinstance(instance, dict):
        errors.extend(_assessor_contract_errors(instance))
    return ValidationReport(valid=len(errors) == 0, errors=errors, schema_path=schema_path, json_path=json_path)


def validate_package(package_path: Path, schemas_dir: Path) -> ValidationReport:
    """
    Validate ``fedramp20x-package.json`` at ``package_path`` against ``fedramp20x-package.schema.json``.

    For **top-level** packages (manifest style produced by ``build_fedramp20x_package``), also validates
    artifact JSON files referenced under ``artifacts`` and ``reports/machine-readable`` using the
    per-artifact schemas in ``schemas_dir``.
    """
    package_path = package_path.resolve()
    schemas_dir = schemas_dir.resolve()
    root_schema_path = schemas_dir / "fedramp20x-package.schema.json"
    registry = _build_registry(schemas_dir)
    root_schema = json.loads(root_schema_path.read_text(encoding="utf-8"))
    instance = _load_json(package_path)
    validator = Draft202012Validator(root_schema, registry=registry)
    errors = list(_format_errors(validator, instance))
    if errors:
        return ValidationReport(valid=False, errors=errors, schema_path=root_schema_path, json_path=package_path)
    if isinstance(instance, dict):
        errors.extend(_assessor_contract_errors(instance))
    if isinstance(instance, dict) and _is_top_level_package(instance):
        errors.extend(_validate_top_level_artifacts(package_path, instance, schemas_dir, registry))
    return ValidationReport(valid=len(errors) == 0, errors=errors, schema_path=root_schema_path, json_path=package_path)


def validate_fedramp20x_document(document: dict[str, Any], schemas_dir: Path) -> ValidationReport:
    """
    Validate an in-memory package document (nested or top-level) before it is written to disk.

    Top-level documents do **not** trigger artifact file validation (those files do not exist yet).
    """
    schemas_dir = schemas_dir.resolve()
    root_schema_path = schemas_dir / "fedramp20x-package.schema.json"
    registry = _build_registry(schemas_dir)
    root_schema = json.loads(root_schema_path.read_text(encoding="utf-8"))
    validator = Draft202012Validator(root_schema, registry=registry)
    errors = _format_errors(validator, document)
    if not errors:
        errors.extend(_assessor_contract_errors(document))
    return ValidationReport(
        valid=len(errors) == 0,
        errors=errors,
        schema_path=root_schema_path,
        json_path=Path("<document>"),
    )
