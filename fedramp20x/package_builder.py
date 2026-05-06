"""Assemble FedRAMP 20x-style machine-readable package from assessment outputs + config.

AuditKit Community Edition evidence-package *examples* (public README patterns) informed how we
place machine-readable mirrors next to assessor reports; implementation is original.
"""

from __future__ import annotations

import hashlib
import json
import shlex
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from core.csv_utils import load_csv_rows
from fedramp20x.eval_ksi_mapping import eval_to_ksi_ids
from fedramp20x.evidence_maturity import (
    compute_ksi_evidence_posture,
    compute_package_evidence_maturity_summary,
    infer_criteria_results_from_ksi_result,
)
from fedramp20x.evidence_links import finalize_evidence_link_tracking, prepare_stable_evidence_ref_attachments
from fedramp20x.evidence_registry import EvidenceRegistry, evidence_registry_to_package_dict, load_evidence_source_registry
from fedramp20x.finding_builder import build_findings
from fedramp20x.ksi_catalog import KsiCatalog, ksi_catalog_to_package_payload, load_ksi_catalog
from fedramp20x.poam_builder import (
    attach_poam_ids_to_findings,
    build_poam_items_from_findings,
    load_poam_policy,
    merge_poam_items_for_package,
    poam_items_from_csv,
    write_poam_items_json,
    write_poam_markdown,
)
from fedramp20x.reconciliation import (
    apply_human_derived_counts_to_reconciliation,
    build_reconciliation_summary,
    deep_reconcile,
    write_deep_reconciliation_outputs,
)
from fedramp20x.report_builder import (
    ASSESSOR_SUMMARY,
    EVIDENCE_INDEX,
    EXCEPTIONS_MANUAL,
    KSI_BY_KSI,
    POAM_MD,
    VALIDATION_METHODOLOGY,
    write_agency_ao_report,
    write_assessor_report,
    write_executive_report,
    write_machine_readable_mirror,
    write_reconciliation_markdown,
)
from fedramp20x.config_normalize import (
    normalize_authorization_scope,
    normalize_reporting_policy,
    normalize_system_boundary,
    normalize_validation_policy,
    validate_against_schema,
)
from fedramp20x.crosswalk_normalize import normalize_rev4_rev5_table, normalize_rev5_ksi_table
from fedramp20x.schema_validator import validate_fedramp20x_document

_CONFIG_SCHEMA_DIR = Path(__file__).resolve().parents[1] / "schemas"
_SCHEMA_URI = "https://observable-security-agent.local/schemas/fedramp20x-package.schema.json"
_PROJECT_SCHEMA_REL = "schemas/fedramp20x-package.schema.json"
_REPO_ROOT = Path(__file__).resolve().parents[1]


def _tool_version_string() -> str:
    try:
        from importlib.metadata import PackageNotFoundError, version

        return version("observable-security-agent")
    except (PackageNotFoundError, Exception):
        pass
    try:
        py = _REPO_ROOT / "pyproject.toml"
        if py.is_file():
            data = tomllib.loads(py.read_bytes())
            return str(data.get("project", {}).get("version", "unknown"))
    except Exception:
        pass
    return "unknown"


def _cli_invocation_string(max_len: int = 4000) -> str | None:
    if not sys.argv:
        return None
    s = shlex.join(sys.argv)
    return s if len(s) <= max_len else s[: max_len - 1] + "…"


def _input_artifact_manifest_rows(assessment_output: Path) -> list[dict[str, Any]]:
    """Audit-style manifest of assessment inputs (paths relative to assessment root)."""
    rows: list[dict[str, Any]] = []
    for name in (
        "eval_results.json",
        "evidence_graph.json",
        "assessment_summary.json",
        "agent_eval_results.json",
        "poam.csv",
    ):
        p = assessment_output / name
        if not p.is_file():
            continue
        try:
            data = p.read_bytes()
            rows.append(
                {
                    "path": name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size_bytes": len(data),
                }
            )
        except OSError:
            rows.append({"path": name, "sha256": None, "size_bytes": None, "note": "unreadable"})
    return rows


def _validate_config_schema(name: str, instance: dict[str, Any], schemas_dir: Path | None) -> None:
    root = schemas_dir or _CONFIG_SCHEMA_DIR
    path = root / f"config-{name}.schema.json"
    if not path.is_file():
        return
    # Skip strict config schemas for legacy flat/minimal fixtures (e.g. unit tests).
    if name == "system-boundary" and not isinstance(instance.get("system"), dict):
        return
    if name == "authorization-scope" and not isinstance(instance.get("included_components"), list):
        return
    try:
        validate_against_schema(instance, path)
    except Exception as ex:
        raise ValueError(f"Config schema validation failed ({name}): {ex}") from ex


class Fedramp20xPackageValidationError(ValueError):
    """Raised when top-level FedRAMP 20x package business rules are violated."""


def _load_yaml(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing config: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Missing assessment artifact: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def _load_csv(path: Path) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    return [dict(r) for r in load_csv_rows(path)]


def _status_precedence(policy: dict[str, Any]) -> list[str]:
    seq = policy.get("ksi_status_precedence")
    if isinstance(seq, list) and seq:
        return [str(x).upper() for x in seq]
    return ["FAIL", "PARTIAL", "OPEN", "NOT_APPLICABLE", "PASS"]


def _rollup_status(statuses: list[str], order: list[str]) -> str:
    st = {str(s).upper() for s in statuses if s}
    for o in order:
        if o in st:
            return o
    return "PASS"


def _evidence_links_from_graph(graph: dict[str, Any], limit: int = 250) -> list[dict[str, Any]]:
    edges = graph.get("edges") if isinstance(graph, dict) else None
    if not isinstance(edges, list):
        return []
    out: list[dict[str, Any]] = []
    for i, e in enumerate(edges[:limit]):
        if not isinstance(e, dict):
            continue
        s = e.get("source") or {}
        t = e.get("target") or {}
        out.append(
            {
                "link_id": f"LINK-GRAPH-{i:04d}",
                "from_ref": {"ref_type": str(s.get("type", "unknown")), "ref_id": str(s.get("id", ""))},
                "to_ref": {"ref_type": str(t.get("type", "unknown")), "ref_id": str(t.get("id", ""))},
                "relationship": str(e.get("relationship") or "related"),
                "artifact_uri": "evidence_graph.json",
            }
        )
    return out


def build_20x_package(
    *,
    assessment_output: Path,
    config_dir: Path,
    package_output: Path,
    mappings_dir: Path,
    schemas_dir: Path,
    validation_artifact_root: Path | None = None,
) -> int:
    assessment_output = assessment_output.resolve()
    config_dir = config_dir.resolve()
    package_output = package_output.resolve()
    mappings_dir = mappings_dir.resolve()
    schemas_dir = schemas_dir.resolve()

    eval_path = assessment_output / "eval_results.json"
    graph_path = assessment_output / "evidence_graph.json"
    poam_path = assessment_output / "poam.csv"
    summary_path = assessment_output / "assessment_summary.json"

    eval_doc = _read_json(eval_path)
    graph = _read_json(graph_path) if graph_path.is_file() else {}
    summary = _read_json(summary_path) if summary_path.is_file() else {}
    evaluations = list(eval_doc.get("evaluations") or [])
    agent_eval_path = assessment_output / "agent_eval_results.json"
    if agent_eval_path.is_file():
        try:
            ag_doc = json.loads(agent_eval_path.read_text(encoding="utf-8"))
            if isinstance(ag_doc, dict):
                evaluations.extend(list(ag_doc.get("evaluations") or []))
        except (json.JSONDecodeError, OSError):
            pass

    system_boundary = normalize_system_boundary(_load_yaml(config_dir / "system-boundary.yaml"))
    _validate_config_schema("system-boundary", system_boundary, schemas_dir)
    auth_scope = normalize_authorization_scope(_load_yaml(config_dir / "authorization-scope.yaml"))
    _validate_config_schema("authorization-scope", auth_scope, schemas_dir)
    evidence_reg = load_evidence_source_registry(config_dir / "evidence-source-registry.yaml")
    ksi_catalog_doc = load_ksi_catalog(config_dir / "ksi-catalog.yaml")
    ksi_catalog = ksi_catalog_to_package_payload(ksi_catalog_doc)
    control_cross_cfg = _load_yaml(config_dir / "control-crosswalk.yaml")
    validation_policy = normalize_validation_policy(_load_yaml(config_dir / "validation-policy.yaml"))
    _validate_config_schema("validation-policy", validation_policy, schemas_dir)
    reporting = normalize_reporting_policy(_load_yaml(config_dir / "reporting-policy.yaml"))
    _validate_config_schema("reporting-policy", reporting, schemas_dir)

    rev4_rev5 = normalize_rev4_rev5_table(_load_csv(mappings_dir / "rev4-to-rev5-crosswalk.csv"))
    rev5_raw_rows = _load_csv(mappings_dir / "rev5-to-20x-ksi-crosswalk.csv")
    crosswalk_warnings: list[dict[str, str]] = []
    for i, row in enumerate(rev5_raw_rows, start=2):
        if (row.get("rev5_control") or row.get("rev5_control_id")) and row.get("ksi_id") and not str(row.get("trace_note") or "").strip():
            crosswalk_warnings.append(
                {
                    "file": "rev5-to-20x-ksi-crosswalk.csv",
                    "row": str(i),
                    "rev5_control": str(row.get("rev5_control") or row.get("rev5_control_id") or ""),
                    "ksi_id": str(row.get("ksi_id") or ""),
                    "warning": "missing trace_note",
                }
            )
    rev5_ksi = normalize_rev5_ksi_table(rev5_raw_rows)
    eval_default_map = {
        str(k): str(v) for k, v in (control_cross_cfg.get("eval_id_default_ksi") or {}).items()
    }
    eval_agent_ksi = {
        str(k): v for k, v in (control_cross_cfg.get("eval_id_agent_ksi") or {}).items()
    }

    order = _status_precedence(validation_policy)

    ksi_to_evals: dict[str, list[tuple[str, str]]] = {}
    for ev in evaluations:
        eid = str(ev.get("eval_id") or "")
        res = str(ev.get("result") or "").upper()
        for ksi in eval_to_ksi_ids(ev, rev5_ksi, eval_default_map, eval_agent_ksi):
            ksi_to_evals.setdefault(ksi, []).append((eid, res))

    catalog_ids = {x["ksi_id"] for x in ksi_catalog}
    all_ksi_ids = sorted(catalog_ids | set(ksi_to_evals.keys()))

    ksi_results: list[dict[str, Any]] = []
    for ksi in all_ksi_ids:
        pairs = ksi_to_evals.get(ksi, [])
        if not pairs:
            status = "NOT_APPLICABLE"
            summary = "No linked evaluations mapped to this KSI for this run."
            linked_evals: list[str] = []
        else:
            linked_evals = sorted({p[0] for p in pairs})
            status = _rollup_status([p[1] for p in pairs], order)
            summary = f"Rolled up from evaluations: {', '.join(linked_evals)} (precedence: {', '.join(order)})."
        controls: set[str] = set()
        for ev in evaluations:
            if str(ev.get("eval_id")) not in linked_evals:
                continue
            for c in ev.get("control_refs") or []:
                controls.add(str(c))
        refs: list[dict[str, str]] = [
            {"artifact": "eval_results.json", "role": "primary", "json_pointer": "#/evaluations"}
        ]
        if any(str(eid).startswith("AGENT_") for eid in linked_evals):
            refs.append(
                {
                    "artifact": "agent_eval_results.json",
                    "role": "supporting",
                    "json_pointer": "#/evaluations",
                }
            )
        ksi_results.append(
            {
                "ksi_id": ksi,
                "status": status,
                "summary": summary,
                "linked_eval_ids": linked_evals,
                "linked_nist_control_refs": sorted(controls),
                "evidence_refs": refs,
            }
        )

    reg_map_posture = {s.id: s for s in evidence_reg.sources}
    catalog_by_ksi = {k.ksi_id: k for k in ksi_catalog_doc.catalog}
    for row in ksi_results:
        kid = str(row.get("ksi_id") or "")
        kd = catalog_by_ksi.get(kid)
        if kd:
            crit = infer_criteria_results_from_ksi_result(kd, row)
            row["evidence_posture"] = compute_ksi_evidence_posture(kd, reg_map_posture, crit)

    stock_csv_poam = poam_items_from_csv(poam_path)
    findings = build_findings(
        evaluations,
        rev4_to_rev5=rev4_rev5,
        rev5_to_ksi=rev5_ksi,
        eval_default_ksi=eval_default_map,
        eval_agent_ksi=eval_agent_ksi,
        validation_policy=validation_policy,
        ksi_validation_results=ksi_results,
        ksi_catalog=ksi_catalog,
        poam_items=stock_csv_poam,
    )
    poam_policy = load_poam_policy(config_dir / "poam-policy.yaml")
    _validate_config_schema("poam-policy", poam_policy, schemas_dir)
    finding_poam = build_poam_items_from_findings(findings, poam_policy, system_boundary=system_boundary)
    attach_poam_ids_to_findings(findings, finding_poam)
    poam_items = merge_poam_items_for_package(stock_csv_poam, finding_poam)
    if validation_artifact_root is not None:
        root = validation_artifact_root.resolve()
        write_poam_items_json(root / "evidence" / "validation-results" / "poam-items.json", finding_poam)
        write_poam_markdown(root / "reports" / "assessor" / "poam.md", finding_poam)
    evidence_links = _evidence_links_from_graph(graph)

    program_display = str(system_boundary.get("short_name") or system_boundary.get("system_id") or "program")
    mat = compute_package_evidence_maturity_summary(ksi_catalog_doc, evidence_reg, ksi_results)
    meta = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "generator_id": "observable-security-agent/fedramp20x",
        "assessment_output_uri": str(assessment_output),
        "system_id": str(system_boundary.get("system_id") or ""),
        "program_display_name": program_display,
        "config_bundle_uri": str(config_dir),
        "mappings_bundle_uri": str(mappings_dir),
        "crosswalk_warnings": crosswalk_warnings,
        "ksi_catalog_version": ksi_catalog_doc.catalog_version,
        "fedramp20x_style_package_schema": {
            "label": "FedRAMP 20x–style evidence package schema",
            "schema_id_uri": _SCHEMA_URI,
            "project_relative_path": _PROJECT_SCHEMA_REL,
        },
        "package_generation_timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "tool_version": _tool_version_string(),
        "cli_invocation": _cli_invocation_string(),
        "input_artifact_manifest": _input_artifact_manifest_rows(assessment_output),
        "validation_run": {
            "nested_package_schema_label": "FedRAMP 20x–style nested bundle (schemas/fedramp20x-package.schema.json)",
            "schema_validation_outcome": "pending",
            "note": "Outcome set to passed only if validate_fedramp20x_document succeeds.",
        },
        "evidence_source_coverage": {
            "registry_registered_sources": len(evidence_reg.sources),
            "summary": dict(mat),
        },
        "provider_summary": {
            "deployment_model": auth_scope.get("deployment_model"),
            "impact_level": auth_scope.get("impact_level"),
            "authorization_boundary_id": auth_scope.get("authorization_boundary_id"),
            "in_scope_categories": [
                (r.get("category") if isinstance(r, dict) else str(r))
                for r in (auth_scope.get("in_scope_services") or [])
            ][:50],
        },
        "framework_control_summary": {
            "catalog_ksi_count": len(ksi_catalog),
            "crosswalk_unique_rev5_controls": len(
                {str(r.get("rev5_control_id")) for r in rev5_ksi if r.get("rev5_control_id")}
            ),
            "catalog_ksi_themes": sorted(
                {str(k.get("theme")) for k in ksi_catalog if isinstance(k, dict) and k.get("theme")}
            )[:60],
        },
        "package_manifest": {
            "description": "Machine-readable primary package and mirrored validation slices (AuditKit-inspired folder ideas; not AuditKit software output).",
            "primary_package_filename": ((reporting.get("machine_readable") or {}).get("primary_package_filename"))
            or "fedramp20x-package.json",
            "validation_artifacts_relative": [
                "evidence/validation-results/ksi-results.json",
                "evidence/validation-results/findings.json",
                "evidence/validation-results/poam-items.json",
                "evidence/validation-results/evidence-links.json",
            ],
            "report_directories_relative": {
                "assessor": "reports/assessor/",
                "executive": "reports/executive/",
                "agency_ao": "reports/agency-ao/",
            },
        },
    }

    snap = {
        "correlation_id": eval_doc.get("correlation_id"),
        "overall_result": eval_doc.get("overall_result"),
        "evidence_chain": eval_doc.get("evidence_chain"),
        "assessment_summary": summary,
        "evidence_maturity_summary": dict(mat),
    }

    pack_body: dict[str, Any] = {
        "schema_version": "1.0",
        "package_metadata": meta,
        "system_boundary": system_boundary,
        "authorization_scope": auth_scope,
        "evidence_source_registry": evidence_registry_to_package_dict(evidence_reg),
        "ksi_catalog": ksi_catalog,
        "control_crosswalk": {
            "rev4_to_rev5": rev4_rev5,
            "rev5_to_20x_ksi": rev5_ksi,
        },
        "ksi_validation_results": ksi_results,
        "findings": findings,
        "poam_items": poam_items,
        "evidence_links": evidence_links,
        "assessment_correlation_snapshot": snap,
    }

    body_hash = hashlib.sha256(
        json.dumps(pack_body, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()

    rep = reporting.get("reports") or {}
    assess_fn = (rep.get("assessor") or {}).get("filename") or "assessor-summary.md"
    exec_fn = (rep.get("executive") or {}).get("filename") or "executive-summary.md"
    ao_fn = (rep.get("agency_ao") or {}).get("filename") or "ao-risk-brief.md"
    include_sha = bool((reporting.get("reconciliation") or {}).get("include_sha256_of_package", True))

    assessor_path = package_output / "reports" / "assessor" / assess_fn
    executive_path = package_output / "reports" / "executive" / exec_fn
    ao_path = package_output / "reports" / "agency-ao" / ao_fn
    recon_out = package_output / "reports" / "reconciliation_report.md"

    assessor_path.parent.mkdir(parents=True, exist_ok=True)
    executive_path.parent.mkdir(parents=True, exist_ok=True)
    ao_path.parent.mkdir(parents=True, exist_ok=True)
    recon_out.parent.mkdir(parents=True, exist_ok=True)

    assessor_dir = assessor_path.parent
    human_manifest = [
        {"path": str((assessor_dir / ASSESSOR_SUMMARY).relative_to(package_output)), "role": "assessor_summary"},
        {"path": str((assessor_dir / KSI_BY_KSI).relative_to(package_output)), "role": "assessor_ksi_by_ksi"},
        {"path": str((assessor_dir / EVIDENCE_INDEX).relative_to(package_output)), "role": "assessor_evidence_index"},
        {"path": str((assessor_dir / VALIDATION_METHODOLOGY).relative_to(package_output)), "role": "assessor_methodology"},
        {"path": str((assessor_dir / EXCEPTIONS_MANUAL).relative_to(package_output)), "role": "assessor_exceptions"},
        {"path": str((assessor_dir / POAM_MD).relative_to(package_output)), "role": "assessor_poam_md"},
        {"path": str(assessor_path.relative_to(package_output)), "role": "assessor_primary"},
        {"path": str(executive_path.relative_to(package_output)), "role": "executive"},
        {"path": str(ao_path.relative_to(package_output)), "role": "agency_ao"},
        {"path": str(recon_out.relative_to(package_output)), "role": "reconciliation"},
    ]

    reconciliation = build_reconciliation_summary(
        package={**pack_body, "findings": findings, "poam_items": poam_items, "ksi_validation_results": ksi_results},
        human_report_paths=human_manifest,
        include_sha256=include_sha,
        package_sha256=body_hash,
    )
    package = {**pack_body, "reconciliation_summary": reconciliation}

    rep = validate_fedramp20x_document(package, schemas_dir)
    if not rep.valid:
        raise ValueError("Package JSON Schema validation failed:\n" + "\n".join(rep.errors))
    vr = package.setdefault("package_metadata", {}).setdefault("validation_run", {})
    vr["schema_validation_outcome"] = "passed"
    vr["validated_at"] = datetime.now(timezone.utc).isoformat()

    package_output.mkdir(parents=True, exist_ok=True)
    pkg_name = ((reporting.get("machine_readable") or {}).get("primary_package_filename")) or "fedramp20x-package.json"
    pkg_path = package_output / pkg_name
    pkg_path.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")

    # Mirror machine slices next to the package for Evidence Explorer / validators (same tree as reconciliation).
    _vr_pkg = package_output / "evidence" / "validation-results"
    _vr_pkg.mkdir(parents=True, exist_ok=True)
    (_vr_pkg / "ksi-results.json").write_text(
        json.dumps({"ksi_validation_results": ksi_results}, indent=2, default=str), encoding="utf-8"
    )
    (_vr_pkg / "findings.json").write_text(json.dumps({"findings": findings}, indent=2, default=str), encoding="utf-8")
    write_poam_items_json(_vr_pkg / "poam-items.json", poam_items)

    evidence_root = (validation_artifact_root or package_output).resolve()
    prepare_stable_evidence_ref_attachments(
        evidence_root=evidence_root,
        assessment_output=assessment_output,
        pkg_path=pkg_path,
        package=package,
        ksi_results=ksi_results,
        findings=findings,
    )
    pkg_path.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")
    (_vr_pkg / "ksi-results.json").write_text(
        json.dumps({"ksi_validation_results": ksi_results}, indent=2, default=str), encoding="utf-8"
    )
    (_vr_pkg / "findings.json").write_text(json.dumps({"findings": findings}, indent=2, default=str), encoding="utf-8")

    write_assessor_report(assessor_path, package)
    write_executive_report(executive_path, package)
    write_agency_ao_report(ao_path, package)

    apply_human_derived_counts_to_reconciliation(package=package, report_root=package_output)
    write_reconciliation_markdown(recon_out, package)
    write_assessor_report(assessor_path, package)

    pkg_path.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")
    (_vr_pkg / "ksi-results.json").write_text(
        json.dumps({"ksi_validation_results": ksi_results}, indent=2, default=str), encoding="utf-8"
    )
    (_vr_pkg / "findings.json").write_text(json.dumps({"findings": findings}, indent=2, default=str), encoding="utf-8")

    # Deep reconciliation (always non-fatal for package build): writes evidence/validation-results/reconciliation.json
    # and reports/assessor/reconciliation-summary.md under validation root or package output.
    try:
        _rec_out = (validation_artifact_root or package_output).resolve()
        _deep = deep_reconcile(package=package, machine_package_path=pkg_path, report_root=package_output)
        write_deep_reconciliation_outputs(_deep, output_root=_rec_out)
    except Exception:
        # Deep reconciliation must not fail package generation; use CLI for strict validation exit codes.
        pass

    mirror_roots: list[Path] = []
    if validation_artifact_root is not None and validation_artifact_root.resolve() != package_output.resolve():
        mirror_roots.append(package_output.resolve())
    _ev_warn, ev_errs = finalize_evidence_link_tracking(
        evidence_root=evidence_root,
        assessment_output=assessment_output,
        package_output=package_output,
        graph_path=graph_path,
        pkg_path=pkg_path,
        package=package,
        ksi_results=ksi_results,
        findings=findings,
        evidence_registry=evidence_reg,
        validation_policy=validation_policy,
        mirror_roots=mirror_roots,
    )
    if ev_errs and bool(validation_policy.get("strict_evidence_links")):
        raise ValueError("Evidence link / artifact validation failed: " + "; ".join(ev_errs))

    write_machine_readable_mirror(package_output, package)

    print(f"Wrote package: {pkg_path}")
    print(f"Reports under: {package_output / 'reports'}")
    return 0


def _load_json_collection(path: Path, array_keys: tuple[str, ...]) -> list[dict[str, Any]]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return [x for x in raw if isinstance(x, dict)]
    if isinstance(raw, dict):
        for k in array_keys:
            v = raw.get(k)
            if isinstance(v, list):
                return [x for x in v if isinstance(x, dict)]
    return []


def _copy_file(src: Path, dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(src.read_bytes())


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha256_file(path: Path) -> str:
    return _sha256_bytes(path.read_bytes())


def _iter_package_files(root: Path, *, exclude_names: set[str]) -> list[Path]:
    out: list[Path] = []
    for p in sorted(root.rglob("*")):
        if not p.is_file():
            continue
        if p.name in exclude_names:
            continue
        try:
            rel = p.relative_to(root)
        except ValueError:
            continue
        out.append(p)
    return out


def _write_checksums_file(package_root: Path, files: list[Path]) -> None:
    lines: list[str] = []
    for p in sorted(files, key=lambda x: str(x.relative_to(package_root))):
        rel = p.relative_to(package_root).as_posix()
        h = _sha256_file(p)
        lines.append(f"{h}  {rel}")
    (package_root / "checksums.sha256").write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


def _merge_ksi_results_with_catalog(
    catalog_doc: KsiCatalog, results: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Ensure every catalog KSI id appears exactly once (catalog order)."""
    catalog_ids = {k.ksi_id for k in catalog_doc.catalog}
    by_id = {str(r.get("ksi_id")): dict(r) for r in results if str(r.get("ksi_id") or "") in catalog_ids}
    out: list[dict[str, Any]] = []
    for k in catalog_doc.catalog:
        kid = k.ksi_id
        if kid in by_id:
            out.append(by_id[kid])
        else:
            out.append(
                {
                    "ksi_id": kid,
                    "status": "NOT_APPLICABLE",
                    "summary": "No KSI result row supplied for this catalog entry; defaulted for package completeness.",
                    "linked_eval_ids": [],
                    "linked_nist_control_refs": [],
                    "evidence_refs": [],
                }
            )
    return out


def _validate_top_level_package_rules(
    *,
    catalog_doc: KsiCatalog,
    ksi_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    poam_items: list[dict[str, Any]],
) -> None:
    catalog_ids = [k.ksi_id for k in catalog_doc.catalog]
    result_ids = {str(r.get("ksi_id")) for r in ksi_results if r.get("ksi_id")}
    if set(catalog_ids) != result_ids:
        missing = set(catalog_ids) - result_ids
        extra = result_ids - set(catalog_ids)
        raise Fedramp20xPackageValidationError(
            f"ksi_results must contain exactly catalog KSIs. missing={sorted(missing)} extra={sorted(extra)}"
        )

    def _finding_touches_ksi(ksi_id: str) -> bool:
        for f in findings:
            kids = f.get("linked_ksi_ids") or f.get("ksi_ids") or []
            if ksi_id in kids:
                return True
        return False

    for r in ksi_results:
        st = str(r.get("status") or "").upper()
        kid = str(r.get("ksi_id") or "")
        if st in ("FAIL", "PARTIAL"):
            if r.get("documented_manual_exception") or r.get("manual_exception_documented"):
                continue
            if not _finding_touches_ksi(kid):
                raise Fedramp20xPackageValidationError(
                    f"KSI {kid!r} is {st} but no finding links to it and no documented_manual_exception on the KSI row."
                )

    poam_by_fid = {str(p.get("finding_id")): p for p in poam_items if p.get("finding_id")}

    def _finding_needs_poam_row(f: dict[str, Any]) -> bool:
        st = str(f.get("status") or "").lower()
        if st in ("risk_accepted", "closed", "false_positive"):
            return False
        ra = f.get("risk_acceptance")
        if isinstance(ra, dict) and ra.get("accepted_by"):
            return False
        return True

    for f in findings:
        if not _finding_needs_poam_row(f):
            continue
        fid = str(f.get("finding_id") or "")
        if f.get("poam_id"):
            continue
        if fid and fid in poam_by_fid:
            continue
        raise Fedramp20xPackageValidationError(
            f"Open finding {fid!r} requires a POA&M row (poam_id on finding or matching poam_items.finding_id)."
        )


def _automation_percentage(catalog_doc: KsiCatalog) -> tuple[int, int, float]:
    total = len(catalog_doc.catalog)
    auto = sum(1 for k in catalog_doc.catalog if k.automation_target)
    pct = round(100.0 * auto / total, 2) if total else 0.0
    return auto, total, pct


def _summary_counts(
    ksi_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    poam_items: list[dict[str, Any]],
    catalog_doc: KsiCatalog,
    evidence_registry: EvidenceRegistry | None = None,
) -> dict[str, Any]:
    total = len(catalog_doc.catalog)
    cat_auto, _, cat_pct = _automation_percentage(catalog_doc)
    if evidence_registry is not None:
        mat = compute_package_evidence_maturity_summary(catalog_doc, evidence_registry, ksi_results)
        auto_n = int(mat["automated_ksis"])
        pct = float(mat["automation_percentage"])
        maturity_extras = {
            "evidence_maturity_automation_percentage": pct,
            "ksi_validation_mode_counts": dict(mat["ksi_validation_mode_counts"]),
            "ksi_manual_mode_count": int(mat["ksi_manual_mode_count"]),
            "ksi_hybrid_mode_count": int(mat["ksi_hybrid_mode_count"]),
            "ksi_automated_mode_count": int(mat["ksi_automated_mode_count"]),
            "ksis_missing_required_evidence": int(mat["ksis_missing_required_evidence"]),
            "ksis_manual_or_file_primary_evidence": int(mat["ksis_manual_or_file_primary_evidence"]),
        }
    else:
        auto_n, pct = cat_auto, cat_pct
        maturity_extras = {}
    passed = failed = partial = na = 0
    for r in ksi_results:
        st = str(r.get("status") or "").upper()
        if st == "PASS":
            passed += 1
        elif st == "FAIL":
            failed += 1
        elif st == "PARTIAL":
            partial += 1
        elif st in ("NOT_APPLICABLE", "N/A"):
            na += 1
        elif st == "OPEN":
            partial += 1
        else:
            na += 1
    open_poam = sum(1 for p in poam_items if str(p.get("status", "")).lower() in ("open", "active", ""))
    crit = sum(
        1
        for f in findings
        if str(f.get("severity", "")).lower() == "critical"
        and str(f.get("status", "open")).lower() == "open"
    )
    high = sum(
        1
        for f in findings
        if str(f.get("severity", "")).lower() == "high"
        and str(f.get("status", "open")).lower() == "open"
    )
    manual_hybrid = sum(1 for k in catalog_doc.catalog if k.validation_mode in ("manual", "hybrid"))
    out = {
        "total_ksis": total,
        "ksis_addressed": sum(1 for r in ksi_results if str(r.get("status") or "").upper() != "NOT_APPLICABLE"),
        "automated_ksis": auto_n,
        "manual_or_hybrid_ksis": manual_hybrid,
        "automation_percentage": pct,
        "catalog_automation_target_ksis": cat_auto,
        "catalog_automation_percentage": cat_pct,
        "passed": passed,
        "failed": failed,
        "partial": partial,
        "not_applicable": na,
        "open_poam_items": open_poam,
        "critical_open_findings": crit,
        "high_open_findings": high,
    }
    out.update(maturity_extras)
    return out


def build_fedramp20x_package(
    *,
    package_output: Path,
    system_boundary_path: Path,
    authorization_scope_path: Path,
    ksi_catalog_path: Path,
    ksi_results_path: Path,
    findings_path: Path,
    poam_items_path: Path,
    evidence_graph_path: Path,
    eval_results_path: Path,
    evidence_registry_path: Path,
    report_paths: dict[str, Path | None] | None = None,
    package_id: str | None = None,
    package_version: str = "1.0.0",
    schema_name: str = "fedramp-20x-evidence-package",
    schema_version: str = "1.0",
    schema_uri: str = "https://observable-security-agent.local/schemas/fedramp20x-top-package.schema.json",
    fail_on_validation: bool = True,
) -> dict[str, Any]:
    """
    Assemble a top-level FedRAMP 20x evidence package layout under ``package_output``:

    - ``fedramp20x-package.json`` / ``fedramp20x-package.yaml``
    - ``manifest.json``
    - ``checksums.sha256``
    - ``artifacts/`` copies of inputs
    - ``reports/`` copies of human-readable reports when paths are provided

    Raises :class:`Fedramp20xPackageValidationError` when ``fail_on_validation`` and business rules fail.
    """
    package_output = package_output.resolve()
    system_boundary = normalize_system_boundary(_load_yaml(system_boundary_path))
    _validate_config_schema("system-boundary", system_boundary, _CONFIG_SCHEMA_DIR)
    auth_scope = normalize_authorization_scope(_load_yaml(authorization_scope_path))
    _validate_config_schema("authorization-scope", auth_scope, _CONFIG_SCHEMA_DIR)
    catalog_doc = load_ksi_catalog(ksi_catalog_path)

    ksi_results = _load_json_collection(ksi_results_path, ("ksi_results", "ksi_validation_results", "results"))
    findings = _load_json_collection(findings_path, ("findings", "results"))
    poam_items = _load_json_collection(poam_items_path, ("poam_items", "items"))
    graph = _read_json(evidence_graph_path) if evidence_graph_path.is_file() else {}
    eval_doc = _read_json(eval_results_path)
    evidence_reg = load_evidence_source_registry(evidence_registry_path)

    ksi_results = _merge_ksi_results_with_catalog(catalog_doc, ksi_results)

    if fail_on_validation:
        _validate_top_level_package_rules(
            catalog_doc=catalog_doc,
            ksi_results=ksi_results,
            findings=findings,
            poam_items=poam_items,
        )

    generated_at = datetime.now(timezone.utc).isoformat()
    pkg_id = package_id or f"PKG-{system_boundary.get('system_id', 'SYSTEM')}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"

    rp = report_paths or {}
    assessor_src = rp.get("assessor_report")
    executive_src = rp.get("executive_report")
    ao_src = rp.get("ao_report")
    recon_src = rp.get("reconciliation_report")

    package_output.mkdir(parents=True, exist_ok=True)
    art = package_output / "artifacts"
    art.mkdir(parents=True, exist_ok=True)
    _copy_file(ksi_results_path, art / "ksi_results.json")
    _copy_file(findings_path, art / "findings.json")
    _copy_file(poam_items_path, art / "poam-items.json")
    if evidence_graph_path.is_file():
        _copy_file(evidence_graph_path, art / "evidence_graph.json")
    else:
        (art / "evidence_graph.json").write_text("{}", encoding="utf-8")
    _copy_file(eval_results_path, art / "eval_results.json")
    _copy_file(evidence_registry_path, art / "evidence-source-registry.yaml")

    reports_dir = package_output / "reports"
    human_manifest: list[dict[str, str]] = []
    report_rel: dict[str, str | None] = {
        "assessor_report": None,
        "executive_report": None,
        "ao_report": None,
        "reconciliation_md": None,
    }
    if assessor_src and assessor_src.is_file():
        dest = reports_dir / "assessor" / assessor_src.name
        _copy_file(assessor_src, dest)
        rel = str(dest.relative_to(package_output))
        human_manifest.append({"path": rel, "role": "assessor"})
        report_rel["assessor_report"] = rel
    if executive_src and executive_src.is_file():
        dest = reports_dir / "executive" / executive_src.name
        _copy_file(executive_src, dest)
        rel = str(dest.relative_to(package_output))
        human_manifest.append({"path": rel, "role": "executive"})
        report_rel["executive_report"] = rel
    if ao_src and ao_src.is_file():
        dest = reports_dir / "agency-ao" / ao_src.name
        _copy_file(ao_src, dest)
        rel = str(dest.relative_to(package_output))
        human_manifest.append({"path": rel, "role": "agency_ao"})
        report_rel["ao_report"] = rel
    if recon_src and recon_src.is_file():
        dest = reports_dir / "reconciliation" / recon_src.name
        dest.parent.mkdir(parents=True, exist_ok=True)
        _copy_file(recon_src, dest)
        rel = str(dest.relative_to(package_output))
        human_manifest.append({"path": rel, "role": "reconciliation"})
        report_rel["reconciliation_md"] = rel

    evidence_links = _evidence_links_from_graph(graph)
    rec_pkg = {
        "findings": findings,
        "poam_items": poam_items,
        "ksi_validation_results": ksi_results,
    }
    body_for_hash = json.dumps(rec_pkg, sort_keys=True, default=str).encode("utf-8")
    rec = build_reconciliation_summary(
        package=rec_pkg,
        human_report_paths=human_manifest,
        include_sha256=True,
        package_sha256=hashlib.sha256(body_for_hash).hexdigest(),
    )

    mr_dir = package_output / "reports" / "machine-readable"
    mr_dir.mkdir(parents=True, exist_ok=True)
    (mr_dir / "evidence_links.json").write_text(json.dumps({"evidence_links": evidence_links}, indent=2), encoding="utf-8")
    (mr_dir / "reconciliation.json").write_text(json.dumps(rec, indent=2), encoding="utf-8")

    summary = _summary_counts(ksi_results, findings, poam_items, catalog_doc, evidence_reg)

    doc: dict[str, Any] = {
        "package_id": pkg_id,
        "package_version": package_version,
        "generated_at": generated_at,
        "system": {
            "id": str(system_boundary.get("system_id") or ""),
            "name": str(system_boundary.get("short_name") or system_boundary.get("system_id") or ""),
            "impact_level": str(auth_scope.get("impact_level") or "moderate"),
            "authorization_path": str(
                system_boundary.get("authorization_path") or auth_scope.get("authorization_path") or "FedRAMP"
            ),
            "cloud_provider": str(system_boundary.get("cloud_provider") or auth_scope.get("cloud_provider") or "multi-cloud"),
            "regions": system_boundary.get("regions") or auth_scope.get("regions") or [],
        },
        "scope": {
            "included_components": auth_scope.get("in_scope_services") or [],
            "excluded_components": auth_scope.get("out_of_scope") or [],
            "minimum_assessment_scope_applied": bool(auth_scope.get("minimum_assessment_scope_applied", True)),
        },
        "summary": summary,
        "schema": {"name": schema_name, "version": schema_version, "uri": schema_uri},
        "artifacts": {
            "ksi_results": "artifacts/ksi_results.json",
            "findings": "artifacts/findings.json",
            "poam_items": "artifacts/poam-items.json",
            "evidence_links": "reports/machine-readable/evidence_links.json",
            "reconciliation": "reports/machine-readable/reconciliation.json",
            "assessor_report": report_rel["assessor_report"],
            "executive_report": report_rel["executive_report"],
            "ao_report": report_rel["ao_report"],
            "reconciliation_report": report_rel["reconciliation_md"],
        },
        "integrity": {
            "checksums_file": "checksums.sha256",
            "signed": False,
            "signature_file": None,
        },
        "embedded": {
            "evidence_source_registry": evidence_registry_to_package_dict(evidence_reg),
            "eval_correlation_id": eval_doc.get("correlation_id"),
        },
    }

    json_path = package_output / "fedramp20x-package.json"
    yaml_path = package_output / "fedramp20x-package.yaml"
    json_path.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    yaml_path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")

    hashed_files = _iter_package_files(package_output, exclude_names={"checksums.sha256", "manifest.json"})
    _write_checksums_file(package_output, hashed_files)
    chk_path = package_output / "checksums.sha256"
    manifest_files = [
        {"path": p.relative_to(package_output).as_posix(), "sha256": _sha256_file(p)} for p in hashed_files
    ]
    manifest_files.append({"path": "checksums.sha256", "sha256": _sha256_file(chk_path)})
    manifest = {
        "schema_version": "1.0",
        "package_id": pkg_id,
        "package_version": package_version,
        "generated_at": generated_at,
        "files": manifest_files,
    }
    (package_output / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    for rel in (
        doc["artifacts"].get("ksi_results"),
        doc["artifacts"].get("findings"),
        doc["artifacts"].get("poam_items"),
        doc["artifacts"].get("evidence_links"),
        doc["artifacts"].get("reconciliation"),
    ):
        if rel:
            p = package_output / rel
            if not p.is_file():
                raise FileNotFoundError(f"Expected artifact missing: {p}")

    return doc
