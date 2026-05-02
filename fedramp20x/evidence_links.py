"""Tracked evidence links (artifact metadata + SHA-256) and checksum manifests."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from collections.abc import Iterable, Mapping, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from fedramp20x.evidence_registry import EvidenceRegistry

ArtifactType = Literal["raw", "normalized", "validation", "report", "package"]


class EvidenceLink(BaseModel):
    """Machine-tracked evidence artifact with integrity metadata."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    evidence_id: str = Field(..., min_length=1)
    source_id: str = Field(..., min_length=1)
    artifact_path: str = Field(..., min_length=1)
    artifact_type: ArtifactType
    collected_at: str = Field(..., min_length=1)
    checksum_sha256: str = Field(..., min_length=64, max_length=64)
    record_locator: str | None = None
    authoritative_for: list[str] = Field(default_factory=list)
    linked_ksi_ids: list[str] = Field(default_factory=list)
    linked_finding_ids: list[str] = Field(default_factory=list)


class EvidenceGap(BaseModel):
    """Expected evidence that is absent (not an :class:`EvidenceLink`)."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    gap_id: str = Field(..., min_length=1)
    logical_path: str = Field(..., min_length=1)
    reason: str = Field(..., min_length=1)
    severity: Literal["warning", "error"] = "warning"


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def _default_source_id(registry: EvidenceRegistry | None) -> str:
    if registry and registry.sources:
        return registry.sources[0].id
    return "assessment"


def _classify_artifact_type(logical_path: str) -> ArtifactType:
    lp = logical_path.replace("\\", "/").lower()
    if lp.startswith("raw/"):
        return "raw"
    if "/normalized/" in f"/{lp}/" or lp.startswith("normalized/"):
        return "normalized"
    if "/validation-results/" in f"/{lp}/" or lp.startswith("validation-results/"):
        return "validation"
    if "/reports/" in f"/{lp}/" or lp.startswith("reports/"):
        return "report"
    return "package"


def _iter_report_files(package_output: Path) -> list[Path]:
    rdir = package_output / "reports"
    if not rdir.is_dir():
        return []
    return sorted(p for p in rdir.rglob("*") if p.is_file())


def _logical_under_root(abs_path: Path, root: Path) -> str | None:
    try:
        return abs_path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return None


def canonical_fedramp_package_logical(pkg_path: Path, evidence_root: Path) -> str:
    """Stable logical path for the primary ``fedramp20x-package.json`` artifact."""
    rel = _logical_under_root(pkg_path, evidence_root)
    if rel and rel.startswith("evidence/"):
        return rel
    if rel == "fedramp20x-package.json":
        return "evidence/package/fedramp20x-package.json"
    if rel:
        return f"evidence/package/{Path(rel).name}"
    return "evidence/package/fedramp20x-package.json"


def collect_artifact_file_specs(
    *,
    evidence_root: Path,
    assessment_output: Path,
    package_output: Path,
    graph_path: Path,
) -> list[tuple[Path, str]]:
    """
    Return ``(absolute_path, logical_posix_path)`` for every on-disk artifact to track.

    Logical paths are rooted at ``evidence_root`` where possible; assessment inputs use ``raw/``.
    """
    er = evidence_root.resolve()
    po = package_output.resolve()
    ao = assessment_output.resolve()
    specs: list[tuple[Path, str]] = []

    for name in ("eval_results.json", "assessment_summary.json"):
        p = ao / name
        if p.is_file():
            specs.append((p, f"raw/{name}"))

    gp = graph_path if graph_path.is_file() else ao / "evidence_graph.json"
    if gp.is_file():
        specs.append((gp.resolve(), "raw/evidence_graph.json"))

    poam = ao / "poam.csv"
    if poam.is_file():
        specs.append((poam, "raw/poam.csv"))

    pkg_json = po / "fedramp20x-package.json"
    if pkg_json.is_file():
        specs.append((pkg_json, canonical_fedramp_package_logical(pkg_json, er)))

    vr = po / "evidence" / "validation-results"
    if vr.is_dir():
        for p in sorted(vr.glob("*.json")):
            lp = _logical_under_root(p, er)
            if lp:
                specs.append((p, lp))
            else:
                specs.append((p, f"evidence/validation-results/{p.name}"))

    mr = po / "reports" / "machine-readable"
    if mr.is_dir():
        for p in sorted(mr.glob("*")):
            if p.is_file():
                lp = _logical_under_root(p, er)
                specs.append((p, lp or f"evidence/package/reports/machine-readable/{p.name}"))

    for p in _iter_report_files(po):
        lp = _logical_under_root(p, er)
        specs.append((p, lp or f"evidence/package/reports/{p.relative_to(po / 'reports').as_posix()}"))

    rec = er / "evidence" / "validation-results" / "reconciliation.json"
    if rec.is_file():
        specs.append((rec, "evidence/validation-results/reconciliation.json"))

    # de-dupe by absolute path
    seen: set[str] = set()
    out: list[tuple[Path, str]] = []
    for abs_p, logical in specs:
        key = str(abs_p.resolve())
        if key in seen:
            continue
        seen.add(key)
        out.append((abs_p, logical))
    return out


def _slug(s: str) -> str:
    x = re.sub(r"[^A-Za-z0-9]+", "-", s).strip("-").upper()
    return x or "X"


def stable_evidence_id(logical_path: str) -> str:
    """Deterministic id from logical path (stable before/after content updates)."""
    return "EV-" + hashlib.sha256(logical_path.encode("utf-8")).hexdigest()[:20].upper()


def build_evidence_links(
    *,
    file_specs: Sequence[tuple[Path, str]],
    evidence_registry: EvidenceRegistry | None,
    ksi_results: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    collected_at: str | None = None,
) -> list[EvidenceLink]:
    """Build :class:`EvidenceLink` rows for existing files (one row per file)."""
    ts = collected_at or datetime.now(timezone.utc).isoformat()
    src = _default_source_id(evidence_registry)
    ksi_ids = sorted({str(r.get("ksi_id")) for r in ksi_results if r.get("ksi_id")})
    finding_by_eval: dict[str, list[str]] = {}
    for f in findings:
        fid = str(f.get("finding_id") or "")
        if not fid:
            continue
        for eid in f.get("linked_eval_ids") or []:
            finding_by_eval.setdefault(str(eid), []).append(fid)

    links: list[EvidenceLink] = []
    for abs_p, logical in file_specs:
        if not abs_p.is_file():
            continue
        digest = sha256_file(abs_p)
        at = _classify_artifact_type(logical)
        eid = stable_evidence_id(logical)
        lf: list[str] = []
        if logical.endswith("eval_results.json") or logical == "raw/eval_results.json":
            for ev_id, fids in finding_by_eval.items():
                lf.extend(fids)
            lf = sorted(set(lf))
        record_loc = None
        if logical.endswith("eval_results.json") or logical == "raw/eval_results.json":
            record_loc = "eval_results.json#/evaluations"
        links.append(
            EvidenceLink(
                evidence_id=eid,
                source_id=src,
                artifact_path=logical,
                artifact_type=at,
                collected_at=ts,
                checksum_sha256=digest,
                record_locator=record_loc,
                authoritative_for=[],
                linked_ksi_ids=list(ksi_ids) if logical.endswith("eval_results.json") or logical == "raw/eval_results.json" else [],
                linked_finding_ids=lf,
            )
        )
    return links


def links_by_logical_path(links: Sequence[EvidenceLink]) -> dict[str, EvidenceLink]:
    out: dict[str, EvidenceLink] = {}
    for l in links:
        out.setdefault(l.artifact_path, l)
    return out


def links_by_id(links: Sequence[EvidenceLink]) -> dict[str, EvidenceLink]:
    return {l.evidence_id: l for l in links}


def build_required_artifact_gaps(
    *,
    evidence_root: Path,
    assessment_output: Path,
    required_raw: Sequence[str] | None,
) -> list[EvidenceGap]:
    """Emit gaps for configured required paths that are missing from disk."""
    gaps: list[EvidenceGap] = []
    req = list(required_raw or ())
    for i, rel in enumerate(req):
        rel = rel.strip().replace("\\", "/")
        if not rel:
            continue
        if rel.startswith("raw/"):
            name = rel.split("/", 1)[1]
            path = assessment_output / name
        else:
            path = evidence_root / rel
        if path.is_file():
            continue
        gaps.append(
            EvidenceGap(
                gap_id=f"GAP-{_slug(rel)}-{i:03d}",
                logical_path=rel,
                reason=f"Required evidence artifact not found: {path}",
                severity="error",
            )
        )
    return gaps


def render_checksums_sha256(file_specs: Sequence[tuple[Path, str]]) -> str:
    """OpenSSL-style ``hex  path`` lines (path is logical); skips missing files."""
    lines: list[str] = []
    for abs_p, logical in sorted(file_specs, key=lambda x: x[1]):
        if not abs_p.is_file():
            continue
        h = sha256_file(abs_p)
        lines.append(f"{h}  {logical}")
    return "\n".join(lines) + ("\n" if lines else "")


def attach_evidence_refs_to_ksi_results(
    ksi_results: list[dict[str, Any]],
    *,
    eval_results_logical_path: str | None,
) -> None:
    """Replace ``evidence_refs`` with ``evidence_id`` pointers (stable id from logical path)."""
    if not eval_results_logical_path:
        return
    eid = stable_evidence_id(eval_results_logical_path)
    for row in ksi_results:
        row["evidence_refs"] = [
            {
                "evidence_id": eid,
                "role": "primary",
                "json_pointer": "#/evaluations",
                "artifact": "eval_results.json",
            }
        ]


def attach_evidence_refs_to_findings(
    findings: list[dict[str, Any]],
    *,
    eval_results_logical_path: str | None,
    package_logical_path: str | None,
) -> None:
    """Add ``evidence_refs`` with evidence ids and record locators."""
    er_id = stable_evidence_id(eval_results_logical_path) if eval_results_logical_path else None
    pkg_id = stable_evidence_id(package_logical_path) if package_logical_path else None
    for f in findings:
        refs: list[dict[str, Any]] = []
        src = str(f.get("source") or "")
        if src == "eval_result" and er_id:
            for eid in f.get("linked_eval_ids") or []:
                refs.append(
                    {
                        "evidence_id": er_id,
                        "role": "primary",
                        "record_locator": f"eval_results.json#/evaluations/{eid}",
                    }
                )
        elif src == "ksi_validation" and pkg_id:
            kid = ""
            ks = f.get("linked_ksi_ids") or f.get("ksi_ids") or []
            if isinstance(ks, list) and ks:
                kid = str(ks[0])
            loc = "fedramp20x-package.json#/ksi_validation_results"
            if kid:
                loc = f"{loc}/{kid}"
            refs.append({"evidence_id": pkg_id, "role": "rollup", "record_locator": loc})
        if refs:
            f["evidence_refs"] = refs


def validate_evidence_refs_resolve(
    *,
    ksi_results: Sequence[Mapping[str, Any]],
    findings: Sequence[Mapping[str, Any]],
    links: Sequence[EvidenceLink],
) -> list[str]:
    """Return errors when ``evidence_id`` values do not match a link row."""
    by_id = links_by_id(links)
    errs: list[str] = []
    for r in ksi_results:
        kid = str(r.get("ksi_id") or "")
        for ref in r.get("evidence_refs") or []:
            if not isinstance(ref, dict):
                continue
            eid = str(ref.get("evidence_id") or "")
            if not eid:
                continue
            if eid not in by_id:
                errs.append(f"KSI {kid}: evidence_ref evidence_id {eid!r} not found in evidence-links inventory")
    for f in findings:
        fid = str(f.get("finding_id") or "")
        for ref in f.get("evidence_refs") or []:
            if not isinstance(ref, dict):
                continue
            eid = str(ref.get("evidence_id") or "")
            if not eid:
                continue
            if eid not in by_id:
                errs.append(f"Finding {fid}: evidence_ref evidence_id {eid!r} not found in evidence-links inventory")
    return errs


def validate_evidence_inventory(
    *,
    gaps: Sequence[EvidenceGap],
    ref_errors: Sequence[str],
    strict: bool,
) -> tuple[list[str], list[str]]:
    """Return ``(warnings, errors)``."""
    warnings: list[str] = []
    errors = list(ref_errors)
    for g in gaps:
        if strict or g.severity == "error":
            errors.append(g.reason)
        else:
            warnings.append(g.reason)
    return warnings, errors


def enrich_package_nested_evidence_links(
    package: dict[str, Any], tracked_by_logical: Mapping[str, EvidenceLink]
) -> None:
    """Attach ``artifact_sha256`` (and optional ``record_locator``) to graph-originated ``evidence_links`` rows."""
    uri_map = {
        "evidence_graph.json": "raw/evidence_graph.json",
        "eval_results.json": "raw/eval_results.json",
    }
    for link in package.get("evidence_links") or []:
        if not isinstance(link, dict):
            continue
        uri = str(link.get("artifact_uri") or "").strip()
        logical = uri_map.get(uri)
        if not logical:
            continue
        row = tracked_by_logical.get(logical)
        if row:
            link["artifact_sha256"] = row.checksum_sha256
            if row.record_locator:
                link["record_locator"] = row.record_locator


def write_evidence_links_bundle(
    *,
    evidence_root: Path,
    links: Sequence[EvidenceLink],
    gaps: Sequence[EvidenceGap],
) -> Path:
    """Write ``evidence/validation-results/evidence-links.json`` under ``evidence_root``."""
    out = evidence_root / "evidence" / "validation-results" / "evidence-links.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    doc = {
        "schema_version": "1.0",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "evidence_links": [l.model_dump(mode="json") for l in links],
        "evidence_gaps": [g.model_dump(mode="json") for g in gaps],
    }
    out.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")
    return out


def write_package_checksums(
    *,
    evidence_root: Path,
    file_specs: Sequence[tuple[Path, str]],
    evidence_links_path: Path | None = None,
) -> Path:
    """
    Write ``evidence/package/checksums.sha256`` under ``evidence_root``.

    Includes ``evidence-links.json`` when present (hashed after write).
    """
    pkg_dir = evidence_root / "evidence" / "package"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    specs = list(file_specs)
    if evidence_links_path and evidence_links_path.is_file():
        try:
            logical = evidence_links_path.resolve().relative_to(evidence_root.resolve()).as_posix()
        except ValueError:
            logical = "evidence/validation-results/evidence-links.json"
        specs.append((evidence_links_path.resolve(), logical))
    text = render_checksums_sha256(specs)
    dest = pkg_dir / "checksums.sha256"
    dest.write_text(text, encoding="utf-8")
    return dest


def prepare_stable_evidence_ref_attachments(
    *,
    evidence_root: Path,
    assessment_output: Path,
    pkg_path: Path,
    package: dict[str, Any],
    ksi_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> None:
    """Mutate KSI rows, findings, and in-memory ``package`` to use stable ``evidence_id`` refs (before reports)."""
    eval_lp: str | None = "raw/eval_results.json" if (assessment_output / "eval_results.json").is_file() else None
    pkg_lp: str | None = None
    if pkg_path.is_file():
        pkg_lp = canonical_fedramp_package_logical(pkg_path, evidence_root)
    attach_evidence_refs_to_ksi_results(ksi_results, eval_results_logical_path=eval_lp)
    attach_evidence_refs_to_findings(
        findings, eval_results_logical_path=eval_lp, package_logical_path=pkg_lp
    )
    package["ksi_validation_results"] = ksi_results
    package["findings"] = findings


def finalize_evidence_link_tracking(
    *,
    evidence_root: Path,
    assessment_output: Path,
    package_output: Path,
    graph_path: Path,
    pkg_path: Path,
    package: dict[str, Any],
    ksi_results: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    evidence_registry: EvidenceRegistry | None,
    validation_policy: Mapping[str, Any] | None = None,
    mirror_roots: Iterable[Path] | None = None,
) -> tuple[list[str], list[str]]:
    """
    After all human-readable reports exist: build evidence link inventory, checksum manifest,
    and rewrite machine-readable JSON under the package tree.

    Returns ``(warnings, errors)`` from :func:`validate_evidence_inventory`.
    """
    policy = dict(validation_policy or {})
    ea = policy.get("evidence_artifacts") if isinstance(policy.get("evidence_artifacts"), dict) else {}
    required_raw = ea.get("required_raw_paths") if isinstance(ea.get("required_raw_paths"), list) else []

    gaps = build_required_artifact_gaps(
        evidence_root=evidence_root, assessment_output=assessment_output, required_raw=required_raw
    )

    package["ksi_validation_results"] = ksi_results
    package["findings"] = findings
    pkg_path.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")

    file_specs = collect_artifact_file_specs(
        evidence_root=evidence_root,
        assessment_output=assessment_output,
        package_output=package_output,
        graph_path=graph_path,
    )
    links = build_evidence_links(
        file_specs=file_specs,
        evidence_registry=evidence_registry,
        ksi_results=ksi_results,
        findings=findings,
    )

    el_path = write_evidence_links_bundle(evidence_root=evidence_root, links=links, gaps=gaps)

    ck_path = write_package_checksums(
        evidence_root=evidence_root, file_specs=file_specs, evidence_links_path=el_path
    )

    vr = package_output / "evidence" / "validation-results"
    vr.mkdir(parents=True, exist_ok=True)
    (vr / "ksi-results.json").write_text(
        json.dumps({"ksi_validation_results": ksi_results}, indent=2, default=str), encoding="utf-8"
    )
    (vr / "findings.json").write_text(json.dumps({"findings": findings}, indent=2, default=str), encoding="utf-8")

    mr = package_output / "reports" / "machine-readable" / "fedramp20x-package.json"

    ref_errs = validate_evidence_refs_resolve(ksi_results=ksi_results, findings=findings, links=links)
    strict = bool(policy.get("strict_evidence_links"))
    warnings, errors = validate_evidence_inventory(gaps=gaps, ref_errors=ref_errs, strict=strict)

    tracked = links_by_logical_path(links)
    enrich_package_nested_evidence_links(package, tracked)
    try:
        el_rel = el_path.resolve().relative_to(evidence_root.resolve()).as_posix()
    except ValueError:
        el_rel = "evidence/validation-results/evidence-links.json"
    pm = package.setdefault("package_metadata", {})
    pm["package_integrity"] = {
        "checksums_manifest_relative_path": "evidence/package/checksums.sha256",
        "evidence_links_bundle_relative_path": el_rel,
    }
    pkg_path.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")
    if mr.parent.is_dir():
        mr.write_text(json.dumps(package, indent=2, default=str), encoding="utf-8")

    for root in mirror_roots or ():
        root = root.resolve()
        if root == evidence_root.resolve():
            continue
        dest_vr = root / "evidence" / "validation-results"
        dest_vr.mkdir(parents=True, exist_ok=True)
        shutil.copy2(el_path, dest_vr / "evidence-links.json")
        ck_src = evidence_root / "evidence" / "package" / "checksums.sha256"
        if ck_src.is_file():
            dest_pkg = root / "evidence" / "package"
            dest_pkg.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ck_src, dest_pkg / "checksums.sha256")

    _ = ck_path
    return warnings, errors
