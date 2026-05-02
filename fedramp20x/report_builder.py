"""Human-facing reports derived from the same package snapshot as machine-readable JSON.

Report section ordering follows assessor workflow; HTML bundle patterns in the industry informed
surface-area only (no embedded third-party templates).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fedramp20x.evidence_maturity import maturity_gaps_for_package
from fedramp20x.poam_builder import write_poam_markdown

# Assessor bundle filenames (under ``reports/assessor/``).
ASSESSOR_SUMMARY = "assessor-summary.md"
KSI_BY_KSI = "ksi-by-ksi-assessment.md"
EVIDENCE_INDEX = "evidence-index.md"
VALIDATION_METHODOLOGY = "validation-methodology.md"
EXCEPTIONS_MANUAL = "exceptions-and-manual-evidence.md"
POAM_MD = "poam.md"

# Executive bundle filenames (under ``reports/executive/``).
EXECUTIVE_SUMMARY = "executive-summary.md"
SECURITY_POSTURE_DASHBOARD = "security-posture-dashboard.md"
AUTHORIZATION_READINESS = "authorization-readiness.md"
MAJOR_RISKS = "major-risks.md"

# Agency / AO bundle (under ``reports/agency-ao/``).
AO_RISK_BRIEF = "ao-risk-brief.md"
AUTHORIZATION_DECISION_SUPPORT = "authorization-decision-support.md"
RESIDUAL_RISK_REGISTER = "residual-risk-register.md"
CUSTOMER_RESP_MATRIX = "customer-responsibility-matrix.md"
INHERITED_CONTROLS_SUMMARY = "inherited-controls-summary.md"

_PACKAGING_DISCLAIMER = (
    "> **Not a FedRAMP approval.** This document is part of a **FedRAMP 20x–style** evidence snapshot for engineering "
    "and assessment workflow support. It does **not** constitute a FedRAMP-approved package, 3PAO attestation, "
    "or Authorizing Official decision. Machine-readable validation uses this repository’s **FedRAMP 20x–style "
    "evidence package schema** (`schemas/fedramp20x-package.schema.json`), not an official GSA JSON schema unless "
    "you explicitly import one elsewhere.\n\n"
)


def _md_cell(s: str, max_len: int = 500) -> str:
    t = str(s or "").replace("\n", " ").replace("|", "/").strip()
    return t if len(t) <= max_len else t[: max_len - 3] + "..."


def _meta(package: dict[str, Any]) -> dict[str, Any]:
    return package.get("package_metadata") or {}


def _rec(package: dict[str, Any]) -> dict[str, Any]:
    return package.get("reconciliation_summary") or {}


def _registry_sources(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    reg = package.get("evidence_source_registry") or {}
    out: dict[str, dict[str, Any]] = {}
    for s in reg.get("sources") or []:
        if isinstance(s, dict) and s.get("id"):
            out[str(s["id"])] = s
    return out


def _catalog_by_id(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for k in package.get("ksi_catalog") or []:
        if isinstance(k, dict) and k.get("ksi_id"):
            out[str(k["ksi_id"])] = k
    return out


def _results_by_id(package: dict[str, Any]) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for r in package.get("ksi_validation_results") or []:
        if isinstance(r, dict) and r.get("ksi_id"):
            out[str(r["ksi_id"])] = r
    return out


def _findings_for_ksi(findings: list[dict[str, Any]], ksi_id: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict):
            continue
        kids = list(f.get("linked_ksi_ids") or f.get("ksi_ids") or [])
        if ksi_id in kids:
            out.append(f)
    return out


def _poam_refs_for_finding(poam_items: list[dict[str, Any]], finding_id: str) -> list[str]:
    ids: list[str] = []
    for p in poam_items:
        if not isinstance(p, dict):
            continue
        if str(p.get("finding_id") or "") == finding_id:
            pid = str(p.get("poam_id") or "").strip()
            if pid:
                ids.append(pid)
    return sorted(set(ids))


def _poam_refs_for_ksi(poam_items: list[dict[str, Any]], ksi_id: str) -> list[str]:
    ids: list[str] = []
    for p in poam_items:
        if not isinstance(p, dict):
            continue
        ks = list(p.get("source_ksi_ids") or [])
        if ksi_id in ks:
            pid = str(p.get("poam_id") or "").strip()
            if pid:
                ids.append(pid)
    return sorted(set(ids))


def _automation_line(catalog_row: dict[str, Any], reg_by_id: dict[str, dict[str, Any]]) -> str:
    target = catalog_row.get("automation_target")
    parts = [f"Catalog `automation_target`: {bool(target)}"]
    for src in catalog_row.get("evidence_sources") or []:
        sid = str(src)
        row = reg_by_id.get(sid)
        if row:
            parts.append(
                f"- `{sid}`: registry `automation_score`={row.get('automation_score', '')}, "
                f"`collection_method`={row.get('collection_method', '')}"
            )
        else:
            parts.append(f"- `{sid}`: no matching entry in `evidence_source_registry` for this package (missing).")
    return "\n".join(parts)


def _assessor_conclusion(status: str, findings_n: int, has_manual_exception: bool) -> str:
    st = str(status or "").upper()
    if has_manual_exception:
        return (
            "A documented manual exception is recorded on the KSI validation row. "
            "Assessor conclusion: verify the exception record outside this generator."
        )
    if st == "PASS":
        return (
            "KSI rollup status is PASS in this package snapshot. "
            "Conclusion is limited to the evaluations and artifacts referenced in machine-readable fields."
        )
    if st in ("FAIL", "PARTIAL", "OPEN"):
        return (
            f"KSI rollup status is {st}. Conclusion: treat as open work until linked findings "
            "and POA&M disposition are closed or formally risk-accepted per program policy."
        )
    if st in ("NOT_APPLICABLE", "N/A"):
        return "Marked not applicable for this assessment run; no PASS/FAIL assertion is implied for out-of-scope areas."
    return f"Status `{st}`; no additional conclusion is asserted beyond stored machine-readable fields."


def _evidence_index_md(package: dict[str, Any]) -> str:
    meta = _meta(package)
    rec = _rec(package)
    lines = [
        "# Evidence index",
        "",
        "This index lists traceable artifacts referenced in the package snapshot. "
        "Checksums are included only when present in `reconciliation_summary`.",
        "",
        "| Artifact | Path / URI | Checksum or digest |",
        "| --- | --- | --- |",
    ]
    pkg_sha = rec.get("package_sha256")
    if pkg_sha:
        lines.append(f"| Machine-readable package (body hash) | `fedramp20x-package.json` | `{pkg_sha}` |")
    else:
        lines.append("| Machine-readable package | `fedramp20x-package.json` | Not recorded in this package. |")

    aou = meta.get("assessment_output_uri")
    if aou:
        lines.append(f"| Assessment output directory | `{_md_cell(aou, 200)}` | Not computed here. |")
    else:
        lines.append("| Assessment output directory | *missing in package metadata* | — |")

    seen: set[str] = set()
    for link in package.get("evidence_links") or []:
        if not isinstance(link, dict):
            continue
        uri = str(link.get("artifact_uri") or "").strip()
        if not uri or uri in seen:
            continue
        seen.add(uri)
        lines.append(f"| Evidence graph / link target | `{_md_cell(uri, 120)}` | Not recorded per link in package. |")

    lines.extend(["", "## Human-readable reports (manifest)", ""])
    for m in rec.get("human_report_manifest") or []:
        if isinstance(m, dict) and m.get("path"):
            lines.append(f"- `{m.get('path')}` — role `{m.get('role', '')}`")
    if not rec.get("human_report_manifest"):
        lines.append("- *No human report manifest entries in reconciliation snapshot.*")

    lines.extend(
        [
            "",
            "## Limitations",
            "",
            "- Per-file SHA-256 for every on-disk artifact is not part of the nested package JSON; "
            "use the package body digest when provided, or external integrity controls.",
            "- This index does not assert completeness of the assessment output directory.",
            "",
        ]
    )
    return "\n".join(lines)


def _validation_methodology_md(package: dict[str, Any]) -> str:
    snap = package.get("assessment_correlation_snapshot") or {}
    lines = [
        "# Validation methodology",
        "",
        "**Audience:** 3PAO, FedRAMP reviewer, technical assessor.",
        "",
        "## Scope of this document",
        "",
        "This section describes how evidence was transformed into the machine-readable package. "
        "It does not add facts beyond what the package records.",
        "",
        "## Evaluation rollup",
        "",
        "- Evaluations from the assessment run are mapped to NIST Rev.5 controls via configured crosswalks, "
        "then to KSI identifiers via `rev5_to_20x_ksi`.",
        "- KSI status is rolled up from linked evaluation outcomes using the precedence order in "
        "`validation-policy.yaml` at assessment time (not embedded verbatim in this human report).",
        "- Where no evaluation maps to a catalog KSI for this run, the KSI may appear as NOT_APPLICABLE "
        "in the machine-readable results.",
        "",
        "## Correlation snapshot (from package)",
        "",
        "```json",
        json.dumps(snap, indent=2, default=str)[:8000],
        "```",
        "",
        "## What this methodology does not do",
        "",
        "- It does not perform live API re-validation.",
        "- It does not infer control effectiveness beyond recorded evaluation results and linked artifacts.",
        "",
    ]
    return "\n".join(lines)


def _exceptions_manual_md(package: dict[str, Any]) -> str:
    lines = [
        "# Exceptions and manual evidence",
        "",
        "Items below are derived only from machine-readable fields. If a section is empty, "
        "nothing was recorded in the package for that category.",
        "",
        "## Definitions (missing evidence vs. manual evidence)",
        "",
        "- **Missing required evidence:** A criterion lists `evidence_required` ids that are **not** present in "
        "`evidence_source_registry` (or cannot be scored). Treat as an **implementation gap** (registry/catalog fix), "
        "not as “we chose manual this quarter.”",
        "- **Manual or file-primary evidence path:** Required ids **are** registered; the KSI uses manual/hybrid "
        "catalog mode and/or evidence sources scored ≤2 (narrative, PDF, screenshots). That is an **expected** "
        "assessor attestation workflow — **not** the same label as missing evidence.",
        "",
    ]
    snap = package.get("assessment_correlation_snapshot") or {}
    mat = snap.get("evidence_maturity_summary") or {}
    if mat:
        lines.extend(
            [
                "## Package evidence posture summary",
                "",
                f"- **Evidence maturity automation %** (catalog KSIs with automation score ≥ 4): **{mat.get('automation_percentage')}%**.",
                f"- **Automated-maturity KSI count:** {mat.get('automated_ksis')}.",
                f"- **Catalog `validation_mode` — manual / hybrid / automated:** "
                f"{mat.get('ksi_manual_mode_count')} / {mat.get('ksi_hybrid_mode_count')} / {mat.get('ksi_automated_mode_count')}.",
                f"- **KSIs with missing required evidence (registry gap):** {mat.get('ksis_missing_required_evidence')}.",
                f"- **KSIs on manual/file-primary path (sources registered; not missing):** "
                f"{mat.get('ksis_manual_or_file_primary_evidence')}.",
                "",
            ]
        )
        mids = mat.get("ksi_ids_missing_required_evidence") or []
        if mids:
            lines.extend(["### KSI ids with missing required evidence", ""])
            for x in mids:
                lines.append(f"- `{x}`")
            lines.append("")
        mpids = mat.get("ksi_ids_manual_or_file_primary_evidence") or []
        if mpids:
            lines.extend(
                [
                    "### KSI ids on manual/file-primary evidence path (attestation planning)",
                    "",
                ]
            )
            for x in mpids:
                lines.append(f"- `{x}`")
            lines.append("")
    lines.extend(
        [
            "## Evidence maturity (KSI automation score below 4)",
            "",
            "Automation scores combine evidence source maturity (0–5), required evidence coverage, "
            "``validation_mode``, and whether pass/fail criteria are evaluated for the KSI.",
            "",
        ]
    )
    gaps = maturity_gaps_for_package(package)
    if not gaps:
        lines.append("- *No KSIs below score 4 in this snapshot.*")
    else:
        for kid, sc, hint in sorted(gaps, key=lambda x: x[0]):
            lines.append(f"- **`{kid}`** — score **{sc}** — {hint}")
    lines.extend(
        [
            "",
            "## Documented manual exceptions (KSI rows)",
            "",
        ]
    )
    any_exc = False
    for r in package.get("ksi_validation_results") or []:
        if not isinstance(r, dict):
            continue
        if r.get("documented_manual_exception") or r.get("manual_exception_documented"):
            any_exc = True
            lines.append(f"- **`{r.get('ksi_id')}`:** exception flag present on validation row.")
    if not any_exc:
        lines.append("- *None recorded.*")

    lines.extend(["", "## Manual or hybrid validation modes (catalog)", ""])
    for k in package.get("ksi_catalog") or []:
        if not isinstance(k, dict):
            continue
        mode = str(k.get("validation_mode") or "")
        if mode in ("manual", "hybrid"):
            lines.append(f"- `{k.get('ksi_id')}` — catalog `validation_mode`: **{mode}**")

    lines.extend(["", "## Criteria marked manual or hybrid", ""])
    crit_rows = 0
    for k in package.get("ksi_catalog") or []:
        if not isinstance(k, dict):
            continue
        kid = k.get("ksi_id")
        for c in k.get("pass_fail_criteria") or []:
            if not isinstance(c, dict):
                continue
            vt = str(c.get("validation_type") or "")
            if vt in ("manual", "hybrid"):
                crit_rows += 1
                lines.append(
                    f"- `{kid}` / `{c.get('criteria_id')}` — `{vt}` — {_md_cell(str(c.get('description')), 200)}"
                )
    if crit_rows == 0:
        lines.append("- *None.*")

    lines.extend(["", "## Risk acceptance blocks on findings", ""])
    ra_any = False
    for f in package.get("findings") or []:
        if not isinstance(f, dict):
            continue
        ra = f.get("risk_acceptance")
        if isinstance(ra, dict) and ra.get("accepted_by"):
            ra_any = True
            lines.append(f"- `{f.get('finding_id')}`: formal acceptance recorded (`accepted_by` present).")
    if not ra_any:
        lines.append("- *No non-empty risk acceptance metadata beyond defaults.*")

    lines.append("")
    return "\n".join(lines)


def _ksi_by_ksi_md(package: dict[str, Any]) -> str:
    catalog = [k for k in (package.get("ksi_catalog") or []) if isinstance(k, dict)]
    results_by_id = _results_by_id(package)
    findings_all = [f for f in (package.get("findings") or []) if isinstance(f, dict)]
    poam_items = [p for p in (package.get("poam_items") or []) if isinstance(p, dict)]
    reg_by_id = _registry_sources(package)
    rec = _rec(package)
    parity = str(rec.get("parity_status") or "unknown")
    lines = [
        "# KSI-by-KSI assessment",
        "",
        "**Audience:** 3PAO, FedRAMP reviewer, technical assessor.",
        "",
        f"**Package reconciliation parity:** `{parity}` (machine vs. human manifest as recorded).",
        "",
        "## Legend (how to read status vs. evidence)",
        "",
        "- **Passed control/capability:** KSI rollup status PASS in this snapshot.",
        "- **Failed capability:** KSI rollup FAIL, or linked evaluation outcome reflected as FAIL in rollup.",
        "- **Missing evidence:** A **registry or catalog gap** — a criterion `evidence_required` id is absent from "
        "`evidence_source_registry`, so the engine cannot score that path. This is **not** the same as "
        "“manual evidence,” where sources are registered and assessor attestation is expected.",
        "- **Manual evidence:** Registered sources plus catalog/criterion `validation_type` manual/hybrid and/or "
        "file- or narrative-primary collection; evidence is expected out-of-band by design.",
        "- **Inherited responsibility:** Out-of-scope items in `authorization_scope` whose rationale states CSP or inherited boundaries.",
        "- **Customer responsibility:** In-scope services/categories in `authorization_scope` and the logical system boundary.",
        "",
    ]

    for k in catalog:
        kid = str(k.get("ksi_id") or "")
        r = results_by_id.get(kid, {})
        status = str(r.get("status") or "MISSING")
        lc = k.get("legacy_controls") or {}
        rev4 = ", ".join(str(x) for x in (lc.get("rev4") or []))
        rev5 = ", ".join(str(x) for x in (lc.get("rev5") or []))
        k_findings = _findings_for_ksi(findings_all, kid)
        manual_exc = bool(r.get("documented_manual_exception") or r.get("manual_exception_documented"))
        mr_path = f"`fedramp20x-package.json` → array `ksi_validation_results` → object with `ksi_id` == `{kid}`"
        lines.extend(
            [
                f"## `{kid}` — {k.get('title', '')}",
                "",
                f"- **Theme:** {k.get('theme', '')}",
                f"- **Objective:** {k.get('objective', '')}",
                f"- **Legacy Rev4 controls:** {rev4 or '*none listed*'}",
                f"- **Legacy Rev5 controls:** {rev5 or '*none listed*'}",
                f"- **Validation mode (catalog):** `{k.get('validation_mode', '')}`",
                "",
                "### Automation and evidence sources",
                "",
                _automation_line(k, reg_by_id),
                "",
                "### Pass/fail criteria (catalog)",
                "",
                "Per-criterion PASS/FAIL is **not** stored separately in this package; only the rolled-up KSI status reflects the run.",
                "",
            ]
        )
        for c in k.get("pass_fail_criteria") or []:
            if not isinstance(c, dict):
                continue
            lines.append(
                f"- **`{c.get('criteria_id')}`** ({c.get('validation_type', '')}): "
                f"{_md_cell(str(c.get('description')), 400)} "
                f"— expected: {_md_cell(str(c.get('expected_result')), 200)}"
            )
            evr = c.get("evidence_required") or []
            if evr:
                lines.append(f"  - Evidence required (ids): {', '.join(str(x) for x in evr)}")
            evrefs = c.get("eval_refs") or []
            if evrefs:
                lines.append(f"  - Linked eval ids (catalog): {', '.join(str(x) for x in evrefs)}")
        lines.extend(["", "### KSI validation row (machine-readable)", ""])
        if r:
            lines.append(f"- **Status:** `{status}`")
            lines.append(f"- **Summary:** {r.get('summary', '')}")
            le = r.get("linked_eval_ids") or []
            if le:
                lines.append(f"- **Linked evaluation ids:** {', '.join(str(x) for x in le)}")
            else:
                lines.append("- **Linked evaluation ids:** *none in package row*")
            evrefs = r.get("evidence_refs") or []
            if evrefs:
                lines.append(f"- **Evidence refs (structured):** `{json.dumps(evrefs, default=str)[:1500]}`")
            else:
                lines.append("- **Evidence refs:** *none on KSI row*")
            ep = r.get("evidence_posture")
            if isinstance(ep, dict):
                lines.append(
                    f"- **Evidence posture (machine):** `missing_required_evidence={ep.get('missing_required_evidence')}`; "
                    f"`relies_on_manual_or_file_primary_evidence={ep.get('relies_on_manual_or_file_primary_evidence')}`; "
                    f"`automation_maturity_score={ep.get('automation_maturity_score')}`"
                )
        else:
            lines.append("- *No matching `ksi_validation_results` row for this catalog KSI in the package (missing).*")

        lines.extend(["", "### Findings linked to this KSI", ""])
        if not k_findings:
            lines.append("- *None linked by `linked_ksi_ids` / `ksi_ids` in this package.*")
        else:
            for f in k_findings:
                fid = str(f.get("finding_id") or "")
                poam_ids = _poam_refs_for_finding(poam_items, fid)
                if f.get("poam_id"):
                    poam_ids = sorted(set(poam_ids + [str(f["poam_id"])]))
                poam_s = ", ".join(f"`{p}`" for p in poam_ids) if poam_ids else "*no POA&M id in package*"
                lines.append(
                    f"- **`{fid}`** — severity `{f.get('severity')}` — POA&M: {poam_s}\n"
                    f"  - Description (excerpt): {_md_cell(str(f.get('description')), 600)}"
                )

        lines.extend(["", "### POA&M references (by KSI linkage)", ""])
        pk = _poam_refs_for_ksi(poam_items, kid)
        if pk:
            lines.append("POA&M ids tied to this KSI via `source_ksi_ids`: " + ", ".join(f"`{x}`" for x in pk))
        else:
            lines.append("- *None via `source_ksi_ids`; see finding-level POA&M above if applicable.*")

        lines.extend(
            [
                "",
                "### Assessor conclusion (evidence-bounded)",
                "",
                _assessor_conclusion(status, len(k_findings), manual_exc),
                "",
                f"**Machine-readable path:** {mr_path} (array order is not guaranteed to match catalog order).",
                f"**Reconciliation status (package-level):** `{parity}`",
                "",
                "---",
                "",
            ]
        )

    return "\n".join(lines)


def _validation_run_and_manifest_md(package: dict[str, Any]) -> str:
    """AuditKit-style provenance section + pointer to evidence index (companion file)."""
    meta = package.get("package_metadata") or {}
    lines = [
        "",
        "## Evidence index (assessor companion)",
        "",
        f"Use **`{EVIDENCE_INDEX}`** in this directory for artifact paths, package digest pointers, "
        "and the human report manifest.",
        "",
        "## Validation run metadata and input manifest",
        "",
        "`fedramp20x-package.json` → `package_metadata` is authoritative for machine-readable fields below.",
        "",
    ]
    vr = meta.get("validation_run") if isinstance(meta.get("validation_run"), dict) else {}
    lines.extend(
        [
            "### Schema validation",
            "",
            f"- **Outcome:** `{vr.get('schema_validation_outcome', '')}`",
            f"- **Validated at:** `{vr.get('validated_at', '')}`",
            f"- **Tool version:** `{meta.get('tool_version', '')}`",
        ]
    )
    ci = meta.get("cli_invocation")
    if ci:
        lines.append(f"- **CLI:** `{_md_cell(str(ci), 700)}`")
    lines.append(f"- **Package generation (UTC):** `{meta.get('package_generation_timestamp_utc', '')}`")
    lines.append("")

    iam = meta.get("input_artifact_manifest") if isinstance(meta.get("input_artifact_manifest"), list) else []
    if iam:
        lines.extend(["### Input artifacts (assessment directory)", "", "| Path | SHA-256 (prefix) | Size (bytes) |", "| --- | --- | ---: |"])
        for row in iam[:30]:
            if not isinstance(row, dict):
                continue
            h = str(row.get("sha256") or "")
            short = (h[:16] + "…") if len(h) > 16 else h
            lines.append(f"| `{row.get('path', '')}` | `{short}` | {row.get('size_bytes', '')} |")
        lines.append("")

    esc = meta.get("evidence_source_coverage") if isinstance(meta.get("evidence_source_coverage"), dict) else {}
    if esc:
        lines.extend(["### Evidence source coverage (summary)", ""])
        lines.append(f"- **Registered sources:** {esc.get('registry_registered_sources', '')}")
        summ = esc.get("summary")
        if isinstance(summ, dict):
            for k in ("automation_percentage", "ksis_missing_required_evidence", "ksi_manual_mode_count"):
                if summ.get(k) is not None:
                    lines.append(f"- **{k}:** {summ.get(k)}")
        lines.append("")

    prov = meta.get("provider_summary") if isinstance(meta.get("provider_summary"), dict) else {}
    if prov:
        lines.extend(["### Provider / scope summary", ""])
        lines.append(f"- **Deployment model:** {prov.get('deployment_model', '')}")
        lines.append(f"- **Impact level:** {prov.get('impact_level', '')}")
        lines.append("")

    fw = meta.get("framework_control_summary") if isinstance(meta.get("framework_control_summary"), dict) else {}
    if fw:
        lines.extend(["### Framework / control summary", ""])
        lines.append(f"- **Catalog KSIs:** {fw.get('catalog_ksi_count', '')}")
        lines.append(f"- **Unique Rev5 controls (crosswalk):** {fw.get('crosswalk_unique_rev5_controls', '')}")
        lines.append("")

    pm = meta.get("package_manifest") if isinstance(meta.get("package_manifest"), dict) else {}
    rels = pm.get("validation_artifacts_relative") if isinstance(pm.get("validation_artifacts_relative"), list) else []
    if rels:
        lines.extend(["### Package manifest (validation slices, relative paths)", ""])
        for p in rels:
            lines.append(f"- `{p}`")
        lines.append("")

    return "\n".join(lines)


def _assessor_summary_md(package: dict[str, Any], bundle_filenames: list[str]) -> str:
    meta = _meta(package)
    rec = _rec(package)
    counts = rec.get("counts") or {}
    sb = package.get("system_boundary") or {}
    auth = package.get("authorization_scope") or {}
    ksi_results = [r for r in (package.get("ksi_validation_results") or []) if isinstance(r, dict)]
    findings = [f for f in (package.get("findings") or []) if isinstance(f, dict)]
    poam_items = [p for p in (package.get("poam_items") or []) if isinstance(p, dict)]

    human_applied = bool(counts.get("human_report_parse_applied"))
    hf = counts.get("findings_human_reports")
    hk = counts.get("ksi_results_human_reports")
    hp = counts.get("poam_items_human_reports")

    lines = [
        "# Assessor summary",
        "",
        _PACKAGING_DISCLAIMER,
        "**Audience:** 3PAO, FedRAMP reviewer, technical assessor.",
        "",
        "## System and scope (from package)",
        "",
        f"- **System id:** `{sb.get('system_id', '')}`",
        f"- **Short name:** {sb.get('short_name', '')}",
        f"- **Impact level:** {auth.get('impact_level', '')}",
        f"- **Authorization / deployment notes:** boundary id `{auth.get('authorization_boundary_id', '')}`, "
        f"model `{auth.get('deployment_model', '')}`",
        "",
        "### Customer vs. inherited (from `authorization_scope`)",
        "",
        "**In scope (customer-asserted categories):**",
        "",
    ]
    for row in auth.get("in_scope_services") or []:
        if isinstance(row, dict):
            lines.append(f"- `{row.get('category', row)}`")
        else:
            lines.append(f"- `{row}`")
    lines.extend(["", "**Out of scope (with rationale):**", ""])
    for row in auth.get("out_of_scope") or []:
        if isinstance(row, dict):
            lines.append(
                f"- `{row.get('category', '')}` — {_md_cell(str(row.get('rationale', '')), 400)}"
            )
        else:
            lines.append(f"- `{row}`")

    lines.extend(
        [
            "",
            "## Generated assessor bundle",
            "",
            "The following files were generated from the same `fedramp20x-package.json` snapshot:",
            "",
        ]
    )
    for fn in bundle_filenames:
        lines.append(f"- `{fn}`")

    lines.append(_validation_run_and_manifest_md(package))

    lines.extend(
        [
            "",
            "## Count reconciliation (machine-readable fields)",
            "",
        ]
    )
    if human_applied:
        lines.extend(
            [
                "| Measure | Package array length | `reconciliation_summary.counts` | Parsed from assessor/poam markdown |",
                "| --- | ---: | --- | ---: |",
                f"| KSI results | {len(ksi_results)} | `{counts.get('ksi_results', '')}` | {hk} |",
                f"| Findings | {len(findings)} | `{counts.get('findings_machine', '')}` | {hf} |",
                f"| POA&M items | {len(poam_items)} | `{counts.get('poam_items_machine', '')}` | {hp} |",
                "",
            ]
        )
    else:
        lines.extend(
            [
                "| Measure | Package array length | `reconciliation_summary.counts` |",
                "| --- | ---: | --- |",
                f"| KSI results | {len(ksi_results)} | `{counts.get('ksi_results', '')}` |",
                f"| Findings | {len(findings)} | `{counts.get('findings_machine', '')}` |",
                f"| POA&M items | {len(poam_items)} | `{counts.get('poam_items_machine', '')}` |",
                "",
            ]
        )
    mismatch: list[str] = []
    if counts.get("ksi_results") not in (None, "") and int(counts["ksi_results"]) != len(ksi_results):
        mismatch.append("KSI results count differs from reconciliation counts.")
    if counts.get("findings_machine") not in (None, "") and int(counts["findings_machine"]) != len(findings):
        mismatch.append("Findings count differs from reconciliation counts.")
    if counts.get("poam_items_machine") not in (None, "") and int(counts["poam_items_machine"]) != len(poam_items):
        mismatch.append("POA&M count differs from reconciliation counts.")
    if human_applied:
        if hf is not None and int(hf) != len(findings):
            mismatch.append("Findings count differs from human-parsed assessor table.")
        if hk is not None and int(hk) != len(ksi_results):
            mismatch.append("KSI results count differs from human-parsed assessor table.")
        if hp is not None and int(hp) != len(poam_items):
            mismatch.append("POA&M count differs from human-parsed poam.md table.")
    if mismatch:
        lines.append("**Note:** " + " ".join(mismatch))
    else:
        lines.append("Counts match between arrays and reconciliation snapshot (or reconciliation counts omitted).")

    snap = package.get("assessment_correlation_snapshot") or {}
    mat = snap.get("evidence_maturity_summary") or {}
    if mat:
        lines.extend(
            [
                "",
                "## Evidence maturity (package snapshot)",
                "",
                f"- **Evidence maturity automation %** (KSIs with automation score ≥ 4): **{mat.get('automation_percentage', '')}%** "
                f"({mat.get('automated_ksis', '')} of {len(package.get('ksi_catalog') or [])} catalog KSIs).",
                f"- **Catalog `validation_mode` counts — manual / hybrid / automated:** "
                f"{mat.get('ksi_manual_mode_count', '')} / {mat.get('ksi_hybrid_mode_count', '')} / {mat.get('ksi_automated_mode_count', '')}.",
                f"- **KSIs with missing required evidence** (registry gap — not attestation): "
                f"**{mat.get('ksis_missing_required_evidence', '')}**.",
                f"- **KSIs on manual or file-primary path** (registered sources; low automation by design): "
                f"**{mat.get('ksis_manual_or_file_primary_evidence', '')}**.",
                "",
            ]
        )

    lines.extend(
        [
            "",
            "## Traceability chain (this snapshot)",
            "",
            "Rev4/Rev5 controls → **20x KSI** (`ksi_catalog` / results) → **criteria** (`pass_fail_criteria`) → "
            "**evidence sources** (registry) → **eval results** → **findings** → **POA&M** → this report set.",
            "",
        ]
    )
    lines.extend(
        [
            "",
            "## KSI status overview",
            "",
            "| KSI | Status |",
            "| --- | --- |",
        ]
    )
    for r in ksi_results:
        lines.append(f"| `{r.get('ksi_id', '')}` | `{r.get('status', '')}` |")

    lines.extend(
        [
            "",
            "## Findings overview",
            "",
            "| Finding | Severity | Linked KSIs | POA&M (on row) |",
            "| --- | --- | --- | --- |",
        ]
    )
    for f in findings:
        ks = ", ".join(str(x) for x in (f.get("linked_ksi_ids") or f.get("ksi_ids") or []))
        lines.append(
            f"| `{f.get('finding_id', '')}` | {f.get('severity', '')} | {ks} | `{f.get('poam_id', '')}` |"
        )

    lines.extend(
        [
            "",
            "## Metadata",
            "",
            f"- **Generated at:** {meta.get('generated_at', '')}",
            f"- **Generator:** {meta.get('generator_id', '')}",
            f"- **Assessment output URI:** `{meta.get('assessment_output_uri', '')}`",
            f"- **Reconciliation parity:** `{rec.get('parity_status', '')}`",
            "",
        ]
    )
    return "\n".join(lines)


def write_assessor_report(assessor_primary_path: Path, package: dict[str, Any]) -> None:
    """
    Write the assessor report bundle under ``assessor_primary_path.parent``.

    Always writes: assessor-summary, ksi-by-ksi-assessment, evidence-index, validation-methodology,
    exceptions-and-manual-evidence, poam. If ``assessor_primary_path.name`` differs from
    ``assessor-summary.md``, the same summary content is also written to the configured primary path
    so reconciliation manifests remain valid.
    """
    assessor_dir = assessor_primary_path.parent
    assessor_dir.mkdir(parents=True, exist_ok=True)

    bundle = [
        ASSESSOR_SUMMARY,
        KSI_BY_KSI,
        EVIDENCE_INDEX,
        VALIDATION_METHODOLOGY,
        EXCEPTIONS_MANUAL,
        POAM_MD,
    ]
    summary_body = _assessor_summary_md(package, bundle)
    (assessor_dir / ASSESSOR_SUMMARY).write_text(summary_body, encoding="utf-8")
    if assessor_primary_path.name != ASSESSOR_SUMMARY:
        assessor_primary_path.write_text(summary_body, encoding="utf-8")

    (assessor_dir / KSI_BY_KSI).write_text(_ksi_by_ksi_md(package), encoding="utf-8")
    (assessor_dir / EVIDENCE_INDEX).write_text(_evidence_index_md(package), encoding="utf-8")
    (assessor_dir / VALIDATION_METHODOLOGY).write_text(_validation_methodology_md(package), encoding="utf-8")
    (assessor_dir / EXCEPTIONS_MANUAL).write_text(_exceptions_manual_md(package), encoding="utf-8")
    write_poam_markdown(assessor_dir / POAM_MD, package.get("poam_items") or [])


def _finding_open_for_risk(f: dict[str, Any]) -> bool:
    st = str(f.get("status") or "open").lower()
    if st in ("risk_accepted", "closed", "false_positive"):
        return False
    ra = f.get("risk_acceptance")
    if isinstance(ra, dict) and ra.get("accepted_by"):
        return False
    return True


def _exec_metrics(package: dict[str, Any]) -> dict[str, Any]:
    catalog = [k for k in (package.get("ksi_catalog") or []) if isinstance(k, dict)]
    results = [r for r in (package.get("ksi_validation_results") or []) if isinstance(r, dict)]
    findings = [f for f in (package.get("findings") or []) if isinstance(f, dict)]
    poam = [p for p in (package.get("poam_items") or []) if isinstance(p, dict)]
    total = len(catalog) or len(results)
    auto_target_n = sum(1 for k in catalog if k.get("automation_target"))
    auto_pct = round(100.0 * auto_target_n / total, 2) if total else 0.0
    by_id = {str(r.get("ksi_id")): r for r in results if r.get("ksi_id")}
    auto_ksi_ids = [str(k.get("ksi_id")) for k in catalog if k.get("ksi_id") and k.get("automation_target")]
    auto_pass = 0
    auto_not_pass: list[str] = []
    for kid in auto_ksi_ids:
        row = by_id.get(kid) or {}
        st = str(row.get("status") or "").upper()
        if st == "PASS":
            auto_pass += 1
        elif st:
            auto_not_pass.append(f"{kid} ({st})")
        else:
            auto_not_pass.append(f"{kid} (no validation row in package)")
    passed = failed = partial = na = 0
    for r in results:
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
    open_poam = sum(1 for p in poam if str(p.get("status", "")).lower() in ("open", "active", ""))
    crit = sum(
        1 for f in findings if str(f.get("severity", "")).lower() == "critical" and _finding_open_for_risk(f)
    )
    high = sum(1 for f in findings if str(f.get("severity", "")).lower() == "high" and _finding_open_for_risk(f))
    snap_mat = (package.get("assessment_correlation_snapshot") or {}).get("evidence_maturity_summary") or {}
    top_sum = package.get("summary") or {}

    def _mat_pick(key: str, alt_key: str | None = None) -> Any:
        if snap_mat and key in snap_mat and snap_mat[key] is not None:
            return snap_mat[key]
        if alt_key and alt_key in top_sum and top_sum[alt_key] is not None:
            return top_sum[alt_key]
        return top_sum.get(key)

    return {
        "total_ksis": total,
        "passed": passed,
        "failed": failed,
        "partial": partial,
        "not_applicable": na,
        "automation_target_ksis": auto_target_n,
        "automation_catalog_percentage": auto_pct,
        "automation_target_passing": auto_pass,
        "automation_target_not_passing": auto_not_pass,
        "open_poam_items": open_poam,
        "critical_open_findings": crit,
        "high_open_findings": high,
        "findings_total": len(findings),
        "poam_total": len(poam),
        "evidence_maturity_automation_pct": _mat_pick("automation_percentage", "evidence_maturity_automation_percentage"),
        "ksi_manual_mode_count": _mat_pick("ksi_manual_mode_count"),
        "ksi_hybrid_mode_count": _mat_pick("ksi_hybrid_mode_count"),
        "ksi_automated_mode_count": _mat_pick("ksi_automated_mode_count"),
        "ksis_missing_required_evidence": int(_mat_pick("ksis_missing_required_evidence") or 0),
        "ksis_manual_file_primary": int(_mat_pick("ksis_manual_or_file_primary_evidence") or 0),
    }


def _readiness_verdict(package: dict[str, Any], m: dict[str, Any]) -> tuple[str, str]:
    """Return (slug, short rationale) using only package fields. Slug: ready | ready_with_conditions | not_ready."""
    rec = package.get("reconciliation_summary") or {}
    parity = str(rec.get("parity_status") or "")
    reasons: list[str] = []
    if m["failed"] > 0:
        reasons.append(f"{m['failed']} KSI(s) in FAIL status.")
    if m["critical_open_findings"] > 0:
        reasons.append(f"{m['critical_open_findings']} open critical finding(s).")
    if parity == "review_required":
        reasons.append("Machine vs. human report reconciliation is `review_required`.")
    if reasons:
        return "not_ready", " ".join(reasons)
    cond: list[str] = []
    if m["high_open_findings"] > 0:
        cond.append(f"{m['high_open_findings']} open high-severity finding(s).")
    if m["partial"] > 0:
        cond.append("One or more KSIs are PARTIAL or OPEN (counts roll OPEN into this bucket in the package metrics).")
    if m["open_poam_items"] > 0:
        cond.append(f"{m['open_poam_items']} POA&M item(s) in open/active status.")
    if m["automation_target_not_passing"]:
        cond.append(
            "Some catalog automation-target KSIs did not record PASS: "
            + "; ".join(m["automation_target_not_passing"][:5])
            + ("; …" if len(m["automation_target_not_passing"]) > 5 else "")
        )
    if cond:
        return "ready_with_conditions", " ".join(cond)
    return "ready", "No FAIL KSIs, no open critical findings, reconciliation aligned, and no residual conditions recorded above."


def _leadership_actions_table(package: dict[str, Any]) -> str:
    poam = [p for p in (package.get("poam_items") or []) if isinstance(p, dict)]
    lines = [
        "## Leadership actions (from POA&M rows only)",
        "",
        "Owners and dates below are copied from machine-readable POA&M fields. "
        "Rows with no owner or date are shown as *not stated in package*.",
        "",
        "| POA&M / focus | Owner (package) | Target date | Expected impact (package) |",
        "| --- | --- | --- | --- |",
    ]
    any_row = False
    for p in poam:
        pid = str(p.get("poam_id") or "")
        if not pid:
            continue
        owners: list[str] = []
        if p.get("risk_owner"):
            owners.append(str(p["risk_owner"]))
        if p.get("system_owner"):
            owners.append(str(p["system_owner"]))
        owner_s = "; ".join(owners) if owners else "*not stated in package*"
        tcd = str(p.get("target_completion_date") or "").strip() or "*not stated in package*"
        impact = _md_cell(str(p.get("customer_impact") or p.get("weakness_description") or ""), 240)
        title = _md_cell(str(p.get("title") or p.get("weakness_name") or pid), 120)
        lines.append(f"| `{pid}` — {title} | {owner_s} | {tcd} | {impact or '*not stated in package*'} |")
        any_row = True
        for step in p.get("remediation_plan") or []:
            if not isinstance(step, dict):
                continue
            desc = _md_cell(str(step.get("description") or ""), 200)
            so = str(step.get("owner") or owner_s)
            due = str(step.get("due_date") or tcd)
            lines.append(f"| Step: {desc} | {so} | {due} | Planned remediation step (package). |")
            any_row = True
    if not any_row:
        lines.append("| *No POA&M rows in package* | — | — | — |")
    lines.append("")
    return "\n".join(lines)


def _major_risks_md(package: dict[str, Any]) -> str:
    findings = [f for f in (package.get("findings") or []) if isinstance(f, dict) and _finding_open_for_risk(f)]
    sev_order = ("critical", "high", "medium", "low", "info")

    def _sev_rank(f: dict[str, Any]) -> int:
        s = str(f.get("severity") or "medium").lower()
        return sev_order.index(s) if s in sev_order else 99

    findings.sort(key=_sev_rank)
    lines = [
        "# Major risks (business view)",
        "",
        "**Audience:** CEO, CTO, COO, CFO, program leadership, capture/proposal leadership.",
        "",
        "Each item maps a recorded finding to business exposure using only text present in the package. "
        "Severity and wording come from the finding record; nothing below adds new technical facts.",
        "",
    ]
    if not findings:
        lines.append("No open findings remain in the package snapshot (or all are closed / risk-accepted).")
        lines.append("")
        return "\n".join(lines)
    for f in findings[:25]:
        sev = str(f.get("severity") or "").lower()
        fid = f.get("finding_id", "")
        title = f.get("title", "")
        rs = str(f.get("risk_statement") or "").strip()
        desc_excerpt = _md_cell(str(f.get("description") or ""), 400)
        biz = rs if rs else desc_excerpt
        lines.append(f"## `{fid}` — {title}")
        lines.append("")
        lines.append(f"- **Severity (package):** {sev or 'unknown'}")
        lines.append(f"- **Business risk (from package text):** {biz}")
        lines.append(f"- **Evidence deficiency (excerpt):** {desc_excerpt}")
        lines.append("")
    if len(findings) > 25:
        lines.append(f"*…{len(findings) - 25} additional open finding(s) omitted here; see machine-readable package.*")
        lines.append("")
    return "\n".join(lines)


def _security_posture_dashboard_md(package: dict[str, Any], m: dict[str, Any]) -> str:
    rec = package.get("reconciliation_summary") or {}
    lines = [
        "# Security posture dashboard",
        "",
        _PACKAGING_DISCLAIMER,
        "**Audience:** CEO, CTO, COO, CFO, program leadership, capture/proposal leadership.",
        "",
        "## KPIs (this package snapshot)",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
        f"| Total KSIs (catalog size used for automation %) | {m['total_ksis']} |",
        f"| KSI status: PASS | {m['passed']} |",
        f"| KSI status: FAIL | {m['failed']} |",
        f"| KSI status: PARTIAL / OPEN rolled here | {m['partial']} |",
        f"| KSI status: NOT_APPLICABLE / other | {m['not_applicable']} |",
        f"| Catalog automation-target KSIs | {m['automation_target_ksis']} |",
        f"| **Automation percentage** (share of catalog KSIs flagged `automation_target`) | **{m['automation_catalog_percentage']}%** |",
        f"| Automation-target KSIs with PASS this run | {m['automation_target_passing']} / {m['automation_target_ksis'] or '—'} |",
        f"| Open / active POA&M rows | {m['open_poam_items']} |",
        f"| Open critical findings | {m['critical_open_findings']} |",
        f"| Open high findings | {m['high_open_findings']} |",
        f"| Total findings in package | {m['findings_total']} |",
    ]
    emp = m.get("evidence_maturity_automation_pct")
    if emp is not None:
        lines.append(
            f"| **Evidence maturity automation %** (catalog KSIs with maturity score ≥ 4) | **{emp}%** |"
        )
    if m.get("ksi_manual_mode_count") is not None:
        lines.append(f"| Catalog KSIs — manual `validation_mode` | {m['ksi_manual_mode_count']} |")
    if m.get("ksi_hybrid_mode_count") is not None:
        lines.append(f"| Catalog KSIs — hybrid `validation_mode` | {m['ksi_hybrid_mode_count']} |")
    if m.get("ksis_missing_required_evidence"):
        lines.append(
            f"| KSIs — **missing required evidence** (not attestation — fix registry/criteria ids) | "
            f"{m['ksis_missing_required_evidence']} |"
        )
    if m.get("ksis_manual_file_primary") is not None:
        lines.append(
            f"| KSIs — manual/file-primary evidence path (registered sources; expected attestation) | "
            f"{m['ksis_manual_file_primary']} |"
        )
    lines.extend(
        [
            "",
        "## Machine vs. human package reconciliation",
        "",
        f"- **Parity status (package):** `{rec.get('parity_status', '')}`",
        "- **Meaning:** `aligned` means the reconciliation record matched counts in this snapshot; "
        "`review_required` means the package explicitly flags a gap (for example missing human report paths).",
        "",
        "## Automation target (plain language)",
        "",
        f"- **{m['automation_catalog_percentage']}%** of catalog KSIs are designated for automation-heavy validation "
        f"(`automation_target` true). That percentage describes catalog design, not pass rate.",
        f"- Of those **{m['automation_target_ksis']}** automation-target KSIs, **{m['automation_target_passing']}** "
        f"show **PASS** in this run.",
        "",
        ],
    )
    if m["automation_target_not_passing"]:
        lines.append("**Automation-target KSIs not at PASS:**")
        for item in m["automation_target_not_passing"][:15]:
            lines.append(f"- {item}")
        if len(m["automation_target_not_passing"]) > 15:
            lines.append("- …")
        lines.append("")
    else:
        lines.append("**Automation-target KSIs not at PASS:** none listed (or none flagged in catalog).")
        lines.append("")
    lines.extend(
        [
            "## Blockers vs. manageable residual (evidence-only)",
            "",
            "**Blockers (authorization / sale-relevant):**",
            "",
        ]
    )
    blockers: list[str] = []
    if m["failed"] > 0:
        blockers.append(f"- **KSI FAIL count ({m['failed']})** — failing KSIs are material gaps until remediated or formally excepted with assessor agreement.")
    if m["critical_open_findings"] > 0:
        blockers.append(
            f"- **Open critical findings ({m['critical_open_findings']})** — executive escalation and funding for remediation typically required."
        )
    if str(rec.get("parity_status") or "") == "review_required":
        blockers.append("- **Reconciliation `review_required`** — machine-readable and human deliverables may not line up; treat as a process blocker until cleared.")
    if not blockers:
        blockers.append("- *None of the above blocker rules fired on this snapshot.*")
    lines.extend(blockers)
    lines.extend(
        [
            "",
            "**Manageable residual (still requires leadership attention but not necessarily a hard stop):**",
            "",
        ]
    )
    residual: list[str] = []
    if m["high_open_findings"] > 0:
        residual.append(f"- **Open high findings ({m['high_open_findings']})** — schedule remediation and monitor until closed.")
    if m["partial"] > 0:
        residual.append(f"- **PARTIAL / OPEN KSIs ({m['partial']})** — evidence gaps may be closable within a plan without a full FAIL.")
    if m["open_poam_items"] > 0:
        residual.append(f"- **Open POA&M items ({m['open_poam_items']})** — track owners and dates; residual risk remains until closure.")
    if not residual:
        residual.append("- *No residual items in the categories above.*")
    lines.extend(residual)
    lines.append("")
    lines.append(_leadership_actions_table(package))
    return "\n".join(lines)


def _authorization_readiness_md(package: dict[str, Any], m: dict[str, Any], verdict: str, rationale: str) -> str:
    auth = package.get("authorization_scope") or {}
    sb = package.get("system_boundary") or {}
    meta = package.get("package_metadata") or {}
    rec = package.get("reconciliation_summary") or {}
    lines = [
        "# Authorization readiness",
        "",
        "**Audience:** CEO, CTO, COO, CFO, program leadership, capture/proposal leadership.",
        "",
        "## Readiness decision (evidence-bounded)",
        "",
        f"**Verdict:** `{verdict}`",
        "",
        f"**Rationale (from this package only):** {rationale}",
        "",
        "## Authorization context (package fields)",
        "",
        f"- **Impact level:** {auth.get('impact_level', '')}",
        f"- **Deployment model:** {auth.get('deployment_model', '')}",
        f"- **System id:** `{sb.get('system_id', '')}`",
        f"- **Program name:** {meta.get('program_display_name', '')}",
        "",
        "### In scope",
        "",
    ]
    for row in auth.get("in_scope_services") or []:
        if isinstance(row, dict):
            lines.append(f"- {row.get('category', row)}")
        else:
            lines.append(f"- {row}")
    lines.extend(["", "### Out of scope / inherited", ""])
    for row in auth.get("out_of_scope") or []:
        if isinstance(row, dict):
            lines.append(f"- **{row.get('category', '')}:** {_md_cell(str(row.get('rationale', '')), 400)}")
        else:
            lines.append(f"- {row}")
    lines.extend(
        [
            "",
            "## Readiness implications (no hidden failures)",
            "",
            "This decision does not replace a 3PAO or AO determination. It summarizes whether the **current** "
            "evidence package snapshot contains hard stops for leadership to treat as authorization / pursuit risk.",
            "",
            f"- **FAIL KSIs:** {m['failed']} (non-zero is a hard readiness concern.)",
            f"- **Open critical findings:** {m['critical_open_findings']}",
            f"- **Reconciliation:** `{rec.get('parity_status', '')}`",
            "",
        ]
    )
    return "\n".join(lines)


def _executive_summary_md(
    package: dict[str, Any], m: dict[str, Any], verdict: str, rationale: str, bundle: list[str]
) -> str:
    meta = package.get("package_metadata") or {}
    lines = [
        _PACKAGING_DISCLAIMER,
        "# Executive summary",
        "",
        "**Audience:** CEO, CTO, COO, CFO, program leadership, capture/proposal leadership.",
        "",
        f"**Program:** {meta.get('program_display_name', 'security program')}",
        f"**Generated:** {meta.get('generated_at', '')}",
        "",
        "## Headline",
        "",
        f"- **KSI snapshot:** {m['passed']} PASS, **{m['failed']} FAIL**, {m['partial']} PARTIAL/OPEN-classified, "
        f"{m['not_applicable']} NOT_APPLICABLE/other — **{m['total_ksis']}** KSIs tracked.",
        f"- **Automation (catalog):** **{m['automation_catalog_percentage']}%** of KSIs are flagged `automation_target`; "
        f"**{m['automation_target_passing']}** of those recorded PASS this run.",
        f"- **Open POA&M (open/active status in package):** {m['open_poam_items']}",
        f"- **Open critical / high findings:** {m['critical_open_findings']} / {m['high_open_findings']}",
        "",
        "**Authorization readiness** for this snapshot is stated under **Readiness decision** below and expanded in "
        f"`{AUTHORIZATION_READINESS}` and `{SECURITY_POSTURE_DASHBOARD}`.",
        "",
        "## Readiness decision",
        "",
        f"**`{verdict}`** — {rationale}",
        "",
        "## Companion documents",
        "",
    ]
    for fn in bundle:
        lines.append(f"- `{fn}`")
    lines.extend(
        [
            "",
            "## Traceability",
            "",
            "All figures above are derived from `fedramp20x-package.json` in the same output directory. "
            "Assessor annex files provide KSI-level detail.",
            "",
        ]
    )
    return "\n".join(lines)


def write_executive_report(executive_primary_path: Path, package: dict[str, Any]) -> None:
    """
    Write the executive bundle under ``executive_primary_path.parent``.

    Files: executive-summary, security-posture-dashboard, authorization-readiness, major-risks.
    If the configured primary filename differs from ``executive-summary.md``, the summary is also
    written to that path for reconciliation manifest compatibility.
    """
    executive_dir = executive_primary_path.parent
    executive_dir.mkdir(parents=True, exist_ok=True)
    m = _exec_metrics(package)
    verdict, rationale = _readiness_verdict(package, m)
    bundle = [EXECUTIVE_SUMMARY, SECURITY_POSTURE_DASHBOARD, AUTHORIZATION_READINESS, MAJOR_RISKS]
    summary_body = _executive_summary_md(package, m, verdict, rationale, bundle)
    (executive_dir / EXECUTIVE_SUMMARY).write_text(summary_body, encoding="utf-8")
    if executive_primary_path.name != EXECUTIVE_SUMMARY:
        executive_primary_path.write_text(summary_body, encoding="utf-8")

    (executive_dir / SECURITY_POSTURE_DASHBOARD).write_text(_security_posture_dashboard_md(package, m), encoding="utf-8")
    (executive_dir / AUTHORIZATION_READINESS).write_text(
        _authorization_readiness_md(package, m, verdict, rationale), encoding="utf-8"
    )
    (executive_dir / MAJOR_RISKS).write_text(_major_risks_md(package), encoding="utf-8")


def _ao_open_high_critical(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for f in findings:
        if not isinstance(f, dict) or not _finding_open_for_risk(f):
            continue
        if str(f.get("severity") or "").lower() in ("high", "critical"):
            out.append(f)
    return out


def _poam_summary_md(package: dict[str, Any]) -> str:
    poam = [p for p in (package.get("poam_items") or []) if isinstance(p, dict)]
    lines = [
        "## POA&M summary (package snapshot)",
        "",
        f"**Total POA&M rows:** {len(poam)}",
        "",
        "| POA&M ID | Status | Finding ID | Severity | Target completion |",
        "| --- | --- | --- | --- | --- |",
    ]
    for p in poam[:40]:
        lines.append(
            f"| `{_md_cell(str(p.get('poam_id')), 40)}` | {_md_cell(str(p.get('status')), 24)} | "
            f"`{_md_cell(str(p.get('finding_id')), 32)}` | {_md_cell(str(p.get('severity')), 12)} | "
            f"{_md_cell(str(p.get('target_completion_date')), 16)} |"
        )
    if len(poam) > 40:
        lines.append(f"| … | ({len(poam) - 40} more rows in machine-readable package) | | | |")
    lines.append("")
    return "\n".join(lines)


def _risk_acceptance_candidates_md(package: dict[str, Any]) -> str:
    lines = [
        "## Risk acceptance candidates (package fields only)",
        "",
        "Findings below are **open** in the package and carry a `risk_acceptance` object. "
        "They are candidates for formal AO / risk-owner decision only if program policy allows; "
        "this list does not recommend acceptance.",
        "",
    ]
    n = 0
    for f in package.get("findings") or []:
        if not isinstance(f, dict) or not _finding_open_for_risk(f):
            continue
        ra = f.get("risk_acceptance")
        if not isinstance(ra, dict):
            continue
        n += 1
        fid = f.get("finding_id", "")
        lines.append(f"### `{fid}`")
        lines.append("")
        lines.append(f"- **Severity:** {f.get('severity', '')}")
        lines.append(f"- **risk_acceptance (JSON excerpt):** `{_md_cell(json.dumps(ra, default=str), 400)}`")
        lines.append("")
    if n == 0:
        lines.append("*No open findings with a `risk_acceptance` object in this package.*")
        lines.append("")
    return "\n".join(lines)


def _residual_risk_register_md(package: dict[str, Any], m: dict[str, Any]) -> str:
    """Residual exposure grouped by catalog theme (KSIs listed; statuses from package only)."""
    by_theme: dict[str, list[dict[str, Any]]] = {}
    for k in package.get("ksi_catalog") or []:
        if not isinstance(k, dict):
            continue
        th = str(k.get("theme") or "Uncategorized")
        by_theme.setdefault(th, []).append(k)
    results = {str(r.get("ksi_id")): r for r in (package.get("ksi_validation_results") or []) if isinstance(r, dict) and r.get("ksi_id")}
    lines = [
        "# Residual risk register (by KSI theme)",
        "",
        "**Audience:** Agency AO, ISSO, ISSM, security reviewer.",
        "",
        "Residual risk here means **unresolved assessment outcomes** visible in the package (KSI rollup status, "
        "linked findings). It does not compute a new risk score.",
        "",
    ]
    for theme, ks in sorted(by_theme.items(), key=lambda x: x[0].lower()):
        lines.append(f"## Theme: {theme}")
        lines.append("")
        lines.append("| KSI | Status | Linked open high/critical findings (by id) |")
        lines.append("| --- | --- | --- |")
        for k in ks:
            kid = str(k.get("ksi_id") or "")
            row = results.get(kid, {})
            st = str(row.get("status") or "*no validation row*")
            linked: list[str] = []
            for f in package.get("findings") or []:
                if not isinstance(f, dict) or not _finding_open_for_risk(f):
                    continue
                if str(f.get("severity") or "").lower() not in ("high", "critical"):
                    continue
                kids = list(f.get("linked_ksi_ids") or f.get("ksi_ids") or [])
                if kid in kids:
                    linked.append(str(f.get("finding_id") or ""))
            lines.append(f"| `{kid}` | {st} | {', '.join(f'`{x}`' for x in linked) if linked else '*none*'} |")
        lines.append("")
    lines.append("### Package-level residual indicators")
    lines.append("")
    lines.append(f"- FAIL KSIs: **{m['failed']}**")
    lines.append(f"- Open critical findings: **{m['critical_open_findings']}**")
    lines.append(f"- Open high findings: **{m['high_open_findings']}**")
    lines.append(f"- Open/active POA&M rows: **{m['open_poam_items']}**")
    lines.append("")
    return "\n".join(lines)


def _customer_responsibility_matrix_md(package: dict[str, Any]) -> str:
    m = _exec_metrics(package)
    auth = package.get("authorization_scope") or {}
    sb = package.get("system_boundary") or {}
    reg = package.get("evidence_source_registry") or {}
    source_ids = []
    for s in reg.get("sources") or []:
        if isinstance(s, dict) and s.get("id"):
            source_ids.append(str(s["id"]))
    ev_sources_cell = ", ".join(f"`{x}`" for x in sorted(set(source_ids))[:30]) if source_ids else "*none in registry*"
    if len(source_ids) > 30:
        ev_sources_cell += " …"
    boundary_note = _md_cell(str(sb.get("notes") or ""), 300)
    lines = [
        "# Customer responsibility matrix",
        "",
        "**Audience:** Agency AO, ISSO, ISSM, security reviewer.",
        "",
        "This matrix uses **authorization_scope** and **system_boundary** text only. "
        "It distinguishes CSP, agency/customer, inherited cloud-provider, and shared patterns as **roles** "
        "described in policy language—not as a substitute for a signed shared-responsibility matrix.",
        "",
        "| area | CSP responsibility | agency responsibility | evidence source | residual risk | required agency action |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    pkg_residual = (
        f"Package snapshot: {m['failed']} FAIL KSIs; {m['critical_open_findings']} critical / "
        f"{m['high_open_findings']} high open findings; {m['open_poam_items']} open POA&M rows."
    )
    for row in auth.get("in_scope_services") or []:
        area = row.get("category", row) if isinstance(row, dict) else str(row)
        csp = (
            "Underlying cloud platform controls operated by the CSP per FedRAMP / agency shared "
            "responsibility (customer configures workloads on top)."
        )
        agency = (
            "Customer/agency: configure, monitor, and evidence security controls for workloads and "
            "data placed in this in-scope category."
        )
        action = (
            "Maintain evidence exports and POA&M closure aligned to mapped KSIs; coordinate with ISSO "
            "for assessor requests."
        )
        lines.append(
            f"| {_md_cell(str(area), 80)} | {_md_cell(csp, 200)} | {_md_cell(agency, 200)} | "
            f"Cross-cutting registry IDs: {ev_sources_cell} | {_md_cell(pkg_residual, 220)} | {_md_cell(action, 200)} |"
        )
    if not auth.get("in_scope_services"):
        lines.append(
            f"| *not stated* | {_md_cell(csp, 200)} | Customer boundary not enumerated in package. | "
            f"{ev_sources_cell} | {_md_cell(pkg_residual, 220)} | Define in-scope services in `authorization_scope`. |"
        )
    lines.extend(
        [
            "",
            "### Shared / inherited nuance (from boundary notes)",
            "",
            boundary_note or "*No `system_boundary.notes` in package.*",
            "",
        ]
    )
    return "\n".join(lines)


def _inherited_controls_summary_md(package: dict[str, Any]) -> str:
    auth = package.get("authorization_scope") or {}
    lines = [
        "# Inherited controls summary",
        "",
        "**Audience:** Agency AO, ISSO, ISSM, security reviewer.",
        "",
        "Rows are built from **`authorization_scope.out_of_scope`** entries that typically describe "
        "CSP/inherited boundaries. The package does **not** include CSP SOC reports or inherited authorization letters.",
        "",
        "| service/provider | inherited authorization status | inherited capability | CSP evidence needed | agency relevance |",
        "| --- | --- | --- | --- | --- |",
    ]
    rows = auth.get("out_of_scope") or []
    if not rows:
        lines.append(
            "| *not listed* | *not stated in package* | *not stated in package* | "
            "Obtain under agency CSP review process (not in this JSON). | "
            "Agency verifies customer boundary vs. inherited claims. |"
        )
    else:
        for row in rows:
            if isinstance(row, dict):
                svc = str(row.get("category") or "unspecified")
                rat = str(row.get("rationale") or "")
                lines.append(
                    f"| {_md_cell(svc, 48)} | Out of customer configuration scope in this package. | "
                    f"{_md_cell(rat, 200)} | "
                    "FedRAMP CSP package / agency-required artifacts **not embedded here**. | "
                    "Agency retains oversight of inherited controls that affect customer security objectives. |"
                )
            else:
                lines.append(
                    f"| {_md_cell(str(row), 48)} | Out of scope in package. | *not stated* | "
                    "CSP evidence per agency process. | Oversight per boundary policy. |"
                )
    lines.append("")
    lines.append(
        "### Distinction (how to read the columns)\n\n"
        "- **CSP responsibility:** Physical facilities, hypervisor layers, and other items the customer "
        "does not configure, as described in out-of-scope rationale.\n"
        "- **Agency / customer responsibility:** In-scope categories in `authorization_scope` and evidence "
        "the customer must produce for KSIs.\n"
        "- **Inherited cloud provider responsibility:** Controls delivered by the CSP and accepted through "
        "the CSP’s authorization; evidence is outside this customer package unless explicitly attached elsewhere.\n"
        "- **Shared responsibility:** Customer configures logical controls on CSP-provided services; both parties "
        "hold obligations described in FedRAMP shared responsibility models (not restated in full here).\n"
    )
    return "\n".join(lines)


def _authorization_decision_support_md(package: dict[str, Any], m: dict[str, Any], verdict: str, rationale: str) -> str:
    rec = package.get("reconciliation_summary") or {}
    meta = package.get("package_metadata") or {}
    sb = package.get("system_boundary") or {}
    lines = [
        "# Authorization decision support",
        "",
        _PACKAGING_DISCLAIMER,
        "**Audience:** Agency AO, ISSO, ISSM, security reviewer.",
        "",
        "## Considerations for authorization (evidence-only)",
        "",
        "- **KSI failures:** Any FAIL status is a material evidence gap for the mapped KSI until remediated or "
        "formally handled under assessor/AO agreement.",
        "- **Open critical / high findings:** Require explicit disposition (remediation, POA&M, or formal risk acceptance).",
        "- **POA&M:** Open rows signal accepted residual work with dates and owners in the machine-readable package.",
        "- **Reconciliation:** "
        f"`{rec.get('parity_status', '')}` — if `review_required`, resolve manifest gaps before relying on the package as complete.",
        "- **Inherited controls:** Review `inherited-controls-summary.md` against the CSP’s current authorization package.",
        "",
        "## Snapshot alignment with executive readiness",
        "",
        f"**Readiness-style verdict (same rules as executive bundle):** `{verdict}`",
        "",
        f"**Rationale:** {rationale}",
        "",
        f"- **System id:** `{sb.get('system_id', '')}`",
        f"- **Assessment output:** `{meta.get('assessment_output_uri', '')}`",
        "",
        _poam_summary_md(package),
        _risk_acceptance_candidates_md(package),
    ]
    return "\n".join(lines)


def _ao_risk_brief_md(package: dict[str, Any], m: dict[str, Any], bundle: list[str], verdict: str, rationale: str) -> str:
    meta = package.get("package_metadata") or {}
    sb = package.get("system_boundary") or {}
    high_crit = _ao_open_high_critical([f for f in (package.get("findings") or []) if isinstance(f, dict)])
    lines = [
        "# AO risk brief",
        "",
        _PACKAGING_DISCLAIMER,
        "**Audience:** Agency AO, ISSO, ISSM, security reviewer.",
        "",
        f"**System:** `{sb.get('system_id', '')}` — {meta.get('program_display_name', '')}",
        f"**Generated:** {meta.get('generated_at', '')}",
        "",
        "## Open risks requiring AO awareness",
        "",
    ]
    if not high_crit:
        lines.append("- *No open **high** or **critical** findings in this package snapshot.*")
    else:
        for f in high_crit:
            lines.append(
                f"- **`{f.get('finding_id')}`** ({f.get('severity', '')}): {_md_cell(str(f.get('title')), 200)} — "
                f"{_md_cell(str(f.get('risk_statement') or f.get('description')), 320)}"
            )
    lines.extend(
        [
            "",
            "## Residual risk (headline)",
            "",
            f"- FAIL KSIs: **{m['failed']}**; PARTIAL/OPEN-classified KSIs: **{m['partial']}**",
            f"- Open POA&M: **{m['open_poam_items']}**",
            f"- Reconciliation parity: **`{package.get('reconciliation_summary', {}).get('parity_status', '')}`**",
            "",
            "## Readiness signal (same thresholds as executive reports)",
            "",
            f"**`{verdict}`** — {rationale}",
            "",
        ]
    )
    lines.append(_poam_summary_md(package))
    lines.append(_risk_acceptance_candidates_md(package))
    lines.extend(
        [
            "",
            "## Companion AO documents",
            "",
            f"**Residual risk (detail by KSI theme):** see **`{RESIDUAL_RISK_REGISTER}`**. "
            f"**Customer vs inherited responsibilities:** see **`{CUSTOMER_RESP_MATRIX}`**.",
            "",
        ]
    )
    for fn in bundle:
        lines.append(f"- `{fn}`")
    lines.extend(
        [
            "",
            "## Traceability",
            "",
            "Source: `fedramp20x-package.json` in the same output directory. No facts added beyond that snapshot.",
            "",
        ]
    )
    return "\n".join(lines)


def write_agency_ao_report(ao_primary_path: Path, package: dict[str, Any]) -> None:
    """
    Write the agency AO bundle under ``ao_primary_path.parent``.

    Files: ao-risk-brief, authorization-decision-support, residual-risk-register,
    customer-responsibility-matrix, inherited-controls-summary.
    """
    ao_dir = ao_primary_path.parent
    ao_dir.mkdir(parents=True, exist_ok=True)
    m = _exec_metrics(package)
    verdict, rationale = _readiness_verdict(package, m)
    bundle = [
        AO_RISK_BRIEF,
        AUTHORIZATION_DECISION_SUPPORT,
        RESIDUAL_RISK_REGISTER,
        CUSTOMER_RESP_MATRIX,
        INHERITED_CONTROLS_SUMMARY,
    ]
    brief = _ao_risk_brief_md(package, m, bundle, verdict, rationale)
    (ao_dir / AO_RISK_BRIEF).write_text(brief, encoding="utf-8")
    if ao_primary_path.name != AO_RISK_BRIEF:
        ao_primary_path.write_text(brief, encoding="utf-8")

    (ao_dir / AUTHORIZATION_DECISION_SUPPORT).write_text(
        _authorization_decision_support_md(package, m, verdict, rationale), encoding="utf-8"
    )
    (ao_dir / RESIDUAL_RISK_REGISTER).write_text(_residual_risk_register_md(package, m), encoding="utf-8")
    (ao_dir / CUSTOMER_RESP_MATRIX).write_text(_customer_responsibility_matrix_md(package), encoding="utf-8")
    (ao_dir / INHERITED_CONTROLS_SUMMARY).write_text(_inherited_controls_summary_md(package), encoding="utf-8")


def write_reconciliation_markdown(path: Path, package: dict[str, Any]) -> None:
    import json as _json

    rec = package.get("reconciliation_summary") or {}
    lines = [
        "# Reconciliation report",
        "",
        f"**Parity status:** `{rec.get('parity_status', '')}`",
        "",
        "## Counts",
        "",
        "```json",
        _json.dumps(rec.get("counts") or {}, indent=2),
        "```",
        "",
        "## Human report manifest",
        "",
    ]
    for m in rec.get("human_report_manifest") or []:
        lines.append(f"- `{m.get('path')}` — {m.get('role', '')}")
    lines.append("")
    if rec.get("package_sha256"):
        lines.append(f"## Package digest\n\n`{rec['package_sha256']}`\n")
    for n in rec.get("notes") or []:
        lines.append(f"- {n}")
    path.write_text("\n".join(lines), encoding="utf-8")


def write_machine_readable_mirror(package_dir: Path, package: dict[str, Any]) -> None:
    import json as _json

    mr = package_dir / "reports" / "machine-readable"
    mr.mkdir(parents=True, exist_ok=True)
    name = "fedramp20x-package.json"
    (mr / name).write_text(_json.dumps(package, indent=2, default=str), encoding="utf-8")
    pm = package.get("package_metadata") or {}
    manifest = {
        "primary_package": name,
        "package_manifest": pm.get("package_manifest"),
        "validation_run": pm.get("validation_run"),
        "input_artifact_manifest": pm.get("input_artifact_manifest"),
        "tool_version": pm.get("tool_version"),
        "fedramp20x_style_schema": {
            "label": "FedRAMP 20x–style evidence package schema",
            "project_relative_path": "schemas/fedramp20x-package.schema.json",
            "schema_id_uri": "https://observable-security-agent.local/schemas/fedramp20x-package.schema.json",
        },
        "generated_at": pm.get("generated_at"),
        "package_generation_timestamp_utc": pm.get("package_generation_timestamp_utc"),
    }
    (mr / "package.manifest.json").write_text(_json.dumps(manifest, indent=2), encoding="utf-8")
