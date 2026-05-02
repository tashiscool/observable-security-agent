"""Reconciliation between machine-readable package and human-oriented reports."""

from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from fedramp20x.report_builder import (
    AO_RISK_BRIEF,
    ASSESSOR_SUMMARY,
    EXECUTIVE_SUMMARY,
    KSI_BY_KSI,
    POAM_MD,
    SECURITY_POSTURE_DASHBOARD,
)


def build_reconciliation_summary(
    *,
    package: dict[str, Any],
    human_report_paths: list[dict[str, str]],
    include_sha256: bool,
    package_sha256: str | None,
) -> dict[str, Any]:
    findings_n = len(package.get("findings") or [])
    poam_n = len(package.get("poam_items") or [])
    ksi_n = len(package.get("ksi_validation_results") or [])
    parity = "aligned"
    notes: list[str] = []
    if not human_report_paths:
        parity = "review_required"
        notes.append("No human report paths recorded in manifest.")
    out: dict[str, Any] = {
        "parity_status": parity,
        "counts": {
            "findings_machine": findings_n,
            "poam_items_machine": poam_n,
            "ksi_results": ksi_n,
        },
        "human_report_manifest": human_report_paths,
        "notes": notes
        + [
            "Machine counts above are from package arrays. Human-row counts (parsed from rendered markdown) "
            "are applied after assessor/poam markdown exists — see `human_report_parse_applied`.",
        ],
    }
    if include_sha256 and package_sha256:
        out["package_sha256"] = package_sha256
    return out


def _md_section(md: str, heading_line: str) -> str:
    """Return markdown body after ``heading_line`` (e.g. ``## Findings overview``) until next ``## `` heading."""
    lines = md.splitlines()
    start: int | None = None
    for i, line in enumerate(lines):
        if line.strip() == heading_line.strip():
            start = i + 1
            break
    if start is None:
        return ""
    out_lines: list[str] = []
    for line in lines[start:]:
        if line.startswith("## ") and line.strip() != heading_line.strip():
            break
        out_lines.append(line)
    return "\n".join(out_lines)


def _count_markdown_table_body_rows(section_md: str) -> int:
    lines = section_md.splitlines()
    found_sep = False
    n = 0
    for line in lines:
        s = line.strip()
        if not s:
            continue
        if s.startswith("|") and "---" in s:
            found_sep = True
            continue
        if s.startswith("|") and found_sep:
            n += 1
    return n


def parse_assessor_summary_table_counts(assessor_summary_md: str) -> tuple[int, int, list[str]]:
    """Return (findings_rows, ksi_rows, parse_errors). Use -1 when a table is missing."""
    errors: list[str] = []
    f_sec = _md_section(assessor_summary_md, "## Findings overview")
    k_sec = _md_section(assessor_summary_md, "## KSI status overview")
    f_n = _count_markdown_table_body_rows(f_sec) if f_sec.strip() else -1
    k_n = _count_markdown_table_body_rows(k_sec) if k_sec.strip() else -1
    if f_n < 0:
        errors.append("assessor-summary: could not locate findings overview table")
    if k_n < 0:
        errors.append("assessor-summary: could not locate KSI status overview table")
    return f_n, k_n, errors


def parse_poam_md_table_rows(poam_md: str) -> tuple[int, list[str]]:
    """Count POA&M rows in the primary table (first markdown table before ``## Remediation``)."""
    errors: list[str] = []
    stop = poam_md.find("## Remediation")
    head = poam_md if stop < 0 else poam_md[:stop]
    n = _count_markdown_table_body_rows(head)
    if n < 0:
        n = 0
    if "| POA&M ID |" not in head:
        errors.append("poam.md: primary POA&M table header not found")
    return n, errors


def apply_human_derived_counts_to_reconciliation(*, package: dict[str, Any], report_root: Path) -> None:
    """
    Parse assessor/poam markdown under ``report_root`` and populate reconciliation human counts.

    Mutates ``package[\"reconciliation_summary\"]`` in place. Sets ``parity_status`` to ``aligned`` only when
    parsed table row counts match machine array lengths for findings, KSI results, and POA&M.
    """
    rec = package.setdefault("reconciliation_summary", {})
    counts = rec.setdefault("counts", {})
    machine_f = len(package.get("findings") or [])
    machine_k = len(package.get("ksi_validation_results") or [])
    machine_p = len(package.get("poam_items") or [])

    assessor_dir = report_root / "reports" / "assessor"
    sum_path = assessor_dir / ASSESSOR_SUMMARY
    poam_path = assessor_dir / POAM_MD

    errors: list[str] = []
    findings_h, ksi_h, e1 = (-1, -1, [])
    if sum_path.is_file():
        ass_txt = sum_path.read_text(encoding="utf-8")
        findings_h, ksi_h, e1 = parse_assessor_summary_table_counts(ass_txt)
    else:
        errors.append(f"missing assessor summary: {sum_path}")

    poam_h, e2 = (-1, [])
    if poam_path.is_file():
        poam_h, e2 = parse_poam_md_table_rows(poam_path.read_text(encoding="utf-8"))
    else:
        errors.append(f"missing poam.md: {poam_path}")

    counts["findings_machine"] = machine_f
    counts["ksi_results"] = machine_k
    counts["poam_items_machine"] = machine_p

    if findings_h >= 0:
        counts["findings_human_reports"] = findings_h
    if ksi_h >= 0:
        counts["ksi_results_human_reports"] = ksi_h
    if poam_h >= 0:
        counts["poam_items_human_reports"] = poam_h

    all_errs = errors + e1 + e2
    counts["human_report_parse_errors"] = all_errs
    counts["human_report_parse_applied"] = True

    ok = (
        findings_h >= 0
        and ksi_h >= 0
        and poam_h >= 0
        and findings_h == machine_f
        and ksi_h == machine_k
        and poam_h == machine_p
    )
    if not rec.get("human_report_manifest"):
        ok = False

    if not ok:
        rec["parity_status"] = "review_required"
        detail = (
            f"findings machine={machine_f} human_table={findings_h}; "
            f"ksi machine={machine_k} human_table={ksi_h}; "
            f"poam machine={machine_p} human_table={poam_h}."
        )
        rec.setdefault("notes", []).append("Human vs machine count mismatch or parse error: " + detail)
    else:
        rec["parity_status"] = "aligned"


def _catalog_ksi_ids(package: dict[str, Any]) -> list[str]:
    return [str(k.get("ksi_id")) for k in (package.get("ksi_catalog") or []) if isinstance(k, dict) and k.get("ksi_id")]


def _registry_source_ids(package: dict[str, Any]) -> set[str]:
    reg = package.get("evidence_source_registry") or {}
    return {str(s.get("id")) for s in (reg.get("sources") or []) if isinstance(s, dict) and s.get("id")}


def _finding_needs_poam(f: dict[str, Any]) -> bool:
    st = str(f.get("status") or "").lower()
    if st in ("risk_accepted", "closed", "false_positive"):
        return False
    ra = f.get("risk_acceptance")
    if isinstance(ra, dict) and ra.get("accepted_by"):
        return False
    return True


def _parse_ksi_assessor_sections(ksi_md: str) -> dict[str, str]:
    """Map KSI id -> section text from ``ksi-by-ksi-assessment.md``."""
    pattern = re.compile(r"^## `([^`]+)`\s", re.MULTILINE)
    matches = list(pattern.finditer(ksi_md))
    out: dict[str, str] = {}
    for i, m in enumerate(matches):
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(ksi_md)
        out[m.group(1)] = ksi_md[start:end]
    return out


def _status_from_assessor_section(section: str) -> str | None:
    m = re.search(r"\*\*Status:\*\* `([^`]+)`", section)
    if m:
        return m.group(1).strip().upper()
    return None


def _float_in_text(text: str) -> list[float]:
    return [float(x) for x in re.findall(r"\b(\d+(?:\.\d+)?)\s*%", text)]


def _md_cell_recon(s: str, max_len: int = 120) -> str:
    t = str(s or "").replace("|", "/").replace("\n", " ")
    return t if len(t) <= max_len else t[: max_len - 3] + "..."


def _exec_automation_catalog_pct(package: dict[str, Any]) -> float:
    from fedramp20x.report_builder import _exec_metrics

    return float(_exec_metrics(package)["automation_catalog_percentage"])


def deep_reconcile(
    *,
    package: dict[str, Any],
    machine_package_path: Path,
    report_root: Path,
    reconciliation_id: str | None = None,
) -> dict[str, Any]:
    """
    Run REC-001 … REC-010 checks between ``package`` JSON and generated reports under ``report_root``.

    Does not raise on failure; returns ``overall_status`` ``pass`` or ``fail`` and per-check records.
    """
    report_root = report_root.resolve()
    generated_at = datetime.now(timezone.utc).isoformat()
    rid = reconciliation_id or f"REC-{uuid.uuid4().hex[:12].upper()}"

    assessor_dir = report_root / "reports" / "assessor"
    executive_dir = report_root / "reports" / "executive"
    ao_dir = report_root / "reports" / "agency-ao"

    ksi_path = assessor_dir / KSI_BY_KSI
    assessor_summary_path = assessor_dir / ASSESSOR_SUMMARY
    exec_summary_path = executive_dir / EXECUTIVE_SUMMARY
    exec_dash_path = executive_dir / SECURITY_POSTURE_DASHBOARD
    ao_brief_path = ao_dir / AO_RISK_BRIEF

    ksi_md = ksi_path.read_text(encoding="utf-8") if ksi_path.is_file() else ""
    exec_summary = exec_summary_path.read_text(encoding="utf-8") if exec_summary_path.is_file() else ""
    exec_dash = exec_dash_path.read_text(encoding="utf-8") if exec_dash_path.is_file() else ""
    ao_brief = ao_brief_path.read_text(encoding="utf-8") if ao_brief_path.is_file() else ""

    from fedramp20x.report_builder import _exec_metrics

    m = _exec_metrics(package)

    sections = _parse_ksi_assessor_sections(ksi_md)
    catalog_ids = _catalog_ksi_ids(package)
    results_by_id = {
        str(r.get("ksi_id")): r
        for r in (package.get("ksi_validation_results") or [])
        if isinstance(r, dict) and r.get("ksi_id")
    }

    checks: list[dict[str, Any]] = []

    # REC-001
    missing_ksi = [k for k in catalog_ids if k not in sections]
    checks.append(
        {
            "id": "REC-001",
            "description": "All KSIs in machine package appear in assessor report",
            "status": "pass" if not missing_ksi else "fail",
            "detail": "All catalog KSIs present in ksi-by-ksi-assessment.md"
            if not missing_ksi
            else f"Missing KSI sections: {missing_ksi}",
        }
    )

    # REC-002
    mismatches: list[str] = []
    for kid, row in results_by_id.items():
        exp = str(row.get("status") or "").upper()
        sec = sections.get(kid, "")
        got = _status_from_assessor_section(sec)
        if got is None:
            mismatches.append(f"{kid}: could not parse assessor status")
        elif got != exp:
            mismatches.append(f"{kid}: package={exp} assessor={got}")
    checks.append(
        {
            "id": "REC-002",
            "description": "KSI status values match between machine package and assessor report",
            "status": "pass" if not mismatches else "fail",
            "detail": "; ".join(mismatches) if mismatches else "Statuses match for all package KSI rows with assessor sections.",
        }
    )

    # REC-003 — executive table vs package lengths
    ksi_n = len(package.get("ksi_validation_results") or [])
    find_n = len(package.get("findings") or [])
    poam_n = len(package.get("poam_items") or [])
    rec_counts = (package.get("reconciliation_summary") or {}).get("counts") or {}
    exec_fail = False
    # Executive summary (current format) states counts in the Headline bullets.
    total_m = re.search(r"—\s*\*\*(\d+)\*\*\s*KSIs tracked", exec_summary)
    if not total_m or int(total_m.group(1)) != m["total_ksis"]:
        exec_fail = True
    poam_m = re.search(
        r"Open POA&M \(open/active status in package\):\*\*\s*(\d+)",
        exec_summary,
    ) or re.search(r"Open POA&M[^\n]+?\*\*\s*(\d+)", exec_summary)
    if not poam_m:
        exec_fail = True
    elif int(poam_m.group(1)) != m["open_poam_items"]:
        exec_fail = True
    crit_high = f"{m['critical_open_findings']} / {m['high_open_findings']}"
    if crit_high not in exec_summary:
        exec_fail = True
    if rec_counts.get("ksi_results") not in (None, "") and int(rec_counts["ksi_results"]) != ksi_n:
        exec_fail = True
    checks.append(
        {
            "id": "REC-003",
            "description": "Executive summary counts match package summary",
            "status": "pass" if not exec_fail else "fail",
            "detail": "Executive summary headline counts match package metrics."
            if not exec_fail
            else "Mismatch between executive-summary.md headline counts and package (or reconciliation counts).",
        }
    )

    # REC-004
    open_hi: list[dict[str, Any]] = []
    for f in package.get("findings") or []:
        if not isinstance(f, dict) or not _finding_needs_poam(f):
            continue
        if str(f.get("severity") or "").lower() not in ("high", "critical"):
            continue
        open_hi.append(f)
    missing_ao = [str(f.get("finding_id")) for f in open_hi if str(f.get("finding_id") or "") not in ao_brief]
    checks.append(
        {
            "id": "REC-004",
            "description": "AO report includes all open high/critical residual risks",
            "status": "pass" if not missing_ao else "fail",
            "detail": "All open high/critical finding ids appear in ao-risk-brief.md"
            if not missing_ao
            else f"Missing in AO brief: {missing_ao}",
        }
    )

    # REC-005
    poam_by_fid = {str(p.get("finding_id")): p for p in (package.get("poam_items") or []) if p.get("finding_id")}
    poam_missing: list[str] = []
    for f in package.get("findings") or []:
        if not isinstance(f, dict) or not _finding_needs_poam(f):
            continue
        fid = str(f.get("finding_id") or "")
        if f.get("poam_id"):
            continue
        if fid and fid in poam_by_fid:
            continue
        poam_missing.append(fid or "(no finding_id)")
    checks.append(
        {
            "id": "REC-005",
            "description": "All open findings have POA&M references unless risk accepted",
            "status": "pass" if not poam_missing else "fail",
            "detail": "Open findings have poam_id or poam_items.finding_id"
            if not poam_missing
            else f"Missing POA&M link: {poam_missing}",
        }
    )

    # REC-006
    finding_ids = {str(f.get("finding_id")) for f in (package.get("findings") or []) if isinstance(f, dict) and f.get("finding_id")}
    bad_poam: list[str] = []
    for p in package.get("poam_items") or []:
        if not isinstance(p, dict):
            continue
        fid = str(p.get("finding_id") or "")
        if fid and fid not in finding_ids:
            bad_poam.append(f"poam {p.get('poam_id')} -> finding_id {fid}")
    checks.append(
        {
            "id": "REC-006",
            "description": "All POA&M items reference valid findings",
            "status": "pass" if not bad_poam else "fail",
            "detail": "All poam finding_id values exist in findings[]"
            if not bad_poam
            else "; ".join(bad_poam),
        }
    )

    # REC-007
    reg_ids = _registry_source_ids(package)
    bad_src: list[str] = []
    for k in package.get("ksi_catalog") or []:
        if not isinstance(k, dict):
            continue
        kid = str(k.get("ksi_id") or "")
        for sid in k.get("evidence_sources") or []:
            s = str(sid)
            if s and s not in reg_ids:
                bad_src.append(f"{kid}: evidence source `{s}`")
    checks.append(
        {
            "id": "REC-007",
            "description": "All evidence source IDs in KSI catalog exist in evidence registry",
            "status": "pass" if not bad_src else "fail",
            "detail": "All catalog evidence_sources registered" if not bad_src else "; ".join(bad_src[:20]),
        }
    )

    # REC-008
    missing_paths: list[str] = []
    rec = package.get("reconciliation_summary") or {}
    for hm in rec.get("human_report_manifest") or []:
        if not isinstance(hm, dict) or not hm.get("path"):
            continue
        rel = str(hm["path"])
        p = report_root / rel
        if not p.is_file():
            missing_paths.append(rel)
    art = package.get("artifacts")
    if isinstance(art, dict):
        for _k, rel in art.items():
            if not rel or not isinstance(rel, str):
                continue
            p = report_root / rel
            if not p.is_file():
                missing_paths.append(rel)
    checks.append(
        {
            "id": "REC-008",
            "description": "All artifact paths listed in package exist under report root",
            "status": "pass" if not missing_paths else "fail",
            "detail": "Manifest and artifact paths resolve" if not missing_paths else f"Missing: {missing_paths[:15]}",
        }
    )

    # REC-009
    expected_pct = _exec_automation_catalog_pct(package)
    pct_vals = _float_in_text(exec_summary) + _float_in_text(exec_dash)
    rec9_fail = True
    for v in pct_vals:
        if abs(v - expected_pct) < 0.01:
            rec9_fail = False
            break
    if expected_pct == 0.0 and not pct_vals:
        rec9_fail = False
    checks.append(
        {
            "id": "REC-009",
            "description": "Automation percentage in executive reports equals computed catalog value",
            "status": "pass" if not rec9_fail else "fail",
            "detail": f"Expected {expected_pct}% from package catalog; found in executive text: {pct_vals[:5]}"
            if rec9_fail
            else f"Matched expected {expected_pct}%",
        }
    )

    # REC-010
    rec10_issues: list[str] = []
    for kid, row in results_by_id.items():
        st = str(row.get("status") or "").upper()
        if st not in ("FAIL", "PARTIAL"):
            continue
        sec = sections.get(kid, "")
        if "Assessor conclusion" not in sec:
            rec10_issues.append(f"{kid}: assessor missing conclusion heading")
        ex_ok = kid in exec_summary or kid in exec_dash
        if not ex_ok:
            if str(m["failed"]) in exec_summary or str(m["partial"]) in exec_summary:
                ex_ok = True
            elif "FAIL" in exec_summary.upper() or "PARTIAL" in exec_summary.upper():
                ex_ok = True
        if not ex_ok:
            rec10_issues.append(f"{kid}: not referenced in executive-summary / security-posture-dashboard")
        ao_ok = kid in ao_brief or str(m["failed"]) in ao_brief or "FAIL" in ao_brief.upper() or "PARTIAL" in ao_brief.upper()
        if not ao_ok:
            rec10_issues.append(f"{kid}: not referenced in ao-risk-brief (and no FAIL/PARTIAL aggregate)")
    checks.append(
        {
            "id": "REC-010",
            "description": "Every failed/partial KSI has assessor conclusion and cross-report mention",
            "status": "pass" if not rec10_issues else "fail",
            "detail": "OK" if not rec10_issues else "; ".join(rec10_issues[:15]),
        }
    )

    cts = (package.get("reconciliation_summary") or {}).get("counts") or {}
    rec11_fail = False
    rec11_detail = "Human markdown parse not recorded on this snapshot (REC-011 skipped)."
    if cts.get("human_report_parse_applied"):
        rec11_detail = "reconciliation_summary human table counts match package array lengths."
        if cts.get("findings_human_reports") != len(package.get("findings") or []):
            rec11_fail = True
        if cts.get("ksi_results_human_reports") != len(package.get("ksi_validation_results") or []):
            rec11_fail = True
        if cts.get("poam_items_human_reports") != len(package.get("poam_items") or []):
            rec11_fail = True
        if rec11_fail:
            rec11_detail = f"Count mismatch vs package arrays; see reconciliation counts {cts}."
    checks.append(
        {
            "id": "REC-011",
            "description": "Reconciliation human-parsed markdown table counts match machine arrays (when parse applied)",
            "status": "pass" if not rec11_fail else "fail",
            "detail": rec11_detail,
        }
    )

    human_reports = []
    for path, role in (
        (str(ksi_path.relative_to(report_root)) if ksi_path.is_file() else None, "assessor_ksi_by_ksi"),
        (str(assessor_summary_path.relative_to(report_root)) if assessor_summary_path.is_file() else None, "assessor_summary"),
        (str(exec_summary_path.relative_to(report_root)) if exec_summary_path.is_file() else None, "executive_summary"),
        (str(exec_dash_path.relative_to(report_root)) if exec_dash_path.is_file() else None, "executive_dashboard"),
        (str(ao_brief_path.relative_to(report_root)) if ao_brief_path.is_file() else None, "ao_brief"),
    ):
        if path:
            human_reports.append({"path": path, "role": role})

    overall = "pass" if all(c["status"] == "pass" for c in checks) else "fail"

    return {
        "reconciliation_id": rid,
        "generated_at": generated_at,
        "machine_package": str(machine_package_path.resolve()),
        "human_reports": human_reports,
        "checks": checks,
        "overall_status": overall,
    }


def write_deep_reconciliation_outputs(result: dict[str, Any], *, output_root: Path) -> None:
    """Write ``evidence/validation-results/reconciliation.json`` and ``reports/assessor/reconciliation-summary.md``."""
    import json

    output_root = output_root.resolve()
    ev_dir = output_root / "evidence" / "validation-results"
    ev_dir.mkdir(parents=True, exist_ok=True)
    assessor_dir = output_root / "reports" / "assessor"
    assessor_dir.mkdir(parents=True, exist_ok=True)

    (ev_dir / "reconciliation.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    lines = [
        "# Reconciliation summary (deep checks)",
        "",
        f"**Reconciliation id:** `{result.get('reconciliation_id', '')}`",
        f"**Generated:** {result.get('generated_at', '')}",
        f"**Machine package:** `{result.get('machine_package', '')}`",
        f"**Overall status:** **`{result.get('overall_status', '')}`**",
        "",
        "## Human inputs reviewed",
        "",
    ]
    for h in result.get("human_reports") or []:
        if isinstance(h, dict):
            lines.append(f"- `{h.get('path')}` — {h.get('role', '')}")
    lines.extend(["", "## Checks", "", "| ID | Status | Description | Detail |", "| --- | --- | --- | --- |"])
    for c in result.get("checks") or []:
        if not isinstance(c, dict):
            continue
        lines.append(
            f"| {c.get('id', '')} | {c.get('status', '')} | {_md_cell_recon(c.get('description', ''))} | {_md_cell_recon(c.get('detail', ''), 200)} |"
        )
    lines.append("")
    (assessor_dir / "reconciliation-summary.md").write_text("\n".join(lines), encoding="utf-8")


def run_reconciliation_cli(
    *,
    package_dir: Path,
    report_root: Path | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Load ``fedramp20x-package.json`` from ``package_dir``, run :func:`deep_reconcile`, write outputs under ``package_dir``.

    ``report_root`` defaults to ``package_dir``; set it when human-readable ``reports/`` lives under a different path
    (paths in ``reconciliation_summary.human_report_manifest`` must still resolve relative to that root).

    Returns ``(exit_code, result)`` where exit_code is 0 on pass, 1 on fail.
    """
    import json

    package_dir = package_dir.resolve()
    pkg_path = package_dir / "fedramp20x-package.json"
    if not pkg_path.is_file():
        raise FileNotFoundError(f"Missing package JSON: {pkg_path}")
    package = json.loads(pkg_path.read_text(encoding="utf-8"))
    rr = (report_root or package_dir).resolve()
    result = deep_reconcile(package=package, machine_package_path=pkg_path, report_root=rr)
    write_deep_reconciliation_outputs(result, output_root=package_dir)
    return (0 if result.get("overall_status") == "pass" else 1, result)
