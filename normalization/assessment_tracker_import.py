"""Import a FedRAMP assessment tracker (CSV/TSV/pasted-text) into a partial fixture scenario.

The tracker is the ASSESSOR's evidence-request worksheet: rows are *requests* for evidence
(e.g. "Provide AWS dump for EC2", "Provide Splunk centralized log examples"). They are NOT
discovered evidence — so this importer never invents asset facts, vulnerability findings,
log entries, or alert rules. It does:

* parse the heterogeneous tracker file (any common delimiter, BOM-tolerant, multiline cells),
* classify each row by keyword into one of: ``inventory``, ``scanner``, ``logging``,
  ``alerting``, ``change_ticket``, ``poam``, ``incident``, ``exploitation_review``,
  ``crypto``, ``backup``, ``iam``, ``traffic_flow``, ``other`` (unknown),
* extract NIST 800-53 control IDs (with enhancements) from the leading column,
* preserve owner / status / dates / assessor comments when present,
* emit fixture-shaped category files (``declared_inventory.csv``, ``scanner_targets.csv``,
  ``scanner_findings.json``, ``central_log_sources.json``, ``alert_rules.json``,
  ``tickets.json``, ``poam.csv``) with **header-only / empty-envelope** payloads when the
  tracker only requested evidence (no facts to record),
* write the structured ``tracker_items.json`` (every parsed row + its classification),
* write ``evidence_gaps.json`` listing requests that are still un-fulfilled,
* write ``auditor_questions.md`` derived from assessor / CSP comments.

The output directory is intended to be consumed by ``providers.assessment_tracker.AssessmentTrackerProvider``
which exposes the parsed tracker items to the rest of the pipeline. Optionally pass
``with_meta_event=True`` to also emit a single synthesized ``cloud_events.json`` "tracker
loaded" meta-event so the existing ``providers.fixture.FixtureProvider`` minimum-bundle
gate can also load the directory (clearly marked ``synthesized_from='assessment_tracker'``).
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

__all__ = [
    "TrackerRow",
    "ImportResult",
    "import_assessment_tracker",
    "import_assessment_tracker_to_dir",
    "parse_tracker_text",
    "classify_row",
    "extract_controls",
    "CATEGORY_TO_FILES",
]

# ---------------------------------------------------------------------------
# Public data shapes
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class TrackerRow:
    """A single parsed evidence-request row from the assessment tracker."""

    row_index: int
    controls: list[str]
    request_text: str
    request_date: str | None
    due_date: str | None
    status: str | None
    owner: str | None
    assessor_comment: str | None
    csp_comment: str | None
    category: str
    classification_signals: list[str]
    raw: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ImportResult:
    """Outcome of an import run."""

    output_dir: Path
    rows: list[TrackerRow] = field(default_factory=list)
    files_written: list[Path] = field(default_factory=list)
    counts_by_category: dict[str, int] = field(default_factory=dict)
    evidence_gaps: list[dict[str, Any]] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Classification rules
# ---------------------------------------------------------------------------

# Keyword sets — case-insensitive substring match. Order in classify_row() is
# significant: more specific categories must come first.

_INVENTORY_HINTS = (
    "integrated inventory workbook",
    "iiw",
    "aws dump",
    "aws account dump",
    "trendmicro inventory",
    "inventory of",
    "asset inventory",
    "ec2 instance",
    "ec2 inventory",
    "rds inventory",
    "load balancer",
    "elb listing",
    "alb listing",
    "s3 bucket listing",
    "s3 inventory",
    "vpc inventory",
    "ip ranges",
    "ip allocation",
    "subnet listing",
    "system component inventory",
)

_SCANNER_HINTS = (
    "nessus",
    "burp",
    "vulnerability scan",
    "vulnerability scanning",
    "vulnerability assessment",
    "scan target list",
    "scan scope",
    "credentialed scan",
    "authenticated scan",
    "plugin",
    "signature",
    "scan plugins",
    "scanner config",
    "scanner profile",
    "tenable",
    "qualys",
    "scan report",
)

_LOGGING_HINTS = (
    "splunk",
    "centralized audit log",
    "centralized log",
    "central log",
    "local audit log",
    "local log",
    "cloudwatch logs",
    "vpc flow logs",
    "vpc flow log",
    "siem",
    "log aggregation",
    "log forwarder",
    "log forwarding",
    "auditd",
    "syslog",
    "log retention",
)

_ALERTING_HINTS = (
    "alert rule",
    "alerting",
    "alert recipient",
    "alert notification",
    "notification recipient",
    "guardduty",
    "cloudwatch alarm",
    "cloudwatch alarms",
    "suspicious activity",
    "saved search",
    "alert configuration",
    "alert dashboard",
)

_CHANGE_TICKET_HINTS = (
    "jira",
    "change ticket",
    "change request",
    "cr ticket",
    "rfc ticket",
    "sia",
    "security impact analysis",
    "test evidence",
    "testing evidence",
    "approval evidence",
    "deployment evidence",
    "verification evidence",
    "post-deploy",
    "cab approval",
    "change advisory board",
)

_POAM_HINTS = (
    "poam",
    "poa&m",
    "plan of action",
    "deviation request",
    "vendor dependency",
    "operational requirement",
    "false positive request",
    "risk acceptance",
)

_INCIDENT_HINTS = (
    "incident response",
    " ir ",
    "ir-",
    "us-cert",
    "cisa report",
    "incident ticket",
    "suspected incident",
    "confirmed incident",
    "incident closure",
    "incident report",
)

_EXPLOITATION_HINTS = (
    "exploitation review",
    "exploit review",
    "ioc",
    "indicator of compromise",
    "high vulnerability review",
    "critical vulnerability review",
    "historical audit log",
    "historical logs",
    "compromise assessment",
)

_CRYPTO_HINTS = (
    "fips 140",
    "fips-140",
    "fips validation",
    "crypto module",
    "cipher list",
    "tls cipher",
    "kms key",
    "key rotation",
    "encryption at rest",
    "encryption in transit",
    "certificate inventory",
)

_BACKUP_HINTS = (
    "backup evidence",
    "backup test",
    "restore test",
    "recovery test",
    "rpo",
    "rto",
    "snapshot evidence",
    "ami backup",
    "rds snapshot",
)

_IAM_HINTS = (
    "account listing",
    "user listing",
    "iam user",
    "iam role",
    "iam policy",
    "privileged account",
    "service account",
    "mfa report",
    "access review",
    "least privilege review",
)

_TRAFFIC_FLOW_HINTS = (
    "traffic flow",
    "data flow diagram",
    "security group",
    "nacl",
    "network acl",
    "ingress rule",
    "egress rule",
    "boundary diagram",
    "port and protocol matrix",
    "ports and protocols",
)

# Order matters: most-specific (logging+alerting+exploitation) before broader inventory/scanner.
_CATEGORY_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("exploitation_review", _EXPLOITATION_HINTS),
    ("incident", _INCIDENT_HINTS),
    ("alerting", _ALERTING_HINTS),
    ("logging", _LOGGING_HINTS),
    ("scanner", _SCANNER_HINTS),
    ("change_ticket", _CHANGE_TICKET_HINTS),
    ("poam", _POAM_HINTS),
    ("crypto", _CRYPTO_HINTS),
    ("backup", _BACKUP_HINTS),
    ("iam", _IAM_HINTS),
    ("traffic_flow", _TRAFFIC_FLOW_HINTS),
    ("inventory", _INVENTORY_HINTS),
)

CATEGORY_TO_FILES: Mapping[str, tuple[str, ...]] = {
    "inventory": ("declared_inventory.csv",),
    "scanner": ("scanner_targets.csv", "scanner_findings.json"),
    "logging": ("central_log_sources.json",),
    "alerting": ("alert_rules.json",),
    "change_ticket": ("tickets.json",),
    "incident": ("tickets.json",),
    "poam": ("poam.csv",),
    "exploitation_review": ("scanner_findings.json",),
    "crypto": (),
    "backup": (),
    "iam": (),
    "traffic_flow": (),
    "other": (),
}


def classify_row(text: str) -> tuple[str, list[str]]:
    """Return ``(category, matched_keywords)`` for the given combined row text."""
    haystack = f" {text.lower().strip()} "
    for category, keywords in _CATEGORY_RULES:
        hits = [kw for kw in keywords if kw in haystack]
        if hits:
            return category, hits
    return "other", []


# ---------------------------------------------------------------------------
# NIST 800-53 control extraction
# ---------------------------------------------------------------------------

# Matches AC-2, AC-2(7), AU-6(1)(c), SC-7(11), CM-3, RA-5(8), CA-7(5)(b), etc.
# Family letters are case-insensitive; enhancement letters preserve their original case
# (FedRAMP / NIST notation uses lowercase sub-letters such as AU-6(1)(c)).
_CONTROL_RE = re.compile(
    r"\b([A-Za-z]{2})-(\d{1,2})((?:\(\s*\w+\s*\))*)",
)


def extract_controls(value: str | None) -> list[str]:
    """Extract NIST 800-53 control identifiers from a free-text cell.

    Handles single controls, comma/semicolon/newline-separated lists, and enhancement
    notations like ``AC-2(7)`` and ``AU-6(1)(c)``. De-duplicated, order preserved.
    Family letters are upper-cased; enhancement letters preserve their original case.
    """
    if not value:
        return []
    out: list[str] = []
    seen: set[str] = set()
    for fam, num, enh in _CONTROL_RE.findall(value):
        cid = f"{fam.upper()}-{int(num)}{enh.replace(' ', '')}"
        if cid not in seen:
            seen.add(cid)
            out.append(cid)
    return out


# ---------------------------------------------------------------------------
# Header detection / column mapping
# ---------------------------------------------------------------------------

# Map normalized header tokens → canonical field names. Multiple synonyms allowed.
_HEADER_SYNONYMS: Mapping[str, str] = {
    # controls column
    "controls": "controls",
    "control": "controls",
    "control id": "controls",
    "controls(s)": "controls",
    "control(s)": "controls",
    "nist controls": "controls",
    "nist control": "controls",
    # request item
    "evidence request": "request_text",
    "evidence/request item": "request_text",
    "evidence / request item": "request_text",
    "evidence request item": "request_text",
    "request item": "request_text",
    "request": "request_text",
    "evidence": "request_text",
    "item": "request_text",
    "description": "request_text",
    "evidence description": "request_text",
    # dates
    "request date": "request_date",
    "date requested": "request_date",
    "requested date": "request_date",
    "due date": "due_date",
    "due": "due_date",
    "deadline": "due_date",
    # status
    "status": "status",
    "state": "status",
    "evidence status": "status",
    # owner
    "owner": "owner",
    "assigned to": "owner",
    "responsible": "owner",
    "responsible party": "owner",
    "csp owner": "owner",
    # comments
    "assessor comments": "assessor_comment",
    "assessor comment": "assessor_comment",
    "3pao comments": "assessor_comment",
    "3pao comment": "assessor_comment",
    "csp comments": "csp_comment",
    "csp comment": "csp_comment",
    "csp response": "csp_comment",
    "comments": "csp_comment",
    "comment": "csp_comment",
    "notes": "csp_comment",
    # assessor/CSP merged column
    "assessor/csp comments": "assessor_comment",
    "assessor / csp comments": "assessor_comment",
}


def _normalize_header(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower()).strip(" :*")


def _build_header_map(headers: list[str]) -> dict[int, str]:
    mapping: dict[int, str] = {}
    for idx, raw in enumerate(headers):
        norm = _normalize_header(raw)
        canonical = _HEADER_SYNONYMS.get(norm)
        if canonical:
            mapping[idx] = canonical
    return mapping


def _looks_like_header(line: list[str]) -> bool:
    norm = [_normalize_header(c) for c in line]
    return any(c in _HEADER_SYNONYMS for c in norm)


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def _detect_dialect(text: str) -> csv.Dialect:
    sample = text[:8192]
    try:
        return csv.Sniffer().sniff(sample, delimiters=",\t|;")
    except csv.Error:
        # Fallback: comma. Quoted multiline fields still work because the csv module
        # honors the embedded quoting state across lines.
        class _Default(csv.Dialect):
            delimiter = ","
            quotechar = '"'
            doublequote = True
            skipinitialspace = True
            lineterminator = "\n"
            quoting = csv.QUOTE_MINIMAL

        return _Default()


def _strip_bom(s: str) -> str:
    if s.startswith("\ufeff"):
        return s[1:]
    return s


def parse_tracker_text(text: str) -> list[TrackerRow]:
    """Parse a tracker file body (CSV/TSV/pipe/semicolon, with or without header)."""
    if text is None:
        return []
    text = _strip_bom(text)
    if not text.strip():
        return []
    dialect = _detect_dialect(text)
    reader = csv.reader(io.StringIO(text), dialect)
    raw_rows: list[list[str]] = [
        [(c if c is not None else "") for c in row] for row in reader if any((c or "").strip() for c in row)
    ]
    if not raw_rows:
        return []

    header_map: dict[int, str]
    if _looks_like_header(raw_rows[0]):
        header_map = _build_header_map(raw_rows[0])
        body = raw_rows[1:]
    else:
        # No recognizable header — assume column 0 is controls + column 1 is request text,
        # and best-effort ignore extras.
        header_map = {0: "controls", 1: "request_text"}
        body = raw_rows

    if "request_text" not in header_map.values():
        # Common shape: first column is controls, second is request item.
        if 0 in header_map and header_map[0] == "controls" and 1 not in header_map:
            header_map[1] = "request_text"

    out: list[TrackerRow] = []
    for i, row in enumerate(body, start=1):
        rec = {"controls": "", "request_text": "", "request_date": "", "due_date": "",
               "status": "", "owner": "", "assessor_comment": "", "csp_comment": ""}
        raw_dump: dict[str, str] = {}
        for col_idx, value in enumerate(row):
            cell = (value or "").strip()
            raw_dump[f"col_{col_idx}"] = cell
            field_name = header_map.get(col_idx)
            if field_name and not rec.get(field_name):
                rec[field_name] = cell
        if not (rec["controls"] or rec["request_text"] or any(rec.values())):
            continue
        controls = extract_controls(rec["controls"]) or extract_controls(rec["request_text"])
        haystack = " ".join(
            [rec.get("request_text", ""), rec.get("assessor_comment", ""), rec.get("csp_comment", "")]
        )
        category, signals = classify_row(haystack)
        out.append(
            TrackerRow(
                row_index=i,
                controls=controls,
                request_text=rec["request_text"],
                request_date=rec["request_date"] or None,
                due_date=rec["due_date"] or None,
                status=rec["status"] or None,
                owner=rec["owner"] or None,
                assessor_comment=rec["assessor_comment"] or None,
                csp_comment=rec["csp_comment"] or None,
                category=category,
                classification_signals=signals,
                raw=raw_dump,
            )
        )
    return out


# ---------------------------------------------------------------------------
# Output writers — emit empty/header-only fixture-shaped files
# ---------------------------------------------------------------------------


def _write_header_only_csv(path: Path, header: list[str]) -> None:
    with path.open("w", encoding="utf-8", newline="") as fh:
        csv.writer(fh).writerow(header)


def _write_envelope_json(path: Path, key: str, items: list[Any], extras: dict[str, Any] | None = None) -> None:
    body: dict[str, Any] = {key: items}
    if extras:
        body.update(extras)
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")


def _emit_inventory(path: Path) -> None:
    _write_header_only_csv(
        path,
        [
            "inventory_id",
            "asset_id",
            "name",
            "asset_type",
            "expected_provider",
            "expected_region",
            "expected_private_ip",
            "expected_public_ip",
            "in_boundary",
            "scanner_required",
            "log_required",
            "owner",
            "system_component",
        ],
    )


def _emit_scanner_targets(path: Path) -> None:
    _write_header_only_csv(
        path,
        ["asset_id", "scanner", "target_type", "hostname", "ip", "scan_profile", "credentialed", "notes"],
    )


def _emit_scanner_findings(path: Path) -> None:
    _write_envelope_json(path, "findings", [], extras={"scanner": "tracker_request", "export_time": _now_iso()})


def _emit_logs(path: Path) -> None:
    _write_envelope_json(path, "sources", [], extras={"siem": "tracker_request"})


def _emit_alerts(path: Path) -> None:
    _write_envelope_json(path, "rules", [], extras={"platform": "tracker_request"})


def _emit_tickets(path: Path) -> None:
    _write_envelope_json(path, "tickets", [], extras={"system": "tracker_request"})


def _emit_poam(path: Path) -> None:
    _write_header_only_csv(
        path, ["poam_id", "weakness_name", "controls", "raw_severity", "status", "asset_identifier", "notes"]
    )


def _emit_discovered_assets(path: Path) -> None:
    _write_envelope_json(path, "assets", [])


def _emit_cloud_events(path: Path, *, with_meta_event: bool) -> None:
    if with_meta_event:
        # `event_type` here is the canonical-event-loader hook into FixtureProvider; it
        # coerces unknown literals to semantic_type='unknown' but preserves everything else
        # in `metadata`. We also stash the synthesized marker in `raw_event_ref` so it
        # survives normalization and can be identified downstream.
        meta = {
            "event_type": "assessment.tracker_loaded",
            "provider": "assessment_tracker",
            "actor": "assessment_tracker_importer",
            "asset_id": "assessment_tracker",
            "timestamp": _now_iso(),
            "raw_event_ref": "assessment_tracker.meta_event:tracker-meta-0001",
            "synthesized_from": "assessment_tracker",
            "narrative": (
                "Synthesized meta-event so the FixtureProvider minimum-bundle gate can load this "
                "scenario for pipeline demonstration. NOT an observed cloud event."
            ),
        }
        _write_envelope_json(path, "events", [meta])
    else:
        _write_envelope_json(path, "events", [])


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------------------------------------------------------------------
# Tracker items + auditor questions + evidence gaps
# ---------------------------------------------------------------------------


_GAP_TYPE_TO_CATEGORY: Mapping[str, str] = {
    "inventory_mismatch": "inventory",
    "scanner_scope_missing": "scanner",
    "vulnerability_scan_evidence_missing": "scanner",
    "credentialed_scan_evidence_missing": "scanner",
    "centralized_log_missing": "logging",
    "local_to_central_log_correlation_missing": "logging",
    "alert_rule_missing": "alerting",
    "alert_sample_missing": "alerting",
    "response_action_missing": "alerting",
    "change_ticket_missing": "change_ticket",
    "sia_missing": "change_ticket",
    "testing_evidence_missing": "change_ticket",
    "approval_missing": "change_ticket",
    "deployment_evidence_missing": "change_ticket",
    "verification_evidence_missing": "change_ticket",
    "exploitation_review_missing": "exploitation_review",
    "poam_update_missing": "poam",
    "deviation_request_missing": "poam",
    "backup_evidence_missing": "backup",
    "restore_test_missing": "backup",
    "identity_listing_missing": "iam",
    "password_policy_evidence_missing": "iam",
    "crypto_fips_evidence_missing": "crypto",
    "traffic_flow_policy_missing": "traffic_flow",
    "unknown": "other",
}


def _category_from_gap_type(gap_type: str) -> str:
    return _GAP_TYPE_TO_CATEGORY.get(gap_type, "other")


# NOTE: structured EvidenceGap / InformationalTrackerItem records are now produced by
# core.evidence_gap.build_evidence_gaps using the classification.classify_tracker_gap
# rules. The legacy `_build_evidence_gaps` helper has been retired in favor of that
# canonical pipeline (see write_evidence_gaps_file in core/evidence_gap.py).


def _build_auditor_questions(rows: list[TrackerRow]) -> str:
    lines: list[str] = []
    lines.append("# Auditor follow-up questions (derived from assessment tracker)\n")
    lines.append(
        "_Generated by `agent.py import-assessment-tracker`. Each question is grounded in a "
        "tracker row's assessor or CSP comment — no invented requirements._\n"
    )
    grouped: dict[str, list[TrackerRow]] = {}
    for r in rows:
        if r.assessor_comment or r.csp_comment:
            grouped.setdefault(r.category, []).append(r)
    if not grouped:
        lines.append("\n_No assessor / CSP comments were present in the tracker._\n")
        return "\n".join(lines)
    for category in sorted(grouped):
        lines.append(f"\n## {category}\n")
        for r in grouped[category]:
            ctl = ", ".join(r.controls) or "(no control id)"
            lines.append(f"- **Row {r.row_index}** ({ctl}) — {r.request_text or '(no request text)'}.")
            if r.assessor_comment:
                lines.append(f"  - Assessor: {r.assessor_comment}")
            if r.csp_comment:
                lines.append(f"  - CSP: {r.csp_comment}")
            if r.owner or r.due_date or r.status:
                meta = []
                if r.owner:
                    meta.append(f"owner={r.owner}")
                if r.due_date:
                    meta.append(f"due={r.due_date}")
                if r.status:
                    meta.append(f"status={r.status}")
                lines.append(f"  - Meta: {', '.join(meta)}")
    return "\n".join(lines).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Top-level entry points
# ---------------------------------------------------------------------------


def import_assessment_tracker(text: str) -> list[TrackerRow]:
    """Pure-function variant: parse text → list of rows. No file IO."""
    return parse_tracker_text(text)


def import_assessment_tracker_to_dir(
    *,
    input_path: Path,
    output_dir: Path,
    with_meta_event: bool = False,
) -> ImportResult:
    """Parse the tracker file at ``input_path`` and write a partial scenario at ``output_dir``."""
    input_path = Path(input_path)
    output_dir = Path(output_dir)
    text = input_path.read_text(encoding="utf-8-sig")
    rows = parse_tracker_text(text)

    output_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    inv = output_dir / "declared_inventory.csv";        _emit_inventory(inv);             written.append(inv)
    targets = output_dir / "scanner_targets.csv";       _emit_scanner_targets(targets);   written.append(targets)
    findings = output_dir / "scanner_findings.json";    _emit_scanner_findings(findings); written.append(findings)
    logs = output_dir / "central_log_sources.json";     _emit_logs(logs);                 written.append(logs)
    alerts = output_dir / "alert_rules.json";           _emit_alerts(alerts);             written.append(alerts)
    tickets = output_dir / "tickets.json";              _emit_tickets(tickets);           written.append(tickets)
    poam = output_dir / "poam.csv";                     _emit_poam(poam);                 written.append(poam)
    discovered = output_dir / "discovered_assets.json"; _emit_discovered_assets(discovered); written.append(discovered)
    events = output_dir / "cloud_events.json";          _emit_cloud_events(events, with_meta_event=with_meta_event); written.append(events)

    tracker_items_path = output_dir / "tracker_items.json"
    tracker_items_path.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "generated_at": _now_iso(),
                "source_input": str(input_path),
                "with_meta_event": bool(with_meta_event),
                "row_count": len(rows),
                "rows": [r.to_dict() for r in rows],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    written.append(tracker_items_path)

    # Structured evidence-gap records: every row → either EvidenceGap or
    # InformationalTrackerItem (no row silently dropped). Schema 2.0.
    from core.evidence_gap import write_evidence_gaps_file

    gaps_path = output_dir / "evidence_gaps.json"
    bundle = write_evidence_gaps_file(
        rows, output_path=gaps_path, source_file=str(tracker_items_path)
    )
    written.append(gaps_path)

    # Legacy gap dicts (kept for backward-compat with the original ImportResult shape).
    gaps = [
        {
            "row_index": int(g.source_item_id) if g.source_item_id.isdigit() else g.source_item_id,
            "controls": g.controls,
            "category": _category_from_gap_type(g.gap_type),
            "request_text": g.description,
            "expected_evidence_files": list(
                CATEGORY_TO_FILES.get(_category_from_gap_type(g.gap_type), ())
            ),
            "owner": g.owner,
            "due_date": g.due_date,
            "status": g.status,
            "narrative": (
                f"{g.title}. Recommended artifact: {g.recommended_artifact or '(none mapped)'}. "
                f"Recommended validation: {g.recommended_validation or '(manual review)'}. "
                f"linked_ksi_ids={g.linked_ksi_ids}"
            ),
            "gap_id": g.gap_id,
            "gap_type": g.gap_type,
            "severity": g.severity,
            "linked_ksi_ids": g.linked_ksi_ids,
            "recommended_artifact": g.recommended_artifact,
            "recommended_validation": g.recommended_validation,
            "poam_required": g.poam_required,
        }
        for g in bundle.evidence_gaps
    ]

    auditor_qs_path = output_dir / "auditor_questions.md"
    auditor_qs_path.write_text(_build_auditor_questions(rows), encoding="utf-8")
    written.append(auditor_qs_path)

    counts: dict[str, int] = {}
    for r in rows:
        counts[r.category] = counts.get(r.category, 0) + 1

    return ImportResult(
        output_dir=output_dir.resolve(),
        rows=rows,
        files_written=[p.resolve() for p in written],
        counts_by_category=counts,
        evidence_gaps=gaps,
    )
