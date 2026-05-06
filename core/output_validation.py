"""Validate generated assessment artifacts (shared by ``agent.py validate`` and ``scripts/validate_outputs.py``)."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from core.failure_narrative_contract import validate_eval_results_fail_partial_contracts

# Canonical eval identifiers expected in ``eval_results.json`` (machine-readable).
REQUIRED_EVAL_IDS: frozenset[str] = frozenset(
    {
        "CM8_INVENTORY_RECONCILIATION",
        "RA5_SCANNER_SCOPE_COVERAGE",
        "AU6_CENTRALIZED_LOG_COVERAGE",
        "SI4_ALERT_INSTRUMENTATION",
        "CROSS_DOMAIN_EVENT_CORRELATION",
        "RA5_EXPLOITATION_REVIEW",
        "CM3_CHANGE_EVIDENCE_LINKAGE",
        "AGENT_TOOL_GOVERNANCE",
        "AGENT_PERMISSION_SCOPE",
        "AGENT_MEMORY_CONTEXT_SAFETY",
        "AGENT_APPROVAL_GATES",
        "AGENT_POLICY_VIOLATIONS",
        "AGENT_AUDITABILITY",
        "CA5_POAM_STATUS",
    }
)

REQUIRED_ARTIFACTS: tuple[str, ...] = (
    "evidence_graph.json",
    "eval_results.json",
    "correlation_report.md",
    "auditor_questions.md",
    "instrumentation_plan.md",
    "poam.csv",
    "evidence_gap_matrix.csv",
    "assessment_summary.json",
)

# ``instrumentation_plan.md`` must mention each platform family.
_INSTRUMENTATION_MARKERS: tuple[tuple[str, str], ...] = (
    ("splunk", "Splunk"),
    ("sentinel", "Sentinel"),
    ("gcp", "GCP"),
    ("aws", "AWS"),
)

# ``auditor_questions.md`` must reference these control families.
_AUDITOR_CONTROL_MARKERS: tuple[str, ...] = (
    "CM-8",
    "RA-5",
    "AU-6",
    "SI-4",
    "CM-3",
    "CA-5",
)

_GAP_MATRIX_ASSESSOR_COLUMNS: frozenset[str] = frozenset(
    {
        "current_state",
        "target_state",
        "priority",
        "estimated_effort",
        "remediation_steps",
    }
)


def _validate_eval_results_structure(data: dict) -> list[str]:
    errs: list[str] = []
    sv = data.get("schema_version")
    if sv is not None and sv not in ("1.2", "1.1", "1.0"):
        errs.append(f"Unexpected schema_version: {sv}")
    for key in ("correlation_id", "overall_result", "evaluations"):
        if key not in data:
            errs.append(f"eval_results.json missing key: {key}")
    if "evaluations" in data:
        for i, e in enumerate(data["evaluations"]):
            if not isinstance(e, dict):
                errs.append(f"evaluations[{i}] is not an object")
                continue
            for k in ("eval_id", "control_refs", "result"):
                if k not in e:
                    errs.append(f"evaluations[{i}] missing {k}")
    sem = data.get("semantic_event") or data.get("event")
    if not sem:
        errs.append("eval_results.json missing semantic_event or event")
    return errs


def _assessor_findings_ok(data: dict) -> list[str]:
    errs: list[str] = []
    required = {
        "control_refs",
        "current_state",
        "target_state",
        "remediation_steps",
        "estimated_effort",
        "priority",
    }
    def check_rows(rows: object, *, label: str) -> None:
        if not isinstance(rows, list):
            return
        for i, e in enumerate(rows):
            if not isinstance(e, dict):
                continue
            if str(e.get("result", "")).upper() not in ("FAIL", "PARTIAL"):
                continue
            findings = e.get("assessor_findings")
            if not isinstance(findings, list) or not findings:
                errs.append(f"{label}[{i}] ({e.get('eval_id')}): missing assessor_findings[]")
                continue
            for j, f in enumerate(findings):
                if not isinstance(f, dict):
                    errs.append(f"{label}[{i}].assessor_findings[{j}] must be an object")
                    continue
                missing = sorted(k for k in required if k not in f)
                if missing:
                    errs.append(
                        f"{label}[{i}].assessor_findings[{j}] missing required key(s): "
                        + ", ".join(missing)
                    )

    check_rows(data.get("evaluations"), label="evaluations")
    check_rows(data.get("eval_result_records"), label="eval_result_records")
    return errs


def _eval_ids_from_results(data: dict) -> set[str]:
    out: set[str] = set()
    for e in data.get("evaluations", []):
        if isinstance(e, dict) and e.get("eval_id"):
            out.add(str(e["eval_id"]))
    for e in data.get("eval_result_records", []) or []:
        if isinstance(e, dict) and e.get("eval_id"):
            out.add(str(e["eval_id"]))
    return out


def _count_fail_evaluations(data: dict) -> int:
    n = 0
    for e in data.get("evaluations", []):
        if isinstance(e, dict) and str(e.get("result", "")).upper() == "FAIL":
            n += 1
    return n


def _poam_has_generated_row(path: Path) -> bool:
    """True if CSV contains at least one auto-generated POA&M row (``POAM-AUTO-`` prefix)."""
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return False
    lines = text.strip().splitlines()
    if len(lines) < 2:
        return False
    reader = csv.DictReader(lines)
    for row in reader:
        pid = (row.get("poam_id") or row.get("POAM ID") or row.get("POA&M ID") or "").strip()
        if pid.startswith("POAM-AUTO"):
            return True
    return False


def _evidence_gap_matrix_ok(path: Path) -> list[str]:
    try:
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            headers = set(reader.fieldnames or [])
    except OSError as e:
        return [f"evidence_gap_matrix.csv: cannot read ({e})"]
    missing = sorted(_GAP_MATRIX_ASSESSOR_COLUMNS - headers)
    if missing:
        return ["evidence_gap_matrix.csv: missing assessor column(s): " + ", ".join(missing)]
    return []


def _node_count(nodes: object) -> int:
    """Count graph nodes whether ``nodes`` is a flat list or a versioned bucket dict."""
    if isinstance(nodes, list):
        return len(nodes)
    if isinstance(nodes, dict):
        n = 0
        for v in nodes.values():
            if isinstance(v, list):
                n += len(v)
        return n
    return 0


def _evidence_graph_ok(path: Path) -> tuple[bool, str]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        return False, f"evidence_graph.json: cannot parse ({e})"
    if not isinstance(data, dict):
        return False, "evidence_graph.json: root must be an object"
    nodes = data.get("nodes")
    edges = data.get("edges")
    if not isinstance(edges, list) or len(edges) == 0:
        return False, "evidence_graph.json: edges must be a non-empty array"
    if _node_count(nodes) == 0:
        return False, "evidence_graph.json: nodes must not be empty"
    return True, ""


def _evidence_graph_schema_ok(path: Path) -> tuple[bool, str]:
    """Optional JSON Schema validation when ``jsonschema`` is available."""
    try:
        import jsonschema
    except ImportError:
        return True, ""
    pkg_root = Path(__file__).resolve().parents[1]
    schema_path = pkg_root / "schemas" / "evidence-graph.schema.json"
    if not schema_path.is_file():
        return True, ""
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
        data = json.loads(path.read_text(encoding="utf-8"))
        jsonschema.validate(instance=data, schema=schema)
    except json.JSONDecodeError as e:
        return False, f"evidence_graph.json schema check: invalid JSON ({e})"
    except jsonschema.ValidationError as e:
        return False, f"evidence_graph.json: schema validation failed: {e.message}"
    except OSError as e:
        return False, f"evidence_graph.json schema: cannot read ({e})"
    return True, ""


def _instrumentation_plan_ok(path: Path) -> list[str]:
    errs: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [f"instrumentation_plan.md: cannot read ({e})"]
    lower = text.lower()
    for needle, label in _INSTRUMENTATION_MARKERS:
        if needle not in lower:
            errs.append(f"instrumentation_plan.md: missing {label} section or marker ({needle!r})")
    return errs


def _auditor_questions_ok(path: Path) -> list[str]:
    errs: list[str] = []
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as e:
        return [f"auditor_questions.md: cannot read ({e})"]
    for marker in _AUDITOR_CONTROL_MARKERS:
        if marker not in text:
            errs.append(f"auditor_questions.md: missing control reference {marker!r}")
    return errs


def validate_evidence_package(output_dir: Path, *, mode: str = "demo") -> list[str]:
    """
    Validate that ``output_dir`` contains a complete evidence package.

    Returns a list of human-readable errors (empty means success).

    ``mode="demo"`` preserves fixture/demo expectations: at least one FAIL and
    at least one generated POA&M row. ``mode="live"`` is for arbitrary cloud
    environments, where all checks may pass and no POA&M rows may be required.
    """
    mode = (mode or "demo").strip().lower()
    if mode not in {"demo", "live"}:
        return [f"Unknown validation mode: {mode!r} (expected demo or live)"]
    od = output_dir.resolve()
    errors: list[str] = []

    for name in REQUIRED_ARTIFACTS:
        p = od / name
        if not p.is_file():
            errors.append(f"Missing required artifact: {p}")

    eg = od / "evidence_graph.json"
    if eg.is_file():
        ok, msg = _evidence_graph_ok(eg)
        if not ok:
            errors.append(msg)
        else:
            sok, smsg = _evidence_graph_schema_ok(eg)
            if not sok:
                errors.append(smsg)

    er_path = od / "eval_results.json"
    if er_path.is_file():
        try:
            data = json.loads(er_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"Invalid JSON in eval_results.json: {e}")
        else:
            struct_errs = _validate_eval_results_structure(data)
            errors.extend(struct_errs)
            found = _eval_ids_from_results(data)
            missing = sorted(REQUIRED_EVAL_IDS - found)
            if missing:
                errors.append(
                    "eval_results.json missing required eval_id(s): " + ", ".join(missing),
                )
            if mode == "demo" and isinstance(data.get("evaluations"), list) and _count_fail_evaluations(data) < 1:
                errors.append(
                    "eval_results.json: expected at least one evaluation with result FAIL "
                    "(fixture-style gap assessment).",
                )
            errors.extend(_assessor_findings_ok(data))
            errors.extend(validate_eval_results_fail_partial_contracts(data))

    inst = od / "instrumentation_plan.md"
    if inst.is_file():
        errors.extend(_instrumentation_plan_ok(inst))

    aud = od / "auditor_questions.md"
    if aud.is_file():
        errors.extend(_auditor_questions_ok(aud))

    poam = od / "poam.csv"
    if mode == "demo" and poam.is_file() and not _poam_has_generated_row(poam):
        errors.append(
            "poam.csv: expected at least one generated row (poam_id starting with POAM-AUTO-).",
        )

    matrix = od / "evidence_gap_matrix.csv"
    if matrix.is_file():
        errors.extend(_evidence_gap_matrix_ok(matrix))

    return errors


def validate_output_directory(output_dir: Path, *, mode: str = "demo") -> tuple[list[str], list[str]]:
    """
    Backward-compatible API: validate the evidence package.

    Returns ``(errors, warnings)``. Warnings are currently unused.
    """
    errs = validate_evidence_package(output_dir, mode=mode)
    return errs, []
