#!/usr/bin/env python3
"""
Observable Security Agent — proves an authorization-ready evidence chain (controls → KSI →
validation → sources → machine results → findings → POA&M → narratives → reconciliation),
not a CSPM scanner, not only a crosswalk, and not a standalone report generator. Evaluations
use only loaded evidence; missing evidence is a first-class FAIL/PARTIAL outcome—never invented.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent
SCHEMAS_DIR = ROOT / "schemas"
MAPPINGS_DIR = ROOT / "mappings"
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.agent_security_outputs import write_agent_security_bundle  # noqa: E402
from core.control_mapper import EVAL_IDS_IN_RUN_ORDER, get_controls_for_eval  # noqa: E402
from core.evaluator import run_evaluations  # noqa: E402
from core.evidence_graph import evidence_graph_from_assessment_bundle  # noqa: E402
from core.human_review import (  # noqa: E402
    filter_review_history,
    list_pending_recommendations,
    load_recommendations,
    load_review_history,
    record_review_decision,
)
from core.models import AssessmentBundle, EvalResult as CanonicalEval  # noqa: E402
from core.normalizer import load_normalized_primary_event  # noqa: E402
from core.output_validation import validate_output_directory  # noqa: E402
from core.pipeline_models import EvalStatus  # noqa: E402
from core.pipeline_models import PipelineCorrelationBundle as CorrelationBundle  # noqa: E402
from core.pipeline_models import PipelineEvalResult  # noqa: E402
from core.pipeline_models import PipelineEvidenceBundle as EvidenceBundle  # noqa: E402
from core.poam import poam_items_from_written_csv  # noqa: E402
from core.poam import write_poam_csv  # noqa: E402
from core.report_writer import (  # noqa: E402
    correlation_bundle_from_eval_results,
    write_agent_instrumentation_plan,
    write_instrumentation_plan,
    write_output_bundle,
)
from core.utils import build_asset_evidence, load_csv_rows, load_json  # noqa: E402
from providers.aws import AwsEvidenceProvider  # noqa: E402
from evals.agent_eval_support import load_agent_assessment_bundle  # noqa: E402
from providers.fixture import FixtureProvider, assessment_bundle_from_evidence_bundle  # noqa: E402
from fedramp20x.package_builder import build_20x_package  # noqa: E402
from fedramp20x.reconciliation import run_reconciliation_cli  # noqa: E402
from fedramp20x.schema_validator import validate_package  # noqa: E402

DEFAULT_FIXTURE_SCENARIO = "scenario_public_admin_vuln_event"

# Human-readable titles for console / list-evals (aligned with assessment narrative).
EVAL_CONSOLE_TITLES: dict[str, str] = {
    "CM8_INVENTORY_RECONCILIATION": "CM-8 Inventory Reconciliation",
    "RA5_SCANNER_SCOPE_COVERAGE": "RA-5 Scanner Scope Coverage",
    "AU6_CENTRALIZED_LOG_COVERAGE": "AU-6/AU-12 Centralized Log Coverage",
    "SI4_ALERT_INSTRUMENTATION": "SI-4 Alert Instrumentation Coverage",
    "CROSS_DOMAIN_EVENT_CORRELATION": "Cross-Domain Security Event Correlation",
    "RA5_EXPLOITATION_REVIEW": "RA-5(8) High/Critical Vulnerability Exploitation Review",
    "CM3_CHANGE_EVIDENCE_LINKAGE": "CM-3/SI-2 Change Evidence Linkage",
    "AGENT_TOOL_GOVERNANCE": "Agent tool governance",
    "AGENT_PERMISSION_SCOPE": "Agent permission scope",
    "AGENT_MEMORY_CONTEXT_SAFETY": "Agent memory context safety",
    "AGENT_APPROVAL_GATES": "Agent approval gates",
    "AGENT_POLICY_VIOLATIONS": "Agent policy violations",
    "AGENT_AUDITABILITY": "Agent auditability",
    "CA5_POAM_STATUS": "CA-5 POA&M rows generated",
}


def _artifact_rel_str(out_dir: Path, name: str) -> str:
    full = (out_dir / name).resolve()
    try:
        return str(full.relative_to(Path.cwd()))
    except ValueError:
        return str(full)


def _load_aws_permission_coverage(raw_evidence: Path | None) -> dict[str, object] | None:
    if raw_evidence is None:
        return None
    for path in (raw_evidence / "manifest.json", raw_evidence / "collection_manifest.json"):
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(data, dict) and isinstance(data.get("permission_coverage"), dict):
            return data["permission_coverage"]
    return None


def _merge_live_permission_summary(out_dir: Path, raw_evidence: Path | None) -> None:
    coverage = _load_aws_permission_coverage(raw_evidence)
    if not coverage:
        return
    summary_path = out_dir / "assessment_summary.json"
    if not summary_path.is_file():
        return
    try:
        summary = json.loads(summary_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(summary, dict):
        return
    summary["permission_coverage"] = coverage
    summary_path.write_text(json.dumps(summary, indent=2, default=str), encoding="utf-8")


def _apply_bundle_overrides(bundle: EvidenceBundle, args: argparse.Namespace) -> None:
    if p := getattr(args, "declared_inventory", None):
        pp = Path(p)
        if pp.is_file():
            bundle.declared_inventory_rows = load_csv_rows(pp)
    if p := getattr(args, "scanner_targets", None):
        pp = Path(p)
        if pp.is_file():
            bundle.scanner_target_rows = load_csv_rows(pp)
    if p := getattr(args, "scanner_findings", None):
        pp = Path(p)
        if pp.is_file():
            bundle.scanner_findings = load_json(pp)
    if p := getattr(args, "tickets", None):
        pp = Path(p)
        if pp.is_file():
            bundle.tickets = load_json(pp)
    if p := getattr(args, "poam", None):
        pp = Path(p)
        if pp.is_file():
            bundle.poam_seed_rows = load_csv_rows(pp)


def _resolve_fixture_root(args: argparse.Namespace) -> Path:
    if getattr(args, "fixture_dir", None):
        return Path(args.fixture_dir).resolve()
    scen = args.scenario or DEFAULT_FIXTURE_SCENARIO
    return (ROOT / "fixtures" / scen).resolve()


def _aws_evidence_root(args: argparse.Namespace) -> Path | None:
    raw = getattr(args, "raw_evidence_dir", None) or getattr(args, "evidence_dir", None)
    if raw is None:
        return None
    return Path(raw).resolve()


def _pipeline_eval_to_canonical(p: PipelineEvalResult) -> CanonicalEval:
    r = p.result
    if r == EvalStatus.FAIL:
        res: str = "FAIL"
    elif r in (EvalStatus.PARTIAL, EvalStatus.OPEN, EvalStatus.GENERATED):
        res = "PARTIAL"
    else:
        res = "PASS"
    m = p.machine or {}
    gaps_raw = m.get("gaps")
    gaps_list: list[str] = list(gaps_raw) if isinstance(gaps_raw, list) else []
    aa_raw = m.get("affected_assets")
    aa_list: list[str] = list(aa_raw) if isinstance(aa_raw, list) else []
    return CanonicalEval(
        eval_id=p.eval_id,
        name=str(m.get("name", p.eval_id)),
        result=res,  # type: ignore[arg-type]
        controls=list(p.control_refs),
        severity=str(m.get("severity", "moderate")),
        summary=str(m.get("summary", "")),
        evidence=list(p.evidence),
        gaps=gaps_list,
        affected_assets=aa_list,
        recommended_actions=[],
    )


def _assessment_for_evidence_graph(evidence: EvidenceBundle, out_dir: Path) -> AssessmentBundle:
    base = assessment_bundle_from_evidence_bundle(evidence)
    poam_path = out_dir / "poam.csv"
    if not poam_path.is_file():
        return base
    merged = poam_items_from_written_csv(poam_path)
    if not merged:
        return base
    return base.model_copy(update={"poam_items": merged})


def _print_assessment_summary(
    *,
    provider: str,
    scenario_root: Path,
    raw_evidence: Path | None,
    assessment: AssessmentBundle,
    result_bundle: CorrelationBundle,
    out_dir: Path,
    extra_artifact_names: list[str] | None = None,
) -> None:
    print("Multi-Cloud Security Evidence Agent")
    print("")
    print(f"Provider: {provider}")
    if provider == "fixture":
        print(f"Scenario: {scenario_root.name}")
    elif raw_evidence is not None:
        print(f"Raw evidence: {raw_evidence}")
    print("")
    print(f"Assets: {len(assessment.assets)}")
    print(f"Events: {len(assessment.events)}")
    print(f"Scanner findings: {len(assessment.scanner_findings)}")
    print(f"Alert rules: {len(assessment.alert_rules)}")
    print(f"Tickets: {len(assessment.tickets)}")
    print("")
    print("Evaluations:")
    for r in result_bundle.eval_results:
        title = EVAL_CONSOLE_TITLES.get(r.eval_id, r.eval_id)
        print(f"[{r.result.value}] {title}")
    print("")
    print("Artifacts:")
    for name in (
        "evidence_graph.json",
        "eval_results.json",
        "correlation_report.md",
        "auditor_questions.md",
        "instrumentation_plan.md",
        "agent_instrumentation_plan.md",
        "poam.csv",
        "evidence_gap_matrix.csv",
        "assessment_summary.json",
    ):
        print(_artifact_rel_str(out_dir, name))
    if extra_artifact_names:
        for name in extra_artifact_names:
            print(_artifact_rel_str(out_dir, name))


def cmd_assess(args: argparse.Namespace) -> int:
    scenario_root: Path
    raw_evidence: Path | None = None

    if args.provider == "fixture":
        scenario_root = _resolve_fixture_root(args)
        prov = FixtureProvider(scenario_root)
        bundle = prov.load()
    elif args.provider == "aws":
        raw_root = _aws_evidence_root(args)
        if raw_root is None:
            print(
                "--raw-evidence-dir is required when --provider aws "
                "(or deprecated --evidence-dir).",
                file=sys.stderr,
            )
            return 2
        raw_evidence = raw_root
        scenario_root = raw_root
        prov = AwsEvidenceProvider(raw_root)
        bundle = prov.load()
    else:
        print(f"Unknown provider: {args.provider}", file=sys.stderr)
        return 2

    _apply_bundle_overrides(bundle, args)

    semantic_event, _events = load_normalized_primary_event(bundle)
    asset_evidence = build_asset_evidence(bundle, semantic_event.asset_id)

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    result_bundle = run_evaluations(bundle, semantic_event, asset_evidence, output_dir=out_dir)

    assessment_g = _assessment_for_evidence_graph(bundle, out_dir)
    canonical_evals = [_pipeline_eval_to_canonical(p) for p in result_bundle.eval_results]
    graph_obj = evidence_graph_from_assessment_bundle(
        assessment_g,
        eval_results=canonical_evals,
        source_root=scenario_root,
    )
    graph = graph_obj.to_dict()
    (out_dir / "evidence_graph.json").write_text(
        json.dumps(graph, indent=2, default=str),
        encoding="utf-8",
    )

    write_instrumentation_plan(out_dir / "instrumentation_plan.md", result_bundle)
    write_agent_instrumentation_plan(
        out_dir / "agent_instrumentation_plan.md",
        bundle=result_bundle,
        evidence_bundle=bundle,
    )

    assessment = assessment_bundle_from_evidence_bundle(bundle)
    corr_path = out_dir / "correlations.json"
    correlations_data = json.loads(corr_path.read_text(encoding="utf-8")) if corr_path.is_file() else None
    write_output_bundle(
        out_dir,
        result_bundle,
        assessment=assessment,
        evidence_graph=graph,
        correlations_data=correlations_data,
        assessment_mode=getattr(args, "mode", "demo"),
    )
    if args.provider == "aws":
        _merge_live_permission_summary(out_dir, raw_evidence)

    extra_agent_artifacts: list[str] | None = None
    if getattr(args, "include_agent_security", False):
        agent_bundle = load_agent_assessment_bundle(scenario_root)
        if agent_bundle is not None:
            extra_agent_artifacts = [
                Path(p).name for p in write_agent_security_bundle(out_dir, full_bundle=result_bundle, agent_assessment=agent_bundle)
            ]
            from core.secure_agent_architecture import write_secure_agent_architecture

            write_secure_agent_architecture(out_dir / "secure_agent_architecture.md", repo_root=ROOT)
            extra_agent_artifacts.append("secure_agent_architecture.md")
        else:
            print(
                "Note: --include-agent-security was set but no agent telemetry was found "
                "(expected agent_identities.json or agent_security/agent_assessment.json next to the scenario).",
                file=sys.stderr,
            )

    _print_assessment_summary(
        provider=args.provider,
        scenario_root=scenario_root,
        raw_evidence=raw_evidence,
        assessment=assessment,
        result_bundle=result_bundle,
        out_dir=out_dir,
        extra_artifact_names=extra_agent_artifacts,
    )
    return 0


def cmd_secure_agent_arch(args: argparse.Namespace) -> int:
    from core.secure_agent_architecture import write_secure_agent_architecture

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    dest = out_dir / "secure_agent_architecture.md"
    write_secure_agent_architecture(dest, repo_root=ROOT)
    print(f"Wrote {dest}")
    return 0


def cmd_threat_hunt(args: argparse.Namespace) -> int:
    """Hypothesis-driven agentic-AI threat hunt; writes threat_hunt_* and agentic_risk_poam.csv."""
    from core.threat_hunt_agentic import load_agent_bundle_for_hunt, run_agentic_threat_hunt

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.provider == "fixture":
        evidence_root = _resolve_fixture_root(args)
        prov = FixtureProvider(evidence_root)
        bundle = prov.load()
    elif args.provider == "aws":
        raw_root = _aws_evidence_root(args)
        if raw_root is None:
            print(
                "threat-hunt --provider aws requires --raw-evidence-dir "
                "(or deprecated --evidence-dir) pointing at canonical evidence files.",
                file=sys.stderr,
            )
            return 2
        evidence_root = raw_root.resolve()
        bundle = AwsEvidenceProvider(evidence_root).load()
    else:
        print(f"Unknown provider: {args.provider}", file=sys.stderr)
        return 2

    agent_root = Path(args.agent_telemetry).resolve() if getattr(args, "agent_telemetry", None) else evidence_root
    agent_bundle = load_agent_bundle_for_hunt(agent_root)

    paths = run_agentic_threat_hunt(
        evidence_root=evidence_root,
        agent_telemetry_root=agent_root,
        bundle=bundle,
        agent_assessment=agent_bundle,
        output_dir=out_dir,
    )
    print("Threat hunt (agentic AI risk)")
    print("")
    for p in paths:
        print(f"  {p}")
    return 0


def cmd_run_agent(args: argparse.Namespace) -> int:
    """Bounded autonomous loop (observe → plan → act → verify → explain); local artifacts only.

    Two modes:

    * Default (legacy) — runs ``run_bounded_agent_loop`` over a fixture scenario.
    * ``--workflow tracker-to-20x`` — runs the categorical task graph end-to-end
      starting from an assessment tracker file (no live cloud credentials).
    """
    from agent_loop.runner import run_bounded_agent_loop, run_tracker_to_20x_workflow

    workflow = getattr(args, "workflow", None)
    cfg = Path(args.config).resolve() if args.config else (ROOT / "config")
    sch = Path(args.schemas).resolve() if args.schemas else None
    mdir = Path(args.mappings).resolve() if args.mappings else None

    if workflow == "tracker-to-20x":
        if not getattr(args, "input", None):
            print(
                "run-agent --workflow tracker-to-20x requires --input <tracker.csv>",
                file=sys.stderr,
            )
            return 2
        out_dir = Path(args.output_dir).resolve()
        pkg_out = (
            Path(args.package_output).resolve()
            if getattr(args, "package_output", None)
            else (out_dir / "package_tracker")
        )
        return run_tracker_to_20x_workflow(
            repo_root=ROOT,
            input_path=Path(args.input).resolve(),
            output_dir=out_dir,
            package_output=pkg_out,
            config_dir=cfg,
            schemas_dir=sch,
            mappings_dir=mdir,
            workflow_name="tracker-to-20x",
        )

    if args.provider != "fixture":
        print("run-agent: only --provider fixture is supported in this release.", file=sys.stderr)
        return 2
    pkg_out_legacy = (
        Path(args.package_output).resolve()
        if getattr(args, "package_output", None)
        else (Path("output") / "agent_run_20x").resolve()
    )
    return run_bounded_agent_loop(
        repo_root=ROOT,
        provider=args.provider,
        scenario=args.scenario,
        fixture_dir=getattr(args, "fixture_dir", None),
        output_dir=Path(args.output_dir).resolve(),
        package_output=pkg_out_legacy,
        config_dir=cfg,
        schemas_dir=sch,
        mappings_dir=mdir,
        include_agent_security=not bool(getattr(args, "no_include_agent_security", False)),
    )


def cmd_report(args: argparse.Namespace) -> int:
    input_path = Path(args.input).resolve()
    if not input_path.is_file():
        print(f"Input not found: {input_path}", file=sys.stderr)
        return 2
    data = json.loads(input_path.read_text(encoding="utf-8"))
    bundle = correlation_bundle_from_eval_results(data)

    out_dir = Path(args.output_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    write_poam_csv(out_dir / "poam.csv", bundle)
    write_instrumentation_plan(out_dir / "instrumentation_plan.md", bundle)
    write_agent_instrumentation_plan(out_dir / "agent_instrumentation_plan.md", bundle=bundle, evidence_bundle=None)

    corr_path = input_path.parent / "correlations.json"
    correlations_data = json.loads(corr_path.read_text(encoding="utf-8")) if corr_path.is_file() else None
    write_output_bundle(
        out_dir,
        bundle,
        assessment=None,
        evidence_graph=None,
        correlations_data=correlations_data,
        assessment_mode="demo",
    )
    print(f"Regenerated reports under {out_dir}")
    return 0


def cmd_list_evals(_args: argparse.Namespace) -> int:
    print("Registered evaluations (run order) and NIST 800-53 control mappings:")
    print("")
    for eid in EVAL_IDS_IN_RUN_ORDER:
        title = EVAL_CONSOLE_TITLES.get(eid, eid)
        ctrls = get_controls_for_eval(eid)
        ctrl_s = ", ".join(ctrls) if ctrls else "(none)"
        print(f"{eid}")
        print(f"  Title: {title}")
        print(f"  Controls: {ctrl_s}")
        print("")
    return 0


def cmd_run_evals(args: argparse.Namespace) -> int:
    """Run the offline platform evaluation harness."""

    from core.eval_harness import DEFAULT_EVAL_FIXTURE, run_eval_harness

    output_dir = Path(args.output_dir).resolve()
    fixture_path = Path(args.input).resolve() if getattr(args, "input", None) else DEFAULT_EVAL_FIXTURE
    doc = run_eval_harness(fixture_path=fixture_path, output_dir=output_dir)
    summary = doc["summary"]
    print("Observable Security Agent eval harness")
    print("")
    print(f"Fixture: {fixture_path}")
    print(f"Output:  {output_dir}")
    print(f"Passed:  {summary['passed']}/{summary['total']}")
    print(f"Failed:  {summary['failed']}/{summary['total']}")
    print("")
    print(output_dir / "eval_results.json")
    print(output_dir / "eval_summary.md")
    return 0 if int(summary["failed"]) == 0 else 1


def cmd_golden_path_demo(args: argparse.Namespace) -> int:
    """Run the offline end-to-end assurance package golden path."""

    from core.golden_path import DEFAULT_FIXTURE_DIR, DEFAULT_OUTPUT_DIR, run_golden_path_demo

    fixture_dir = Path(args.fixture_dir).resolve() if getattr(args, "fixture_dir", None) else DEFAULT_FIXTURE_DIR
    output_dir = Path(args.output_dir).resolve() if getattr(args, "output_dir", None) else DEFAULT_OUTPUT_DIR
    result = run_golden_path_demo(fixture_dir=fixture_dir, output_dir=output_dir)
    print("Observable Security Agent golden path demo")
    print("")
    print(f"Fixture: {fixture_dir}")
    print(f"Output:  {output_dir}")
    print(f"Schema:  {'PASS' if result['schemaValid'] else 'FAIL'}")
    print(f"Evals:   {'PASS' if result['evalsPassed'] else 'FAIL'}")
    print("")
    print(output_dir / "assurance-package.json")
    print(output_dir / "metrics.json")
    print(output_dir / "eval_results.json")
    print(output_dir / "agent-run-log.json")
    return 0 if result["schemaValid"] and result["evalsPassed"] else 1


def _parse_cli_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def cmd_debug_context(args: argparse.Namespace) -> int:
    """Build a deterministic RAG context debug document from offline fixture data."""

    from core.eval_harness import DEFAULT_EVAL_FIXTURE, _control, _evidence, _finding, load_eval_cases
    from core.rag_context_debug import rag_context_debug_document, write_rag_context_debug_document
    from core.rag_context_builder import build_rag_context

    fixture_path = Path(args.input).resolve() if getattr(args, "input", None) else DEFAULT_EVAL_FIXTURE
    cases = load_eval_cases(fixture_path)
    controls = []
    evidence = []
    findings = []
    for case in cases:
        inputs = case.get("inputs") or {}
        controls.extend(_control(row) for row in inputs.get("controls") or [])
        start_evidence_index = len(evidence)
        evidence.extend(_evidence(row, start_evidence_index + i + 1) for i, row in enumerate(inputs.get("evidence") or []))
        start_finding_index = len(findings)
        findings.extend(_finding(row, start_finding_index + i + 1) for i, row in enumerate(inputs.get("findings") or []))

    # De-dupe controls by controlId while preserving first definition.
    by_control: dict[str, Any] = {}
    for control in controls:
        by_control.setdefault(control.control_id, control)

    request = f"Debug RAG context for {args.control}."
    bundle = build_rag_context(
        user_request=request,
        control_ids=[args.control],
        asset_ids=[args.asset] if args.asset else [],
        account_ids=[args.account] if args.account else [],
        time_window_start=_parse_cli_datetime(getattr(args, "from_date", None)),
        time_window_end=_parse_cli_datetime(getattr(args, "to_date", None)),
        evidence_artifacts=evidence,
        findings=findings,
        controls=list(by_control.values()),
    )
    document = rag_context_debug_document(bundle)
    if args.output:
        path = write_rag_context_debug_document(Path(args.output).resolve(), document)
        print(path)
    else:
        print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=False))
    return 0


def cmd_import_findings(args: argparse.Namespace) -> int:
    """Convert scanner exports into ``scanner_findings.json`` under a scenario dir (or legacy .json path).

    Scanner rows are **input only**; KSI pass/fail and coverage remain driven by evidence-chain evals.
    """
    inp = Path(args.input).resolve()
    outp = Path(args.output).resolve()
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 2
    fmt = str(args.format).strip().lower()
    emit_events = not getattr(args, "no_security_events", False)
    if fmt in ("auto", "universal", "nessus", "electriceye"):
        from providers.scanner_router import import_scanner_to_file

        router_fmt = "auto" if fmt in ("auto", "universal") else fmt
        dest = import_scanner_to_file(inp, outp, source_format=router_fmt, emit_security_events=emit_events)
    elif fmt == "prowler":
        from providers.prowler import import_prowler_to_file

        dest = import_prowler_to_file(inp, outp, emit_security_events=emit_events)
    elif fmt == "cloudsploit":
        from providers.cloudsploit import import_cloudsploit_to_file

        dest = import_cloudsploit_to_file(inp, outp, emit_security_events=emit_events)
    elif fmt == "ocsf":
        from providers.ocsf import import_ocsf_to_file
        from providers.prowler import resolve_scanner_findings_output_path

        dest = resolve_scanner_findings_output_path(outp)
        import_ocsf_to_file(inp, dest, emit_security_events=emit_events)
    else:
        print(
            f"Unknown --format {args.format!r} (use auto, prowler, cloudsploit, ocsf, electriceye, or nessus)",
            file=sys.stderr,
        )
        return 2
    print(f"Wrote {dest}")
    return 0


def cmd_import_tickets(args: argparse.Namespace) -> int:
    inp = Path(args.input).resolve()
    outp = Path(args.output).resolve()
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 2
    from providers.ticket_export import import_tickets_to_file

    dest = import_tickets_to_file(inp, outp, default_system=args.system)
    print(f"Wrote {dest}")
    return 0


def cmd_import_inventory_graph(args: argparse.Namespace) -> int:
    inp = Path(args.input).resolve()
    outp = Path(args.output).resolve()
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 2
    from providers.inventory_graph import import_graph_assets_to_file

    dest = import_graph_assets_to_file(inp, outp)
    print(f"Wrote {dest}")
    return 0


def cmd_export_ocsf(args: argparse.Namespace) -> int:
    """Write an OCSF-like JSON bundle (events + detection findings) from normalized assessment inputs."""
    from normalization.ocsf_export import FORMAT_LABEL, export_ocsf_like_json

    assessment = Path(args.assessment_output).resolve()
    out_arg = Path(args.output)
    dest = out_arg if out_arg.is_absolute() else (assessment / out_arg)
    export_ocsf_like_json(assessment, dest)
    print(f"Wrote {FORMAT_LABEL} bundle: {dest}")
    return 0


def cmd_import_assessment_tracker(args: argparse.Namespace) -> int:
    """Convert a FedRAMP assessment-tracker CSV/TSV/text into a partial fixture scenario."""
    from normalization.assessment_tracker_import import import_assessment_tracker_to_dir

    inp = Path(args.input).resolve()
    outp = Path(args.output).resolve()
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 2
    result = import_assessment_tracker_to_dir(
        input_path=inp,
        output_dir=outp,
        with_meta_event=bool(getattr(args, "with_meta_event", False)),
    )
    print(f"Parsed {len(result.rows)} tracker rows from {inp}")
    if result.counts_by_category:
        cats = ", ".join(f"{k}={v}" for k, v in sorted(result.counts_by_category.items()))
        print(f"Categories: {cats}")
    print(f"Open evidence gaps: {len(result.evidence_gaps)}")
    print(f"Output directory: {result.output_dir}")
    print("Files written:")
    for p in result.files_written:
        print(f"  {p}")
    if not getattr(args, "with_meta_event", False):
        print(
            "Note: cloud_events.json was emitted empty (no invented evidence). To exercise the "
            "full FixtureProvider pipeline, re-run with --with-meta-event or add real events."
        )
    return 0


def cmd_assess_tracker(args: argparse.Namespace) -> int:
    """End-to-end: import a tracker file, run TRACKER_EVIDENCE_GAP_ANALYSIS, write reports."""
    import json as _json

    from evals.tracker_evidence_gap_eval import run_tracker_evidence_gap_eval
    from evals.tracker_evidence_gap_report import write_all_tracker_gap_outputs
    from normalization.assessment_tracker_import import import_assessment_tracker_to_dir

    inp = Path(args.input).resolve()
    out_dir = Path(args.output_dir).resolve()
    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    scenario_dir = out_dir / "scenario_from_tracker"

    import_result = import_assessment_tracker_to_dir(
        input_path=inp,
        output_dir=scenario_dir,
        with_meta_event=bool(getattr(args, "with_meta_event", False)),
    )

    gaps_path = scenario_dir / "evidence_gaps.json"
    if not gaps_path.exists():
        print(f"Importer did not produce evidence_gaps.json at {gaps_path}", file=sys.stderr)
        return 2
    envelope = _json.loads(gaps_path.read_text(encoding="utf-8"))
    eval_result = run_tracker_evidence_gap_eval(evidence_gaps_envelope=envelope)

    written = write_all_tracker_gap_outputs(
        eval_result,
        output_dir=out_dir,
        source_questions_md=scenario_dir / "auditor_questions.md",
    )

    print(
        f"Parsed {len(import_result.rows)} tracker rows "
        f"({len(import_result.evidence_gaps)} evidence gaps).",
    )
    print(
        f"Eval result: {eval_result.eval_result.result} "
        f"(severity={eval_result.eval_result.severity}, "
        f"open_gaps={eval_result.total_open_gaps}, "
        f"high_impact={eval_result.high_impact_count}, "
        f"poam_required={eval_result.poam_required_count}).",
    )
    print(f"Output directory: {out_dir}")
    for name, p in written.items():
        print(f"  {name}: {p}")
    return 0


def _tracker_eval_to_evaluation_record(eval_result: Any) -> dict[str, Any]:
    """Coerce the canonical EvalResult from the tracker eval into the legacy
    ``evaluations[]`` schema used by ``eval_results.json`` (so build_20x_package
    sees it and rolls it into KSIs / findings)."""
    record = {
        "eval_id": eval_result.eval_id,
        "name": eval_result.name,
        "control_refs": list(eval_result.controls or []),
        "result": eval_result.result,
        "evidence": list(eval_result.evidence or []),
        "gap": (eval_result.gaps[0] if eval_result.gaps else (eval_result.summary or "")),
        "gaps": list(eval_result.gaps or []),
        "recommended_action": "; ".join(eval_result.recommended_actions or []),
        "recommended_actions": list(eval_result.recommended_actions or []),
        "severity": eval_result.severity,
        "summary": eval_result.summary,
        "affected_assets": list(eval_result.affected_assets or []),
        "remediation_disposition": "poam_or_risk_acceptance",
    }
    record["assessor_findings"] = _assessor_findings_for_tracker_eval_record(record)
    return record


def _assessor_findings_for_tracker_eval_record(record: dict[str, Any]) -> list[dict[str, Any]]:
    if str(record.get("result") or "").upper() == "PASS":
        return []
    gaps = [str(x).strip() for x in (record.get("gaps") or []) if str(x).strip()]
    actions = [str(x).strip() for x in (record.get("recommended_actions") or []) if str(x).strip()]
    if not actions and str(record.get("recommended_action") or "").strip():
        actions = [x.strip() for x in str(record["recommended_action"]).split(";") if x.strip()]
    if not actions:
        actions = [
            "Collect the requested tracker evidence artifact.",
            "Link the artifact to the affected tracker row and control/KSI.",
            "Re-run tracker-to-20x and retain the validation outputs.",
        ]
    controls = [str(x).strip() for x in (record.get("control_refs") or []) if str(x).strip()]
    affected = [str(x).strip() for x in (record.get("affected_assets") or []) if str(x).strip()]
    out: list[dict[str, Any]] = []
    for i, gap in enumerate(gaps or [str(record.get("gap") or record.get("summary") or "Tracker evidence gap")], start=1):
        out.append(
            {
                "finding_id": f"{record.get('eval_id')}-GAP-{i:03d}",
                "control_refs": controls,
                "current_state": gap,
                "target_state": (
                    "Each open tracker row has objective evidence attached, mapped to the cited "
                    "control/KSI, and retestable from the generated tracker-to-20x package."
                ),
                "remediation_steps": actions,
                "estimated_effort": "0.5-2 days",
                "priority": "critical"
                if str(record.get("severity") or "").lower() == "critical"
                else ("high" if str(record.get("result") or "").upper() == "FAIL" else "moderate"),
                "affected_subjects": affected,
            }
        )
    return out


def cmd_tracker_to_20x(args: argparse.Namespace) -> int:
    """End-to-end: assessment tracker -> assess -> tracker-gap eval -> 20x package + reports + reconciliation."""
    import json as _json

    from core.failure_narrative_contract import validate_eval_results_fail_partial_contracts
    from evals.tracker_evidence_gap_eval import run_tracker_evidence_gap_eval
    from evals.tracker_evidence_gap_report import write_all_tracker_gap_outputs
    from fedramp20x.poam_builder import write_poam_markdown
    from fedramp20x.report_builder import (
        POAM_MD,
        write_agency_ao_report,
        write_assessor_report,
        write_executive_report,
        write_reconciliation_markdown,
    )
    from normalization.assessment_tracker_import import import_assessment_tracker_to_dir

    inp = Path(args.input).resolve()
    out_dir = Path(args.output_dir).resolve()
    pkg_out = Path(args.package_output).resolve()
    cfg_dir = Path(args.config).resolve()
    mappings = Path(args.mappings).resolve() if getattr(args, "mappings", None) else MAPPINGS_DIR
    schemas = Path(args.schemas).resolve() if getattr(args, "schemas", None) else SCHEMAS_DIR

    if not inp.is_file():
        print(f"Input not found: {inp}", file=sys.stderr)
        return 2
    if not cfg_dir.is_dir():
        print(f"Config directory not found: {cfg_dir}", file=sys.stderr)
        return 2

    out_dir.mkdir(parents=True, exist_ok=True)
    pkg_out.mkdir(parents=True, exist_ok=True)
    scenario_dir = out_dir / "scenario_from_tracker"

    print(f"[1/11] Importing assessment tracker -> {scenario_dir}")
    import_result = import_assessment_tracker_to_dir(
        input_path=inp, output_dir=scenario_dir, with_meta_event=True
    )
    print(
        f"       parsed={len(import_result.rows)} rows; evidence_gaps={len(import_result.evidence_gaps)}"
    )

    print(f"[2/11] Running normal eval pipeline -> {out_dir}")
    assess_args = argparse.Namespace(
        provider="fixture",
        scenario="_",
        fixture_dir=str(scenario_dir),
        evidence_dir=None,
        raw_evidence_dir=None,
        declared_inventory=None,
        scanner_targets=None,
        scanner_findings=None,
        tickets=None,
        poam=None,
        output_dir=str(out_dir),
        include_agent_security=False,
    )
    rc = cmd_assess(assess_args)
    if rc != 0:
        print(f"       assess returned rc={rc}", file=sys.stderr)
        return rc

    print(f"[3/11] Running TRACKER_EVIDENCE_GAP_ANALYSIS")
    gaps_envelope_path = scenario_dir / "evidence_gaps.json"
    if not gaps_envelope_path.is_file():
        print(f"       missing {gaps_envelope_path}", file=sys.stderr)
        return 2
    gaps_envelope = _json.loads(gaps_envelope_path.read_text(encoding="utf-8"))
    tracker_eval = run_tracker_evidence_gap_eval(evidence_gaps_envelope=gaps_envelope)
    print(
        f"       result={tracker_eval.eval_result.result} "
        f"open={tracker_eval.total_open_gaps} "
        f"high_impact={tracker_eval.high_impact_count} "
        f"poam_required={tracker_eval.poam_required_count}"
    )
    # Write tracker artifacts into a SEPARATE sub-directory so we don't overwrite the
    # assess-produced poam.csv / auditor_questions.md / instrumentation_plan.md. Then
    # copy the unique-named tracker_gap_*.* files up to out_dir, and merge poam.csv +
    # auditor_questions.md content explicitly in the next steps.
    tracker_artifact_dir = out_dir / ".tracker_artifacts"
    written = write_all_tracker_gap_outputs(
        tracker_eval,
        output_dir=tracker_artifact_dir,
        source_questions_md=scenario_dir / "auditor_questions.md",
    )
    import shutil as _shutil

    for name in (
        "tracker_gap_report.md",
        "tracker_gap_matrix.csv",
        "tracker_gap_eval_results.json",
    ):
        src = tracker_artifact_dir / name
        if src.exists():
            dst = out_dir / name
            _shutil.copy2(src, dst)
            print(f"       wrote {name} -> {dst}")
    if (tracker_artifact_dir / "instrumentation_plan.md").exists():
        # The assess pipeline already wrote one; preserve a tracker-specific copy.
        dst = out_dir / "tracker_instrumentation_plan.md"
        _shutil.copy2(tracker_artifact_dir / "instrumentation_plan.md", dst)
        print(f"       wrote tracker_instrumentation_plan.md -> {dst}")

    print(f"[4/11] Folding TRACKER_EVIDENCE_GAP_ANALYSIS into eval_results.json")
    eval_results_path = out_dir / "eval_results.json"
    eval_doc = _json.loads(eval_results_path.read_text(encoding="utf-8"))
    evaluations = list(eval_doc.get("evaluations") or [])
    legacy_record = _tracker_eval_to_evaluation_record(tracker_eval.eval_result)
    if not any(str(e.get("eval_id")) == legacy_record["eval_id"] for e in evaluations):
        evaluations.append(legacy_record)
    eval_doc["evaluations"] = evaluations
    record_records = list(eval_doc.get("eval_result_records") or [])
    canonical_record = tracker_eval.eval_result.model_dump()
    canonical_record.setdefault("remediation_disposition", "poam_or_risk_acceptance")
    canonical_record.setdefault("linked_ksi_ids", [])
    canonical_record.setdefault("assessor_findings", legacy_record.get("assessor_findings") or [])
    if not any(str(r.get("eval_id")) == canonical_record["eval_id"] for r in record_records):
        record_records.append(canonical_record)
    eval_doc["eval_result_records"] = record_records
    eval_results_path.write_text(_json.dumps(eval_doc, indent=2), encoding="utf-8")

    print(f"[5/11] Writing tracker-derived POA&M as tracker_poam.csv (alongside poam.csv)")
    main_poam = out_dir / "poam.csv"
    tracker_poam = tracker_artifact_dir / "poam.csv"
    # The assess-generated poam.csv uses the canonical legacy POA&M schema (used by
    # the FedRAMP 20x package builder via fedramp20x.poam_builder.poam_items_from_csv).
    # The tracker eval emits its own POA&M schema (POAM-TRK-* IDs, gap_id, ksi links,
    # etc.). Merging the two would confuse poam_items_from_csv, so we keep the
    # tracker-derived POA&M as a stand-alone artifact (tracker_poam.csv). The tracker
    # findings still flow into the 20x package via the TRACKER_EVIDENCE_GAP_ANALYSIS
    # eval row added to evaluations[] in step [4]: build_findings +
    # build_poam_items_from_findings turn the FAIL eval into native package POA&M items.
    if tracker_poam.exists():
        _shutil.copy2(tracker_poam, out_dir / "tracker_poam.csv")

    print(f"[6/11] Appending tracker auditor questions to auditor_questions.md")
    main_aq = out_dir / "auditor_questions.md"
    tracker_aq = scenario_dir / "auditor_questions.md"
    if main_aq.exists() and tracker_aq.exists():
        existing = main_aq.read_text(encoding="utf-8")
        appendix = tracker_aq.read_text(encoding="utf-8").strip()
        if appendix and "Tracker auditor questions" not in existing:
            main_aq.write_text(
                existing.rstrip()
                + "\n\n## Tracker auditor questions (from assessment tracker)\n\n"
                + appendix
                + "\n",
                encoding="utf-8",
            )

    print(f"[7/11] Building FedRAMP 20x package -> {pkg_out}")
    rc = build_20x_package(
        assessment_output=out_dir,
        config_dir=cfg_dir,
        package_output=pkg_out,
        mappings_dir=mappings,
        schemas_dir=schemas,
        validation_artifact_root=None,
    )
    if rc != 0:
        print(f"       build_20x_package returned rc={rc}", file=sys.stderr)
        return rc

    print(f"[8/11] Generating assessor/executive/agency-AO reports")
    import yaml as _yaml

    rp = cfg_dir / "reporting-policy.yaml"
    if rp.is_file():
        reporting = _yaml.safe_load(rp.read_text(encoding="utf-8")) or {}
        rp_reports = (reporting.get("reports") or {}) if isinstance(reporting, dict) else {}
    else:
        rp_reports = {}
    pkg_path = pkg_out / "fedramp20x-package.json"
    if not pkg_path.is_file():
        print(f"       missing {pkg_path}", file=sys.stderr)
        return 2
    package = _json.loads(pkg_path.read_text(encoding="utf-8"))
    assess_fn = (rp_reports.get("assessor") or {}).get("filename") or "assessor-summary.md"
    exec_fn = (rp_reports.get("executive") or {}).get("filename") or "executive-summary.md"
    ao_fn = (rp_reports.get("agency_ao") or {}).get("filename") or "ao-risk-brief.md"
    assessor_path = pkg_out / "reports" / "assessor" / assess_fn
    executive_path = pkg_out / "reports" / "executive" / exec_fn
    ao_path = pkg_out / "reports" / "agency-ao" / ao_fn
    recon_md = pkg_out / "reports" / "reconciliation_report.md"
    for d in (assessor_path.parent, executive_path.parent, ao_path.parent, recon_md.parent):
        d.mkdir(parents=True, exist_ok=True)
    write_assessor_report(assessor_path, package)
    write_executive_report(executive_path, package)
    write_agency_ao_report(ao_path, package)
    write_reconciliation_markdown(recon_md, package)
    write_poam_markdown(assessor_path.parent / POAM_MD, package.get("poam_items") or [])

    print(f"[9/11] Running deep reconciliation (REC-001 ... REC-010)")
    rc_code, rc_result = run_reconciliation_cli(package_dir=pkg_out)
    if rc_code != 0:
        print(f"       RECONCILIATION FAILED: {rc_result.get('overall_status')}", file=sys.stderr)
        for c in rc_result.get("checks") or []:
            if isinstance(c, dict) and c.get("status") != "pass":
                print(f"       {c.get('id')}: {c.get('detail')}", file=sys.stderr)
        return rc_code

    print(f"[10/11] Validating 20x package schema")
    rep = validate_package(pkg_path, schemas)
    if not rep.valid:
        print(f"       Schema: {rep.schema_path}", file=sys.stderr)
        print(f"       Document: {rep.json_path}", file=sys.stderr)
        for line in rep.errors:
            print(f"       {line}", file=sys.stderr)
        return 1

    print(f"[11/11] Validating FAIL/PARTIAL narrative contract on eval_results.json")
    eval_doc_after = _json.loads(eval_results_path.read_text(encoding="utf-8"))
    contract_errs = validate_eval_results_fail_partial_contracts(eval_doc_after)
    if contract_errs:
        for e in contract_errs:
            print(f"       NARRATIVE_CONTRACT: {e}", file=sys.stderr)
        return 1

    print("")
    print("tracker-to-20x: ALL STEPS PASSED")
    print(f"  Output dir:        {out_dir}")
    print(f"  Tracker reports:   {out_dir / 'tracker_gap_report.md'}")
    print(f"  Eval results:      {eval_results_path}")
    print(f"  POA&M:             {main_poam}")
    print(f"  Auditor questions: {main_aq}")
    print(f"  20x package:       {pkg_path}")
    print(f"  Assessor report:   {assessor_path}")
    print(f"  Executive report:  {executive_path}")
    print(f"  Agency AO report:  {ao_path}")
    print(f"  Reconciliation:    {recon_md}")
    return 0


def cmd_conmon_reasonableness(args: argparse.Namespace) -> int:
    """Evaluate ConMon tracker/system evidence against the 3PAO reasonableness catalog."""
    from core.conmon_reasonableness import (
        assess_conmon_reasonableness,
        load_conmon_catalog,
        load_tracker_rows,
        write_reasonableness_outputs,
    )

    catalog_path = Path(args.catalog).resolve()
    tracker_path = Path(args.tracker).resolve() if args.tracker else None
    out_dir = Path(args.output_dir).resolve()

    catalog = load_conmon_catalog(catalog_path)
    rows = load_tracker_rows(tracker_path)
    result = assess_conmon_reasonableness(catalog=catalog, tracker_rows=rows)
    json_path, md_path = write_reasonableness_outputs(result, out_dir)

    summary = result.get("summary") or {}
    print("CONMON REASONABLENESS")
    print(f"  Catalog:       {catalog_path}")
    print(f"  Tracker rows:  {summary.get('tracker_rows', 0)}")
    print(f"  Obligations:   {summary.get('obligations', 0)}")
    print(f"  Reasonable:    {summary.get('reasonable', 0)}")
    print(f"  Partial:       {summary.get('partial', 0)}")
    print(f"  Missing:       {summary.get('missing', 0)}")
    print(f"  JSON:          {json_path}")
    print(f"  Markdown:      {md_path}")
    return 0


def cmd_build_20x_package(args: argparse.Namespace) -> int:
    assessment_out = Path(args.assessment_output).resolve()
    cfg = Path(args.config).resolve()
    pkg_out = Path(args.package_output).resolve()
    mappings = Path(args.mappings).resolve() if getattr(args, "mappings", None) else MAPPINGS_DIR
    schemas = Path(args.schemas).resolve() if getattr(args, "schemas", None) else SCHEMAS_DIR
    return build_20x_package(
        assessment_output=assessment_out,
        config_dir=cfg,
        package_output=pkg_out,
        mappings_dir=mappings,
        schemas_dir=schemas,
        validation_artifact_root=getattr(args, "validation_artifact_root", None),
    )


def cmd_validate(args: argparse.Namespace) -> int:
    od = Path(args.output_dir).resolve()
    errors, _warnings = validate_output_directory(od, mode=getattr(args, "mode", "demo"))
    if errors:
        for line in errors:
            print(line, file=sys.stderr)
        return 1
    print("VALIDATION PASSED")
    return 0


def cmd_reconcile_reports(args: argparse.Namespace) -> int:
    root = Path(args.package_output).resolve()
    code, result = run_reconciliation_cli(package_dir=root)
    if code != 0:
        print(f"RECONCILIATION FAILED: {result.get('overall_status')}", file=sys.stderr)
        for c in result.get("checks") or []:
            if isinstance(c, dict) and c.get("status") != "pass":
                print(f"  {c.get('id')}: {c.get('detail')}", file=sys.stderr)
    else:
        print("RECONCILIATION: PASS")
    return code


def cmd_validate_20x_package(args: argparse.Namespace) -> int:
    pkg = Path(args.package).resolve()
    schemas = Path(args.schemas).resolve()
    rep = validate_package(pkg, schemas)
    if rep.valid:
        print("FEDRAMP 20X PACKAGE SCHEMA: OK")
        return 0
    print(f"Schema: {rep.schema_path}", file=sys.stderr)
    print(f"Document: {rep.json_path}", file=sys.stderr)
    for line in rep.errors:
        print(line, file=sys.stderr)
    return 1


def cmd_list_pending_recommendations(args: argparse.Namespace) -> int:
    recommendations = load_recommendations(Path(args.recommendations).resolve())
    history = load_review_history(Path(args.history).resolve())
    pending = list_pending_recommendations(recommendations, history)
    print(
        json.dumps(
            {
                "pendingRecommendations": [rec.model_dump(mode="json", by_alias=True) for rec in pending],
                "count": len(pending),
            },
            indent=2,
        )
    )
    return 0


def cmd_record_review_decision(args: argparse.Namespace) -> int:
    recommendations = load_recommendations(Path(args.recommendations).resolve())
    decision = record_review_decision(
        history_path=Path(args.history).resolve(),
        recommendations=recommendations,
        recommendation_id=args.recommendation_id,
        reviewer=args.reviewer,
        decision=args.decision,
        justification=args.justification,
        evidence_ids=args.evidence_id or None,
        finding_ids=args.finding_id or None,
        control_id=args.control_id,
    )
    print(decision.model_dump_json(indent=2, by_alias=True))
    return 0


def cmd_show_review_history(args: argparse.Namespace) -> int:
    history = load_review_history(Path(args.history).resolve())
    filtered = filter_review_history(
        history,
        control_id=args.control_id,
        finding_id=args.finding_id,
        recommendation_id=args.recommendation_id,
    )
    print(
        json.dumps(
            {
                "reviewHistory": [decision.model_dump(mode="json", by_alias=True) for decision in filtered],
                "count": len(filtered),
            },
            indent=2,
        )
    )
    return 0


def cmd_generate_20x_reports(args: argparse.Namespace) -> int:
    """Regenerate human-readable 20x markdown reports from an existing fedramp20x-package.json."""
    import yaml

    from fedramp20x.poam_builder import write_poam_markdown
    from fedramp20x.report_builder import (
        POAM_MD,
        write_agency_ao_report,
        write_assessor_report,
        write_executive_report,
        write_reconciliation_markdown,
    )

    pkg_path = Path(args.package).resolve()
    if not pkg_path.is_file():
        print(f"Package not found: {pkg_path}", file=sys.stderr)
        return 2
    package = json.loads(pkg_path.read_text(encoding="utf-8"))
    cfg = Path(args.config).resolve()
    rp = cfg / "reporting-policy.yaml"
    if not rp.is_file():
        print(f"Missing reporting policy: {rp}", file=sys.stderr)
        return 2
    reporting = yaml.safe_load(rp.read_text(encoding="utf-8"))
    if not isinstance(reporting, dict):
        reporting = {}
    rep = reporting.get("reports") or {}
    assess_fn = (rep.get("assessor") or {}).get("filename") or "assessor-summary.md"
    exec_fn = (rep.get("executive") or {}).get("filename") or "executive-summary.md"
    ao_fn = (rep.get("agency_ao") or {}).get("filename") or "ao-risk-brief.md"
    package_output = pkg_path.parent
    assessor_path = package_output / "reports" / "assessor" / assess_fn
    executive_path = package_output / "reports" / "executive" / exec_fn
    ao_path = package_output / "reports" / "agency-ao" / ao_fn
    recon_out = package_output / "reports" / "reconciliation_report.md"
    assessor_path.parent.mkdir(parents=True, exist_ok=True)
    executive_path.parent.mkdir(parents=True, exist_ok=True)
    ao_path.parent.mkdir(parents=True, exist_ok=True)
    recon_out.parent.mkdir(parents=True, exist_ok=True)
    write_assessor_report(assessor_path, package)
    write_executive_report(executive_path, package)
    write_agency_ao_report(ao_path, package)
    write_reconciliation_markdown(recon_out, package)
    write_poam_markdown(assessor_path.parent / POAM_MD, package.get("poam_items") or [])
    print(f"Regenerated 20x reports under {package_output / 'reports'}")
    return 0


def cmd_reconcile_20x(args: argparse.Namespace) -> int:
    """Deep reconciliation (REC-001…REC-010): ``--package`` may be fedramp20x-package.json or its parent directory."""
    pkg_arg = Path(args.package).resolve()
    if pkg_arg.is_file():
        package_dir = pkg_arg.parent
    elif pkg_arg.is_dir():
        package_dir = pkg_arg
    else:
        print(f"Invalid --package: {pkg_arg}", file=sys.stderr)
        return 2
    report_root = Path(args.reports).resolve() if args.reports is not None else None
    code, result = run_reconciliation_cli(package_dir=package_dir, report_root=report_root)
    if code != 0:
        print(f"RECONCILIATION FAILED: {result.get('overall_status')}", file=sys.stderr)
        for c in result.get("checks") or []:
            if isinstance(c, dict) and c.get("status") != "pass":
                print(f"  {c.get('id')}: {c.get('detail')}", file=sys.stderr)
    else:
        print("RECONCILIATION: PASS")
    return code


def main() -> int:
    p = argparse.ArgumentParser(
        description="Multi-cloud security evidence assessment — observability and audit readiness.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    assess = sub.add_parser("assess", help="Load evidence, run evals, write reports")
    assess.add_argument(
        "--provider",
        choices=["fixture", "aws"],
        required=True,
        help="Evidence source (fixture scenario dir or AWS raw export directory)",
    )
    assess.add_argument(
        "--scenario",
        default=None,
        help=f"Fixture subdirectory under fixtures/ (default: {DEFAULT_FIXTURE_SCENARIO} if --fixture-dir omitted)",
    )
    assess.add_argument(
        "--fixture-dir",
        default=None,
        type=Path,
        help="Use this directory as the fixture root instead of fixtures/<scenario>",
    )
    assess.add_argument(
        "--raw-evidence-dir",
        default=None,
        type=Path,
        help="Directory with canonical evidence files (required for --provider aws)",
    )
    assess.add_argument(
        "--evidence-dir",
        default=None,
        type=Path,
        help=argparse.SUPPRESS,
    )
    assess.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Output directory (default: output)",
    )
    assess.add_argument(
        "--declared-inventory",
        default=None,
        type=Path,
        help="Optional CSV to override declared_inventory.csv from the bundle",
    )
    assess.add_argument(
        "--scanner-targets",
        default=None,
        type=Path,
        help="Optional CSV to override scanner_targets.csv",
    )
    assess.add_argument(
        "--scanner-findings",
        default=None,
        type=Path,
        help="Optional JSON to override scanner_findings.json",
    )
    assess.add_argument(
        "--tickets",
        default=None,
        type=Path,
        help="Optional JSON to override tickets.json",
    )
    assess.add_argument(
        "--poam",
        default=None,
        type=Path,
        help="Optional CSV to override poam.csv seed rows",
    )
    assess.add_argument(
        "--include-agent-security",
        action="store_true",
        help="When agent telemetry is present, also write agent_eval_results.json, agent_risk_report.md, "
        "agent_threat_hunt_findings.json, and agent_poam.csv under --output-dir.",
    )
    assess.add_argument(
        "--mode",
        choices=["demo", "live"],
        default="demo",
        help="Assessment profile recorded in assessment_summary.json. Use live for arbitrary cloud environments.",
    )
    assess.set_defaults(func=cmd_assess)

    threat = sub.add_parser(
        "threat-hunt",
        help="Agentic AI risk threat hunt (hypothesis-driven findings, queries, POA&M hints)",
    )
    threat.add_argument(
        "--provider",
        choices=["fixture", "aws"],
        required=True,
        help="Evidence source (fixture scenario or AWS raw export directory)",
    )
    threat.add_argument(
        "--scenario",
        default=None,
        help=f"Fixture subdirectory under fixtures/ (default: {DEFAULT_FIXTURE_SCENARIO} if --fixture-dir omitted)",
    )
    threat.add_argument(
        "--fixture-dir",
        default=None,
        type=Path,
        help="Use this directory as the fixture / evidence root instead of fixtures/<scenario>",
    )
    threat.add_argument(
        "--raw-evidence-dir",
        default=None,
        type=Path,
        help="Directory with canonical evidence files (required for --provider aws)",
    )
    threat.add_argument(
        "--evidence-dir",
        default=None,
        type=Path,
        help=argparse.SUPPRESS,
    )
    threat.add_argument(
        "--agent-telemetry",
        default=None,
        type=Path,
        help="Directory containing agent_identities.json (split layout) or agent_security/agent_assessment.json; "
        "defaults to the same path as the evidence root",
    )
    threat.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Output directory (default: output)",
    )
    threat.set_defaults(func=cmd_threat_hunt)

    run_agent = sub.add_parser(
        "run-agent",
        help="Bounded autonomous loop: observe → plan → act → verify → explain (local artifacts only; "
        "writes output/agent_run_trace.json and output/agent_run_summary.md)",
    )
    run_agent.add_argument(
        "--provider",
        choices=["fixture", "aws"],
        default="fixture",
        help="Evidence source (default: fixture)",
    )
    run_agent.add_argument(
        "--scenario",
        default="scenario_agentic_risk",
        help="Fixture subdirectory under fixtures/ (default: scenario_agentic_risk)",
    )
    run_agent.add_argument(
        "--fixture-dir",
        default=None,
        type=Path,
        help="Fixture root directory (overrides --scenario path)",
    )
    run_agent.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Assessment output directory (default: output)",
    )
    run_agent.add_argument(
        "--package-output",
        type=Path,
        default=None,
        help="FedRAMP 20x package output directory. Default: <output-dir>/package_tracker for "
        "--workflow tracker-to-20x; output/agent_run_20x for legacy mode.",
    )
    run_agent.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Config directory (default: ./config)",
    )
    run_agent.add_argument(
        "--schemas",
        type=Path,
        default=None,
        help="JSON Schema directory (default: ./schemas)",
    )
    run_agent.add_argument(
        "--mappings",
        type=Path,
        default=None,
        help="Mappings directory (default: ./mappings)",
    )
    run_agent.add_argument(
        "--no-include-agent-security",
        action="store_true",
        help="Omit agent security bundle (default: include when telemetry exists)",
    )
    run_agent.add_argument(
        "--workflow",
        choices=["tracker-to-20x"],
        default=None,
        help="Run a categorical task-graph workflow instead of the legacy bounded loop. "
        "Currently supports: tracker-to-20x (assessment tracker -> 20x package via 15-task DAG).",
    )
    run_agent.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Input file for the selected workflow (e.g. assessment tracker CSV/TSV/text "
        "for --workflow tracker-to-20x).",
    )
    run_agent.set_defaults(func=cmd_run_agent)

    arch = sub.add_parser(
        "secure-agent-arch",
        help="Write secure_agent_architecture.md (identity, tool/context boundaries, policy, observability, evidence)",
    )
    arch.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory for secure_agent_architecture.md (default: output)",
    )
    arch.set_defaults(func=cmd_secure_agent_arch)

    report = sub.add_parser("report", help="Re-render reports from eval_results.json")
    report.add_argument(
        "--input",
        type=Path,
        default=Path("output/eval_results.json"),
        help="Path to eval_results.json (default: output/eval_results.json)",
    )
    report.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Output directory (default: output)",
    )
    report.set_defaults(func=cmd_report)

    list_e = sub.add_parser("list-evals", help="Print eval ids and control mappings")
    list_e.set_defaults(func=cmd_list_evals)

    run_e = sub.add_parser(
        "run-evals",
        help="Run offline platform eval fixtures for retrieval, validation, mapping, recommendations, packaging, and guardrails",
    )
    run_e.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Eval fixture JSON file. Default: fixtures/eval_harness/builtins.json",
    )
    run_e.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output") / "eval_harness",
        help="Directory for eval_results.json and eval_summary.md.",
    )
    run_e.set_defaults(func=cmd_run_evals)

    golden = sub.add_parser(
        "golden-path-demo",
        help="Run the full offline assurance package pipeline on fixture data.",
    )
    golden.add_argument(
        "--fixture-dir",
        type=Path,
        default=None,
        help="Fixture directory. Default: fixtures/golden_path.",
    )
    golden.add_argument(
        "--output-dir",
        type=Path,
        default=Path("build") / "assurance-package-demo",
        help="Output directory for demo artifacts.",
    )
    golden.set_defaults(func=cmd_golden_path_demo)

    debug_ctx = sub.add_parser(
        "debug-context",
        help="Explain why RAG context evidence was selected or rejected for a control/asset/account scope.",
    )
    debug_ctx.add_argument("--control", required=True, help="Control ID to retrieve, such as RA-5")
    debug_ctx.add_argument("--asset", default=None, help="Optional asset/resource ID scope")
    debug_ctx.add_argument("--account", default=None, help="Optional account ID scope")
    debug_ctx.add_argument("--from", dest="from_date", default=None, help="Optional ISO start timestamp/date")
    debug_ctx.add_argument("--to", dest="to_date", default=None, help="Optional ISO end timestamp/date")
    debug_ctx.add_argument(
        "--input",
        type=Path,
        default=None,
        help="Eval fixture JSON to use as offline source data. Default: fixtures/eval_harness/builtins.json",
    )
    debug_ctx.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Optional JSON output path. If omitted, debug JSON is printed to stdout.",
    )
    debug_ctx.set_defaults(func=cmd_debug_context)

    validate_p = sub.add_parser("validate", help="Validate generated artifacts under output-dir")
    validate_p.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Directory containing eval_results.json and related artifacts",
    )
    validate_p.add_argument(
        "--mode",
        choices=["demo", "live"],
        default="demo",
        help="Validation profile: demo preserves fixture expectations; live allows clean environments.",
    )
    validate_p.set_defaults(func=cmd_validate)

    v20 = sub.add_parser(
        "validate-20x-package",
        help="Validate fedramp20x-package.json (and top-level artifact JSON) against schemas/",
    )
    v20.add_argument(
        "--package",
        type=Path,
        required=True,
        help="Path to fedramp20x-package.json",
    )
    v20.add_argument(
        "--schemas",
        type=Path,
        required=True,
        help="Directory containing *.schema.json (e.g. schemas/)",
    )
    v20.set_defaults(func=cmd_validate_20x_package)

    pending = sub.add_parser(
        "list-pending-recommendations",
        help="List AgentRecommendation records that do not yet have a human review decision.",
    )
    pending.add_argument("--recommendations", type=Path, required=True, help="JSON file containing AgentRecommendation[]")
    pending.add_argument(
        "--history",
        type=Path,
        required=True,
        help="Append-only review history JSONL file.",
    )
    pending.set_defaults(func=cmd_list_pending_recommendations)

    review = sub.add_parser(
        "record-review-decision",
        help="Append a human review decision for an AgentRecommendation.",
    )
    review.add_argument("--recommendations", type=Path, required=True, help="JSON file containing AgentRecommendation[]")
    review.add_argument("--history", type=Path, required=True, help="Append-only review history JSONL file.")
    review.add_argument("--recommendation-id", required=True, help="AgentRecommendation.recommendationId to decide")
    review.add_argument("--reviewer", required=True, help="Reviewer identity")
    review.add_argument(
        "--decision",
        required=True,
        choices=[
            "ACCEPTED",
            "ACCEPTED_WITH_EDITS",
            "REJECTED",
            "NEEDS_MORE_EVIDENCE",
            "FALSE_POSITIVE",
            "RISK_ACCEPTED",
            "COMPENSATING_CONTROL_ACCEPTED",
            "ESCALATED_TO_AO",
            "ESCALATED_TO_3PAO",
        ],
        help="Human review decision.",
    )
    review.add_argument("--justification", required=True, help="Reviewer justification")
    review.add_argument("--control-id", default=None, help="Optional control ID override")
    review.add_argument("--finding-id", action="append", default=None, help="Optional finding ID reference; repeatable")
    review.add_argument("--evidence-id", action="append", default=None, help="Optional evidence ID reference; repeatable")
    review.set_defaults(func=cmd_record_review_decision)

    show_review = sub.add_parser(
        "show-review-history",
        help="Show human review history, optionally filtered by control/finding/recommendation.",
    )
    show_review.add_argument("--history", type=Path, required=True, help="Append-only review history JSONL file.")
    show_review.add_argument("--control-id", default=None, help="Filter by control ID")
    show_review.add_argument("--finding-id", default=None, help="Filter by finding ID")
    show_review.add_argument("--recommendation-id", default=None, help="Filter by recommendation ID")
    show_review.set_defaults(func=cmd_show_review_history)

    gen20 = sub.add_parser(
        "generate-20x-reports",
        help="Regenerate FedRAMP 20x markdown reports from an existing fedramp20x-package.json",
    )
    gen20.add_argument(
        "--package",
        type=Path,
        required=True,
        help="Path to fedramp20x-package.json",
    )
    gen20.add_argument(
        "--config",
        type=Path,
        default=Path("config"),
        help="Config directory containing reporting-policy.yaml (default: config)",
    )
    gen20.set_defaults(func=cmd_generate_20x_reports)

    rec20 = sub.add_parser(
        "reconcile-20x",
        help="Run REC-001…REC-010 reconciliation (same as reconcile-reports; --package may be JSON file or package dir)",
    )
    rec20.add_argument(
        "--package",
        type=Path,
        required=True,
        help="Path to fedramp20x-package.json or directory containing it",
    )
    rec20.add_argument(
        "--reports",
        type=Path,
        default=None,
        help="Root containing reports/ tree (default: directory of fedramp20x-package.json)",
    )
    rec20.set_defaults(func=cmd_reconcile_20x)

    rec = sub.add_parser(
        "reconcile-reports",
        help="Run REC-001…REC-010 reconciliation on fedramp20x-package.json vs generated reports (nonzero exit if fail)",
    )
    rec.add_argument(
        "--package-output",
        type=Path,
        required=True,
        help="Directory containing fedramp20x-package.json and reports/ tree",
    )
    rec.set_defaults(func=cmd_reconcile_reports)

    build20 = sub.add_parser(
        "build-20x-package",
        help="Build FedRAMP 20x-style KSI evidence package + human reports from assessment output",
    )
    build20.add_argument(
        "--assessment-output",
        type=Path,
        required=True,
        help="Directory containing eval_results.json, evidence_graph.json, poam.csv, etc.",
    )
    build20.add_argument(
        "--config",
        type=Path,
        required=True,
        help="Directory containing system-boundary.yaml, ksi-catalog.yaml, and related config",
    )
    build20.add_argument(
        "--package-output",
        type=Path,
        required=True,
        help="Output directory for fedramp20x-package.json and reports/ tree",
    )
    build20.add_argument(
        "--mappings",
        type=Path,
        default=None,
        help=f"Mappings directory (default: {MAPPINGS_DIR})",
    )
    build20.add_argument(
        "--schemas",
        type=Path,
        default=None,
        help=f"JSON Schema directory (default: {SCHEMAS_DIR})",
    )
    build20.add_argument(
        "--validation-artifact-root",
        type=Path,
        default=None,
        help="Optional project root for evidence/validation-results/poam-items.json and reports/assessor/poam.md",
    )
    build20.set_defaults(func=cmd_build_20x_package)

    impf = sub.add_parser(
        "import-findings",
        help="Convert scanner exports to scanner_findings.json "
        "(input adapters; evals still drive KSI/log/alert/CM outcomes)",
    )
    impf.add_argument(
        "--format",
        required=True,
        choices=["auto", "universal", "prowler", "cloudsploit", "ocsf", "electriceye", "nessus"],
        help="Source export format",
    )
    impf.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to scanner export (JSON, CSV, or NDJSON as supported by the adapter)",
    )
    impf.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Scenario directory (writes scanner_findings.json inside) or explicit path ending in .json",
    )
    impf.add_argument(
        "--no-security-events",
        action="store_true",
        help="Do not emit derived SecurityEvent rows (ScannerFinding list only)",
    )
    impf.set_defaults(func=cmd_import_findings)

    impt = sub.add_parser(
        "import-tickets",
        help="Normalize generic/Jira-like/ServiceNow-like/Smartsheet-like ticket exports to tickets.json",
    )
    impt.add_argument("--input", type=Path, required=True, help="Ticket export JSON or CSV")
    impt.add_argument("--output", type=Path, required=True, help="Scenario directory or explicit tickets.json path")
    impt.add_argument(
        "--system",
        choices=["jira", "servicenow", "github", "manual", "unknown"],
        default="unknown",
        help="Default ticket system when the export row does not identify one",
    )
    impt.set_defaults(func=cmd_import_tickets)

    impg = sub.add_parser(
        "import-inventory-graph",
        help="Normalize graph/inventory JSON exports to discovered_assets.json",
    )
    impg.add_argument("--input", type=Path, required=True, help="Graph/inventory JSON export")
    impg.add_argument("--output", type=Path, required=True, help="Scenario directory or explicit discovered_assets.json path")
    impg.set_defaults(func=cmd_import_inventory_graph)

    exo = sub.add_parser(
        "export-ocsf",
        help="Export normalized SecurityEvent and ScannerFinding rows as one OCSF-like JSON file "
        "(not schema-validated; see docs/ocsf_alignment.md)",
    )
    exo.add_argument(
        "--assessment-output",
        type=Path,
        required=True,
        help="Assessment directory (fixture scenario or assess output with cloud_events.json, scanner_findings.json, …)",
    )
    exo.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output JSON path (relative paths are resolved under --assessment-output)",
    )
    exo.set_defaults(func=cmd_export_ocsf)

    iat = sub.add_parser(
        "import-assessment-tracker",
        help="Parse a FedRAMP assessment tracker (CSV/TSV/text) into a partial fixture scenario "
        "(tracker_items.json + evidence gaps + auditor questions + empty fixture stubs)",
    )
    iat.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the tracker file (CSV, TSV, semicolon, or pipe-delimited; multiline cells supported)",
    )
    iat.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output scenario directory (will be created if missing)",
    )
    iat.add_argument(
        "--with-meta-event",
        action="store_true",
        help="Emit a single synthesized 'assessment.tracker_loaded' meta-event in cloud_events.json so "
        "the existing FixtureProvider minimum-bundle gate can also load the directory. Off by default.",
    )
    iat.set_defaults(func=cmd_import_assessment_tracker)

    at = sub.add_parser(
        "assess-tracker",
        help="Run TRACKER_EVIDENCE_GAP_ANALYSIS over a FedRAMP assessment tracker file. "
        "Imports the tracker, builds EvidenceGap records, evaluates them, and writes "
        "tracker_gap_report.md, tracker_gap_matrix.csv, tracker_gap_eval_results.json, "
        "poam.csv, auditor_questions.md, and instrumentation_plan.md (when applicable).",
    )
    at.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the tracker file (CSV, TSV, semicolon, or pipe-delimited; multiline cells supported)",
    )
    at.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Output directory for the eval reports (will be created if missing)",
    )
    at.add_argument(
        "--with-meta-event",
        action="store_true",
        help="Also synthesize an 'assessment.tracker_loaded' meta-event in the imported scenario.",
    )
    at.set_defaults(func=cmd_assess_tracker)

    t20 = sub.add_parser(
        "tracker-to-20x",
        help="End-to-end: import a FedRAMP assessment tracker, run the full eval pipeline + "
        "TRACKER_EVIDENCE_GAP_ANALYSIS, fold tracker gaps into KSIs/findings/POA&M, build the "
        "FedRAMP 20x package, generate assessor/executive/agency-AO reports, run REC-001..REC-010 "
        "reconciliation, and validate package schema + FAIL/PARTIAL narrative contract. "
        "No live cloud credentials required.",
    )
    t20.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to the assessment tracker file (CSV/TSV/text).",
    )
    t20.add_argument(
        "--config",
        type=Path,
        required=True,
        help="FedRAMP / agent config directory (system-boundary.yaml, ksi-catalog.yaml, etc.).",
    )
    t20.add_argument(
        "--output-dir",
        type=Path,
        required=True,
        help="Assessment output directory (eval_results.json, tracker_gap_report.md, poam.csv, ...).",
    )
    t20.add_argument(
        "--package-output",
        type=Path,
        required=True,
        help="Output directory for the FedRAMP 20x package (fedramp20x-package.json + reports/).",
    )
    t20.add_argument(
        "--mappings",
        type=Path,
        default=None,
        help="Override the rev4/rev5 + KSI crosswalk mappings directory.",
    )
    t20.add_argument(
        "--schemas",
        type=Path,
        default=None,
        help="Override the JSON Schema directory used for package + config validation.",
    )
    t20.set_defaults(func=cmd_tracker_to_20x)

    cr = sub.add_parser(
        "conmon-reasonableness",
        help="Evaluate ConMon/annual-assessment tracker evidence against a 3PAO reasonableness catalog.",
    )
    cr.add_argument(
        "--tracker",
        type=Path,
        default=None,
        help="Optional Smartsheet/Jira/ServiceNow-style CSV/TSV export to map against ConMon obligations.",
    )
    cr.add_argument(
        "--catalog",
        type=Path,
        default=ROOT / "config" / "conmon-catalog.yaml",
        help="ConMon reasonableness catalog YAML.",
    )
    cr.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output") / "conmon_reasonableness",
        help="Directory for conmon_reasonableness.json and conmon_reasonableness.md.",
    )
    cr.set_defaults(func=cmd_conmon_reasonableness)

    args = p.parse_args()
    try:
        return int(args.func(args))
    except (FileNotFoundError, ValueError, json.JSONDecodeError, OSError) as e:
        print(str(e), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
