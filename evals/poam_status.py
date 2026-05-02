"""CA-5 / CA-7 / RA-5 — POA&M tracking for FAIL/PARTIAL evaluations."""

from __future__ import annotations

from datetime import date
from pathlib import Path

from core.control_mapper import get_controls_for_eval
from core.poam import build_poam_generation, write_poam_csv_file
from core.pipeline_models import (
    EvalStatus,
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvalResult as PipelineEvalResult,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from providers.fixture import assessment_bundle_from_evidence_bundle

EVAL_ID = "CA5_POAM_STATUS"
EVAL_NAME = "CA-5 POA&M status and gap tracking"
CONTROL_REFS = list(get_controls_for_eval(EVAL_ID))


def eval_poam_status(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
    prior: list[PipelineEvalResult],
    *,
    output_dir: Path | None = None,
    reference_date: date | None = None,
) -> PipelineEvalResult:
    """
    For FAIL/PARTIAL eval results (excluding this eval), ensure POA&M coverage or generate CSV rows.

    When ``output_dir`` is set, writes ``output/poam.csv`` (merged with existing POA&M items from the bundle).
    """
    _ = asset
    failing = [
        r
        for r in prior
        if r.eval_id != EVAL_ID and r.result in (EvalStatus.FAIL, EvalStatus.PARTIAL)
    ]
    ref = reference_date or date.today()
    assessment = assessment_bundle_from_evidence_bundle(bundle)
    rows, stats = build_poam_generation(
        prior,
        event,
        assessment.poam_items,
        bundle.poam_seed_rows,
        reference_date=ref,
    )

    generated: list[str] = []
    if output_dir is not None:
        out_path = output_dir / "poam.csv"
        write_poam_csv_file(out_path, rows)
        generated.append("output/poam.csv")

    if not failing:
        return PipelineEvalResult(
            eval_id=EVAL_ID,
            control_refs=CONTROL_REFS,
            result=EvalStatus.PASS,
            evidence=["No FAIL or PARTIAL evaluations — POA&M generation not required."],
            gap="",
            recommended_action="Maintain CA-7 continuous monitoring when new evidence gaps appear.",
            machine={
                "name": EVAL_NAME,
                "summary": "No open control gaps in this assessment run.",
                "poam_rows_added": 0,
                "generated_artifacts": generated,
            },
        )

    if stats["added"] == 0 and stats["skipped_duplicate"] == len(failing):
        return PipelineEvalResult(
            eval_id=EVAL_ID,
            control_refs=CONTROL_REFS,
            result=EvalStatus.PASS,
            evidence=[
                f"Existing POA&M records already cover all {len(failing)} failing/partial evaluation(s).",
                *[f"{r.eval_id}: {r.result.value}" for r in failing],
            ],
            gap="",
            recommended_action="Update milestone status and closure evidence in the official POA&M repository.",
            machine={
                "name": EVAL_NAME,
                "summary": "POA&M tracking present for all identified gaps.",
                "poam_rows_added": 0,
                "skipped_duplicate": stats["skipped_duplicate"],
                "generated_artifacts": generated,
            },
        )

    return PipelineEvalResult(
        eval_id=EVAL_ID,
        control_refs=CONTROL_REFS,
        result=EvalStatus.OPEN,
        evidence=[
            f"Added {stats['added']} POA&M row(s) for failing/partial evaluations "
            f"(duplicates skipped: {stats['skipped_duplicate']}).",
            *[f"{r.eval_id}: {r.result.value}" for r in failing],
        ],
        gap="Continuous monitoring evidence incomplete; new POA&M rows written to poam.csv.",
        recommended_action="Enter responsible roles, funding, and milestone owners in the official POA&M system.",
        machine={
            "name": EVAL_NAME,
            "summary": "New POA&M rows generated for control gaps.",
            "poam_rows_added": stats["added"],
            "skipped_duplicate": stats["skipped_duplicate"],
            "generated_artifacts": generated,
        },
    )
