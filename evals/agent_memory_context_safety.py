"""AGENT_MEMORY_CONTEXT_SAFETY — sensitive memory, external context, traceability."""

from __future__ import annotations

from core.pipeline_models import (
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.agent_eval_support import (
    AGENT_MEMORY_CONTEXT_SAFETY_CONTROLS,
    run_agent_eval,
    run_agent_memory_context_safety,
)

EVAL_ID = "AGENT_MEMORY_CONTEXT_SAFETY"
EVAL_NAME = "Agent memory context safety"


def eval_agent_memory_context_safety(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
):
    return run_agent_eval(
        bundle,
        runner=run_agent_memory_context_safety,
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        controls=AGENT_MEMORY_CONTEXT_SAFETY_CONTROLS,
    )
