"""AGENT_AUDITABILITY — instruction → context → tool → policy → output trace."""

from __future__ import annotations

from core.pipeline_models import (
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.agent_eval_support import (
    AGENT_AUDITABILITY_CONTROLS,
    run_agent_eval,
    run_agent_auditability,
)

EVAL_ID = "AGENT_AUDITABILITY"
EVAL_NAME = "Agent auditability"


def eval_agent_auditability(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
):
    return run_agent_eval(
        bundle,
        runner=run_agent_auditability,
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        controls=AGENT_AUDITABILITY_CONTROLS,
    )
