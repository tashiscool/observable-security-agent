"""AGENT_APPROVAL_GATES — human approval for risky or destructive actions."""

from __future__ import annotations

from core.pipeline_models import (
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.agent_eval_support import (
    AGENT_APPROVAL_GATES_CONTROLS,
    run_agent_eval,
    run_agent_approval_gates,
)

EVAL_ID = "AGENT_APPROVAL_GATES"
EVAL_NAME = "Agent approval gates"


def eval_agent_approval_gates(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
):
    return run_agent_eval(
        bundle,
        runner=run_agent_approval_gates,
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        controls=AGENT_APPROVAL_GATES_CONTROLS,
    )
