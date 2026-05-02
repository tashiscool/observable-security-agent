"""AGENT_PERMISSION_SCOPE — least privilege and credential posture for agents."""

from __future__ import annotations

from core.pipeline_models import (
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.agent_eval_support import (
    AGENT_PERMISSION_SCOPE_CONTROLS,
    run_agent_eval,
    run_agent_permission_scope,
)

EVAL_ID = "AGENT_PERMISSION_SCOPE"
EVAL_NAME = "Agent permission scope"


def eval_agent_permission_scope(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
):
    return run_agent_eval(
        bundle,
        runner=run_agent_permission_scope,
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        controls=AGENT_PERMISSION_SCOPE_CONTROLS,
    )
