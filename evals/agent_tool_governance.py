"""AGENT_TOOL_GOVERNANCE — tool allow lists, actions, scopes, and policy decisions."""

from __future__ import annotations

from core.pipeline_models import (
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.agent_eval_support import (
    AGENT_TOOL_GOVERNANCE_CONTROLS,
    run_agent_eval,
    run_agent_tool_governance,
)

EVAL_ID = "AGENT_TOOL_GOVERNANCE"
EVAL_NAME = "Agent tool governance"


def eval_agent_tool_governance(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
):
    return run_agent_eval(
        bundle,
        runner=run_agent_tool_governance,
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        controls=AGENT_TOOL_GOVERNANCE_CONTROLS,
    )
