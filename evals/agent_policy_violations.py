"""AGENT_POLICY_VIOLATIONS — guardrail breaches and incident-relevant agent abuse."""

from __future__ import annotations

from core.pipeline_models import (
    PipelineAssetEvidence as AssetEvidence,
    PipelineEvidenceBundle as EvidenceBundle,
    PipelineSemanticEvent as SemanticEvent,
)
from evals.agent_eval_support import (
    AGENT_POLICY_VIOLATIONS_CONTROLS,
    run_agent_eval,
    run_agent_policy_violations,
)

EVAL_ID = "AGENT_POLICY_VIOLATIONS"
EVAL_NAME = "Agent policy violations"


def eval_agent_policy_violations(
    bundle: EvidenceBundle,
    event: SemanticEvent,
    asset: AssetEvidence,
):
    return run_agent_eval(
        bundle,
        runner=run_agent_policy_violations,
        eval_id=EVAL_ID,
        name=EVAL_NAME,
        controls=AGENT_POLICY_VIOLATIONS_CONTROLS,
    )
