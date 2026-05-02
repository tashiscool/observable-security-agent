"""Grounded prompts, deterministic fallbacks, optional OpenAI-compatible LLM call."""

from __future__ import annotations

import json
import os
import re
from typing import Any, Literal

from core.evidence_contract import (
    deterministic_eval_footer,
    deterministic_package_footer,
    evidence_contract_markdown,
    primary_artifacts_for_prompt,
    user_message_artifact_clause,
)

TRACE_RULES: dict[str, dict[str, str]] = {
    "CM8_INVENTORY_RECONCILIATION": {
        "rule": (
            "Declared authoritative inventory must reconcile to discovered in-boundary production assets: "
            "no duplicate authoritative keys, no rogue production assets absent from inventory, "
            "and expected attributes consistent with discovery."
        ),
        "inputs": "declared_inventory.csv; discovered_assets.json.",
        "logic": (
            "Compare declared rows to discovered asset_ids; flag duplicate name or asset_id; "
            "flag in-boundary declared rows without matching discovery; flag rogue discovered assets; "
            "compare expected_private_ip to discovered when both exist."
        ),
        "conclusion": "FAIL when any reconciliation rule fires.",
    },
    "RA5_SCANNER_SCOPE_COVERAGE": {
        "rule": (
            "In-boundary assets with scanner_required=true must have scanner target coverage "
            "(asset_id, hostname, or IP) unless exempt in evidence."
        ),
        "inputs": "declared_inventory.csv; scanner_targets.csv; scanner_findings.json.",
        "logic": "Match required assets to targets; flag contradictions (e.g. finding without target).",
        "conclusion": "FAIL when coverage is missing or contradicted.",
    },
    "AU6_CENTRALIZED_LOG_COVERAGE": {
        "rule": "Required assets must have active central log ingestion in the assessment window.",
        "inputs": "declared_inventory.csv (log_required); central_log_sources.json.",
        "logic": "Derive LogSource status from fixture flags; require active central path.",
        "conclusion": "FAIL when required assets lack active central logs.",
    },
    "SI4_ALERT_INSTRUMENTATION": {
        "rule": "Risky semantics must have enabled alert rules with recipients; proof may require sample/last_fired.",
        "inputs": "alert_rules.json; normalized event semantic types.",
        "logic": "Map semantics to rules; fail on disabled rules or missing recipients.",
        "conclusion": "FAIL when no enabled recipient-backed rule covers required semantics.",
    },
    "CROSS_DOMAIN_EVENT_CORRELATION": {
        "rule": "Each correlated risky event must satisfy the cross-domain evidence chain.",
        "inputs": "correlations.json (per-row flags and missing_evidence).",
        "logic": "Evaluate each correlation row against inventory, scanner, logs, alerts, tickets.",
        "conclusion": "FAIL when any row has missing chain evidence.",
    },
    "RA5_EXPLOITATION_REVIEW": {
        "rule": (
            "Open High/Critical findings require exploitation-review evidence and sufficient logging posture."
        ),
        "inputs": "scanner_findings.json (exploitation_review); tickets.json; central_log_sources.json.",
        "logic": "Check exploitation_review flags and linked ticket verification; may require active logs.",
        "conclusion": "FAIL when review evidence is absent for qualifying findings.",
    },
    "CM3_CHANGE_EVIDENCE_LINKAGE": {
        "rule": "Security-relevant events must link to tickets with required CM-3 evidence flags.",
        "inputs": "cloud_events.json; tickets.json.",
        "logic": "Match events to tickets; evaluate SIA, test, approval, deploy, verification flags.",
        "conclusion": "FAIL when links or evidence flags are missing.",
    },
    "CA5_POAM_STATUS": {
        "rule": "Failed/partial evaluations should be reflected in POA&M tracking.",
        "inputs": "eval_results.json; poam.csv.",
        "logic": "Compare eval outcomes to generated POAM-AUTO rows and seeds.",
        "conclusion": "OPEN/PARTIAL/FAIL based on POA&M coverage vs gaps.",
    },
    "AGENT_TOOL_GOVERNANCE": {
        "rule": "Agent tool calls must stay within registered allow lists and data scopes.",
        "inputs": "agent_security/agent_assessment.json (tool_calls, agent_identities).",
        "logic": "Compare each tool_name/action/target to identity allow lists; flag unknown policy on high risk.",
        "conclusion": "FAIL when any invocation violates governance.",
    },
    "AGENT_PERMISSION_SCOPE": {
        "rule": "Agents must not hold wildcard admin credentials or out-of-scope production access.",
        "inputs": "agent_assessment.json identities and tool targets.",
        "logic": "Detect wildcards, human-style credential refs, prod touches from non-prod agents.",
        "conclusion": "FAIL on scope or credential posture violations.",
    },
    "AGENT_MEMORY_CONTEXT_SAFETY": {
        "rule": "Sensitive memory writes and untrusted external context must be labeled and policy-bound.",
        "inputs": "agent_assessment.json memory_events; related tool_calls.",
        "logic": "PII/secret long-term writes; unlabeled external_context; retrieve→tool without raw_ref.",
        "conclusion": "FAIL when memory handling is unsafe or untraceable.",
    },
    "AGENT_APPROVAL_GATES": {
        "rule": "High-risk or destructive actions require recorded approvals.",
        "inputs": "agent_assessment.json tool_calls (approval_* fields).",
        "logic": "Flag approval_required with missing status; destructive verbs with allowed policy.",
        "conclusion": "FAIL when approval gates are bypassed.",
    },
    "AGENT_POLICY_VIOLATIONS": {
        "rule": "Recorded violations (injection, credential abuse, escalation) drive severity-based outcomes.",
        "inputs": "agent_assessment.json policy_violations[].",
        "logic": "Map violation_type and severity to PASS/PARTIAL/FAIL.",
        "conclusion": "FAIL on critical/high patterns; PARTIAL on medium.",
    },
    "AGENT_AUDITABILITY": {
        "rule": "Each tool invocation must be attributable and evidence-linked.",
        "inputs": "agent_identities; tool_calls (raw_ref, policy_decision).",
        "logic": "Require identities when tools exist; forbid missing raw_ref and unknown policy.",
        "conclusion": "FAIL when the decision chain cannot be replayed from artifacts.",
    },
}

Audience = Literal["assessor", "executive", "ao", "engineer"]

MODE_ALIASES: dict[str, str] = {
    "trace_ksi_to_evidence": "trace_ksi_evidence",
    "explain_rev4_to_20x_mapping": "explain_crosswalk",
    "draft_assessor_response": "assessor_response",
    "draft_executive_summary": "executive_summary",
    "draft_ao_risk_explanation": "ao_risk_brief",
    "explain_reconciliation_failure": "reconciliation_failure",
    "auditor_response": "assessor_response",
}

_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "credential",
    "private_key",
    "bearer",
    "authorization",
    "client_secret",
    "access_key",
)


def redact_secrets(obj: Any) -> Any:
    """Remove obvious secret-bearing fields from structures serialized into LLM prompts."""

    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for k, v in obj.items():
            lk = str(k).lower()
            if any(anyfrag in lk for anyfrag in _SENSITIVE_KEY_FRAGMENTS):
                out[k] = "[REDACTED]"
            else:
                out[k] = redact_secrets(v)
        return out
    if isinstance(obj, list):
        return [redact_secrets(x) for x in obj]
    if isinstance(obj, str) and re.fullmatch(r"Bearer\s+[\w\-._~+/]+=*", obj, re.I):
        return "[REDACTED_BEARER]"
    return obj


def _normalize_mode(mode: str) -> str:
    m = (mode or "explain_eval").strip()
    return MODE_ALIASES.get(m, m)


def _normalize_audience(audience: str | None) -> str:
    a = (audience or "engineer").strip().lower()
    if a in ("assessor", "executive", "ao", "engineer"):
        return a
    return "engineer"


def _poam_list(selected_poam: dict[str, Any] | list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    if selected_poam is None:
        return []
    if isinstance(selected_poam, dict):
        return [selected_poam] if selected_poam else []
    return [x for x in selected_poam if isinstance(x, dict)]


def _merge_fedramp20x_context(
    *,
    fedramp20x_context: dict[str, Any] | None,
    selected_ksi: dict[str, Any] | None,
    selected_finding: dict[str, Any] | None,
    selected_poam: dict[str, Any] | list[dict[str, Any]] | None,
    related_evidence: dict[str, Any] | None,
    related_reconciliation: dict[str, Any] | None,
) -> dict[str, Any]:
    base: dict[str, Any] = dict(fedramp20x_context) if fedramp20x_context else {}
    if selected_ksi:
        base["selected_ksi"] = selected_ksi
    if selected_finding:
        base["selected_finding"] = selected_finding
    plist = _poam_list(selected_poam)
    if plist:
        base["selected_poam_items"] = plist
    if related_reconciliation:
        base["reconciliation"] = related_reconciliation
    if related_evidence:
        base["related_evidence"] = related_evidence
        cw = related_evidence.get("control_crosswalk")
        if cw:
            base["control_crosswalk"] = cw
        kvr = related_evidence.get("ksi_validation_row")
        if isinstance(kvr, dict):
            base["ksi_validation_row"] = kvr
        for k in ("package_summary", "executive_excerpt", "ao_excerpt"):
            if related_evidence.get(k) is not None:
                base[k] = related_evidence[k]
    return base


def _grounded_system_preamble(*, audience: str) -> str:
    aud = _normalize_audience(audience)
    tone = {
        "assessor": "Use precise control language; cite criteria and evidence source ids.",
        "executive": "Use concise business and readiness language; avoid deep implementation jargon.",
        "ao": "Use risk, residual risk, and acceptance framing; tie to findings and POA&M when present.",
        "engineer": "Use actionable technical language; name artifacts and fields explicitly.",
    }.get(aud, "Be precise and neutral.")
    return (
        "You are explaining a security evidence assessment result.\n"
        "Rules:\n"
        "- Use only the provided artifacts.\n"
        "- Do not invent evidence.\n"
        "- If evidence is missing, say **missing evidence** (exact phrase).\n"
        "- Distinguish evidence gap (artifact not provided) from failed security implementation (evidence shows control weakness).\n"
        "- Cite artifact names and fields.\n"
        "- Explain trace when relevant: Rev4 control → Rev5 control → KSI → criterion → evidence source → "
        "validation result → finding → POA&M.\n"
        f"- Tailor language to audience: {aud}. {tone}\n"
        "\n"
        + evidence_contract_markdown()
        + "\n"
    )


def build_grounded_user_message(
    *,
    mode: str,
    question: str | None,
    audience: str,
    selected_eval: dict[str, Any] | None,
    related_evidence: dict[str, Any] | None,
    related_graph: dict[str, Any] | None,
    related_poam: list[dict[str, Any]] | None,
    fedramp20x_context: dict[str, Any] | None,
    selected_ksi: dict[str, Any] | None = None,
    selected_finding: dict[str, Any] | None = None,
    selected_poam: dict[str, Any] | list[dict[str, Any]] | None = None,
    related_reconciliation: dict[str, Any] | None = None,
) -> str:
    merged = _merge_fedramp20x_context(
        fedramp20x_context=fedramp20x_context,
        selected_ksi=selected_ksi,
        selected_finding=selected_finding,
        selected_poam=selected_poam,
        related_evidence=related_evidence,
        related_reconciliation=related_reconciliation,
    )
    payload = redact_secrets(
        {
            "mode": mode,
            "question": question,
            "audience": audience,
            "selected_ksi": selected_ksi,
            "selected_eval": selected_eval,
            "selected_finding": selected_finding,
            "selected_poam": selected_poam,
            "related_evidence": related_evidence,
            "related_reconciliation": related_reconciliation,
            "related_graph_summary": {
                "root_event": (related_graph or {}).get("root_event"),
                "edge_count": len((related_graph or {}).get("edges") or []),
            },
            "related_poam_legacy": related_poam,
            "fedramp20x_context": merged,
        }
    )
    arts = primary_artifacts_for_prompt(
        related_evidence=related_evidence,
        related_graph=related_graph,
        selected_eval=selected_eval,
        fedramp20x_context=fedramp20x_context,
        related_reconciliation=related_reconciliation,
    )
    parts = [
        f"Task mode: {mode}",
        f"Audience: {audience}",
        "",
        "User question:",
        question or "(none)",
        "",
        "Structured inputs (JSON, redacted where applicable):",
        json.dumps(payload, indent=2, default=str)[:28000],
        "",
        "Instruction: Use only the artifacts and fields above. Do not invent evidence.",
        user_message_artifact_clause(arts),
        "",
        "The Evidence contract in the system message is binding (including alert/ticket/exploitation-review rules).",
    ]
    return "\n".join(parts)


def _first_criterion(ksi: dict[str, Any]) -> dict[str, Any] | None:
    crit = ksi.get("pass_fail_criteria") or []
    if isinstance(crit, list) and crit and isinstance(crit[0], dict):
        return crit[0]
    return None


def _deterministic_fedramp20x(
    *,
    mode: str,
    audience: str,
    question: str | None,
    ctx: dict[str, Any],
    selected_eval: dict[str, Any] | None,
) -> tuple[str, list[str]] | None:
    warnings: list[str] = ["FedRAMP 20x / package mode: deterministic template from provided fields only."]
    aud = _normalize_audience(audience)
    ksi = ctx.get("selected_ksi") or ctx.get("ksi_catalog_entry") or {}
    kid = str(ksi.get("ksi_id") or "")
    row = ctx.get("ksi_validation_row") or {}
    evrefs = row.get("evidence_refs") or ksi.get("evidence_refs") or []
    crit = _first_criterion(ksi)
    crit_id = str((crit or {}).get("criteria_id") or "UNKNOWN-CRITERION")
    crit_desc = str((crit or {}).get("description") or "")[:400]
    ev_req = (crit or {}).get("evidence_required") or []
    first_src = str(ev_req[0]) if ev_req else "UNKNOWN-SOURCE"
    st = str(row.get("status") or "").upper() or "UNKNOWN"
    lc = ksi.get("legacy_controls") or {}
    rev4s = ", ".join(str(x) for x in (lc.get("rev4") or [])[:6]) or "—"
    rev5s = ", ".join(str(x) for x in (lc.get("rev5") or [])[:6]) or "—"
    finding = ctx.get("selected_finding") or (ctx.get("selected_findings") or [None])[0]
    fid = str((finding or {}).get("finding_id") or "")
    sev = str((finding or {}).get("severity") or "")
    poams = ctx.get("selected_poam_items") or _poam_list(ctx.get("selected_poam"))
    poam_id = str((poams[0] or {}).get("poam_id") or "") if poams else ""

    if mode == "explain_ksi":
        refs_s = json.dumps(evrefs, indent=2)[:2000] if evrefs else "[] (no evidence_refs on validation row)"
        body = (
            f"KSI `{kid}` — validation status from package row: **{st}**.\n"
            f"Evidence refs (fedramp20x-package.json / ksi_validation_results): {refs_s}\n"
            f"Catalog theme/title: {ksi.get('theme', '')} / {ksi.get('title', '')}\n"
            f"Linked Rev4 / Rev5 (legacy_controls): {rev4s} | {rev5s}\n"
        )
        if aud == "assessor":
            body += (
                f"Assessor template: Criterion `{crit_id}` is reflected in rollup `{st}`. "
                f"Evidence source `{first_src}` is required by the criterion; if absent in exports, state **missing evidence** "
                f"rather than asserting implementation failure. Description (excerpt): {crit_desc}\n"
            )
        elif aud == "executive":
            body += "Executive template: Treat non-PASS KSI status as a readiness signal until closed with cited artifacts.\n"
        elif aud == "ao":
            body += "AO template: Residual risk ties to open findings linked to this KSI in the package; verify POA&M coverage.\n"
        else:
            body += "Engineer template: Close gaps by attaching the evidence_refs artifacts and re-running validation.\n"
        if question:
            body += f"\nUser follow-up: {question}\n"
        return body, warnings

    if mode == "trace_ksi_evidence":
        body = (
            f"Trace for KSI `{kid}` (artifact-bound chain):\n"
            f"1) Rev4 / Rev5 controls (legacy_controls): {rev4s} → {rev5s}\n"
            f"2) KSI catalog: theme={ksi.get('theme','')}; validation_mode={ksi.get('validation_mode','')}\n"
            f"3) Criterion example: `{crit_id}` — {crit_desc[:300]}\n"
            f"4) Evidence sources (catalog ids): {json.dumps(ksi.get('evidence_sources') or [], indent=2)}\n"
            f"5) Validation result row status: {st}\n"
            f"6) evidence_refs on result row: {json.dumps(evrefs, indent=2)[:2000]}\n"
        )
        if fid:
            body += f"7) Finding `{fid}` (severity {sev}) if linked in package\n"
        if poam_id:
            body += f"8) POA&M `{poam_id}` if linked\n"
        return body, warnings

    if mode == "explain_crosswalk":
        cw = ctx.get("control_crosswalk") or (ctx.get("related_evidence") or {}).get("control_crosswalk")
        if not cw:
            return (
                "Crosswalk: **missing evidence** — provide `control_crosswalk` under related_evidence or "
                "fedramp20x_context (see fedramp20x-package.json).",
                warnings,
            )
        body = (
            "Rev4 → Rev5 → KSI crosswalk (fedramp20x-package.json `control_crosswalk` only):\n"
            f"{json.dumps(cw, indent=2, default=str)[:14000]}\n"
            "Explain mapping using only these rows; do not infer unpublished NIST mappings."
        )
        return body, warnings

    if mode == "assessor_response":
        gaps = (selected_eval or {}).get("gap") or "; ".join((selected_eval or {}).get("gaps") or [])
        eid = str((selected_eval or {}).get("eval_id") or "")
        body = (
            f"Assessor-facing draft (audience={aud}):\n"
            f"We acknowledge evaluation `{eid}` with documented gaps: {str(gaps)[:1200]}\n"
            f"KSI `{kid}` rollup status `{st}` with evidence_refs: {json.dumps(evrefs, indent=2)[:1500]}\n"
            "Required closure evidence: attach exports for each evidence line cited in eval_results.json / package evidence_refs.\n"
        )
        return body, warnings

    if mode == "executive_summary":
        summ = ctx.get("package_summary") or (ctx.get("related_evidence") or {}).get("package_summary") or {}
        ex = ctx.get("executive_excerpt") or ""
        body = (
            "Executive summary draft (evidence-bounded):\n"
            f"This is a readiness risk because package summary fields show: {json.dumps(summ, indent=2)[:4000]}\n"
        )
        if ex:
            body += f"Executive artifact excerpt (if provided): {ex[:2500]}\n"
        body += "Do not claim PASS/FAIL beyond what the summary JSON states.\n"
        return body, warnings

    if mode == "ao_risk_brief":
        ao_ex = ctx.get("ao_excerpt") or ""
        body = "AO risk framing (from package only):\n"
        if finding and fid:
            body += f"The residual risk being accepted or tracked is tied to finding `{fid}` (severity `{sev}`).\n"
        else:
            body += "No selected finding in payload; describe only reconciliation / KSI status if present.\n"
        if poam_id:
            body += f"POA&M `{poam_id}` records planned treatment.\n"
        if ao_ex:
            body += f"AO excerpt: {ao_ex[:2500]}\n"
        body += f"KSI `{kid}` status `{st}`.\n"
        return body, warnings

    if mode == "reconciliation_failure":
        rec = ctx.get("reconciliation") or {}
        checks = [
            c
            for c in (rec.get("checks") or [])
            if isinstance(c, dict) and str(c.get("status", "")).lower() != "pass"
        ]
        if not checks:
            return (
                "Reconciliation: no failing checks in `related_reconciliation.checks` (or all pass). "
                f"Overall status: {rec.get('overall_status', 'unknown')}.",
                warnings,
            )
        lines = [
            "Reconciliation mismatch (deterministic): the following checks did not pass.",
            "Explain each by citing its `id`, `description`, and `detail` fields only.",
        ]
        for c in checks[:25]:
            cid = str(c.get("id") or "")
            lines.append(f"- **{cid}**: {c.get('description','')} — detail: {str(c.get('detail',''))[:500]}")
        return "\n".join(lines), warnings

    if mode == "poam_remediation_plan":
        plist = poams or _poam_list(ctx.get("selected_poam"))
        if not plist:
            return (
                "POA&M remediation plan: **missing evidence** — provide selected_poam or selected_poam_items "
                "(fedramp20x-package.json / POA&M slice).",
                warnings,
            )
        p0 = plist[0]
        pid = str(p0.get("poam_id") or "")
        title = str(p0.get("title") or p0.get("weakness_name") or "")
        rem = str((finding or {}).get("recommended_remediation") or "")
        body = (
            f"POA&M remediation plan draft for `{pid}`:\n"
            f"- Weakness: {title}\n"
            f"- Tie to finding `{fid}` recommended remediation (from package): {rem[:1500]}\n"
            "- Milestones: (1) implement controls, (2) attach evidence exports, (3) re-run assess + validate_outputs.\n"
        )
        return body, warnings

    return None


def deterministic_answer(
    *,
    mode: str,
    question: str | None,
    audience: str,
    selected_eval: dict[str, Any] | None,
    fedramp20x_context: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    warnings: list[str] = []
    ev = selected_eval or {}
    eid = str(ev.get("eval_id") or "")
    T = TRACE_RULES.get(eid)
    ctx = fedramp20x_context or {}

    fed = _deterministic_fedramp20x(
        mode=mode,
        audience=audience,
        question=question,
        ctx=ctx,
        selected_eval=selected_eval,
    )
    if fed is not None:
        body, w = fed
        body = f"{body.rstrip()}\n\n{deterministic_package_footer()}"
        return body, w

    if mode == "trace_derivation" or mode == "explain_eval":
        if T:
            body = "\n".join(
                [
                    f"Eval: {eid}",
                    f"Result: {ev.get('result')}",
                    "",
                    "Rule:",
                    T["rule"],
                    "",
                    "Inputs:",
                    T["inputs"],
                    "",
                    "Logic:",
                    T["logic"],
                    "",
                    "Conclusion:",
                    T["conclusion"],
                    "",
                    "From eval_results.json:",
                    f"- summary: {ev.get('summary')}",
                    f"- gap: {str(ev.get('gap') or '')[:2000]}",
                ]
            )
            body += deterministic_eval_footer(mode=mode, selected_eval=selected_eval)
            return body, warnings
        warnings.append("No local trace template for eval_id; using summary/gap only.")
        body = (
            f"Eval {eid}\nResult: {ev.get('result')}\nSummary: {ev.get('summary')}\nGap: {ev.get('gap')}"
        )
        body += deterministic_eval_footer(mode=mode, selected_eval=selected_eval)
        return body, warnings
    if mode == "remediation_ticket":
        body = (
            "Title: Close observability gaps for "
            + eid
            + "\n\nDescription:\n"
            + str(ev.get("recommended_action") or ev.get("summary") or "")
            + "\n\nControls: "
            + ", ".join(ev.get("control_refs") or [])
            + "\n\nAcceptance criteria:\n"
            "- Attach exports proving each gap is closed.\n"
            "- Re-run agent assess and validate_outputs.\n"
            "(Ground in **eval_results.json**; absent proof remains **missing evidence**.)"
        )
        body += deterministic_eval_footer(mode=mode, selected_eval=selected_eval)
        return body, warnings
    if mode == "instrumentation_plan":
        body = (
            "Use **instrumentation_plan.md** in the output package: implement Splunk/Sentinel/GCP/AWS "
            "queries shown there, enable alerts with recipients, and attach sample alert exports "
            "(`sample_alert_ref` or equivalent) so alert firing is not **missing evidence**."
        )
        body += "\n\n" + deterministic_package_footer()
        return body, warnings
    body = f"Mode {mode}: {question or 'No question.'}\n{json.dumps(ev, indent=2)[:4000]}"
    body += "\n\n" + deterministic_package_footer()
    return body, warnings


def call_openai_compatible(prompt: str, *, audience: str) -> str | None:
    try:
        import httpx
    except ImportError:
        return None
    key = (os.environ.get("AI_API_KEY") or "").strip()
    if not key:
        return None
    base = (os.environ.get("AI_API_BASE") or "https://api.openai.com/v1").rstrip("/")
    model = (os.environ.get("AI_MODEL") or "gpt-4o-mini").strip()
    url = f"{base}/chat/completions"
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": _grounded_system_preamble(audience=audience)},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
    }
    with httpx.Client(timeout=120.0) as client:
        r = client.post(url, headers={"Authorization": f"Bearer {key}"}, json=payload)
        r.raise_for_status()
        data = r.json()
        return str(data["choices"][0]["message"]["content"])


def run_explain(
    *,
    mode: str,
    question: str | None = None,
    audience: str | None = None,
    selected_ksi: dict[str, Any] | None = None,
    selected_eval: dict[str, Any] | None = None,
    selected_finding: dict[str, Any] | None = None,
    selected_poam: dict[str, Any] | list[dict[str, Any]] | None = None,
    related_evidence: dict[str, Any] | None = None,
    related_reconciliation: dict[str, Any] | None = None,
    related_graph: dict[str, Any] | None = None,
    related_poam: list[dict[str, Any]] | None = None,
    fedramp20x_context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    m = _normalize_mode(mode)
    aud = _normalize_audience(audience)
    merged_ctx = _merge_fedramp20x_context(
        fedramp20x_context=fedramp20x_context,
        selected_ksi=selected_ksi,
        selected_finding=selected_finding,
        selected_poam=selected_poam,
        related_evidence=related_evidence,
        related_reconciliation=related_reconciliation,
    )
    used = ["eval_results.json"]
    if merged_ctx:
        used.append("fedramp20x-package.json (context slice)")
    warnings: list[str] = []

    user_msg = build_grounded_user_message(
        mode=m,
        question=question,
        audience=aud,
        selected_eval=selected_eval,
        related_evidence=related_evidence,
        related_graph=related_graph,
        related_poam=related_poam,
        fedramp20x_context=merged_ctx if merged_ctx else None,
        selected_ksi=selected_ksi,
        selected_finding=selected_finding,
        selected_poam=selected_poam,
        related_reconciliation=related_reconciliation,
    )
    full_prompt = _grounded_system_preamble(audience=aud) + "\n" + user_msg

    try:
        llm = call_openai_compatible(full_prompt, audience=aud)
    except Exception as ex:  # noqa: BLE001
        llm = None
        warnings.append(f"LLM unavailable: {ex}")

    if llm:
        used.append("llm")
        return {"answer": llm, "used_artifacts": used, "warnings": warnings}

    text, w2 = deterministic_answer(
        mode=m,
        question=question,
        audience=aud,
        selected_eval=selected_eval,
        fedramp20x_context=merged_ctx if merged_ctx else None,
    )
    warnings.extend(w2)
    return {
        "answer": text,
        "used_artifacts": used + ["deterministic_templates"],
        "warnings": warnings or ["AI_API_KEY not set; returned deterministic explanation."],
    }
