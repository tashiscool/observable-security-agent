"""
Agentic AI risk threat-hunt mode: hypothesis-driven findings from evidence + agent telemetry.

Language is conservative: suspected / requires review / blocked attempt — not asserted compromise.
"""

from __future__ import annotations

import json
import re
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

from core.agent_models import (
    AgentAssessmentBundle,
    AgentIdentity,
    AgentMemoryEvent,
    AgentPolicyViolation,
    AgentToolCall,
)
from core.pipeline_models import PipelineEvidenceBundle as EvidenceBundle
from core.poam import milestone_due_date_for_severity, write_poam_csv_file
from evals.agent_eval_support import load_agent_assessment_bundle

_INSTRUCTION_PATTERNS = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior)\s+instructions?|disregard\s+(the\s+)?(above|prior)|"
    r"system\s*:\s*you\s+are|override\s+(safety|policy)|export\s+(customer|user)\s+data)",
    re.IGNORECASE,
)

_NEXT_ID = 0


def _fid(prefix: str) -> str:
    global _NEXT_ID
    _NEXT_ID += 1
    return f"th-{prefix}-{_NEXT_ID:04d}"


def _identity_by_agent(ab: AgentAssessmentBundle) -> dict[str, AgentIdentity]:
    return {i.agent_id: i for i in ab.agent_identities}


def _alert_rules_rows(bundle: EvidenceBundle) -> list[dict[str, Any]]:
    ar = bundle.alert_rules
    if isinstance(ar, dict):
        rules = ar.get("rules", ar)
        return rules if isinstance(rules, list) else []
    return []


def _tickets_text_blobs(bundle: EvidenceBundle) -> list[tuple[str, str, str]]:
    """(ticket_id, combined_text, ref) for pattern scans."""
    tix = bundle.tickets
    rows = tix.get("tickets", tix) if isinstance(tix, dict) else []
    if not isinstance(rows, list):
        return []
    out: list[tuple[str, str, str]] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        tid = str(row.get("id") or row.get("ticket_id") or "").strip()
        parts = [str(row.get("title") or ""), str(row.get("notes") or ""), str(row.get("description") or "")]
        blob = " ".join(parts)
        ref = f"tickets.json#ticket_id={tid}" if tid else "tickets.json"
        out.append((tid or "unknown", blob, ref))
    return out


def _has_agentic_alert_coverage(rules: list[dict[str, Any]]) -> bool:
    """True if an enabled rule plausibly covers agentic abuse / prompt injection (heuristic)."""
    keys = (
        "prompt injection",
        "prompt_injection",
        "agent policy",
        "agent tool",
        "agentic",
        "llm guardrail",
        "genai",
        "ai agent",
        "tool gateway",
        "unauthorized tool",
        "shadow ai",
    )
    for r in rules:
        if not r or not isinstance(r, dict):
            continue
        if not bool(r.get("enabled", False)):
            continue
        blob = " ".join(
            [
                str(r.get("name") or ""),
                str(r.get("matches_event_type") or ""),
                " ".join(str(x) for x in (r.get("mapped_semantic_types") or []) if x),
                " ".join(str(x) for x in (r.get("event_types") or []) if x),
            ],
        ).lower()
        if any(k in blob for k in keys):
            return True
    return False


def has_agentic_siem_rule_coverage(rules: list[dict[str, Any]]) -> bool:
    """Public wrapper: True if enabled rules plausibly cover agentic / prompt-injection telemetry (heuristic)."""
    return _has_agentic_alert_coverage(rules)


def _collect_findings(
    *,
    evidence_root: Path,
    agent_telemetry_root: Path,
    bundle: EvidenceBundle,
    ab: AgentAssessmentBundle | None,
) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    rules = _alert_rules_rows(bundle)
    disclaim = "Assessment language only; requires review with primary evidence. Does not assert compromise."

    if ab is None:
        findings.append(
            {
                "finding_id": _fid("no-telemetry"),
                "detection_type": "shadow_ai_usage",
                "hypothesis": "Agentic activity may be present but was not loaded for correlation (no agent bundle).",
                "signals_observed": ["No agent_security/agent_assessment.json or split agent_identities.json at telemetry root."],
                "evidence_refs": [f"{agent_telemetry_root.as_posix()}/"],
                "confidence": "low",
                "severity": "low",
                "recommended_containment": "Re-run with --agent-telemetry pointing at a directory containing agent telemetry exports.",
                "recommended_instrumentation": "Ensure agent gateways emit structured JSON aligned to this tool's loader paths.",
                "linked_ksi_control_refs": ["AU-2", "AU-3", "SI-4"],
                "narrative_disclaimer": disclaim,
            },
        )
        return findings

    idmap = _identity_by_agent(ab)

    # --- shadow_ai_usage ---
    allowed_union: set[str] = set()
    for ident in ab.agent_identities:
        allowed_union.update(ident.allowed_tools)
    for tc in ab.tool_calls:
        ident = idmap.get(tc.agent_id)
        if isinstance(ident, AgentIdentity) and tc.tool_name not in ident.allowed_tools:
            findings.append(
                {
                    "finding_id": _fid("shadow"),
                    "detection_type": "shadow_ai_usage",
                    "hypothesis": "An agent attempted a tool invocation outside its registered allow list (unapproved capability; requires review).",
                    "signals_observed": [
                        f"tool_name `{tc.tool_name}` not in allowed_tools for agent `{tc.agent_id}`.",
                        f"policy_decision={tc.policy_decision}",
                    ],
                    "evidence_refs": [
                        f"{agent_telemetry_root.as_posix()}/agent_tool_calls.json#call_id={tc.call_id}",
                        f"{agent_telemetry_root.as_posix()}/agent_identities.json#agent_id={tc.agent_id}",
                    ],
                    "confidence": "high" if tc.policy_decision == "blocked" else "medium",
                    "severity": "high" if tc.risk_level in ("high", "critical") else "medium",
                    "recommended_containment": "Block execution at gateway; rotate agent credentials if policy allowed execution paths; confirm no successful API mutation.",
                    "recommended_instrumentation": "Log allow-list denials with agent_id, tool_name, and requestor principal; alert on first occurrence per agent per day.",
                    "linked_ksi_control_refs": ["CM-10", "CM-11", "SA-9", "AC-6"],
                    "narrative_disclaimer": disclaim,
                },
            )

    # --- compromised_agent_behavior ---
    blocked = [tc for tc in ab.tool_calls if tc.policy_decision == "blocked"]
    if blocked:
        findings.append(
            {
                "finding_id": _fid("comp"),
                "detection_type": "compromised_agent_behavior",
                "hypothesis": "Agent behavior may be abnormal: repeated or high-severity policy blocks suggest drift, misuse, or hostile prompting (requires review).",
                "signals_observed": [
                    f"policy_decision=blocked on {len(blocked)} tool invocation(s).",
                    "Blocked attempts may indicate guardrails working; correlate with tickets and identity sessions.",
                ],
                "evidence_refs": [
                    f"{agent_telemetry_root.as_posix()}/agent_tool_calls.json#policy_decision=blocked",
                ],
                "confidence": "medium",
                "severity": "high" if any(tc.risk_level in ("high", "critical") for tc in blocked) else "medium",
                "recommended_containment": "Preserve audit logs; temporarily reduce agent scopes; require human-in-the-loop for high-risk tools.",
                "recommended_instrumentation": "Dashboard blocked/rejected tool rate per agent; anomaly alert on spike vs 14d baseline.",
                "linked_ksi_control_refs": ["SI-4", "AU-6", "IR-4"],
                "narrative_disclaimer": disclaim,
            },
        )

    # unusual sequence: read-class then admin-class within 10 minutes
    ordered = sorted(ab.tool_calls, key=lambda t: t.timestamp)
    for i, a in enumerate(ordered):
        for b in ordered[i + 1 :]:
            delta = (b.timestamp - a.timestamp).total_seconds()
            if delta < 0 or delta > 600:
                break
            if "read" in a.action.lower() and ("mutate" in b.action.lower() or "admin" in b.tool_name.lower()):
                findings.append(
                    {
                        "finding_id": _fid("seq"),
                        "detection_type": "compromised_agent_behavior",
                        "hypothesis": "Unusual tool sequencing (read workflow followed quickly by administrative mutation attempt) warrants review.",
                        "signals_observed": [
                            f"Prior call {a.call_id} ({a.tool_name}/{a.action}) then {b.call_id} ({b.tool_name}/{b.action}) within {int(delta)}s.",
                        ],
                        "evidence_refs": [
                            f"{agent_telemetry_root.as_posix()}/agent_tool_calls.json#call_id={a.call_id}",
                            f"{agent_telemetry_root.as_posix()}/agent_tool_calls.json#call_id={b.call_id}",
                        ],
                        "confidence": "medium",
                        "severity": "medium",
                        "recommended_containment": "Review session transcript; confirm ticket intent vs tool actions.",
                        "recommended_instrumentation": "Sequence analytics on tool audit stream keyed by session_id.",
                        "linked_ksi_control_refs": ["AU-2", "SI-4"],
                        "narrative_disclaimer": disclaim,
                    },
                )
                break

    # data outside stated purpose (heuristic)
    seen_scope: set[str] = set()
    for ident in ab.agent_identities:
        for tc in ab.tool_calls:
            if tc.agent_id != ident.agent_id:
                continue
            if ident.environment != "prod" and tc.target_resource and "prod" in tc.target_resource.lower():
                if ident.allowed_data_scopes and not any(
                    str(tc.target_resource).startswith(s) for s in ident.allowed_data_scopes
                ):
                    if tc.call_id in seen_scope:
                        continue
                    seen_scope.add(tc.call_id)
                    findings.append(
                        {
                            "finding_id": _fid("scope"),
                            "detection_type": "compromised_agent_behavior",
                            "hypothesis": "Agent may be accessing production-shaped resources inconsistent with registered non-prod scope (requires review).",
                            "signals_observed": [
                                f"agent environment={ident.environment!r} with target_resource containing prod marker: `{tc.target_resource}`.",
                            ],
                            "evidence_refs": [
                                f"{agent_telemetry_root.as_posix()}/agent_tool_calls.json#call_id={tc.call_id}",
                            ],
                            "confidence": "medium",
                            "severity": "high",
                            "recommended_containment": "Validate data scopes; deny prod mutations from non-prod agents.",
                            "recommended_instrumentation": "Alert on prod ARN prefix access from non-prod workload identities.",
                            "linked_ksi_control_refs": ["AC-3", "AC-6", "SC-7"],
                            "narrative_disclaimer": disclaim,
                        },
                    )

    # --- agentic_insider_risk ---
    seen_purpose_tc: set[str] = set()
    for ident in ab.agent_identities:
        purpose_l = ident.purpose.lower()
        cr = (ident.credentials_ref or "").lower()
        if re.search(r"\b(admin|root|human_user|breakglass)\b", cr):
            findings.append(
                {
                    "finding_id": _fid("insider"),
                    "detection_type": "agentic_insider_risk",
                    "hypothesis": "Privileged agent configuration may reference human-style or break-glass credential material (requires review).",
                    "signals_observed": ["credentials_ref matches human/admin-style token heuristic."],
                    "evidence_refs": [f"{agent_telemetry_root.as_posix()}/agent_identities.json#agent_id={ident.agent_id}"],
                    "confidence": "medium",
                    "severity": "high",
                    "recommended_containment": "Replace with workload identity / short-lived scoped roles; remove shared secrets.",
                    "recommended_instrumentation": "Secret scanning on agent registration manifests; periodic credential_ref review.",
                    "linked_ksi_control_refs": ["IA-5", "AC-2", "AC-6"],
                    "narrative_disclaimer": disclaim,
                },
            )
        for tc in ab.tool_calls:
            if tc.agent_id != ident.agent_id:
                continue
            if "mutate" in tc.action.lower() or "admin" in tc.tool_name.lower():
                if "ticket" in purpose_l and "draft" in purpose_l and "security" not in purpose_l:
                    if tc.call_id in seen_purpose_tc:
                        continue
                    seen_purpose_tc.add(tc.call_id)
                    findings.append(
                        {
                            "finding_id": _fid("purpose"),
                            "detection_type": "agentic_insider_risk",
                            "hypothesis": "Agent registered for ticket support workflows attempted an administrative mutation-class action (blocked attempt requires review).",
                            "signals_observed": [
                                f"purpose mentions ticket/draft support; observed `{tc.tool_name}` / `{tc.action}`.",
                                f"policy_decision={tc.policy_decision}",
                            ],
                            "evidence_refs": [
                                f"{agent_telemetry_root.as_posix()}/agent_tool_calls.json#call_id={tc.call_id}",
                                f"{agent_telemetry_root.as_posix()}/agent_identities.json#agent_id={ident.agent_id}",
                            ],
                            "confidence": "high",
                            "severity": "high",
                            "recommended_containment": "Tighten allow list; enforce separation between support bots and cloud control tools.",
                            "recommended_instrumentation": "SOAR playbooks for admin-tool attempts from non-admin agent classes.",
                            "linked_ksi_control_refs": ["AC-6", "CM-5", "SA-9"],
                            "narrative_disclaimer": disclaim,
                        },
                    )

    for v in ab.policy_violations:
        if v.violation_type == "approval_bypass":
            findings.append(
                {
                    "finding_id": _fid("bypass"),
                    "detection_type": "agentic_insider_risk",
                    "hypothesis": "Recorded approval-bypass class signal (requires review; may be blocked).",
                    "signals_observed": [f"violation_type={v.violation_type}", v.evidence[:500]],
                    "evidence_refs": [f"{agent_telemetry_root.as_posix()}/agent_policy_violations.json#violation_id={v.violation_id}"],
                    "confidence": "high",
                    "severity": v.severity,
                    "recommended_containment": "Suspend agent; rotate tokens; inspect gateway logs.",
                    "recommended_instrumentation": "Real-time deny events for bypass heuristics to SOC queue.",
                    "linked_ksi_control_refs": ["AC-6", "CA-7", "SI-4"],
                    "narrative_disclaimer": disclaim,
                },
            )

    # chain: sensitive memory write then outbound-ish tool (draft) — insider pattern (suspected)
    mem_writes = [m for m in ab.memory_events if m.action == "write" and m.sensitivity in ("pii", "secret")]
    for m in mem_writes:
        later = [tc for tc in ab.tool_calls if tc.timestamp > m.timestamp and (tc.timestamp - m.timestamp).total_seconds() < 300]
        if later:
            findings.append(
                {
                    "finding_id": _fid("chain"),
                    "detection_type": "agentic_insider_risk",
                    "hypothesis": "Sensitive memory write followed by tool activity within a short window may indicate data exfiltration staging (suspected; requires review).",
                    "signals_observed": [
                        f"memory {m.memory_event_id} sensitivity={m.sensitivity} action={m.action}",
                        f"subsequent tool calls: {', '.join(x.call_id for x in later[:3])}",
                    ],
                    "evidence_refs": [
                        f"{agent_telemetry_root.as_posix()}/agent_memory_events.json#memory_event_id={m.memory_event_id}",
                    ],
                    "confidence": "low",
                    "severity": "medium",
                    "recommended_containment": "Review session; verify DLP on agent outputs; confirm policy_decision on memory writes.",
                    "recommended_instrumentation": "Correlate memory write events with external egress / ticket update APIs.",
                    "linked_ksi_control_refs": ["SC-28", "AC-4", "SI-12"],
                    "narrative_disclaimer": disclaim,
                },
            )
            break

    # --- prompt_injection_suspected ---
    for v in ab.policy_violations:
        if v.violation_type == "unauthorized_tool_use":
            findings.append(
                {
                    "finding_id": _fid("unauth"),
                    "detection_type": "credential_misuse",
                    "hypothesis": "Recorded unauthorized tool use signal (typically a blocked attempt; requires review with gateway and IAM logs).",
                    "signals_observed": [f"violation_type={v.violation_type}", f"severity={v.severity}", v.evidence[:400]],
                    "evidence_refs": [
                        f"{agent_telemetry_root.as_posix()}/agent_policy_violations.json#violation_id={v.violation_id}",
                    ],
                    "confidence": "high" if v.severity in ("high", "critical") else "medium",
                    "severity": v.severity,
                    "recommended_containment": "Confirm gateway denied cloud side-effects; open incident if any successful API mutation is suspected.",
                    "recommended_instrumentation": "Alert on violation_type=unauthorized_tool_use from agent telemetry feed within 15m SLA.",
                    "linked_ksi_control_refs": ["AC-6", "IA-5", "SI-4"],
                    "narrative_disclaimer": disclaim,
                },
            )

    for v in ab.policy_violations:
        if v.violation_type == "prompt_injection_suspected":
            findings.append(
                {
                    "finding_id": _fid("inj"),
                    "detection_type": "prompt_injection_suspected",
                    "hypothesis": "Untrusted content may contain instruction-override patterns consistent with prompt injection (suspected).",
                    "signals_observed": [f"policy_violations record: {v.evidence[:400]}"],
                    "evidence_refs": [
                        f"{agent_telemetry_root.as_posix()}/agent_policy_violations.json#violation_id={v.violation_id}",
                    ],
                    "confidence": "high" if v.severity in ("high", "critical") else "medium",
                    "severity": v.severity,
                    "recommended_containment": "Quarantine ticket/thread from autonomous processing; human review before further tool use.",
                    "recommended_instrumentation": "Deploy classifier on inbound ticket/email bodies; block autonomous export tools when score > threshold.",
                    "linked_ksi_control_refs": ["SI-4", "AC-6", "SA-9"],
                    "narrative_disclaimer": disclaim,
                },
            )

    for tid, blob, ref in _tickets_text_blobs(bundle):
        if _INSTRUCTION_PATTERNS.search(blob):
            findings.append(
                {
                    "finding_id": _fid("ticket"),
                    "detection_type": "prompt_injection_suspected",
                    "hypothesis": "Ticket or document text matches instruction-override heuristics (suspected prompt injection; requires review).",
                    "signals_observed": ["Instruction-override pattern match in ticket text.", f"ticket_id={tid}"],
                    "evidence_refs": [f"{evidence_root.as_posix()}/{ref}"],
                    "confidence": "medium",
                    "severity": "medium",
                    "recommended_containment": "Do not auto-execute tools using this thread as sole instruction source.",
                    "recommended_instrumentation": "Pre-tool static scan for override phrases on support ingestion path.",
                    "linked_ksi_control_refs": ["SI-4", "AU-9"],
                    "narrative_disclaimer": disclaim,
                },
            )

    # tool after untrusted external_context (external_influence)
    ext_reads = [m for m in ab.memory_events if m.memory_type == "external_context" and m.action in ("read", "retrieve")]
    for m in ext_reads:
        src = m.source.lower()
        if "trusted:" in src or "untrusted" in src:
            continue
        later_tools = [tc for tc in ab.tool_calls if tc.timestamp >= m.timestamp and (tc.timestamp - m.timestamp).total_seconds() < 600]
        if later_tools:
            findings.append(
                {
                    "finding_id": _fid("ext"),
                    "detection_type": "external_influence",
                    "hypothesis": "Unlabeled external context was ingested before downstream tool calls; behavior may be influenced by untrusted text (requires review).",
                    "signals_observed": [
                        f"memory_event_id={m.memory_event_id} source lacks explicit trusted/untrusted label.",
                        f"Following tool calls within 10m: {[t.call_id for t in later_tools[:5]]}",
                    ],
                    "evidence_refs": [
                        f"{agent_telemetry_root.as_posix()}/agent_memory_events.json#memory_event_id={m.memory_event_id}",
                    ],
                    "confidence": "medium",
                    "severity": "medium",
                    "recommended_containment": "Force explicit untrusted labeling; strip autonomous tool triggers from that context unless approved.",
                    "recommended_instrumentation": "Block tool execution when preceding context chunk is unlabeled external.",
                    "linked_ksi_control_refs": ["SI-12", "AC-4", "AU-9"],
                    "narrative_disclaimer": disclaim,
                },
            )

    # --- credential_misuse (lightweight heuristics) ---
    for ident in ab.agent_identities:
        cr = ident.credentials_ref or ""
        if cr and "vault://" not in cr.lower() and "oidc" not in cr.lower() and "://" in cr:
            findings.append(
                {
                    "finding_id": _fid("cred"),
                    "detection_type": "credential_misuse",
                    "hypothesis": "Agent credential reference format is non-standard vs vault/OIDC patterns (requires review; not proof of misuse).",
                    "signals_observed": [f"credentials_ref={cr!r}"],
                    "evidence_refs": [f"{agent_telemetry_root.as_posix()}/agent_identities.json#agent_id={ident.agent_id}"],
                    "confidence": "low",
                    "severity": "low",
                    "recommended_containment": "Validate secret storage and rotation; prefer workload identity.",
                    "recommended_instrumentation": "Inventory agents with non-standard credential_ref schemes.",
                    "linked_ksi_control_refs": ["IA-5", "AC-2"],
                    "narrative_disclaimer": disclaim,
                },
            )

    # --- SIEM gap: policy violations without mapped alerting ---
    if ab.policy_violations and not _has_agentic_alert_coverage(rules):
        findings.append(
            {
                "finding_id": _fid("siem"),
                "detection_type": "instrumentation_gap",
                "hypothesis": "Recorded agent policy violations exist but no enabled alert rule appears to cover agentic / prompt-injection classes (observability gap).",
                "signals_observed": [
                    f"{len(ab.policy_violations)} policy_violation record(s) in telemetry.",
                    "No enabled alert rule matched heuristic keywords (prompt injection, agent tool gateway, genai, etc.).",
                ],
                "evidence_refs": [
                    f"{agent_telemetry_root.as_posix()}/agent_policy_violations.json",
                    f"{evidence_root.as_posix()}/alert_rules.json",
                ],
                "confidence": "medium",
                "severity": "medium",
                "recommended_containment": "Treat as process gap: prioritize SOC runbooks for agent gateway denies and violation webhook feed.",
                "recommended_instrumentation": "Add enabled SIEM correlation: agent_tool_gateway deny + policy_violation webhook; include agent_id, violation_type, ticket_id.",
                "linked_ksi_control_refs": ["SI-4", "AU-6", "IR-4"],
                "narrative_disclaimer": disclaim,
            },
        )

    return findings


def _timeline_md(
    *,
    ab: AgentAssessmentBundle | None,
    bundle: EvidenceBundle,
    evidence_root: Path,
    agent_root: Path,
) -> str:
    lines = ["# Threat hunt timeline (agentic risk)", "", f"- Evidence root: `{evidence_root}`", f"- Agent telemetry root: `{agent_root}`", ""]
    events: list[tuple[datetime, str]] = []
    if ab:
        for tc in ab.tool_calls:
            events.append((tc.timestamp, f"TOOL `{tc.tool_name}` ({tc.call_id}) agent={tc.agent_id} decision={tc.policy_decision}"))
        for m in ab.memory_events:
            events.append((m.timestamp, f"MEMORY `{m.memory_event_id}` type={m.memory_type} action={m.action} sensitivity={m.sensitivity}"))
        for v in ab.policy_violations:
            events.append((v.timestamp, f"VIOLATION `{v.violation_id}` type={v.violation_type} sev={v.severity}"))
    tix = bundle.tickets
    rows = tix.get("tickets", []) if isinstance(tix, dict) else []
    for row in rows:
        if not isinstance(row, dict):
            continue
        ts = row.get("created_at")
        if ts:
            try:
                s = str(ts).replace("Z", "+00:00")
                dt = datetime.fromisoformat(s)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                events.append((dt, f"TICKET `{row.get('id')}` created: {row.get('title', '')[:120]}"))
            except ValueError:
                continue
    events.sort(key=lambda x: x[0])
    for dt, desc in events:
        lines.append(f"- **{dt.isoformat()}** — {desc}")
    lines.append("")
    return "\n".join(lines)


def _queries_md(findings: list[dict[str, Any]]) -> str:
    lines = [
        "# Threat hunt queries (starter templates)",
        "",
        "Tune indexes and fields to your SIEM. These are **hypothesis drivers**, not confirmed detections.",
        "",
    ]
    templates = [
        (
            "shadow_ai_usage / unapproved tools",
            'index=agent_audit (tool_result="denied" OR policy_decision="blocked" OR policy_decision="unknown")\n'
            '| stats count by agent_id, tool_name',
        ),
        (
            "prompt_injection_suspected",
            'index=support_tickets ("ignore previous instructions" OR "disregard prior" OR "export customer data")\n'
            '| join type=left agent_session_id [ search index=agent_audit ]',
        ),
        (
            "agent policy violations feed",
            'index=agent_governance sourcetype=agent_policy_violation\n| stats latest(_time) by violation_type, agent_id, linked_ticket_id',
        ),
        (
            "external_influence / unlabeled context",
            'index=agent_memory memory_type=external_context NOT (source=*trusted:* OR source=*untrusted*)\n| sort _time',
        ),
    ]
    for title, q in templates:
        lines.extend([f"## {title}", "", "```", q.strip(), "```", ""])
    lines.append("## Derived from this run\n")
    for f in findings[:12]:
        lines.append(f"- `{f.get('finding_id')}` ({f.get('detection_type')}): see `threat_hunt_findings.json`.")
    lines.append("")
    return "\n".join(lines)


def _poam_rows_from_findings(findings: list[dict[str, Any]], *, reference: date) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    seq = 1
    for f in findings:
        sev = str(f.get("severity") or "medium").lower()
        if sev not in ("critical", "high", "medium", "low", "info"):
            sev = "medium"
        bucket = "high" if sev in ("critical", "high") else ("moderate" if sev == "medium" else "low")
        due = milestone_due_date_for_severity(bucket, reference)
        disp = {"critical": "Critical", "high": "High", "moderate": "Moderate", "low": "Low"}.get(bucket, "Moderate")
        hyp = str(f.get("hypothesis") or f.get("detection_type") or "finding")[:500]
        pid = f"POAM-TH-{seq:04d}"
        seq += 1
        rows.append(
            {
                "POA&M ID": pid,
                "Controls": "; ".join(f.get("linked_ksi_control_refs") or ["CA-5", "SI-4"]),
                "Weakness Name": str(f.get("detection_type") or "agentic_risk")[:200],
                "Weakness Description": hyp,
                "Asset Identifier": "organization-wide",
                "Original Detection Date": reference.isoformat(),
                "Weakness Source": "Observable Security Agent threat-hunt (agentic)",
                "Raw Severity": disp,
                "Adjusted Risk Rating": disp,
                "Planned Remediation": str(f.get("recommended_containment") or "")[:2000],
                "Milestone": f"Containment review for {f.get('finding_id')}",
                "Milestone Due Date": due.isoformat(),
                "Status": "Open",
                "Vendor Dependency": "",
                "Operational Requirement": "",
                "Source Eval ID": str(f.get("finding_id") or ""),
            },
        )
    return rows


def run_agentic_threat_hunt(
    *,
    evidence_root: Path,
    agent_telemetry_root: Path,
    bundle: EvidenceBundle,
    agent_assessment: AgentAssessmentBundle | None,
    output_dir: Path,
) -> list[str]:
    """Write threat-hunt artifacts; returns paths written."""
    global _NEXT_ID
    _NEXT_ID = 0
    out = output_dir.resolve()
    out.mkdir(parents=True, exist_ok=True)

    findings = _collect_findings(
        evidence_root=evidence_root,
        agent_telemetry_root=agent_telemetry_root,
        bundle=bundle,
        ab=agent_assessment,
    )

    doc = {
        "schema_version": "1.0",
        "mode": "agentic_ai_risk",
        "evidence_root": str(evidence_root),
        "agent_telemetry_root": str(agent_telemetry_root),
        "finding_count": len(findings),
        "findings": findings,
        "language_note": "Findings are hypothesis-oriented; use suspected / requires review / blocked attempt language. No asserted compromise.",
    }
    p_json = out / "threat_hunt_findings.json"
    p_json.write_text(json.dumps(doc, indent=2, default=str), encoding="utf-8")

    p_tl = out / "threat_hunt_timeline.md"
    p_tl.write_text(
        _timeline_md(ab=agent_assessment, bundle=bundle, evidence_root=evidence_root, agent_root=agent_telemetry_root),
        encoding="utf-8",
    )

    p_q = out / "threat_hunt_queries.md"
    p_q.write_text(_queries_md(findings), encoding="utf-8")

    ref = date.today()
    poam_findings = [
        f
        for f in findings
        if f.get("severity") in ("critical", "high")
        or f.get("detection_type") == "instrumentation_gap"
        or (f.get("confidence") == "high" and str(f.get("severity")) in ("high", "medium"))
    ]
    if not poam_findings:
        poam_findings = findings[:8]
    p_poam = out / "agentic_risk_poam.csv"
    write_poam_csv_file(p_poam, _poam_rows_from_findings(poam_findings, reference=ref))

    return [str(p_json), str(p_tl), str(p_poam), str(p_q)]


def load_agent_bundle_for_hunt(agent_telemetry_root: Path) -> AgentAssessmentBundle | None:
    """Load agent assessment from telemetry directory (split files or monolithic)."""
    return load_agent_assessment_bundle(agent_telemetry_root)


__all__ = [
    "has_agentic_siem_rule_coverage",
    "load_agent_bundle_for_hunt",
    "run_agentic_threat_hunt",
]
