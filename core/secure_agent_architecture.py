"""Generate ``secure_agent_architecture.md`` — secure agent boundary & evidence-chain artifact."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _read_json(path: Path) -> Any | None:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def _agent_identity_snippets(repo_root: Path) -> tuple[str, str]:
    """Return (markdown block, source path note) for registered agent identity."""
    paths = [
        repo_root / "fixtures/scenario_agentic_risk/agent_identities.json",
        repo_root / "fixtures/scenario_public_admin_vuln_event/agent_security/agent_assessment.json",
        repo_root / "fixtures/agent_security/agent_assessment_pass.json",
    ]
    for p in paths:
        data = _read_json(p)
        if not data:
            continue
        identities: list[dict[str, Any]] = []
        if isinstance(data, list):
            identities = [x for x in data if isinstance(x, dict)]
        elif isinstance(data, dict) and "agent_identities" in data:
            identities = [x for x in data["agent_identities"] if isinstance(x, dict)]
        if not identities:
            continue
        i0 = identities[0]
        lines = [
            f"- **Source:** `{p.relative_to(repo_root)}`",
            f"- **agent_id:** `{i0.get('agent_id', '—')}`",
            f"- **owner:** {i0.get('owner', '—')}",
            f"- **purpose:** {i0.get('purpose', '—')}",
            f"- **environment:** {i0.get('environment', '—')}",
            f"- **allowed_tools:** `{', '.join(i0.get('allowed_tools') or []) or '—'}`",
            f"- **allowed_data_scopes:** `{', '.join(i0.get('allowed_data_scopes') or []) or '—'}`",
            f"- **allowed_actions:** `{', '.join(i0.get('allowed_actions') or []) or '—'}`",
            f"- **human_approval_required_for:** `{', '.join(i0.get('human_approval_required_for') or []) or '—'}`",
            f"- **credentials_ref (boundary):** `{i0.get('credentials_ref') or '—'}`",
        ]
        return "\n".join(lines), str(p.relative_to(repo_root))
    return (
        "*No agent identity fixture found at expected paths "
        "(e.g. `fixtures/scenario_agentic_risk/agent_identities.json`).*",
        "",
    )


def _tool_boundary_snippet(repo_root: Path) -> str:
    p = repo_root / "fixtures/scenario_agentic_risk/agent_tool_calls.json"
    data = _read_json(p)
    if not isinstance(data, list):
        return "*Load `fixtures/scenario_agentic_risk/agent_tool_calls.json` for concrete tool-call examples.*"
    approved: set[str] = set()
    blocked: list[str] = []
    high_risk: list[str] = []
    for row in data:
        if not isinstance(row, dict):
            continue
        name = str(row.get("tool_name") or "")
        pol = str(row.get("policy_decision") or "")
        risk = str(row.get("risk_level") or "")
        appr = row.get("approval_required")
        if pol == "blocked":
            blocked.append(f"`{name}` ({row.get('call_id')})")
        if risk in ("high", "critical"):
            high_risk.append(f"`{name}` risk={risk} call_id={row.get('call_id')}")
    id_path = repo_root / "fixtures/scenario_agentic_risk/agent_identities.json"
    id_data = _read_json(id_path)
    if isinstance(id_data, list) and id_data and isinstance(id_data[0], dict):
        approved.update(str(t) for t in (id_data[0].get("allowed_tools") or []) if t)
    lines = [f"- **Fixture:** `{p.relative_to(repo_root)}`"]
    if approved:
        lines.append("- **Approved tools (registered):** " + ", ".join(f"`{t}`" for t in sorted(approved)))
    if blocked:
        lines.append("- **Blocked attempts (telemetry):** " + "; ".join(blocked))
    if high_risk:
        lines.append("- **High / critical risk invocations:** " + "; ".join(high_risk))
    if len(lines) <= 1:
        return "*Load `fixtures/scenario_agentic_risk/agent_tool_calls.json` for concrete tool-call examples.*"
    return "\n".join(lines)


def _context_boundary_snippet(repo_root: Path) -> str:
    p = repo_root / "fixtures/scenario_agentic_risk/agent_memory_events.json"
    data = _read_json(p)
    if not isinstance(data, list) or not data:
        return "*See `fixtures/scenario_agentic_risk/agent_memory_events.json` when present for memory / retrieval labels.*"
    lines = [f"- **Fixture:** `{p.relative_to(repo_root)}`"]
    for row in data[:6]:
        if not isinstance(row, dict):
            continue
        src = str(row.get("source") or "")
        if len(src) > 80:
            src = src[:80] + "…"
        lines.append(
            f"  - `{row.get('memory_event_id')}` type=`{row.get('memory_type')}` action=`{row.get('action')}` "
            f"sensitivity=`{row.get('sensitivity')}` policy=`{row.get('policy_decision')}` source=`{src}`",
        )
    return "\n".join(lines)


def _policy_violation_snippet(repo_root: Path) -> str:
    p = repo_root / "fixtures/scenario_agentic_risk/agent_policy_violations.json"
    data = _read_json(p)
    if not isinstance(data, list) or not data:
        return "*No `agent_policy_violations.json` in repo snapshot — policy engine section remains generic.*"
    lines = [f"- **Fixture:** `{p.relative_to(repo_root)}`"]
    for row in data:
        if not isinstance(row, dict):
            continue
        lines.append(
            f"  - `{row.get('violation_id')}` type=`{row.get('violation_type')}` severity=`{row.get('severity')}` "
            f"ticket_link=`{row.get('linked_ticket_id')}`",
        )
    return "\n".join(lines)


def _alert_rules_snippet(repo_root: Path) -> str:
    p = repo_root / "fixtures/scenario_agentic_risk/alert_rules.json"
    data = _read_json(p)
    if not isinstance(data, dict):
        return f"*Expected `alert_rules.json` at `{p.relative_to(repo_root)}`.*"
    rules = data.get("rules", [])
    if not isinstance(rules, list):
        return ""
    enabled = sum(1 for r in rules if isinstance(r, dict) and r.get("enabled"))
    lines = [
        f"- **Fixture:** `{p.relative_to(repo_root)}`",
        f"- **Rule count:** {len(rules)}; **enabled:** {enabled}",
        "- **Note:** Agentic / prompt-injection-specific alerting may still be absent even when rules exist "
        "(see `threat-hunt` instrumentation_gap heuristics).",
    ]
    return "\n".join(lines)


def build_secure_agent_architecture_markdown(repo_root: Path) -> str:
    """Full markdown document with optional fixture-derived inserts."""
    ident_block, ident_src = _agent_identity_snippets(repo_root)
    tool_snip = _tool_boundary_snippet(repo_root)
    ctx_snip = _context_boundary_snippet(repo_root)
    viol_snip = _policy_violation_snippet(repo_root)
    alert_snip = _alert_rules_snippet(repo_root)

    return f"""# Secure agent architecture

This artifact describes **defense-in-depth boundaries** for autonomous and semi-autonomous agents: identity, tools,
context, policy, observability, response, and how evidence is packaged for audit. Wording is deliberate: **suspected**,
**blocked attempt**, and **requires review** — not asserted compromise unless primary logs prove it.

**Repository-relative fixture references** (when present in a clone of this repo):

- **`fixtures/scenario_agentic_risk/`** — Rich agentic-risk scenario (split agent JSON + cloud evidence).
- **`fixtures/scenario_public_admin_vuln_event/agent_security/agent_assessment.json`** — Monolithic agent bundle sample.
- **`fixtures/agent_security/agent_assessment_pass.json`** — Passing-style agent assessment JSON.

---

## 1. Agent identity

**Goal:** Every automated actor is **registered**, owned, purpose-bound, scope-limited, and uses a **credential boundary** appropriate to machine identity (not human interactive admin).

### Registered identity (example from fixtures)

{ident_block}

*(Primary identity source in this run: `{ident_src or "none"}`.)*

### ASCII — identity plane

```
┌─────────────────────────────────────────────────────────────────┐
│                     REGISTERED AGENT IDENTITY                    │
│  agent_id ──► owner ──► purpose ──► environment                │
│       │              │                                           │
│       └── allowed_tools / allowed_actions / allowed_data_scopes │
│       └── credentials_ref (vault/OIDC/workload; NOT human SSO) │
└─────────────────────────────────────────────────────────────────┘
           │                              │
           ▼                              ▼
    Policy engine                   Audit / SIEM identity
```

---

## 2. Tool boundary

**Approved tools** — only names on the allow list may be invoked by the runtime. **Blocked tools** — anything else
should be denied at the gateway (a **blocked attempt** is a successful control, not a successful attack). **High-risk
tools** require explicit risk classification. **Approval-required tools** need human or CAB evidence before execution.

### Fixture-derived tool signals

{tool_snip}

### ASCII — tool gateway

```
  Caller                Tool gateway              Cloud / SaaS API
    │                        │                          │
    │  tool_name, args       │  allow-list match        │
    ├───────────────────────►│  policy_decision        │
    │                        │──► allowed / blocked    ├──► (only if allowed)
    │                        │    / warned / unknown   │
    │◄───────────────────────┤                          │
          audit: call_id, raw_ref, approval_status
```

---

## 3. Context boundary

- **Trusted instructions** — System / developer policy text, versioned prompts, runbooks **not** supplied by end users.
- **Untrusted external content** — Tickets, email bodies, web fetches, customer uploads — must be **labeled** before influencing tools.
- **Memory stores** — Short-term buffer, long-term store, vector DB, file context — each needs **sensitivity** and **retention** rules.
- **Retrieval sources** — RAG indices, KB snippets — trace `source` and whether content is `trusted:` / `untrusted`.
- **Sensitivity labels** — e.g. public / internal / confidential / **pii** / **secret** — drive allow/block on **write** to durable memory.

### Fixture-derived memory / context

{ctx_snip}

---

## 4. Policy engine

- **Allow / block / warn** — Deterministic decisions before side effects; **warn** must not silently persist sensitive data.
- **Policy decision logs** — Structured records: `policy_decision`, `call_id`, `agent_id`, timestamp, `raw_ref` to raw log object.
- **Approval gates** — `approval_required` + `approval_status` (approved / denied / not_required / **missing**).
- **Exception handling** — Time-bounded break-glass with ticket linkage and retroactive review.

### Policy violations (telemetry examples)

{viol_snip}

---

## 5. Observability

- **Tool-call logs:** gateway + downstream API audit (who / what / target / outcome).
- **Policy violation logs:** `agent_policy_violations.json` (or SIEM sourcetype).
- **Memory access logs:** read/write/retrieve with sensitivity and store type.
- **Central SIEM forwarding:** normalize to common schema; retain `raw_ref` for pivot.
- **Alert rules:** map to agentic signals (blocked high-risk tool, injection heuristics, violation webhook).

### Alert rules (fixture excerpt)

{alert_snip}

---

## 6. Response

- **Ticket creation** — Link agent session, `call_id`, and customer thread ID.
- **Incident escalation** — Severity from violation + blast radius of **attempted** target resources.
- **POA&M item** — Control gap when governance cannot be closed short-term (`agentic_risk_poam.csv`, main `poam.csv`).
- **Containment** — Disable agent, revoke tokens, tighten allow list, preserve logs for IR.

---

## 7. Evidence package

- **`eval_results.json`** — Machine-readable pipeline eval rows + `eval_result_records`.
- **`agent_eval_results.json`** — *(Optional)* Agent-only eval slice when `--include-agent-security` is used.
- **`correlation_report.md` / `auditor_questions.md`** — Human-readable narratives.
- **`threat_hunt_findings.json`** — Hypothesis-oriented agentic hunt output from `agent.py threat-hunt`.
- **`reconcile-reports` / validation** — Reconciliation status vs package schema.

**Derivation trace:** evals and agent evals cite loaded JSON/CSV only — see `core/output_validation.py` and
`core/failure_narrative_contract.py` for FAIL/PARTIAL narrative requirements.

---

## Related commands

```bash
python agent.py assess --provider fixture --scenario scenario_agentic_risk --include-agent-security --output-dir output
python agent.py threat-hunt --provider fixture --scenario scenario_agentic_risk --output-dir output
python agent.py secure-agent-arch --output-dir output
```

*Generated by `core/secure_agent_architecture.py` / `agent.py secure-agent-arch`. Regenerate after changing fixtures.*
"""


def write_secure_agent_architecture(path: Path, *, repo_root: Path) -> None:
    """Write markdown to ``path`` (parent dirs created)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(build_secure_agent_architecture_markdown(repo_root), encoding="utf-8")


__all__ = ["build_secure_agent_architecture_markdown", "write_secure_agent_architecture"]
