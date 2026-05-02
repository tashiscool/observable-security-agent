# Secure agent architecture

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

- **Source:** `fixtures/scenario_agentic_risk/agent_identities.json`
- **agent_id:** `support-ticket-agent`
- **owner:** it-support@example.com
- **purpose:** Read support tickets and create draft customer responses
- **environment:** stage
- **allowed_tools:** `read_tickets, draft_response`
- **allowed_data_scopes:** `https://support.example/tickets/`
- **allowed_actions:** `read, draft`
- **human_approval_required_for:** `mutate_security_group, delete_bucket, cloud_admin_tool`
- **credentials_ref (boundary):** `vault://kv/agents/support-ticket-agent`

*(Primary identity source in this run: `fixtures/scenario_agentic_risk/agent_identities.json`.)*

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

- **Fixture:** `fixtures/scenario_agentic_risk/agent_tool_calls.json`
- **Approved tools (registered):** `draft_response`, `read_tickets`
- **Blocked attempts (telemetry):** `cloud_admin_tool` (tc-admin-blocked)
- **High / critical risk invocations:** `cloud_admin_tool` risk=high call_id=tc-admin-blocked

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

- **Fixture:** `fixtures/scenario_agentic_risk/agent_memory_events.json`
  - `mem-ctx-ticket-4477` type=`external_context` action=`read` sensitivity=`internal` policy=`allowed` source=`zendesk-webhook:batch-12/ticket/TICK-4477/plaintext`
  - `mem-lt-pii-warn` type=`long_term` action=`write` sensitivity=`pii` policy=`warned` source=`session_buffer:customer_contact_fields`
  - `mem-vec-retrieve` type=`vector` action=`retrieve` sensitivity=`internal` policy=`allowed` source=`trusted:vector-store/snippets-v1`

---

## 4. Policy engine

- **Allow / block / warn** — Deterministic decisions before side effects; **warn** must not silently persist sensitive data.
- **Policy decision logs** — Structured records: `policy_decision`, `call_id`, `agent_id`, timestamp, `raw_ref` to raw log object.
- **Approval gates** — `approval_required` + `approval_status` (approved / denied / not_required / **missing**).
- **Exception handling** — Time-bounded break-glass with ticket linkage and retroactive review.

### Policy violations (telemetry examples)

- **Fixture:** `fixtures/scenario_agentic_risk/agent_policy_violations.json`
  - `viol-prompt-inj-001` type=`prompt_injection_suspected` severity=`high` ticket_link=`TICK-4477`
  - `viol-unauth-tool-001` type=`unauthorized_tool_use` severity=`high` ticket_link=`None`

---

## 5. Observability

- **Tool-call logs:** gateway + downstream API audit (who / what / target / outcome).
- **Policy violation logs:** `agent_policy_violations.json` (or SIEM sourcetype).
- **Memory access logs:** read/write/retrieve with sensitivity and store type.
- **Central SIEM forwarding:** normalize to common schema; retain `raw_ref` for pivot.
- **Alert rules:** map to agentic signals (blocked high-risk tool, injection heuristics, violation webhook).

### Alert rules (fixture excerpt)

- **Fixture:** `fixtures/scenario_agentic_risk/alert_rules.json`
- **Rule count:** 4; **enabled:** 2
- **Note:** Agentic / prompt-injection-specific alerting may still be absent even when rules exist (see `threat-hunt` instrumentation_gap heuristics).

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
