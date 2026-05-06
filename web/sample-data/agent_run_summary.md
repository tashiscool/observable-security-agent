# Agent run summary (bounded autonomous loop)

**Provider:** `fixture`  
**Scenario:** `scenario_agentic_risk`  
**Output directory:** `<repo>/output_agentic`  
**20x package directory:** `<repo>/output_agentic/agent_run_20x`  

## Playbook

Fixture `scenario_agentic_risk` with agent_telemetry=True: run correlation evals + optional threat hunt, normalize outputs, emit draft ticket JSON, build and validate 20x package, reconcile, then summarize.

## Policy

Autonomous actions are limited to **local evidence generation** (assess, threat hunt, drafts, package, validate, reconcile).
The following categories **require human approval** and are **not** executed by this loop:

- **cloud_remediation**: Apply or revert changes in cloud accounts (CSP APIs).
- **permission_change**: IAM / RBAC / policy mutations in live directories or clouds.
- **destructive_change**: Delete, overwrite production data, or modify non-local resources.
- **external_notification**: Email, Slack, PagerDuty, webhooks to third parties.
- **real_ticket_create**: Create or update tickets in Jira/ServiceNow/etc.

## Derivation trace (high level)

0. **observe** — `—` — policy: ALLOW — verify: **PASS** — artifact: `—`
1. **plan** — `plan` — policy: ALLOW — verify: **PASS** — artifact: `—`
2. **act** — `assess_run_evals` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/eval_results.json`
3. **act** — `threat_hunt_agentic` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_threat_hunt_findings.json`
4. **act** — `normalize_findings` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_normalized_findings.json`
5. **act** — `generate_instrumentation_recommendations` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/instrumentation_plan.md`
6. **act** — `generate_poam_drafts` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/poam.csv`
7. **act** — `draft_tickets_json_only` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_draft_tickets.json`
8. **act** — `build_20x_package` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_run_20x/fedramp20x-package.json`
9. **act** — `validate_assessment_outputs` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/eval_results.json`
10. **act** — `validate_20x_package` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_run_20x/fedramp20x-package.json`
11. **act** — `reconcile_20x_reports` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_run_20x`
12. **explain** — `write_agent_run_summary` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_run_summary.md`
13. **explain** — `write_trace_json` — policy: ALLOW — verify: **PASS** — artifact: `<repo>/output_agentic/agent_run_trace.json`

## Full trace

See `<repo>/output_agentic/agent_run_trace.json` for machine-readable steps.
