# Exceptions and manual evidence

Items below are derived only from machine-readable fields. If a section is empty, nothing was recorded in the package for that category.

## Definitions (missing evidence vs. manual evidence)

- **Missing required evidence:** A criterion lists `evidence_required` ids that are **not** present in `evidence_source_registry` (or cannot be scored). Treat as an **implementation gap** (registry/catalog fix), not as “we chose manual this quarter.”
- **Manual or file-primary evidence path:** Required ids **are** registered; the KSI uses manual/hybrid catalog mode and/or evidence sources scored ≤2 (narrative, PDF, screenshots). That is an **expected** assessor attestation workflow — **not** the same label as missing evidence.

## Package evidence posture summary

- **Evidence maturity automation %** (catalog KSIs with automation score ≥ 4): **8.33%**.
- **Automated-maturity KSI count:** 1.
- **Catalog `validation_mode` — manual / hybrid / automated:** 1 / 11 / 0.
- **KSIs with missing required evidence (registry gap):** 0.
- **KSIs on manual/file-primary path (sources registered; not missing):** 2.

### KSI ids on manual/file-primary evidence path (attestation planning)

- `KSI-REC-01`
- `KSI-SCRM-01`

## Evidence maturity (KSI automation score below 4)

Automation scores combine evidence source maturity (0–5), required evidence coverage, ``validation_mode``, and whether pass/fail criteria are evaluated for the KSI.

- **`KSI-AGENT-01`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-AGENT-02`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-AGENT-03`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-AGENT-04`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-CM-01`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-IAM-01`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-INV-01`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-IR-01`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-REC-01`** — score **2** — [Manual or file-primary evidence path — sources registered; low automation by design, not the same as missing evidence] Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-SCRM-01`** — score **1** — [Manual or file-primary evidence path — sources registered; low automation by design, not the same as missing evidence] Raise ``validation_mode`` toward ``automated`` or ``hybrid`` once controls can be machine-checked. Increase evidence maturity (structured exports → automated → continuous validation).
- **`KSI-VULN-01`** — score **3** — Complete hybrid validation to reach score 4; score 5 requires fully automated mode plus continuous, alerting-backed evidence. Increase evidence maturity (structured exports → automated → continuous validation).

## Documented manual exceptions (KSI rows)

- *None recorded.*

## Manual or hybrid validation modes (catalog)

- `KSI-IAM-01` — catalog `validation_mode`: **hybrid**
- `KSI-LOG-01` — catalog `validation_mode`: **hybrid**
- `KSI-VULN-01` — catalog `validation_mode`: **hybrid**
- `KSI-CM-01` — catalog `validation_mode`: **hybrid**
- `KSI-INV-01` — catalog `validation_mode`: **hybrid**
- `KSI-IR-01` — catalog `validation_mode`: **hybrid**
- `KSI-REC-01` — catalog `validation_mode`: **hybrid**
- `KSI-SCRM-01` — catalog `validation_mode`: **manual**
- `KSI-AGENT-01` — catalog `validation_mode`: **hybrid**
- `KSI-AGENT-02` — catalog `validation_mode`: **hybrid**
- `KSI-AGENT-03` — catalog `validation_mode`: **hybrid**
- `KSI-AGENT-04` — catalog `validation_mode`: **hybrid**

## Criteria marked manual or hybrid

- `KSI-IAM-01` / `IAM-CRI-001` — `hybrid` — Privileged users must be approved through a documented workflow.
- `KSI-IAM-01` / `IAM-CRI-003` — `hybrid` — Terminated users must not retain active access to in-scope systems.
- `KSI-IAM-01` / `IAM-CRI-004` — `manual` — Break-glass accounts must be documented, monitored, and reviewed.
- `KSI-LOG-01` / `LOG-CRI-002` — `hybrid` — Logs are centralized to the approved SIEM or log analytics service.
- `KSI-LOG-01` / `LOG-CRI-003` — `manual` — Logs are encrypted and access-controlled per policy.
- `KSI-LOG-01` / `LOG-CRI-004` — `hybrid` — Security-relevant events are alertable with accountable routing.
- `KSI-LOG-01` / `LOG-CRI-005` — `hybrid` — Local-to-central evidence is available where required for AU reviews.
- `KSI-VULN-01` / `VULN-CRI-002` — `hybrid` — High/critical vulnerabilities meet SLA or have an approved exception on record.
- `KSI-VULN-01` / `VULN-CRI-003` — `hybrid` — Exploitation review is performed for high/critical vulnerabilities.
- `KSI-CM-01` / `CM-CRI-001` — `hybrid` — Risky changes have traceable tickets or equivalent change records.
- `KSI-CM-01` / `CM-CRI-002` — `manual` — Change tickets include SIA, testing, approval, deployment, and verification evidence.
- `KSI-CM-01` / `CM-CRI-003` — `hybrid` — Deployment evidence links to the approved change record.
- `KSI-CM-01` / `CM-CRI-004` — `hybrid` — Configuration drift is detectable for critical service classes.
- `KSI-INV-01` / `INV-CRI-002` — `hybrid` — Inventory includes boundary status, owner, component type, and scanner/log requirements.
- `KSI-IR-01` / `IR-CRI-001` — `hybrid` — Suspicious events have documented response evidence within policy timelines.
- `KSI-IR-01` / `IR-CRI-002` — `manual` — Incidents include event timeline, action log, notification, and closure evidence.
- `KSI-IR-01` / `IR-CRI-003` — `hybrid` — High-risk detections link to accountable tickets or cases.
- `KSI-REC-01` / `REC-CRI-001` — `manual` — Critical assets have backups meeting policy frequency and retention.
- `KSI-REC-01` / `REC-CRI-002` — `manual` — Backups are encrypted and access-controlled.
- `KSI-REC-01` / `REC-CRI-003` — `manual` — Restore tests are documented with outcomes.
- `KSI-REC-01` / `REC-CRI-004` — `manual` — RTO/RPO evidence exists for prioritized workloads.
- `KSI-SCRM-01` / `SCRM-CRI-001` — `manual` — Vendor inventory exists for in-scope external services and software.
- `KSI-SCRM-01` / `SCRM-CRI-002` — `manual` — External services are mapped to authorization boundary and inheritance statements.
- `KSI-SCRM-01` / `SCRM-CRI-003` — `hybrid` — Dependencies or SBOM artifacts are tracked for critical workloads.
- `KSI-SCRM-01` / `SCRM-CRI-004` — `manual` — Critical supplier risks are tracked with mitigation owners.
- `KSI-AGENT-01` / `AGENT-IAM-CRI-001` — `hybrid` — Every agent has a registered identity with stable agent_id in telemetry.
- `KSI-AGENT-01` / `AGENT-IAM-CRI-002` — `hybrid` — Every agent has documented owner and purpose fields.
- `KSI-AGENT-01` / `AGENT-IAM-CRI-003` — `hybrid` — Every agent has explicit allowed scopes for tools and data.
- `KSI-AGENT-01` / `AGENT-IAM-CRI-004` — `hybrid` — Privileged or high-risk agent actions require recorded approvals.
- `KSI-AGENT-01` / `AGENT-IAM-CRI-005` — `hybrid` — Agent credentials are not shared with human operators (no shared long-lived secrets).
- `KSI-AGENT-02` / `AGENT-LOG-CRI-001` — `hybrid` — Tool calls are logged with agent identity raw_ref and policy decision fields.
- `KSI-AGENT-02` / `AGENT-LOG-CRI-002` — `hybrid` — Policy decisions for agent actions are logged and attributable.
- `KSI-AGENT-02` / `AGENT-LOG-CRI-003` — `hybrid` — Approval decisions for gated actions are logged.
- `KSI-AGENT-02` / `AGENT-LOG-CRI-004` — `hybrid` — Memory and external context access events are logged and labeled.
- `KSI-AGENT-02` / `AGENT-LOG-CRI-005` — `hybrid` — Alerts exist for high-risk agent behavior semantics per SOC policy.
- `KSI-AGENT-03` / `AGENT-IR-CRI-001` — `hybrid` — Prompt injection or adversarial prompt detections are tracked with evidence.
- `KSI-AGENT-03` / `AGENT-IR-CRI-002` — `hybrid` — Unauthorized tool use creates a security finding and accountable ticket path.
- `KSI-AGENT-03` / `AGENT-IR-CRI-003` — `hybrid` — Compromised-agent hypotheses produce a documented threat-hunt timeline.
- `KSI-AGENT-03` / `AGENT-IR-CRI-004` — `manual` — Containment guidance exists for high-severity agent incidents.
- `KSI-AGENT-04` / `AGENT-CM-CRI-001` — `hybrid` — New or expanded agent tools require documented approval before production use.
- `KSI-AGENT-04` / `AGENT-CM-CRI-002` — `hybrid` — Tool permission changes are ticketed and traceable.
- `KSI-AGENT-04` / `AGENT-CM-CRI-003` — `hybrid` — Prompts and agent policies are versioned with history.
- `KSI-AGENT-04` / `AGENT-CM-CRI-004` — `manual` — Material policy changes include review evidence (peer or CAB).

## Risk acceptance blocks on findings

- *No non-empty risk acceptance metadata beyond defaults.*
