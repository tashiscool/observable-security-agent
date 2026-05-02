# Evidence data elements (FedRAMP-style patterns)

The product is an **evidence-correlation and assessment-evaluation layer**. For each **asset / event / finding** in scope, it keys on data needed to answer: *Can we prove it is in inventory, in scanner scope, centrally logged, covered by an alert, linked to a ticket, reviewed for exploitation if High/Critical, and tracked in POA&M if unresolved?* This document maps those proof-chain expectations to **concrete fields** assessors and ISSOs usually ask for—and to **canonical models** and **fixture files**.

The agent does **not** invent missing facts: absent or weak fields produce **gaps** (FAIL/PARTIAL) and POA&M rows rather than treated-as-present evidence.

---

## Canonical model and fixtures

| Concept | Pydantic types (`core/models.py`) | Typical fixture inputs (`fixtures/scenario_public_admin_vuln_event/`) |
| --- | --- | --- |
| Authoritative inventory | `DeclaredInventoryRecord` | `declared_inventory.csv` |
| Live discovery | `Asset` | `discovered_assets.json` → `assets[]` |
| Control-plane / security events | `SecurityEvent` | `cloud_events.json` (normalized to semantic types) |
| Scanner scope | `ScannerTarget` | `scanner_targets.csv` |
| Scanner results | `ScannerFinding` | `scanner_findings.json` → `findings[]` |
| Central logging posture | `LogSource` | `central_log_sources.json` → `sources[]` |
| Detection rules | `AlertRule` | `alert_rules.json` → `rules[]` |
| Change / vuln workflow | `Ticket` | `tickets.json` → `tickets[]` |
| Existing POA&M seeds | `PoamItem` | `poam.csv` (optional seed rows) |

The **fixture provider** (`providers/fixture.py`) maps CSV/JSON columns into `AssessmentBundle`. Evaluations read that bundle (and pipeline evidence where needed). Field names below are the **canonical** names after parsing unless noted as “fixture-only.”

---

## 1. Inventory / CM-8

FedRAMP assessors look for a **single authoritative inventory** (IIW/CMDB) that matches **what is actually running** in production, with clear boundary and ownership—especially when correlating incidents to assets.

| Data element (assessment pattern) | Why it matters | Canonical / agent use | Fixture source |
| --- | --- | --- | --- |
| **Declared asset name** | Human identity; duplicate names break reconciliation | `DeclaredInventoryRecord.name` | `declared_inventory.csv` → `name` |
| **Discovered asset id** | Join key to logs, findings, tickets | `Asset.asset_id` | `discovered_assets.json` → `asset_id` |
| **Private IP** | CMDB vs live network reconciliation | Declared: `expected_private_ip`; Discovered: `Asset.private_ips` | CSV `expected_private_ip`; JSON `private_ip` → list |
| **Public IP** | Edge exposure context | `expected_public_ip` / `Asset.public_ips` | Same pattern |
| **Region** | Scope of control / logging | `expected_region`; `Asset.region` | CSV; JSON `region` |
| **Account / subscription / project** | Multi-tenant isolation proof | `Asset.account_id`, `project_id`, `subscription_id` (optional hints) | JSON `account` → `account_id` |
| **Component type** | Control selection (compute vs storage, etc.) | `DeclaredInventoryRecord.asset_type`; `Asset.asset_type` (normalized from `resource_type`) | CSV `asset_type`; JSON `resource_type` |
| **In-boundary flag** | Rogue vs sanctioned workloads | `DeclaredInventoryRecord.in_boundary` | CSV `in_boundary` |
| **Owner** | Accountability | `DeclaredInventoryRecord.owner` | CSV `owner` |
| **Environment** | Prod vs non-prod policy | `Asset.environment` (from tags `Environment` / `environment`) | JSON `tags` |
| **Scanner required** | RA-5 scope expectations for CM-8 rows | `DeclaredInventoryRecord.scanner_required` | CSV `scanner_required` |
| **Log required** | AU expectations for CM-8 rows | `DeclaredInventoryRecord.log_required` | CSV `log_required` |
| **Duplicate asset identifiers** | IIW integrity | Detected in eval `CM8_INVENTORY_RECONCILIATION`: duplicate `name`, duplicate `asset_id` across declared rows | Same CSV |
| **Stale inventory records** | Drift (IP, attributes) | Compared declared `expected_private_ip` / `expected_public_ip` to discovered asset when `asset_id` matches | CSV vs JSON |
| **Rogue discovered assets** | Shadow IT / boundary violations | Discovered high/criticality prod-class `Asset` with no matching declared row (by `asset_id`) | `discovered_assets.json` vs CSV |

**Primary eval:** `CM8_INVENTORY_RECONCILIATION` (and inputs to `CROSS_DOMAIN_EVENT_CORRELATION` for `asset_in_inventory`).

---

## 2. Vulnerability scanning / RA-5

Assessors expect **documented scope** (targets), **frequency / methodology** hints, and **findings** tied to assets—with severity, CVE/plugin lineage, and lifecycle status.

| Data element | Why it matters | Canonical / agent use | Fixture source |
| --- | --- | --- | --- |
| **Scanner name** | Tool traceability | `ScannerTarget.scanner_name`; `ScannerFinding.scanner_name` | `scanner_targets.csv` → `scanner`; findings wrapper `scanner` default |
| **Scanner version** | Reproducibility | Not a first-class canonical field today; may appear in `ScannerFinding.evidence` text or future metadata | Optional in JSON |
| **Plugin / signature update time** | Currency of detection | Not first-class; plugin freshness implied via `plugin_id` + assessor follow-up | `plugin_id` on finding |
| **Scanner target list** | “Was this asset in scope?” | `ScannerTarget` rows | `scanner_targets.csv` |
| **Asset-to-target mapping** | Join asset ↔ target ↔ finding | Match by `asset_id`, `hostname`, `ip`, `target_id` (eval logic) | CSV columns `asset_id`, `hostname`, `ip` |
| **Credentialed scan flag** | Depth of coverage | `ScannerTarget.credentialed` | CSV `credentialed` |
| **Scan frequency** | Continuous vs point-in-time | Partially reflected in `ScannerTarget.last_scan_time` when populated | CSV `last_scan_time` (optional) |
| **Finding severity** | POA&M / escalation | `ScannerFinding.severity` | JSON `severity` |
| **CVE / plugin id** | Vuln identity | `ScannerFinding.cve_ids`, `plugin_id` | JSON `cve` / `cve_ids`, `plugin_id` |
| **First seen / last seen** | Exposure window | `ScannerFinding.first_seen`, `last_seen` | JSON ISO timestamps |
| **Remediation status** | Accepted risk vs open work | `ScannerFinding.status` | JSON `status` |
| **Trend / comparison availability** | Continuous monitoring narrative | Not modeled separately; gap if only point-in-time export | Out of scope unless carried in `evidence` text |

**Primary eval:** `RA5_SCANNER_SCOPE_COVERAGE`. High/Critical open findings also feed `RA5_EXPLOITATION_REVIEW` and correlation.

---

## 3. Logging / AU-2, AU-6, AU-12

Assessors expect **audit-relevant events** to exist **locally**, to appear in a **central SIEM/logging service**, and for **freshness** to be demonstrable (recent `last_seen` / equivalent).

| Data element | Why it matters | Canonical / agent use | Fixture source |
| --- | --- | --- | --- |
| **Local log source** | Origin of record | `LogSource.local_source` | `central_log_sources.json` → `local_source` |
| **Central log destination** | AU-12 aggregation | `LogSource.central_destination` (`splunk`, `sentinel`, `cloud_logging`, …) | `central_destination` |
| **Last event seen timestamp** | Stale vs active ingestion | `LogSource.last_seen` when set; otherwise status derived from fixture flags | `last_seen` OR `seen_last_24h` + `local_only` |
| **Sample local event** | Copy-of-record | `LogSource.sample_local_event_ref` | `sample_local_event_ref` (optional) |
| **Matching central event** | Same event ID / hash in SIEM | `LogSource.sample_central_event_ref` | `sample_central_event_ref` (optional) |
| **Source type** | AU-2 relevancy | `LogSource.source_type` (`os_auth`, `cloud_control_plane`, …) | `source_type` |
| **Log retention** | AU-11 style discussions | Not first-class in `LogSource`; assessor question / future field | — |
| **Audit processing failure alert** | AU-6 processing / SIEM health | Not first-class; may be inferred from separate alert rules on `logging.audit_disabled` semantics | `alert_rules.json` + events |

Fixture-derived **status**: `active` if `seen_last_24h` and not `local_only`; `stale` if local-only path without recent central evidence; `missing` otherwise (`providers/fixture.py` → `_log_source_status_from_row`).

**Primary eval:** `AU6_CENTRALIZED_LOG_COVERAGE`.

---

## 4. Monitoring and alerting / SI-4

Assessors expect **enabled** detections for risky semantics, **routing** to operations, and **proof of operation** (sample alert or firing history) where claiming effectiveness.

| Data element | Why it matters | Canonical / agent use | Fixture source |
| --- | --- | --- | --- |
| **Alert rule name** | Traceability | `AlertRule.name` | `alert_rules.json` → `name` |
| **Enabled / disabled** | “Paper rule” vs live control | `AlertRule.enabled` | `enabled` |
| **Event types covered** | AU-2 / SI-4 mapping | `AlertRule.mapped_semantic_types` (merged from `event_types`, `mapped_semantic_types`, `matches_event_type`) | `event_types`, `mapped_semantic_types`, `matches_event_type` |
| **Recipient list** | Operational accountability | `AlertRule.recipients` | `recipients` |
| **Last fired timestamp** | Control operating | `AlertRule.last_fired` | `last_fired` |
| **Sample alert notification** | Evidence artifact | `AlertRule.sample_alert_ref` | `sample_alert_ref` |
| **Response ticket** | IR / SOC workflow | Linked via `Ticket` + event/finding correlation (separate from rule object) | `tickets.json` |
| **Closure action** | Control effectiveness loop | Ticket `status`, `closed_at`; not on `AlertRule` | `tickets.json` |

**Primary eval:** `SI4_ALERT_INSTRUMENTATION`. Missing recipients, disabled rules, or absent `sample_alert_ref` / `last_fired` contribute to gaps depending on eval rules.

---

## 5. Change management / CM-3, SI-2

Assessors expect **security-relevant changes** (including rule changes implicated by events) to tie to **approved change records** with **SIA, test, approval, deploy, verify** evidence—not only a vulnerability ticket.

| Data element | Why it matters | Canonical / agent use | Fixture source |
| --- | --- | --- | --- |
| **Change ticket id** | Primary artifact | `Ticket.ticket_id` | `id` / `ticket_id` |
| **Linked asset** | Scope | `Ticket.linked_asset_ids` | `links_asset_id` (fixture expands to list) |
| **Linked event** | Event-to-CAB trace | `Ticket.linked_event_ids` | `links_event_ref` |
| **Linked vulnerability** | Patch / vuln track | `Ticket.linked_finding_ids` | `linked_finding_ids` |
| **Security impact analysis** | CM-3 SIA | `Ticket.has_security_impact_analysis` | `security_impact_analysis` |
| **Testing evidence** | CM-3(2) | `Ticket.has_testing_evidence` | `test_evidence` |
| **Approval evidence** | Governance | `Ticket.has_approval` | `approval_recorded` |
| **Deployment evidence** | Implementer proof | `Ticket.has_deployment_evidence` | `has_deployment_evidence` / `deployment_recorded` |
| **Post-deployment verification** | Effectiveness | `Ticket.has_verification_evidence` | `has_verification_evidence` / `post_deploy_verification` |
| **Vulnerability rescan closure** | RA-5 / SI-2 loop | Partially via finding `status` + ticket verification flags | `scanner_findings.json` + `tickets.json` |

**Primary eval:** `CM3_CHANGE_EVIDENCE_LINKAGE`. Vulnerability-only tickets without change evidence are a common gap pattern (see fixture `VULN-9912`).

---

## 6. Exploitation review / RA-5(8)

For **open High/Critical** findings, assessors expect evidence that **logs or other telemetry were reviewed** for exploitation indicators in a defined window—not only that a scanner reported a CVE.

| Data element | Why it matters | Canonical / agent use | Fixture source |
| --- | --- | --- | --- |
| **High/Critical vulnerability id** | Anchor | `ScannerFinding.finding_id` + `severity` + `status` | JSON finding row |
| **Affected asset** | Scope of review | `ScannerFinding.asset_id` + `Asset` for IPs/host | JSON + `discovered_assets.json` |
| **Vulnerability time window** | Query window | `ScannerFinding.first_seen`, `last_seen` (also used in generated query text) | JSON |
| **Generated IoC / search terms** | Agent output artifact | Written to `output/exploitation_review_queries.md` when eval runs with `output_dir` | Generated (not stored in `ScannerFinding` by default) |
| **Log query performed** | RA-5(8) proof | `exploitation_review` dict: `queries` list (supporting evidence only) | JSON `exploitation_review.queries` |
| **Analyst / agent identity** | Non-repudiation | Not first-class; assessor evidence outside bundle | — |
| **Query timestamp** | When review ran | Not first-class; gap if missing | — |
| **Query result** | Outcome of review | Not first-class; use `review_artifact_ref` / ticket verification | — |
| **Linked ticket / evidence artifact** | Traceable record | `exploitation_review.log_review_performed`, `exploitation_review_complete`, `review_artifact_ref` / `review_artifact_url`; or `Ticket.has_verification_evidence` for linked finding | JSON `exploitation_review`; `tickets.json` |

Eval `RA5_EXPLOITATION_REVIEW` treats review as satisfied if any of: `log_review_performed`, `exploitation_review_complete`, non-empty `review_artifact_ref` / `review_artifact_url`, or a linked ticket with `has_verification_evidence` (see `evals/vulnerability_exploitation_review.py`). **Active central logging** for the asset is also required in the current rule set before claiming log-based review.

---

## 7. POA&M / CA-5

POA&M rows tie **weakness → controls → asset → remediation → milestone**, and (for this agent) **back to the eval** that generated the gap.

| Data element | Why it matters | Canonical / agent use | Fixture / output |
| --- | --- | --- | --- |
| **POA&M id** | Unique tracking | `PoamItem.poam_id`; generated IDs `POAM-AUTO-…` | Seed: `poam.csv`; merged output in `output/poam.csv` |
| **Controls** | CA-5 mapping | `PoamItem.controls` | CSV `controls` |
| **Weakness name** | Executive summary | `PoamItem.weakness_name` | CSV / generated from eval |
| **Weakness description** | Detail | `PoamItem.weakness_description` | `notes` / gap text |
| **Asset id** | Scope | `PoamItem.asset_identifier` | `asset_identifier` / `asset_id` |
| **Severity** | Risk | `raw_severity`, `adjusted_risk_rating` | CSV + bucket from eval |
| **Planned remediation** | Corrective action | `PoamItem.planned_remediation` | Generated narrative |
| **Milestone due date** | CA-5 scheduling | `PoamItem.milestone_due_date` | Computed from severity bucket |
| **Status** | Lifecycle | `PoamItem.status` | `open`, etc. |
| **Vendor dependency** | External constraints | CSV column present; often empty for auto rows | `core/poam.py` |
| **Operational requirement** | Compensating context | CSV column present; often empty for auto rows | Same |
| **Source eval id** | Automation traceability | `PoamItem.source_eval_id` | Set on generated rows to eval id (e.g. `CM8_INVENTORY_RECONCILIATION`) |

**Primary eval / output:** failing evals produce rows via `core/poam.py`; `CA5_POAM_STATUS` checks generation when failures exist.

---

## Correlation and semantic events

Scenario **`correlations.json`** (under the fixture tree for demos) lists additional **semantic events** the pipeline treats as **correlated risky events**. Each must satisfy the same cross-domain chain (inventory, scanner, logs, alerts, tickets) as the primary incident—**missing links are gaps**, not assumed passes.

Primary narrative events come from **`cloud_events.json`**, normalized to `SecurityEvent.semantic_type` (closed vocabulary in `core/models.py`).

---

## Summary

| Control theme | Key canonical objects | Main fixture files |
| --- | --- | --- |
| CM-8 | `DeclaredInventoryRecord`, `Asset` | `declared_inventory.csv`, `discovered_assets.json` |
| RA-5 | `ScannerTarget`, `ScannerFinding` | `scanner_targets.csv`, `scanner_findings.json` |
| AU / logging | `LogSource` | `central_log_sources.json` |
| SI-4 | `AlertRule` | `alert_rules.json` |
| CM-3 / SI-2 | `Ticket`, `SecurityEvent` | `tickets.json`, `cloud_events.json` |
| RA-5(8) | `ScannerFinding.exploitation_review`, `Ticket`, `LogSource` | Same + generated `exploitation_review_queries.md` |
| CA-5 | `PoamItem`, generated POA&M CSV | `poam.csv` (seed), `output/poam.csv` |

For adapter authors: **populate `AssessmentBundle` fields faithfully**; the eval layer is intentionally strict so that **missing evidence reads as a finding**, consistent with FedRAMP evidence interviews.
