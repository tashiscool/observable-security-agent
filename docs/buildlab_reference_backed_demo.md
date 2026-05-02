# BuildLab demo — reference-backed, not reinvention

**Purpose:** Show judges we **cloned upstream, studied excerpts, and reused outputs as adapters**—then invested in the **audit evidence chain** they do not ship.

**Canonical detail:** [`reference_gap_matrix.md`](reference_gap_matrix.md), [`reference_to_implementation_traceability.md`](reference_to_implementation_traceability.md), [`reference_samples/manifest.json`](../reference_samples/manifest.json), [`reference_repo_inventory.md`](reference_repo_inventory.md).

---

## 1. Reference projects studied

| Project | Role |
| ------- | ---- |
| **Prowler**, **CloudSploit**, **ElectricEye**, **Aurelian** | CSPM / exposure / recon **inputs** |
| **CloudGraph**, **Fix Inventory**, **Cartography** | Asset and relationship **graph** thinking |
| **OCSF** (schema) | **Event / finding** vocabulary |
| **Nisify** | Evidence aggregation / **maturity** communication patterns |
| **FedRAMP20xMCP** | **20x pattern / requirement** surfaces (MCP-style) |
| **Knox FedRAMP 20x pilot** | **Package / validation** publication examples |
| **AuditKit CE** | Assessor **bundle / narrative** layout ideas |

---

## 2. What each solves

- **Scanners (Prowler, CloudSploit, ElectricEye, Aurelian):** Misconfigurations, public exposure, recon breadth—**what failed** in the cloud.
- **Graph tools (CloudGraph, Fix Inventory, Cartography):** Inventory topology, relationships, “what connects to what.”
- **OCSF:** Shared **taxonomy** for structured events and findings.
- **Nisify:** CSF-oriented evidence **rollup and maturity** storytelling.
- **FedRAMP20xMCP:** **Lookup** for 20x-aligned patterns and requirement text.
- **Knox pilot:** **Examples** of machine-readable assessment payloads and schemas.
- **AuditKit CE:** **Human assessor** packaging and documentation patterns.

---

## 3. What each does not solve

- **Not** end-to-end **program proof**: inventory ↔ scanner ↔ logs ↔ alerts ↔ tickets ↔ POA&M ↔ **KSI package** ↔ **AO/executive** narrative.
- **Not** deterministic **evaluators** that fail when the **evidence chain** is broken (only our bundle + evals do that).
- **Not** **reconciliation** between rendered reports and machine JSON counts.
- **Not** **AI** constrained to **artifact-grounded** explanation (hallucination-safe contract).

---

## 4. What we reused (inputs / adapters / `reference_samples/`)

- **`reference_samples/`** — licensed excerpts: scan row shapes, sec-group catalogs, OCSF snippets, graph doc patterns, Knox/MCP/AuditKit examples ([`manifest.json`](../reference_samples/manifest.json)).
- **Adapters** — ingest Prowler / CloudSploit / OCSF-style **exports** into our models (`providers/prowler.py`, `providers/cloudsploit.py`, `providers/ocsf.py`); **public exposure** catalog informed by ElectricEye/Aurelian samples (`config/public-exposure-policy.yaml`).
- **No runtime import** of `reference/` or `reference_samples/` in product code—validated in CI (`scripts/audit_reference_reuse.py`, `scripts/validate_everything.py`).

---

## 5. What remains unique (our layer)

| Capability | One-line |
| ---------- | -------- |
| **Evidence-chain correlation** | Events, assets, controls/KSIs, and findings in one graph and bundle. |
| **Scanner scope proof** | In-scope assets must meet scanner coverage policy—not just “findings exist.” |
| **Central logging proof** | Required log sources / coverage evals, not raw log shipping. |
| **Alert instrumentation proof** | Rule coverage vs. required semantic event types. |
| **Ticket / change evidence linkage** | Fail when ticket/CM evidence is missing for required gaps. |
| **Exploitation-review proof** | High/critical vuln path requires explicit review evidence where policy says so. |
| **POA&M generation** | Row-level linkage from evals/findings to remediation tracking. |
| **FedRAMP 20x–style KSI package** | Nested `fedramp20x-package.json`, schema-checked, evidence links + checksum discipline. |
| **Assessor / executive / AO reports** | Bundles from the same snapshot, aligned to package JSON. |
| **AI grounded explanation** | Explanations tied to artifacts and deterministic contract—not pass/fail by LLM. |
| **Human/machine reconciliation** | Deep checks that markdown and JSON tell the same story (e.g. REC series). |

---

## 6. Demo artifact paths

After a full local validation run (recommended):

```bash
python scripts/validate_everything.py \
  --tracker fixtures/assessment_tracker/sample_tracker.csv \
  --output-root validation_run
```

| Artifact | Path (under repo root unless noted) |
| -------- | ----------------------------------- |
| Validation rollup | `validation_run/validation_summary.md` |
| Reference subset | `validation_run/reference_validation_summary.md` |
| Reuse audit report | `validation_run/reference_reuse_audit.md` |
| Cloud fixture assessment | `validation_run/fixture_assessment/eval_results.json`, `correlations.json`, `evidence_graph.json`, `poam.csv` |
| Agentic + security | `validation_run/agentic_assessment/agent_eval_results.json`, `agent_risk_report.md` |
| 20x package (readiness) | `validation_run/package_readiness/fedramp20x-package.json` + `evidence/`, `reports/` |
| Tracker → 20x | `validation_run/tracker_to_20x/package_tracker/` |
| Agent loop trace | `validation_run/agent_run_tracker/agent_run_trace.json`, `agent_run_summary.md` |
| Web explorer (static) | `web/index.html` — serve via `make web` or `python scripts/serve_web.py` |
| Web sample data (post-run) | `web/sample-data/tracker/` |

Smaller demos without the full harness: `make assess-fixture`, `make build-20x`, fixture scenarios under `fixtures/`.

---

## 7. One-minute spoken explanation

> **Script (verbatim thesis):**  
> Prowler and CloudSploit tell us what failed. CloudGraph/FixInventory/Cartography show how to think about the asset graph. OCSF gives event vocabulary. FedRAMP20xMCP and the Knox pilot inform the 20x package shape. Our layer correlates all of that into audit-ready proof: did we know the asset existed, scan it, log it, alert on it, investigate it, ticket it, and track it?

**Spoken version (same idea, ~60s):** We did not pretend scanner vendors or graph projects were wrong—we **studied** them. **Prowler and CloudSploit** tell us **what failed**. **CloudGraph, Fix Inventory, and Cartography** show **how to think about the asset graph**. **OCSF** gives **event vocabulary**. **FedRAMP20xMCP** and the **Knox pilot** inform the **20x package shape**. **AuditKit** and **Nisify** help with how assessors talk about bundles and maturity. **Our layer correlates all of that into audit-ready proof:** did we **know the asset existed**, **scan** it, **log** it, **alert** on it, **investigate** it, **ticket** it, and **track** it—in one **KSI package**, **POA&M**, **reports**, and **reconciliation**, with **AI that stays grounded in the artifacts**. Upstream tools give **inputs and ideas**; we deliver the **defensible evidence chain**.
