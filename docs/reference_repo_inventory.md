# Reference repository inventory

This document records **local clones under `reference/`** (gitignored full trees for design study only) against the names you expected. Verification was done on disk at inventory time: **2026-05-02** (repo root: `observable-security-agent`).

**Policy reminder:** Runtime code must not import from `reference/` or `reference_samples/`. Treat these trees as read-only inspiration; any excerpt shipped in-repo belongs in `reference_samples/` with license attribution (see `reference_samples/manifest.json` → `files`).

---

## Verification summary

| You asked for (folder) | Present locally? | Actual path (if different) |
| ---------------------- | ---------------- | --------------------------- |
| `prowler/`             | **EXISTS**       | — |
| `cloudsploit/`         | **EXISTS**       | — |
| `cloudgraph/`          | **Alias**        | Present as **`reference/cloudgraph-cli/`** (upstream [cloudgraphdev/cli](https://github.com/cloudgraphdev/cli)) |
| `fixinventory/`        | **EXISTS**       | — |
| `aurelian/`            | **EXISTS**       | — |
| `nisify/`              | **EXISTS**       | — |
| `FedRAMP20xMCP/`       | **EXISTS**       | — |
| `fedramp_20x_pilot/`   | **Alias**        | Present as **`reference/knox-fedramp-20x-pilot/`** (upstream [Knox-Gov/fedramp_20x_pilot](https://github.com/Knox-Gov/fedramp_20x_pilot)) |
| `ocsf-schema/`         | **MISSING**      | — |
| `cartography/`         | **MISSING**      | — |
| `ElectricEye/`         | **MISSING**      | — |
| `AuditKit-Community-Edition/` | **MISSING** | — |

**Notes on aliases:** If you standardize folder names locally, either rename the clone to match your convention or keep this table as the source of truth so scripts and humans do not look for a non-existent directory.

---

## Per-repository detail (existing clones only)

Fields use this legend for **Likely reusable layer** (for our agent—not a claim about upstream’s goals):

- `scanner input` — findings/checks to normalize as evidence
- `asset graph` — inventory / relationship / snapshot model
- `event schema` — vendor-neutral or structured event vocabulary
- `compliance mapping` — control/framework mapping packs
- `FedRAMP 20x requirement lookup` — machine-readable 20x requirement surfaces
- `evidence package/reporting` — assessor-style bundles, narratives, or pilots
- `public exposure/recon` — exposure / attack-path style discovery
- `not useful` — no strong fit for our evidence-correlation layer (still useful for positioning)

### prowler (`reference/prowler/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | `prowler` (Poetry `pyproject.toml`) |
| **Detected license** | **Apache-2.0** (`LICENSE`) |
| **Primary language/framework** | Python (Poetry); UI components include Node for web UI |
| **Main purpose** | Multi-cloud security and compliance scanning (AWS, Azure, GCP, K8s, etc.) with extensive framework packs (incl. NIST/FedRAMP-style mappings). |
| **Likely reusable layer** | **scanner input**, **compliance mapping** (study output shape and control mapping density—not a substitute for our evidence-chain evals). |
| **Important files/directories** | `prowler/compliance/`, `util/compliance/`, `tests/`, `docs/`, `pyproject.toml` |
| **Appears runnable** | **Yes** — install via Poetry/pip per upstream docs (requires cloud/API config for live runs). |
| **Sample outputs / fixtures** | **Yes** — compliance test JSON, examples under `util/` / docs paths; extensive in `tests/` and compliance trees. |
| **Schemas** | **Partial** — compliance JSON acts as structured output; upstream may ship JSON schema in-repo; not a single “one OCSF-style” event schema. |
| **Compliance mappings** | **Yes** — large mapping surface (FedRAMP, NIST, CIS, PCI, SOC2, etc.). |
| **Tests** | **Yes** — Python `tests/` tree. |
| **Direct code reuse** | **Avoid for copy-paste** without license and architectural review; **prefer adapter** that **consumes** Prowler output JSON. Apache-2.0 is permissive, but vendoring large slices increases maintenance and blurs “scanner vs evidence agent” positioning. |

---

### cloudsploit (`reference/cloudsploit/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | `cloudsploit` (`package.json`) |
| **Detected license** | **GPL-3.0** (`LICENSE` — GNU General Public License v3) |
| **Primary language/framework** | JavaScript (Node.js); plugin-oriented engine |
| **Main purpose** | Cloud security posture / misconfiguration detection across AWS, Azure, GCP, OCI, GitHub, etc. |
| **Likely reusable layer** | **scanner input** (check results as evidence), not FedRAMP narrative generation. |
| **Important files/directories** | `plugins/` (per-cloud collectors), `engine.js`, `helpers/`, `config_example.js`, `docs/` |
| **Appears runnable** | **Yes** — Node project; live scans need credentials. |
| **Sample outputs / fixtures** | **Limited in shallow clone** — primary “samples” are plugin/test JSON patterns; no dedicated `samples/` tree at top level. |
| **Schemas** | **Mostly implicit** — result objects defined by code and tests. |
| **Compliance mappings** | **Indirect** — risk/findings oriented; not a FedRAMP 20x package generator. |
| **Tests** | **Yes** — large `*.spec.js` suite (Jest-style). |
| **Direct code reuse** | **Strongly avoid incorporating source** into a non-GPL product **GPL-3.0 is copyleft**. Safe pattern: **run as external tool** and ingest **outputs only**, with counsel if you redistribute combined works. |

---

### cloudgraph — see `cloudgraph-cli` (`reference/cloudgraph-cli/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | `@cloudgraph/cli` (`package.json`) |
| **Detected license** | **MPL-2.0** (`LICENSE`) |
| **Primary language/framework** | TypeScript / Node (`src/`, `test/`, `jest.config.js`) |
| **Main purpose** | Multi-cloud GraphQL API and CSPM-style tooling (AWS, Azure, GCP, K8s, etc.) with resource relationship graph. |
| **Likely reusable layer** | **asset graph**, partial **scanner input** (compliance-related plugins). |
| **Important files/directories** | `src/`, `test/`, `examples/`, `docs/`, `bin/` |
| **Appears runnable** | **Yes** — CLI via npm/yarn; requires provider configuration. |
| **Sample outputs / fixtures** | **Examples** under `examples/`; no large canned assessment bundle at repo root. |
| **Schemas** | **GraphQL-oriented** — schema lives in code/docs rather than one static JSON file at root. |
| **Compliance mappings** | **Some** — CSPM/compliance alignment varies by plugin; study per provider. |
| **Tests** | **Yes** — `test/` + Jest. |
| **Direct code reuse** | **Avoid file-level copy without MPL compliance review**; prefer **inspiration** for graph modeling or **integration at API/output boundary**. |

---

### fixinventory (`reference/fixinventory/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | **Fix Inventory** (monorepo; components e.g. `fixcore`, `fixworker`, `fixshell`) |
| **Detected license** | **Apache-2.0** (`LICENSE`) |
| **Primary language/framework** | Python (multiple packages under `fixcore/`, `fixworker/`, `plugins/`); Docker-compose operations |
| **Main purpose** | Agentless cloud asset inventory, graph-oriented normalization, and risk/cleanup workflows across AWS, GCP, Azure, K8s, GitHub, etc. |
| **Likely reusable layer** | **asset graph**, **scanner input** (resource + risk data as evidence feed). |
| **Important files/directories** | `fixcore/`, `fixworker/`, `fixshell/`, `plugins/`, `docker-compose.yaml`, `README.md` |
| **Appears runnable** | **Yes** — typically via Docker Compose / local components (heavier than a single CLI). |
| **Sample outputs / fixtures** | **Sparse in shallow clone** — some JSON under plugins/tests; graph output is produced at runtime. |
| **Schemas** | **Yes (internal)** — graph models defined across `fixlib` / plugins; study code and docs rather than one `schemas/` folder at root. |
| **Compliance mappings** | **Partial** — risk and inventory first; not FedRAMP artifact packager. |
| **Tests** | **Yes** — distributed (`plugins/*/test`, `fixworker/test`, etc.). |
| **Direct code reuse** | **Avoid vendoring** a large fork; **prefer API/export ingestion** or narrow, attributed excerpts in `reference_samples/` after review. |

---

### aurelian (`reference/aurelian/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | `github.com/praetorian-inc/aurelian` (`go.mod`) |
| **Detected license** | **Apache-2.0** (`LICENSE`) |
| **Primary language/framework** | Go 1.25 (`go.mod`, `cmd/`, `pkg/`, `internal/`) |
| **Main purpose** | Multi-cloud **reconnaissance**: misconfigurations, secrets, public exposure, privilege escalation paths. |
| **Likely reusable layer** | **public exposure/recon**; optional **scanner input** (findings). |
| **Important files/directories** | `cmd/`, `pkg/`, `internal/`, `docs/`, `docker-compose.yml` |
| **Appears runnable** | **Yes** — `go build` / releases; cloud credentials needed for live recon. |
| **Sample outputs / fixtures** | **Some** — JSON/report examples under `test/` / tool outputs (varies by command). |
| **Schemas** | **Mostly code-defined** — no single shared security-event schema like OCSF in-tree. |
| **Compliance mappings** | **No** (not FedRAMP/control-pack oriented). |
| **Tests** | **Yes** — Go tests under `test/`, `pkg/`, etc. |
| **Direct code reuse** | **Avoid** pulling offensive/recon code into compliance runtime; **run sidecar** and ingest **structured results** if integrated. |

---

### nisify (`reference/nisify/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | `nisify` (`pyproject.toml`) |
| **Detected license** | **MIT** (`LICENSE`) |
| **Primary language/framework** | Python 3.11+ (`pyproject.toml`, `src/`, `tests/`) |
| **Main purpose** | **NIST CSF 2.0** evidence aggregation from many SaaS/cloud connectors; maturity scoring and dashboards. |
| **Likely reusable layer** | **compliance mapping** (CSF—not FedRAMP 20x), **evidence package/reporting** (conceptual), **scanner input** (connector outputs). |
| **Important files/directories** | `src/`, `tests/`, `examples/sample_evidence/`, `data/`, `docs/` |
| **Appears runnable** | **Yes** — Python package / CLI patterns per README. |
| **Sample outputs / fixtures** | **Yes** — `examples/sample_evidence/` |
| **Schemas** | **Partial** — evidence objects in Python models and examples. |
| **Compliance mappings** | **Yes** — NIST CSF 2.0 (106 controls in marketing/README; verify in code). |
| **Tests** | **Yes** — `tests/` |
| **Direct code reuse** | MIT is permissive, but **framework differs (CSF vs FedRAMP 20x)**—use for **pattern comparison**, not as a drop-in KSI engine. |

---

### FedRAMP20xMCP (`reference/FedRAMP20xMCP/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | `fedramp-20x-mcp` (`pyproject.toml`) |
| **Detected license** | **MIT** (`LICENSE`) |
| **Primary language/framework** | Python 3.10+ MCP server (`src/`, `tests/`, `data/`) |
| **Main purpose** | **FedRAMP 20x requirement lookup** over an MCP interface (query by control, family, keyword). |
| **Likely reusable layer** | **FedRAMP 20x requirement lookup** (adjacent to our `config/ksi-catalog.yaml` / crosswalk—not a replacement). |
| **Important files/directories** | `src/`, `data/`, `examples/`, `tests/`, `docs/` |
| **Appears runnable** | **Yes** — MCP server; runs with Python env per README. |
| **Sample outputs / fixtures** | **Examples** under `examples/`; structured data under `data/`. |
| **Schemas** | **Yes (light)** — JSON config/data files for requirement corpus. |
| **Compliance mappings** | **Yes** — FedRAMP 20x oriented. |
| **Tests** | **Yes** — `tests/` |
| **Direct code reuse** | **Avoid duplicating the MCP server inside our agent**; consider **sidecar MCP** or **mirror the data shape** we already maintain. |

---

### fedramp_20x_pilot — see `knox-fedramp-20x-pilot` (`reference/knox-fedramp-20x-pilot/`)

| Field | Value |
| ----- | ----- |
| **Detected project name** | **FedRAMP 20x Pilot Submission: Adobe Learning Manager (ALM)** (README title) |
| **Detected license** | **Not found at repo root** — no `LICENSE` / `LICENSE.md` in shallow clone; treat as **unspecified / publication-only** until you confirm upstream terms. |
| **Primary language/framework** | **Documentation + machine-readable artifacts** (not an application monolith) |
| **Main purpose** | Public **pilot submission** materials: narrative, machine-readable assessment, schemas, visualizations for continuous compliance / 20x positioning. |
| **Likely reusable layer** | **evidence package/reporting**, **FedRAMP 20x requirement lookup** (indirectly via packaged artifacts), **schemas** (submission formats). |
| **Important files/directories** | `machine-readable-assessment/`, `schemas/` (e.g. `fedramp-output-schema.json`), `documentation/`, `3pao-assessment/`, `visualizations/` |
| **Appears runnable** | **No** — not a scanner/runtime; **reference pack**. |
| **Sample outputs / fixtures** | **Yes** — pilot JSON under `machine-readable-assessment/` and related dirs. |
| **Schemas** | **Yes** — `schemas/` includes JSON schema style files. |
| **Compliance mappings** | **Yes** — FedRAMP 20x pilot alignment (assessment structure). |
| **Tests** | **No** automated test tree observed at shallow depth. |
| **Direct code reuse** | **Avoid copying narrative or branding**; use as **structural inspiration** for report/package layout; confirm **license/terms** before redistributing excerpts. |

---

## MISSING repositories (expected path absent under `reference/`)

Clone when convenient (shell names only—adjust if you prefer different directory conventions):

```bash
cd reference
git clone --depth 1 https://github.com/ocsf/ocsf-schema.git ocsf-schema
git clone --depth 1 https://github.com/lyft/cartography.git cartography
git clone --depth 1 https://github.com/jonrau1/ElectricEye.git ElectricEye
git clone --depth 1 https://github.com/guardian-nexus/AuditKit-Community-Edition.git AuditKit-Community-Edition
```

| Expected folder | Upstream (typical) | Why it matters here |
| --------------- | ------------------- | -------------------- |
| `ocsf-schema/` | [ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema) | **event schema** normalization reference (we already keep small excerpts under `reference_samples/ocsf/`). |
| `cartography/` | [lyft/cartography](https://github.com/lyft/cartography) | **asset graph** patterns (AWS-centric graph sync). |
| `ElectricEye/` | [jonrau1/ElectricEye](https://github.com/jonrau1/ElectricEye) | **scanner input** (AWS exposure/regional checks). |
| `AuditKit-Community-Edition/` | [guardian-nexus/AuditKit-Community-Edition](https://github.com/guardian-nexus/AuditKit-Community-Edition) | **evidence package/reporting** / assessor workflow text (excerpts already in `reference_samples/auditkit/`). |

---

## Machine-readable companion

Structured entries (including **MISSING** rows) live in `reference_samples/manifest.json` under the key **`reference_directory_inventory`**.
