# Reference samples (not vendored dependencies)

This directory is a **controlled sample area**: small, representative files copied from upstream open-source projects to inform **adapters**, **tests**, **schemas**, **reports**, and documentation for **Observable Security Agent**.

## What this is **not**

- **Not** a vendor mirror — no full repositories, no `node_modules`, no lockfiles from upstream, no large source trees.
- **Not** a runtime dependency — **no code under `core/`, `evals/`, `providers/`, `instrumentation/`, or `agent.py` may import or load paths under `reference_samples/`**. That invariant is enforced by `tests/test_reference_samples.py` and `scripts/validate_everything.py` (reference reuse audit).
- **Not** permission to copy-paste production logic into shipping modules without a **separate license and design review** (especially for **GPL-3.0** or **MPL-2.0** upstreams).
- **Not** a substitute for cloning upstream — for full context, use gitignored clones under `reference/` (see `docs/reference_repo_inventory.md`).

## How samples are produced

1. **Preferred:** shallow-clone upstream under `reference/`, pick **one** high-signal file (or a **short excerpt**), copy it into the layout below, run `python scripts/_build_reference_samples_layout.py` (merges new files into `manifest.json` and checks parity), or hand-edit `manifest.json` if you add a file manually.
2. **Fallback:** fetch a small blob from raw.githubusercontent.com and note truncation in `manifest.json` → `notes`.

Every **file** under this tree (except `README.md` and `manifest.json`) **must** appear in `manifest.json` → `files` with provenance and reuse guidance.

## Directory layout

Paths mirror *categories* of evidence we care about (scanner output, compliance mapping, graphs, FedRAMP packs, etc.), not upstream repo structure.

| Path | Purpose |
| ---- | ------- |
| `licenses/` | Upstream `LICENSE` texts for attribution. |
| `prowler/outputs/`, `prowler/schemas/`, `prowler/compliance/`, `prowler/checks/`, `prowler/docs/` | Prowler compliance JSON, check metadata, output/reporting examples. |
| `cloudsploit/checks/`, `cloudsploit/outputs/`, `cloudsploit/docs/` | CSPM check plugins (study only; GPL), README excerpt, result-shape excerpt. |
| `cloudgraph/graph_models/`, `cloudgraph/schemas/`, `cloudgraph/docs/` | CloudGraph CLI pointers, package identity JSON, README excerpt ([cloudgraphdev/cli](https://github.com/cloudgraphdev/cli)). |
| `fixinventory/graph_models/`, `fixinventory/schemas/`, `fixinventory/collectors/`, `fixinventory/docs/` | Asset-graph README excerpt, minimal AWS API fixtures, SECURITY excerpt. |
| `aurelian/recon_patterns/`, `aurelian/outputs/`, `aurelian/docs/` | Public-exposure recon docs, README excerpt. |
| `nisify/evidence_model/`, `nisify/mappings/`, `nisify/reports/`, `nisify/docs/` | NIST CSF-style evidence JSON, mapping excerpt, product README excerpt, config example. |
| `fedramp20xmcp/requirements/`, `fedramp20xmcp/mappings/`, `fedramp20xmcp/docs/` | MCP `server.json`, KSI pattern YAML, setup and pattern-schema excerpts. |
| `knox_20x_pilot/package_examples/`, `knox_20x_pilot/reports/`, `knox_20x_pilot/schemas/`, `knox_20x_pilot/docs/` | FedRAMP 20x pilot machine-readable JSON, schema, documentation and reporting excerpts. |
| `ocsf/schemas/`, `ocsf/examples/`, `ocsf/docs/` | OCSF object snippets and event examples. |
| `cartography/graph_models/`, `cartography/schemas/`, `cartography/docs/` | Graph metadata and detector expectation examples. |
| `electriceye/checks/`, `electriceye/outputs/`, `electriceye/docs/` | AWS exposure check excerpts and sample policy/output JSON. |
| `auditkit/evidence_packages/`, `auditkit/reports/`, `auditkit/schemas/`, `auditkit/docs/` | Assessor-style package and framework text excerpts. |

## Canonical index

- **`manifest.json`** — machine-readable list of every file, with `source_repo_url`, `source_license`, `original_path`, `direct_code_reuse_allowed`, and narrative fields.
- **`docs/reference_samples_index.md`** — human-readable index (if present) cross-linking samples to design choices.
- **`reference_directory_inventory`** (inside `manifest.json`) — status of full clones under `reference/` (`EXISTS` / `MISSING`).

## Refreshing from `reference/` clones

Expected clone names are documented in `docs/reference_repo_inventory.md`. After adding or replacing a sample, run:

```bash
python scripts/_build_reference_samples_layout.py
```

The script refreshes `manifest.json` → `files`, preserves `reference_directory_inventory`, and asserts **every on-disk file** (except `README.md` / `manifest.json`) has a manifest row.
