# Graph model references: CloudGraph, Fix Inventory, Cartography

BuildLab ships a **JSON evidence graph** (no Neo4j/GraphQL runtime requirement). This note summarizes how three open graph projects model cloud and security data, and what we **adapt** vs **avoid** in `core/evidence_graph.py` v3.

---

## CloudGraph (formerly OG / cloudgraphify)

**Role:** Read-only AWS (and some multi-cloud) asset/config graph, historically backed by DGraph and later PostgreSQL + GraphQL APIs.

| Topic | CloudGraph-style idea | Observable agent v3 |
| --- | --- | --- |
| **Node types** | Resources as vertices (accounts, EC2, SG, IAM, etc.) with provider-specific shapes | `asset`, `cloud_account`, `scanner_finding`, `log_source`, `alert_rule`, `ticket`, `poam_item`, `control`, `ksi`, `evidence_artifact`, plus `event`, `scanner_target`, `declared_inventory_record`, `evaluation`, `event_mtype`, `network_exposure` |
| **Edge / relationship types** | Typed relationships between resources (attachment, membership, policy link) | Fixed UPPER_SNAKE vocabulary (see schema + `REL_*` in `evidence_graph.py`) |
| **Account / project / subscription** | Strong **account** (or org) partition as graph root | `cloud_account` node; `scope_id` like `aws:111122223333` or `gcp:project:...`; `BELONGS_TO_ACCOUNT` from `asset` |
| **Identity → resource** | IAM users/roles/groups linked to policies and resources | Not first-class in v3; identity signals stay in `event` / `scanner_finding` payloads; optional future `identity_principal` node |
| **Network exposure** | SG rules / ENI / paths often modeled as separate nodes or rich properties | `network_exposure` for semantic public-admin (and similar) events; `HAS_PUBLIC_EXPOSURE` from `asset` |
| **Finding → resource** | Findings (Inspector, etc.) attached to resources | `HAS_FINDING` **from** `asset` **to** `scanner_finding` |
| **History / snapshot** | Sync jobs produce point-in-time graph snapshots | Our graph is **one assessment run**; “snapshot” = single `evidence_graph.json` |
| **Adapt** | Account scoping, resource-as-node, finding attachment, read-only export | `cloud_account`, `BELONGS_TO_ACCOUNT`, `HAS_FINDING`, Cypher export for optional tooling |
| **Avoid** | Requiring DGraph/GraphQL, large auto-synced multi-region inventory in demo | No mandatory graph DB; JSON + web explorer only |

---

## Fix Inventory

**Role:** Cloud asset inventory from **multiple collectors**, normalized graph in ArangoDB; strong **plugin** model.

| Topic | Fix-style idea | Observable agent v3 |
| --- | --- | --- |
| **Node types** | Normalized cloud resources + metadata from AWS/Azure/GCP/K8s/etc. | Same high-level `asset`/`cloud_account` split; evidence types (`log_source`, `alert_rule`) are first-class |
| **Edge types** | Rich edges (membership, access, depends_on) from collectors | Smaller, **assessment** edge set focused on controls / KSI / POA&M |
| **Account modeling** | Accounts / subscriptions as roots of resource trees | `cloud_account` + `BELONGS_TO_ACCOUNT` |
| **Identity → resource** | Often via access / role edges | Same gap as CloudGraph — use events + findings for demo |
| **Network exposure** | Security-group and network-related resources | `network_exposure` + public-admin semantics |
| **Finding → resource** | Vuln/config issues linked to assets | `HAS_FINDING` |
| **History / snapshot** | Collector runs version inventory; time indexed | One JSON graph per `assess` |
| **Adapt** | Multi-source inventory thinking; explicit gap edges (`MISSING_*`) when policy requires coverage | `MISSING_SCANNER_TARGET`, `MISSING_CENTRAL_LOGGING`, `MISSING_ALERT` |
| **Avoid** | ArangoDB-only assumptions; full collector graph in BuildLab | Keep bundle-driven, small graph |

---

## Cartography (Lyft)

**Role:** Neo4j-synced **AWS / GCP / Kubernetes** asset graph with **intel modules** (analysis jobs writing new nodes/edges).

| Topic | Cartography-style idea | Observable agent v3 |
| --- | --- | --- |
| **Node types** | Accounts, LB, EC2, IAM, RDS, K8s workloads, intel-derived entities | Subset oriented to **evidence** and **FedRAMP** (`control`, `ksi`, `evaluation`) |
| **Edge types** | Many relationship types from sync + intel | Named like Cartography *ideas* (account membership, finding on asset) but **not** Lyft’s labels |
| **Account modeling** | `(AWSAccount)-[:RESOURCE]->...` patterns | `asset -[:BELONGS_TO_ACCOUNT]-> cloud_account` |
| **Identity → resource** | IAMUser/IAMRole → policies / instances | Deferred; events carry actor strings |
| **Network exposure** | Load balancers / DNS / SG-style intel | `network_exposure` + `HAS_PUBLIC_EXPOSURE` |
| **Finding → resource** | Intel or vuln nodes to resources | `HAS_FINDING` |
| **History / snapshot** | Periodic sync jobs; Neo4j **point-in-time** | Single-run JSON artifact |
| **Adapt** | Topology mental model, optional Cypher MERGE export for viz | `scripts/export_graph_cypher.py`, `evidence_graph_dict_to_cypher` |
| **Avoid** | Duplicating Neo4j sync modules, intel job DAG, Lyft schema | No dependency on Cartography code or DB |

---

## Structural edges (not in the FedRAMP chain table)

- `INVENTORY_DESCRIBES_ASSET` — declared row → `asset` (CM-8).
- `EVENT_TARGETS_ASSET` — `event` → `asset`.
- `INSTANCE_OF_EVENT_TYPE` — `event` → `event_mtype`.

These keep the graph connected for evaluators and the web explorer without requiring Neo4j.

---

## Relationship vocabulary (v3)

See `schemas/evidence-graph.schema.json` and `REL_*` constants in `core/evidence_graph.py`:

`BELONGS_TO_ACCOUNT`, `HAS_PUBLIC_EXPOSURE`, `HAS_FINDING`, `COVERED_BY_SCANNER_TARGET`, `MISSING_SCANNER_TARGET`, `EMITS_LOGS_TO`, `MISSING_CENTRAL_LOGGING`, `COVERED_BY_ALERT`, `MISSING_ALERT`, `LINKED_TO_TICKET`, `MISSING_TICKET`, `TRACKED_BY_POAM`, `MAPS_TO_CONTROL`, `MAPS_TO_KSI`, `SUPPORTED_BY_EVIDENCE`.

`MISSING_TICKET` is reserved for future correlation-driven gaps; v3 may omit edges.
