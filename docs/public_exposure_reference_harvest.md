# Public exposure reference harvest (ElectricEye + Aurelian)

This note records what was **lifted verbatim from reference samples** versus what this repo **derives or extends** for `config/public-exposure-policy.yaml`.

## ElectricEye (`reference_samples/electriceye/checks/electriceye_secgroup_auditor_config.json`)

**Harvested (port + check identity):**

- Port ranges and check identifiers for broadly Internet-exposed listeners (examples: `security-group-kafka-open-check` → TCP 9092, `security-group-docker-open-check` → 2375, `security-group-k8sapi-open-check` → 10250 kubelet surface, `security-group-nfs-open-check` → 2049, `security-group-rabbitmq-open-check` → 5672, OpenVPN UDP 1194, SMTP 25, SMB/NetBIOS 137–139, MongoDB/DocumentDB 27017, Redshift 5439, Cassandra/Keyspaces 9142, Memcached UDP 11211, and related titles).

**How we use it:**

- `service_name.match_check_id_substrings` and `rules.*.match_check_id_substrings` align ElectricEye-style `CheckId` fragments so `providers.exposure_policy.semantic_type_from_public_exposure_policy()` can classify scanner rows without hardcoding provider code tables.

**Extensions (not in the JSON sample):**

- **Kubernetes API server** TCP **6443** is the community-default API listener; ElectricEye’s catalog emphasizes **10250** (kubelet). Policy lists **both** under `kubernetes_api_kubelet` so AWS SG normalization matches real-world API exposure while staying compatible with the sample’s kubelet-oriented check.
- **Severity**, `controls`, `linked_ksi_ids`, `alert_required`, `scanner_required`, `exploitation_review_required_if_vulnerable`, and `default_remediation` are **assessment vocabulary** fields — they are not copied from ElectricEye JSON; they tie each row to FedRAMP-style evidence expectations (see `config/ksi-catalog.yaml`).

## Aurelian (`reference_samples/aurelian/recon_patterns/aws_recon_public_resources.md`)

**Harvested (intent, not port math):**

- The **recon** command surfaces “publicly accessible AWS resources” via policy/property evaluation — i.e., the **same risk class** as wide security-group ingress: assets discoverable or reachable from the Internet without equivalent compensating detective controls.

**How we use it:**

- Aurelian does not publish a port matrix in-repo; we treat it as a **category-level** justification for maintaining a **shared, provider-neutral** exposure policy: AWS security groups today, **future Azure NSG / GCP firewall rule** adapters reuse `semantic_type_for_exposed_port()` and the same YAML.

## Semantic typing

| Policy semantic | Typical use |
|-----------------|-------------|
| `network.public_admin_port_opened` | Interactive admin/remoting (SSH, RDP, Telnet, legacy FTP control) |
| `network.public_database_port_opened` | Data stores with SQL/CQL-style threat models |
| `network.public_sensitive_service_opened` | High-abuse middleware, orchestration APIs, caches, brokers, admin UIs (per policy rows) |

All three map to **SC-7 / CM-7–style** boundary configuration expectations via `core.control_mapper` and emit **`SecurityEvent`** semantics consumed by correlation and instrumentation evals.

## Generated detection keywords

`generated_query_keywords` are **SIEM-tuning hints** (service names, representative ports, ElectricEye check fragments, and CSPM event names). They are merged per `semantic_type` and appended into Splunk/Sentinel/GCP generators (`instrumentation/policy_keywords.py`) and summarized in `write_instrumentation_plan()`.
