# Observable Security Agent — BuildLab pitch

This document is for **judges and competition reviewers**. The technical product description, API, and workflows live in [README.md](README.md).

---

## Elevator pitch

Security and compliance teams are buried in scanner output, log schemas, and narrative reports that **do not connect**. Meanwhile, generic LLMs happily draft “remediation plans” with **no proof** that the underlying controls are actually satisfied. **Observable Security Agent** is a different thing: a **deterministic evidence-correlation and assessment-evaluation layer** that answers, for each asset, event, and finding, whether the **proof chain** is demonstrable—inventory, scanner scope, centralized logging, alerting, change linkage, exploitation review when it matters, and POA&M when gaps remain.

The system **does not invent evidence**. Gaps are **FAIL/PARTIAL** with explicit narratives about what was missing. Optional AI explanation is **grounded**: it consumes the same structured artifacts (eval results, graph, POA&M) and carries an **evidence contract** footer so reviewers see what was—and was not—allowed into the answer.

**Bounded autonomy** matters for real operations. The `run-agent` playbook runs observe → plan → act → explain with **policy decisions on every step**, a fixed blocked-action catalog, and **no silent execution** of cloud mutation or ticket creation. This is autonomy with guardrails, not an unconstrained agent with API keys.

---

## Why this solves real compliance problems

| Pain | How this project addresses it |
| --- | --- |
| “We passed the scanner” ≠ defensible ATO narrative | Evaluations tie **controls and (when enabled) FedRAMP 20x KSI-style** rolls ups to **explicit evidence**, not tool marketing language. |
| Reports drift from machine-readable truth | **Reconciliation** and validation scripts check that human-facing outputs align with the **same** JSON package the machine validated. |
| LLM hallucinations in audits | Explain paths are **artifact-bounded**; deterministic modes run with **no** model; LLM paths are optional and wired to fail closed into deterministic explanations. |
| Agentic risk | Dedicated evals and **threat-hunt** outputs cite **evidence_refs** into agent tool calls, memory, policy violations, and identities—no orphan narratives. |

---

## Proof: exhaustive verification (GovCloud)

An end-to-end harness (`scripts/verify_all_features.sh`) was executed with **live AWS GovCloud** credentials and **`REGION=us-gov-west-1`**. It exercises, among other things:

- Full **pytest** suite  
- Every major **`agent.py`** path (fixtures, AWS-shaped raw dirs, imports, 20x package, reconcile)  
- **FastAPI** `/api/health` and `/api/explain`  
- Static **Security Evidence Explorer** (`web/`) HTTP contract  
- **Prowler** and **OCSF** importers  
- **Cypher export** (Neo4j-oriented graph export)  
- **CSV → creds → STS → live `collect_aws_evidence` → `assess` → `validate_outputs` → `threat-hunt` on live raw**

**Outcome (representative run):**

- **Pytest:**  **692 passed** (full suite, ~58s locally)  
- **Feature harness:** **32 × PASS**, **0 × SKIP** (live AWS path enabled; no gates skipped)  
- **GovCloud:** STS caller identity succeeded; live collection and assessment **VALIDATION PASSED**  

To reproduce (use your own access key CSV; do not commit credentials):

```bash
cd observable-security-agent
pip install -r requirements.txt
pip install -e '.[api]'   # FastAPI + uvicorn for harness API checks

make verify-all-features OS_AGENT_CSV=/path/to/YOUR_accessKeys.csv REGION=us-gov-west-1
# Also works: export OS_AGENT_CSV=... REGION=... && make verify-all-features
# Or:        env OS_AGENT_CSV=... REGION=... bash scripts/verify_all_features.sh
```

Detailed console capture from the proof run is retained locally as `/tmp/verify_all_features_run.log` (not shipped in-repo).

---

## Security Evidence Explorer (visual)

Headless capture of the static explorer (sample data):

![Security Evidence Explorer — main UI](docs/competition/explorer-main.png)

**Replay locally for video or deeper UI review:**

```bash
# Terminal A — static Explorer (serves repo root; default http://127.0.0.1:8080/web/index.html)
python3 scripts/serve_web.py

# Terminal B — optional explain API for live AI explanation tab against your outputs
python3 -m uvicorn api.server:app --host 127.0.0.1 --port 8081
```

Then open `http://127.0.0.1:8080/web/index.html` in a browser. For a judge-ready **screen recording**, drop `buildlab-walkthrough.mp4` (or similar) alongside the PNG under `docs/competition/` and link it here.

---

## License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
