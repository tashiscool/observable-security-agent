# AI Security Agent BuildLab / AgentLab — testing runbook

This ties the **Observable Security Agent** demo and gates to the **AI Security Agent BuildLab** schedule. It reuses the same patterns we verified: **fixture-first evidence**, **bounded `run-agent`**, **CSV → `/tmp` creds → `run-with-creds.sh`**, and **optional live GovCloud/commercial AWS** only where it adds real evidence (never as a substitute for a complete bundle).

**Product line (one sentence):** a **bounded security agent** that produces **observable, testable, audit-ready evidence** for the **cloud proof chain** and **AI agent governance**—not a chatbot stapled onto compliance. See `docs/why_this_is_not_reinventing_the_wheel.md`.

---

## Schedule anchor (ET) — map your work

| When (ET) | Block | What to have working |
|-----------|--------|----------------------|
| **10:00 AM – 12:00 PM** | AgentLab Session 1 — setup, team formation, live challenge briefing | Environment + **green fixture path** + Explainer trace (no LLM required). |
| **12:15 PM – 1:15 PM** | Final development + submissions | **`make verify-demo`** (or equivalent) clean + **`buildlab_readiness`** PASS + optional **live AWS** smoke documented. |
| **1:15 PM – 1:30 PM** | AgentLab closes — submissions & judging | Frozen artifacts: `output/`, `evidence/package/`, `web/sample-data/` trace, `output/buildlab_readiness.md`, walkthrough. |
| **1:30 PM – 3:30 PM** | Session 2 — refine automation | Same gates; iterate only if judges allow resubmission—keep **reproducible commands** in README or this file. |

*(Room / “Share session” links are organizer-specific—omit from zip bundles.)*

---

## Pattern A — always-on (no AWS keys): fixture + 20x + bounded loop

From **`observable-security-agent/`** (directory containing `agent.py`):

```bash
pip install -r requirements.txt
make verify-demo
```

That runs **`scripts/verify_demo.sh`**: full **pytest**, **`make all`**, **`python scripts/buildlab_readiness.py`**, a **bounded `run-agent`** pass, cloud + agentic **threat hunt**, **20x** build + schema validate, **deterministic AI explain** (`trace_derivation`), and **`assess --provider aws`** using the **fixture directory** as the raw bundle (same as CI—proves the AWS code path without inventing cloud events).

**Story for judges:** “We prove gaps from **loaded evidence**; missing proof is **FAIL/PARTIAL**, not LLM filler. Autonomy is **bounded**: observe → plan → act → verify → explain, with **policy-blocked** remediation and external tickets.”

---

## Pattern B — org creds without committing secrets: CSV → `/tmp` → `run-with-creds`

Use this when BuildLab gives you **access-key CSV** and you must not write long-lived keys into the repo.

From **`security-infra`** repo root:

```bash
TMP=$(mktemp -d /tmp/os_buildlab_creds_XXXXXX)
REGION=us-gov-west-1   # or us-east-1, etc.—match the account partition

bash infrastructure/packer/bootstrap-creds-json-from-csv.sh \
  --csv-file /path/to/your_accessKeys.csv \
  --creds-file "$TMP/creds.json" \
  --source-creds-file "$TMP/creds.source.json" \
  --region "$REGION"

cd infrastructure/packer
SECURITY_CREDS_FILE="$TMP/creds.json" \
SECURITY_SOURCE_CREDS_FILE="$TMP/creds.source.json" \
SECURITY_AWS_REGION="$REGION" \
./run-with-creds.sh --mode validate --region "$REGION"
```

**What this proves:** refreshed session creds load; **Packer template validate** passes (infrastructure side). It does **not** by itself prove **`observable-security-agent`** live assess—see Pattern C.

**Cleanup:** `rm -rf "$TMP"` after the session (or after exporting session creds for a short live smoke).

---

## Pattern C — live cloud evidence (optional, honest limits)

1. **Export session env from `$TMP/creds.json`** (read `Credentials.AccessKeyId`, `SecretAccessKey`, `SessionToken`—do not paste into chat or slides).

2. **Collect read-only raw JSON** (GovCloud example):

   ```bash
   cd observable-security-agent
   export AWS_REGION=us-gov-west-1 AWS_DEFAULT_REGION=us-gov-west-1
   python scripts/collect_aws_evidence.py --region "$AWS_REGION" --output-dir raw/buildlab-smoke --fixture-compatible
   ```

3. **`assess --provider aws --raw-evidence-dir …`** on the **directory that contains `manifest.json`** (usually `raw/.../aws/<account>/<region>/`). With **`--fixture-compatible`**, the collector writes **`cloud_events.json`** (and related companions) **both** at the collect output root **and** next to **`manifest.json`** so this path works end-to-end.

**One-shot (CSV + full verify):** from **`observable-security-agent/`**, **`make aws-bootstrap-verify CSV_FILE=/path/to/accessKeys.csv`** (optional **`REGION=…`**).

**Sparse evidence:** if CloudTrail lookup returns nothing, the bundle still includes a **placeholder** event so normalization can run; replace with real CloudTrail exports before treating correlation as production-grade.

---

## Submission checklist (before 1:15 PM ET)

- [ ] **`make test`** — all pytest green.
- [ ] **`make verify-demo`** or **`make all`** + **`python scripts/buildlab_readiness.py`** — readiness **PASS** (cloud STS may be **WARN** only).
- [ ] **`output/demo_walkthrough.md`** present (from **`make all`** / **`make demo`**).
- [ ] **`output/buildlab_readiness.md`** attached or linked for judges.
- [ ] **Bounded autonomy:** `agent_run_trace.json` / summary (from **`run-agent`** or `web/sample-data/` fallback for static Explorer).
- [ ] **No secrets** in zip: exclude `creds.json`, `.env`, `/tmp` cred dirs, `venv/`.

---

## Elevator pitch vs. “autonomous agent” hype

| Judge concern | Your answer |
|---------------|-------------|
| Is this just RAG on compliance PDFs? | **No** — evals and KSIs are **deterministic** over **structured inputs**; explain adds **grounded** narrative with **evidence contract** footer. |
| Does it “fix” my cloud? | **No** — **policy blocks** remediation, IAM changes, external tickets; loop only **generates local evidence** and drafts. |
| What is “autonomous” then? | **Orchestrated playbook** with **logged policy decisions** (`agent_run_trace.json`), not unbounded tool use. |

---

## Quick reference (commands)

| Goal | Command |
|------|---------|
| Full local + BuildLab gates | `make verify-demo` |
| Readiness markdown | `python scripts/buildlab_readiness.py` → `output/buildlab_readiness.md` |
| Explorer | `python scripts/serve_web.py` → open **`/web/index.html`** on the printed URL |
| Optional explain API | `pip install -e ".[api]"` then `uvicorn api.server:app --host 127.0.0.1 --port 8081` |

For CSV bootstrap details, see **`README.md`** (section on **`make verify-demo`** and **`bootstrap-creds-json-from-csv.sh`**).
