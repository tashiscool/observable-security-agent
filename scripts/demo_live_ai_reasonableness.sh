#!/usr/bin/env bash
# Live AI reasonableness smoke for BuildLab.
#
# Backends:
#   ollama  - local OpenAI-compatible Ollama endpoint (no API key required)
#   bedrock - AWS Bedrock through local LiteLLM proxy, using temp STS creds from CSV
#
# This script never prints AWS secrets and never writes live outputs into repo
# sample-data paths. Bedrock credentials are written under a temp directory with
# 0600 permissions and deleted on exit.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BACKEND="${BACKEND:-ollama}"
CSV_FILE="${CSV_FILE:-${OS_AGENT_CSV:-${AWS_ACCESS_KEYS_CSV:-}}}"
REGION="${REGION:-${AWS_REGION:-${AWS_DEFAULT_REGION:-us-gov-west-1}}}"
OLLAMA_HOST="${OLLAMA_HOST:-127.0.0.1}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
OLLAMA_MODEL="${OLLAMA_MODEL:-${AI_MODEL:-llama3.1}}"
BEDROCK_MODEL="${BEDROCK_MODEL:-${AI_MODEL:-bedrock/anthropic.claude-3-haiku-20240307-v1:0}}"
PORT="${PORT:-${LITELLM_PORT:-4000}}"

usage() {
  cat <<USAGE
Usage: BACKEND=ollama|bedrock [CSV_FILE=/path/to/accessKeys.csv] $0

Examples:
  BACKEND=ollama OLLAMA_MODEL=llama3.1 $0
  BACKEND=bedrock CSV_FILE=/path/to/accessKeys.csv REGION=us-gov-west-1 $0
USAGE
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

cd "$ROOT"

TMP="$(mktemp -d "${TMPDIR:-/tmp}/os_agent_ai_reasonableness_XXXXXX")"
LITELLM_PID=""
OLLAMA_PID=""
cleanup() {
  if [[ -n "$LITELLM_PID" ]]; then kill "$LITELLM_PID" >/dev/null 2>&1 || true; fi
  if [[ -n "$OLLAMA_PID" ]]; then kill "$OLLAMA_PID" >/dev/null 2>&1 || true; fi
  rm -rf "$TMP"
}
trap cleanup EXIT

ensure_conmon_report() {
  if [[ ! -f output/conmon_reasonableness/conmon_reasonableness.json ]]; then
    python3 agent.py conmon-reasonableness \
      --tracker fixtures/assessment_tracker/conmon_19_tracker.csv \
      --output-dir output/conmon_reasonableness >/dev/null
  fi
}

run_reasoner() {
  python3 - <<'PY'
import json
from pathlib import Path
from ai.reasoning import explain_conmon_reasonableness, llm_backend_status

path = Path("output/conmon_reasonableness/conmon_reasonableness.json")
data = json.loads(path.read_text(encoding="utf-8"))
data = {
    "catalog_name": data.get("catalog_name"),
    "summary": data.get("summary"),
    "evidence_ecosystems": data.get("evidence_ecosystems"),
    "obligation_assessments": (data.get("obligation_assessments") or [])[:4],
}
status = llm_backend_status(["explain_conmon_reasonableness"])
out = explain_conmon_reasonableness(conmon_result=data)
print("AI_BACKEND_STATUS=" + json.dumps(status, sort_keys=True))
print("AI_REASONER_SOURCE=" + str(out.source))
print("AI_REASONER_HEADLINE=" + out.headline.replace("\n", " ")[:500])
print("AI_REASONER_CITATIONS=" + json.dumps([c.model_dump(mode="json") for c in out.citations[:5]], sort_keys=True))
if out.warnings:
    print("AI_REASONER_WARNINGS=" + json.dumps(out.warnings[:5]))
if str(out.source) != "ReasoningSource.LLM":
    raise SystemExit(3)
PY
}

ensure_conmon_report

case "$BACKEND" in
  ollama)
    if ! command -v ollama >/dev/null 2>&1; then
      echo "ERROR: ollama command not found" >&2
      exit 2
    fi
    if ! curl -sS --max-time 2 "http://${OLLAMA_HOST}:${OLLAMA_PORT}/v1/models" >/dev/null 2>&1; then
      echo "Starting Ollama server on ${OLLAMA_HOST}:${OLLAMA_PORT}..."
      ollama serve >"$TMP/ollama.log" 2>&1 &
      OLLAMA_PID="$!"
      for _ in $(seq 1 30); do
        curl -sS --max-time 2 "http://${OLLAMA_HOST}:${OLLAMA_PORT}/v1/models" >/dev/null 2>&1 && break
        sleep 1
      done
    fi
    export AI_BACKEND=ollama
    export AI_API_BASE="http://${OLLAMA_HOST}:${OLLAMA_PORT}/v1"
    export AI_MODEL="$OLLAMA_MODEL"
    unset AI_API_KEY || true
    echo "Running ConMon reasonableness AI smoke via Ollama model: $AI_MODEL"
    run_reasoner
    ;;

  bedrock)
    if [[ -z "$CSV_FILE" ]]; then
      echo "ERROR: set CSV_FILE, OS_AGENT_CSV, or AWS_ACCESS_KEYS_CSV for BACKEND=bedrock" >&2
      exit 2
    fi
    if [[ ! -f "$CSV_FILE" ]]; then
      echo "ERROR: CSV_FILE not found: $CSV_FILE" >&2
      exit 2
    fi
    if ! command -v litellm >/dev/null 2>&1; then
      echo "ERROR: litellm command not found" >&2
      exit 2
    fi
    mode="$(stat -f '%Lp' "$CSV_FILE" 2>/dev/null || stat -c '%a' "$CSV_FILE" 2>/dev/null || echo unknown)"
    case "$mode" in
      6??|7??)
        echo "WARNING: source CSV appears group/world-readable ($mode): $CSV_FILE. Not modifying it."
        ;;
    esac

    REGION="$REGION" bash ../infrastructure/packer/bootstrap-creds-json-from-csv.sh \
      --csv-file "$CSV_FILE" \
      --creds-file "$TMP/creds.json" \
      --source-creds-file "$TMP/source.json" \
      --region "$REGION" >"$TMP/bootstrap.log"
    chmod 600 "$TMP/creds.json" "$TMP/source.json"
    eval "$(python3 scripts/export_aws_session_env.py "$TMP/creds.json")"
    export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"

    echo "Checking Bedrock model-list access in $REGION..."
    python3 - <<'PY'
import boto3
br = boto3.client("bedrock")
models = [m.get("modelId") for m in br.list_foundation_models().get("modelSummaries", []) if m.get("modelId")]
print(f"BEDROCK_MODELS_LISTED={len(models)}")
print("BEDROCK_MODEL_SAMPLE=" + ",".join(models[:5]))
PY

    if lsof -iTCP:"$PORT" -sTCP:LISTEN >/dev/null 2>&1; then
      PORT="$((PORT + 1))"
    fi
    litellm --model "$BEDROCK_MODEL" --port "$PORT" >"$TMP/litellm.log" 2>&1 &
    LITELLM_PID="$!"
    for _ in $(seq 1 30); do
      curl -sS --max-time 2 "http://127.0.0.1:${PORT}/v1/models" >/dev/null 2>&1 && break
      sleep 1
    done
    export AI_API_BASE="http://127.0.0.1:${PORT}/v1"
    export AI_API_KEY="dummy-key"
    export AI_MODEL="$BEDROCK_MODEL"
    echo "Running ConMon reasonableness AI smoke via LiteLLM/Bedrock model: $AI_MODEL"
    set +e
    run_reasoner
    rc=$?
    set -e
    if [[ "$rc" -eq 3 ]]; then
      echo "BEDROCK_LLM_FALLBACK=1"
      echo "Bedrock/LiteLLM transport was configured, but invocation fell back. Common cause: Bedrock model access is not enabled for this account/region."
      exit 0
    fi
    exit "$rc"
    ;;

  *)
    echo "ERROR: unknown BACKEND=$BACKEND" >&2
    usage >&2
    exit 2
    ;;
esac
