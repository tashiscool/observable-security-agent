#!/usr/bin/env bash
# Bootstrap AWS session creds from a root access-key CSV (via security-infra packer script), export env vars,
# then run observable-security-agent full verification (make verify-demo).
#
# Usage (from observable-security-agent/):
#   bash scripts/aws_bootstrap_verify.sh --csv-file /path/to/accessKeys.csv [--region us-gov-west-1]
#
# Requires repo layout: this directory is security-infra/observable-security-agent (sibling of infrastructure/).

set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SI="$(cd "$ROOT/.." && pwd)"
CSV=""
REGION="${AWS_REGION:-${AWS_DEFAULT_REGION:-us-gov-west-1}}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --csv-file)
      CSV="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 --csv-file PATH [--region REGION]"
      exit 0
      ;;
    *)
      echo "Unknown: $1" >&2
      exit 2
      ;;
  esac
done

if [[ ! -f "$CSV" ]]; then
  echo "ERROR: --csv-file must point to an existing CSV" >&2
  exit 2
fi
BOOT="$SI/infrastructure/packer/bootstrap-creds-json-from-csv.sh"
if [[ ! -f "$BOOT" ]]; then
  echo "ERROR: expected bootstrap script at $BOOT (wrong monorepo layout?)" >&2
  exit 2
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/os_agent_csv_verify_XXXXXX")"
CREDS="$TMP/creds.json"
SOURCE="$TMP/creds.source.json"
trap 'rm -rf "$TMP"' EXIT

echo "=== Bootstrap session creds (region=$REGION) ==="
bash "$BOOT" --csv-file "$CSV" --creds-file "$CREDS" --source-creds-file "$SOURCE" --region "$REGION"

eval "$(python3 "$ROOT/scripts/export_aws_session_env.py" "$CREDS")"
export AWS_REGION="$REGION" AWS_DEFAULT_REGION="$REGION"

echo "=== STS ==="
python3 -c "import boto3; i=boto3.client('sts', region_name='$REGION').get_caller_identity(); print(i.get('Account'), i.get('Arn'))"

cd "$ROOT"
echo "=== make verify-demo ==="
make verify-demo
