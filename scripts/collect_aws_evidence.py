#!/usr/bin/env python3
"""Collect AWS API evidence as raw JSON (and optionally fixture-shaped companion files)."""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import boto3  # noqa: E402

from providers.aws_evidence_raw import collect_aws_raw_evidence  # noqa: E402


def _resolve_region(arg: str | None) -> str:
    r = arg or os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION")
    if not r:
        raise SystemExit(
            "Region required: pass --region or set AWS_REGION / AWS_DEFAULT_REGION in the environment."
        )
    return r


def main() -> int:
    p = argparse.ArgumentParser(
        description="Collect AWS read-only evidence into raw JSON under raw/aws/{account_id}/{region}/."
    )
    p.add_argument("--profile", default=None, help="Optional boto3 profile name")
    p.add_argument(
        "--region",
        default=None,
        help="AWS region (required unless AWS_REGION or AWS_DEFAULT_REGION is set)",
    )
    p.add_argument("--output-dir", required=True, type=Path, help="Base directory for raw/ and optional fixtures")
    p.add_argument(
        "--account-label",
        default=None,
        help="Optional human label (environment name) recorded in manifest.json only",
    )
    p.add_argument(
        "--fixture-compatible",
        action="store_true",
        help="Also write discovered_assets.json, cloud_events.json, central_log_sources.json, alert_rules.json under output-dir",
    )
    args = p.parse_args()

    region = _resolve_region(args.region)
    session = boto3.Session(profile_name=args.profile, region_name=region)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    manifest_path = collect_aws_raw_evidence(
        session,
        region=region,
        output_dir=args.output_dir,
        account_label=args.account_label,
        fixture_compatible=args.fixture_compatible,
        collected_at_iso=now,
    )

    print(f"Wrote manifest: {manifest_path}")
    if args.fixture_compatible:
        od = args.output_dir.resolve()
        print(f"Fixture-shaped files (if generated): {od / 'discovered_assets.json'} …")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
