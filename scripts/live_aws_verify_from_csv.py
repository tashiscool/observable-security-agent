#!/usr/bin/env python3
"""Credential-safe live AWS verification for Observable Security Agent.

The wrapper accepts an AWS access-key CSV, creates temporary source/session JSON
credential files with 0600 permissions, runs read-only collection and assessment
checks, then removes the temporary credential files. Live outputs are written to
a temp or explicitly supplied run directory, never to committed sample paths.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SECURITY_INFRA = ROOT.parent
BOOTSTRAP = SECURITY_INFRA / "infrastructure" / "packer" / "bootstrap-creds-json-from-csv.sh"

FORBIDDEN_OUTPUT_PARTS: tuple[tuple[str, ...], ...] = (
    ("web", "sample-data"),
    ("fixtures",),
    ("reference_samples",),
)
FORBIDDEN_OUTPUT_NAMES: frozenset[str] = frozenset(
    {"output", "evidence", "reports", "web", "fixtures", "reference_samples"}
)


def _mask_account(account: str) -> str:
    s = str(account or "")
    return ("*" * max(0, len(s) - 4)) + s[-4:] if len(s) > 4 else "****"


def _mask_arn(arn: str) -> str:
    s = str(arn or "")
    parts = s.split(":")
    if len(parts) > 4 and parts[4]:
        parts[4] = _mask_account(parts[4])
        return ":".join(parts)
    return s


def _run(cmd: list[str], *, env: dict[str, str], cwd: Path = ROOT) -> None:
    shown = " ".join(cmd)
    print(f"=== {shown} ===", flush=True)
    subprocess.run(cmd, cwd=str(cwd), env=env, check=True)


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _load_session_env(creds_file: Path, region: str) -> dict[str, str]:
    data = _read_json(creds_file)
    creds = data.get("Credentials") if isinstance(data, dict) else None
    if not isinstance(creds, dict):
        creds = data if isinstance(data, dict) else {}
    access_key = str(creds.get("AccessKeyId") or "")
    secret_key = str(creds.get("SecretAccessKey") or "")
    session_token = str(creds.get("SessionToken") or "")
    if not access_key or not secret_key:
        raise SystemExit("Session credential JSON is missing AccessKeyId or SecretAccessKey.")
    env = os.environ.copy()
    env.update(
        {
            "AWS_ACCESS_KEY_ID": access_key,
            "AWS_SECRET_ACCESS_KEY": secret_key,
            "AWS_REGION": region,
            "AWS_DEFAULT_REGION": region,
            "AWS_EC2_METADATA_DISABLED": "true",
        }
    )
    if session_token:
        env["AWS_SESSION_TOKEN"] = session_token
    return env


def _warn_csv_mode(path: Path) -> None:
    mode = stat.S_IMODE(path.stat().st_mode)
    if mode & 0o077:
        print(
            f"WARNING: source CSV is group/world-readable ({oct(mode)}): {path}. "
            "The verifier will not modify it.",
            file=sys.stderr,
        )


def _guard_output_dir(path: Path, *, allow_repo_output: bool) -> None:
    resolved = path.resolve()
    try:
        rel = resolved.relative_to(ROOT)
    except ValueError:
        return
    if allow_repo_output:
        return
    parts = rel.parts
    if parts and parts[0] in FORBIDDEN_OUTPUT_NAMES:
        raise SystemExit(
            f"Refusing live output under committed/demo path {resolved}; choose a temp directory "
            "or pass --allow-repo-output intentionally."
        )
    for forbidden in FORBIDDEN_OUTPUT_PARTS:
        if len(parts) >= len(forbidden) and parts[: len(forbidden)] == forbidden:
            raise SystemExit(f"Refusing live output under committed sample path {resolved}.")


def _discover_region_evidence_dirs(raw_dir: Path) -> list[Path]:
    root_manifest = raw_dir / "collection_manifest.json"
    if root_manifest.is_file():
        doc = _read_json(root_manifest)
        dirs: list[Path] = []
        for item in doc.get("region_manifests", []) if isinstance(doc, dict) else []:
            p = Path(str(item))
            if p.is_file():
                dirs.append(p.parent.resolve())
        if dirs:
            return dirs
    dirs = []
    for p in sorted(raw_dir.glob("raw/aws/*/*/manifest.json")):
        dirs.append(p.parent.resolve())
    if (raw_dir / "cloud_events.json").is_file():
        dirs.append(raw_dir.resolve())
    seen: set[Path] = set()
    out: list[Path] = []
    for d in dirs:
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out


def _run_sts_identity(env: dict[str, str], region: str) -> None:
    code = (
        "import boto3;"
        f"i=boto3.client('sts', region_name={region!r}).get_caller_identity();"
        "acct=str(i.get('Account',''));"
        "mask=('*'*(len(acct)-4)+acct[-4:]) if len(acct)>4 else '****';"
        "arn=str(i.get('Arn','')).replace(acct, mask);"
        "print('STS caller identity: account=' + mask + ' arn=' + arn)"
    )
    _run([sys.executable, "-c", code], env=env)


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run read-only live AWS verification from an access-key CSV.")
    default_csv = os.environ.get("OS_AGENT_CSV") or os.environ.get("AWS_ACCESS_KEYS_CSV")
    p.add_argument(
        "--csv-file",
        type=Path,
        default=Path(default_csv) if default_csv else None,
        help="AWS access-key CSV. Defaults to OS_AGENT_CSV or AWS_ACCESS_KEYS_CSV when set.",
    )
    p.add_argument("--region", default=os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION") or "us-gov-west-1")
    p.add_argument("--regions", nargs="+", default=None, help="One or more regions, or comma-separated lists.")
    p.add_argument("--all-enabled-regions", action="store_true")
    p.add_argument("--output-dir", type=Path, default=None, help="Live run output directory (default: temp dir).")
    p.add_argument("--keep-output", action="store_true", help="Keep temp output when --output-dir is omitted.")
    p.add_argument("--allow-repo-output", action="store_true", help="Allow live artifacts under this repo.")
    p.add_argument("--skip-20x", action="store_true", help="Skip package/report/reconciliation checks.")
    p.add_argument("--skip-threat-hunt", action="store_true")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if args.csv_file is None:
        print(
            "CSV file is required. Pass --csv-file or set OS_AGENT_CSV/AWS_ACCESS_KEYS_CSV.",
            file=sys.stderr,
        )
        return 2
    csv_file = args.csv_file.expanduser().resolve()
    if not csv_file.is_file():
        print(f"CSV file not found: {csv_file}", file=sys.stderr)
        return 2
    if not BOOTSTRAP.is_file():
        print(f"Bootstrap script not found: {BOOTSTRAP}", file=sys.stderr)
        return 2
    _warn_csv_mode(csv_file)

    temp_output_created = False
    if args.output_dir is None:
        output_dir = Path(tempfile.mkdtemp(prefix="os_agent_live_aws_")).resolve()
        temp_output_created = True
    else:
        output_dir = args.output_dir.expanduser().resolve()
    _guard_output_dir(output_dir, allow_repo_output=bool(args.allow_repo_output))
    output_dir.mkdir(parents=True, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="os_agent_live_creds_") as cred_tmp:
        cred_dir = Path(cred_tmp)
        cred_dir.chmod(0o700)
        creds_file = cred_dir / "creds.json"
        source_file = cred_dir / "creds.source.json"
        subprocess.run(
            [
                "bash",
                str(BOOTSTRAP),
                "--csv-file",
                str(csv_file),
                "--creds-file",
                str(creds_file),
                "--source-creds-file",
                str(source_file),
                "--region",
                str(args.region),
            ],
            cwd=str(ROOT),
            check=True,
        )
        for p in (creds_file, source_file):
            if p.is_file():
                p.chmod(0o600)

        env = _load_session_env(creds_file, str(args.region))
        _run_sts_identity(env, str(args.region))

        raw_dir = output_dir / "raw_collect"
        collect_cmd = [
            sys.executable,
            "scripts/collect_aws_evidence.py",
            "--output-dir",
            str(raw_dir),
            "--fixture-compatible",
        ]
        if args.all_enabled_regions:
            collect_cmd.extend(["--region", str(args.region), "--all-enabled-regions"])
        elif args.regions:
            collect_cmd.extend(["--regions", *[str(r) for r in args.regions]])
        else:
            collect_cmd.extend(["--region", str(args.region)])
        _run(collect_cmd, env=env)

        evidence_dirs = _discover_region_evidence_dirs(raw_dir)
        if not evidence_dirs:
            raise SystemExit(f"No per-region evidence directories found under {raw_dir}.")

        assess_dirs: list[Path] = []
        for idx, evidence_dir in enumerate(evidence_dirs, start=1):
            region_name = evidence_dir.name
            assess_dir = output_dir / f"assessment_{idx}_{region_name}"
            pkg_dir = output_dir / f"package_{idx}_{region_name}"
            threat_dir = output_dir / f"threat_hunt_{idx}_{region_name}"
            assess_dirs.append(assess_dir)
            _run(
                [
                    sys.executable,
                    "agent.py",
                    "assess",
                    "--provider",
                    "aws",
                    "--raw-evidence-dir",
                    str(evidence_dir),
                    "--output-dir",
                    str(assess_dir),
                    "--mode",
                    "live",
                ],
                env=env,
            )
            _run([sys.executable, "agent.py", "validate", "--output-dir", str(assess_dir), "--mode", "live"], env=env)
            _run([sys.executable, "scripts/validate_outputs.py", "--output-dir", str(assess_dir), "--mode", "live"], env=env)

            if not args.skip_20x:
                _run(
                    [
                        sys.executable,
                        "agent.py",
                        "build-20x-package",
                        "--assessment-output",
                        str(assess_dir),
                        "--config",
                        "config",
                        "--package-output",
                        str(pkg_dir),
                    ],
                    env=env,
                )
                package_json = pkg_dir / "fedramp20x-package.json"
                _run(
                    [
                        sys.executable,
                        "agent.py",
                        "validate-20x-package",
                        "--package",
                        str(package_json),
                        "--schemas",
                        "schemas",
                    ],
                    env=env,
                )
                _run([sys.executable, "agent.py", "generate-20x-reports", "--package", str(package_json), "--config", "config"], env=env)
                _run([sys.executable, "agent.py", "reconcile-20x", "--package", str(package_json), "--reports", str(pkg_dir)], env=env)

            if not args.skip_threat_hunt:
                _run(
                    [
                        sys.executable,
                        "agent.py",
                        "threat-hunt",
                        "--provider",
                        "aws",
                        "--raw-evidence-dir",
                        str(evidence_dir),
                        "--output-dir",
                        str(threat_dir),
                    ],
                    env=env,
                )

        _run([sys.executable, "scripts/scan_generated_outputs.py", "--paths", str(output_dir), "--quiet"], env=env)

    print("Temporary credential files removed.")
    print(f"Live verification output: {output_dir}")
    if temp_output_created and not args.keep_output:
        shutil.rmtree(output_dir, ignore_errors=True)
        print("Temporary live output removed. Re-run with --keep-output to inspect artifacts.")
    print("LIVE AWS VERIFICATION PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
