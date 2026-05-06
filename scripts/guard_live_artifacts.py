#!/usr/bin/env python3
"""Guard curated/demo artifacts against accidental live cloud identifiers.

Secret scanners catch keys and tokens; they do not catch a real AWS account ID
or ARN copied from a live assessment into sample-data or demo packages. This
guard treats non-example 12-digit AWS account IDs as reportable in curated
artifacts while allowing documented fixture/example accounts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

DEFAULT_PATHS: tuple[Path, ...] = (
    REPO_ROOT / "web" / "sample-data",
    REPO_ROOT / "evidence" / "package",
    REPO_ROOT / "evidence" / "package_tracker",
    REPO_ROOT / "reports",
    REPO_ROOT / "validation_run",
)

DEFAULT_ALLOWED_ACCOUNTS: frozenset[str] = frozenset(
    {
        "000000000000",
        "111111111111",
        "111122223333",
        "123456789012",
        "234567890123",
        "345678901234",
        "999999999999",
    }
)

ACCOUNT_RE = re.compile(r"(?<!\d)(\d{12})(?!\d)")
ARN_RE = re.compile(r"\barn:aws(?:-[a-z-]+)?:[A-Za-z0-9_-]*:[A-Za-z0-9-]*:(\d{12}):")
ECR_RE = re.compile(r"\b(\d{12})\.dkr\.ecr\.[A-Za-z0-9-]+\.amazonaws\.com\b")
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tgz", ".pyc"}
SKIP_DIRS = {".git", "__pycache__", "node_modules", ".venv"}


@dataclass(frozen=True)
class LiveArtifactFinding:
    file: str
    line: int
    account_id: str
    context: str

    def to_dict(self) -> dict[str, object]:
        return {
            "file": self.file,
            "line": self.line,
            "account_id": self.account_id[:4] + "********",
            "context": self.context,
        }


def _iter_files(paths: list[Path]) -> list[Path]:
    out: list[Path] = []
    for root in paths:
        if not root.exists():
            continue
        if root.is_file():
            out.append(root)
            continue
        for p in root.rglob("*"):
            if not p.is_file() or p.is_symlink():
                continue
            if any(part in SKIP_DIRS for part in p.parts):
                continue
            if p.suffix.lower() in SKIP_SUFFIXES:
                continue
            out.append(p)
    return out


def _accounts_in_line(line: str) -> set[str]:
    accounts = {m.group(1) for m in ARN_RE.finditer(line)}
    accounts.update(m.group(1) for m in ECR_RE.finditer(line))
    # Plain 12-digit ids are only meaningful in cloud-ish context; this avoids
    # false positives from dates, hashes, or counters in unrelated docs.
    cloudish = any(token in line.lower() for token in ("aws", "account", "arn:", "ecr", "cloudtrail"))
    if cloudish:
        accounts.update(m.group(1) for m in ACCOUNT_RE.finditer(line))
    return accounts


def scan_paths(paths: list[Path], *, allowed_accounts: set[str], base: Path = REPO_ROOT) -> list[LiveArtifactFinding]:
    findings: list[LiveArtifactFinding] = []
    for path in _iter_files(paths):
        try:
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except OSError:
            continue
        for line_no, line in enumerate(lines, start=1):
            for acct in sorted(_accounts_in_line(line) - allowed_accounts):
                try:
                    label = str(path.resolve().relative_to(base.resolve()))
                except ValueError:
                    label = str(path)
                findings.append(
                    LiveArtifactFinding(
                        file=label,
                        line=line_no,
                        account_id=acct,
                        context=line.strip()[:220],
                    )
                )
    return findings


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Detect non-example AWS account IDs in curated/demo artifacts.")
    p.add_argument("--paths", nargs="+", type=Path, default=list(DEFAULT_PATHS))
    p.add_argument("--allow-account", action="append", default=[], help="Additional 12-digit account id to allow.")
    p.add_argument("--json", action="store_true", dest="emit_json")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    allowed = set(DEFAULT_ALLOWED_ACCOUNTS)
    allowed.update(str(x).strip() for x in args.allow_account if str(x).strip())
    findings = scan_paths([p.resolve() for p in args.paths], allowed_accounts=allowed)
    if args.emit_json:
        json.dump(
            {
                "schema_version": "1.0",
                "tool": "guard_live_artifacts",
                "ok": not findings,
                "findings": [f.to_dict() for f in findings],
            },
            sys.stdout,
            indent=2,
        )
        sys.stdout.write("\n")
    else:
        print(f"guard_live_artifacts: {len(findings)} reportable live identifier(s)")
        for f in findings[:50]:
            print(f"  {f.file}:{f.line}: account={f.account_id[:4]}********")
    return 0 if not findings else 1


if __name__ == "__main__":
    raise SystemExit(main())
