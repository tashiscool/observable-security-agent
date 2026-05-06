from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from scripts.guard_live_artifacts import DEFAULT_ALLOWED_ACCOUNTS, scan_paths

ROOT = Path(__file__).resolve().parents[1]


def test_guard_allows_fixture_example_accounts(tmp_path: Path) -> None:
    p = tmp_path / "sample.json"
    p.write_text('{"arn":"arn:aws:iam::111122223333:user/alice"}\n', encoding="utf-8")

    assert scan_paths([p], allowed_accounts=set(DEFAULT_ALLOWED_ACCOUNTS), base=tmp_path) == []


def test_guard_flags_unallowlisted_live_account(tmp_path: Path) -> None:
    p = tmp_path / "sample.json"
    p.write_text('{"raw_ref":"arn:aws-us-gov:iam::578463482707:user/tash"}\n', encoding="utf-8")

    findings = scan_paths([p], allowed_accounts=set(DEFAULT_ALLOWED_ACCOUNTS), base=tmp_path)

    assert len(findings) == 1
    assert findings[0].account_id == "578463482707"
    assert findings[0].to_dict()["account_id"] == "5784********"


def test_guard_cli_json_exits_one_for_live_identifier(tmp_path: Path) -> None:
    p = tmp_path / "sample.md"
    p.write_text("AWS account 578463482707 was collected live.\n", encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "guard_live_artifacts.py"), "--paths", str(p), "--json"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )

    assert proc.returncode == 1
    assert "5784********" in proc.stdout
