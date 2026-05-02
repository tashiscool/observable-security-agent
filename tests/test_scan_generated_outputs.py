"""Tests for ``scripts/scan_generated_outputs.py``.

Covers the pure helpers (redaction, Luhn, allowlist heuristics), the pattern
catalog (every required category present), end-to-end scanning of synthetic
trees (clean → no findings, injected fake → reportable findings, allowlisted
→ silent or downgraded), the CLI (rc 0/1, JSON output), and the contract that
the FULL secret value never appears in scanner output.
"""

from __future__ import annotations

import json
import subprocess
import sys
from importlib import util as _ilu
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT = REPO_ROOT / "scripts" / "scan_generated_outputs.py"


def _load_module():
    if "scan_generated_outputs" in sys.modules:
        return sys.modules["scan_generated_outputs"]
    spec = _ilu.spec_from_file_location("scan_generated_outputs", SCRIPT)
    assert spec and spec.loader
    mod = _ilu.module_from_spec(spec)
    sys.modules["scan_generated_outputs"] = mod
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


# Synthetic high-entropy tokens that match the patterns *exactly*.
# These are NOT real credentials; tests inject them into temp dirs only.
FAKE_AWS_KEY_NO_MARKER = "AKIAQYZGXY3HQ7P5LMNB"  # 20 chars, no FAKE/EXAMPLE/etc.
FAKE_GH_PAT = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"  # ghp_ + 36 alnum
FAKE_GOOGLE_KEY = "AIzaSyQwErTyUiOpAsDfGhJkLzXcVbNm1234567"  # AIza + 35 alnum
FAKE_BEARER = "Bearer abcdefghijklmnopqrstuvwxyzABCDEF1234567890"


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


def test_module_exports_expected_surface() -> None:
    mod = _load_module()
    for name in (
        "PATTERN_CATALOG",
        "DEFAULT_SCAN_PATHS",
        "DEFAULT_ALLOWLISTED_EMAILS",
        "ALLOWLISTED_EMAIL_DOMAINS",
        "ALLOWLIST_MARKERS",
        "Finding",
        "ScanResult",
        "scan_text",
        "scan_path",
        "scan_paths",
        "redact",
        "main",
    ):
        assert hasattr(mod, name), f"module missing {name}"


def test_pattern_catalog_covers_required_categories() -> None:
    mod = _load_module()
    cats = {p.category for p in mod.PATTERN_CATALOG}
    required = {
        "aws_access_key_id",
        "aws_secret_access_key",
        "aws_session_token",
        "private_key_block",
        "bearer_token",
        "api_key",
        "password",
        "github_pat_classic",
        "github_pat_fine_grained",
        "github_oauth",
        "github_user_server",
        "slack_token",
        "stripe_live_key",
        "google_api_key",
        "jwt",
        "email",
        "ssn",
        "pii_credit_card_like",
    }
    missing = required - cats
    assert not missing, f"pattern catalog is missing: {sorted(missing)}"


def test_default_email_allowlist_matches_spec() -> None:
    mod = _load_module()
    assert {
        "fixture@example.com",
        "alice@example.com",
        "bob@example.com",
        "security@example.com",
    } <= mod.DEFAULT_ALLOWLISTED_EMAILS


def test_default_scan_paths_include_required_dirs() -> None:
    mod = _load_module()
    for d in (
        "output",
        "output_tracker",
        "output_agent_run",
        "evidence",
        "reports",
        "web/sample-data",
    ):
        assert d in mod.DEFAULT_SCAN_PATHS, f"missing default path {d}"


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_redact_keeps_first_four_and_hides_length() -> None:
    mod = _load_module()
    out = mod.redact("AKIAQYZGXY3HQ7P5LMNB")
    assert "AKIA" in out
    assert "QYZGXY3HQ7P5LMNB" not in out
    assert "[redacted len=20]" in out


def test_redact_short_value_is_fully_hidden() -> None:
    mod = _load_module()
    out = mod.redact("abc")
    # Short values must NOT leak any character of the secret.
    assert "abc" not in out
    assert "[redacted len=3]" in out


def test_luhn_validator() -> None:
    mod = _load_module()
    assert mod._luhn_valid("4111111111111111") is True
    assert mod._luhn_valid("4111-1111-1111-1111") is True
    assert mod._luhn_valid("1234567812345678") is False
    assert mod._luhn_valid("12345678901") is False  # too short


# ---------------------------------------------------------------------------
# scan_text
# ---------------------------------------------------------------------------


def test_clean_text_produces_no_findings() -> None:
    mod = _load_module()
    findings = mod.scan_text(
        "This file is fine. Owner is alice@example.com.\n", scan_emails=True
    )
    assert all(f.allowlisted for f in findings)
    assert not [f for f in findings if not f.allowlisted]


def test_aws_key_without_marker_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text(f"key={FAKE_AWS_KEY_NO_MARKER}\n")
    rep = [f for f in findings if not f.allowlisted]
    assert any(f.category == "aws_access_key_id" for f in rep)


def test_aws_key_with_explicit_FAKE_marker_is_allowlisted() -> None:
    mod = _load_module()
    text = f"# FAKE — fixture only\naws_key={FAKE_AWS_KEY_NO_MARKER}\n"
    findings = mod.scan_text(text)
    assert findings  # the pattern must still match
    assert all(
        f.allowlisted for f in findings if f.category == "aws_access_key_id"
    ), f"FAKE-marked AWS key should be allowlisted, got: {findings}"


def test_aws_example_key_AKIAIOSFODNN7EXAMPLE_is_allowlisted_via_EXAMPLE_marker() -> None:
    mod = _load_module()
    findings = mod.scan_text("key=AKIAIOSFODNN7EXAMPLE\n")
    assert findings
    assert all(f.allowlisted for f in findings if f.category == "aws_access_key_id")


def test_github_pat_with_no_marker_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text(FAKE_GH_PAT + "\n")
    rep = [f for f in findings if not f.allowlisted]
    assert any(f.category == "github_pat_classic" for f in rep), findings


def test_google_api_key_with_no_marker_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text(f"GOOGLE_API_KEY={FAKE_GOOGLE_KEY}\n")
    rep = [f for f in findings if not f.allowlisted]
    assert any(f.category == "google_api_key" for f in rep)


def test_private_key_block_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text(
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA…\n-----END RSA PRIVATE KEY-----\n"
    )
    assert any(f.category == "private_key_block" and not f.allowlisted for f in findings)


def test_bearer_token_is_reported_and_secret_value_never_printed_full() -> None:
    mod = _load_module()
    text = f"Authorization: {FAKE_BEARER}\n"
    findings = mod.scan_text(text)
    rep = [f for f in findings if not f.allowlisted]
    assert any(f.category == "bearer_token" for f in rep)
    rendered = "\n".join(mod.format_finding(f) for f in rep)
    # The full token after "Bearer " must not appear anywhere.
    assert "abcdefghijklmnopqrstuvwxyzABCDEF1234567890" not in rendered


def test_password_assignment_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text('password = "supersecretpassword"\n')
    assert any(f.category == "password" and not f.allowlisted for f in findings)


def test_api_key_assignment_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text('app_api_key="abcd1234efgh5678ijkl9012mnop3456"\n')
    assert any(f.category == "api_key" and not f.allowlisted for f in findings)


def test_email_default_off_and_opt_in_works() -> None:
    mod = _load_module()
    text = "contact: ops@yahoo.com\n"
    # Default: emails not scanned at all.
    assert mod.scan_text(text) == []
    # Opt-in: yahoo.com is reportable.
    findings = mod.scan_text(text, scan_emails=True)
    rep = [f for f in findings if not f.allowlisted]
    assert any(f.category == "email" for f in rep)


def test_email_allowlist_via_default_addresses() -> None:
    mod = _load_module()
    findings = mod.scan_text("user: alice@example.com\n", scan_emails=True)
    assert findings and all(f.allowlisted for f in findings)


def test_email_allowlist_via_extra_address() -> None:
    mod = _load_module()
    findings = mod.scan_text(
        "user: ops@acme.com\n",
        scan_emails=True,
        extra_allowlist_emails=["ops@acme.com"],
    )
    assert findings and all(f.allowlisted for f in findings)


def test_email_allowlist_via_example_domain() -> None:
    mod = _load_module()
    findings = mod.scan_text("user: anybody@example.org\n", scan_emails=True)
    assert findings and all(f.allowlisted for f in findings)


def test_ssn_pattern_is_reported() -> None:
    mod = _load_module()
    findings = mod.scan_text("SSN on file: 123-45-6789\n")
    assert any(f.category == "ssn" and not f.allowlisted for f in findings)


def test_credit_card_only_reported_when_luhn_valid_and_separator_delimited() -> None:
    """Tightened CC pattern: requires separators (spaces or dashes) AND Luhn.

    This avoids false positives on contiguous digit runs inside content
    hashes (sha256 / sha1) and other identifiers.
    """
    mod = _load_module()
    valid = [
        f
        for f in mod.scan_text("card 4111-1111-1111-1111\n")
        if f.category == "pii_credit_card_like"
    ]
    valid_spaces = [
        f
        for f in mod.scan_text("card 4111 1111 1111 1111\n")
        if f.category == "pii_credit_card_like"
    ]
    invalid_luhn = [
        f
        for f in mod.scan_text("card 1234-5678-1234-5678\n")
        if f.category == "pii_credit_card_like"
    ]
    no_separators = [
        f
        for f in mod.scan_text("card 4111111111111111\n")
        if f.category == "pii_credit_card_like"
    ]
    assert valid and not any(f.allowlisted for f in valid)
    assert valid_spaces and not any(f.allowlisted for f in valid_spaces)
    assert invalid_luhn == []
    assert no_separators == []  # contiguous digits no longer match


def test_credit_card_inside_sha256_checksum_line_is_not_flagged() -> None:
    """Regression: hex hash digests in checksums files used to false-positive."""
    mod = _load_module()
    # A real sha256-style line as written by checksums.sha256.
    text = (
        "f180a4c90e34986213b26c38e1e92b0a592569346343021e6a8870bd2e83d62f"
        "  reports/assessor/evidence-index.md\n"
    )
    findings = [
        f
        for f in mod.scan_text(text)
        if f.category in ("pii_credit_card_like", "ssn")
    ]
    assert findings == [], f"hash line should not produce CC/SSN findings: {findings}"


def test_per_line_fixture_only_marker_downgrades_match() -> None:
    mod = _load_module()
    text = f'aws_key="{FAKE_AWS_KEY_NO_MARKER}"  # fixture-only\n'
    findings = mod.scan_text(text)
    assert findings
    assert all(f.allowlisted for f in findings if f.category == "aws_access_key_id")


# ---------------------------------------------------------------------------
# scan_paths + ScanResult
# ---------------------------------------------------------------------------


def test_scan_paths_clean_directory_has_no_reportable(tmp_path: Path) -> None:
    mod = _load_module()
    (tmp_path / "ok.md").write_text("Hello world.\n", encoding="utf-8")
    (tmp_path / "ok.json").write_text('{"owner": "alice@example.com"}\n', encoding="utf-8")
    res = mod.scan_paths([tmp_path], base=tmp_path)
    assert res.reportable == []
    assert res.files_scanned == 2


def test_scan_paths_injected_fake_key_fails(tmp_path: Path) -> None:
    """Acceptance test: injected fake unallowlisted key fails the scan."""
    mod = _load_module()
    (tmp_path / "leak.txt").write_text(f"AWS_KEY={FAKE_AWS_KEY_NO_MARKER}\n", encoding="utf-8")
    res = mod.scan_paths([tmp_path], base=tmp_path)
    assert res.reportable, "injected fake key MUST be reported"
    assert res.reportable[0].category == "aws_access_key_id"
    rendered = mod.render_summary_text(res)
    assert FAKE_AWS_KEY_NO_MARKER[4:] not in rendered, "secret tail leaked into output"


def test_scan_paths_injected_fake_key_passes_when_marked(tmp_path: Path) -> None:
    """Same fake key, but with FAKE marker → no report."""
    mod = _load_module()
    (tmp_path / "leak_marked.txt").write_text(
        f"# FAKE — for tests only\nAWS_KEY={FAKE_AWS_KEY_NO_MARKER}\n",
        encoding="utf-8",
    )
    res = mod.scan_paths([tmp_path], base=tmp_path)
    assert res.reportable == []


def test_scan_paths_skips_missing_dir(tmp_path: Path) -> None:
    mod = _load_module()
    res = mod.scan_paths([tmp_path / "does_not_exist"], base=tmp_path)
    assert res.reportable == []
    assert res.files_scanned == 0


# ---------------------------------------------------------------------------
# Real repository: existing fixtures must pass
# ---------------------------------------------------------------------------


def test_existing_repo_outputs_pass_without_email_scan() -> None:
    """ACCEPTANCE: fixture outputs pass."""
    mod = _load_module()
    paths = [
        REPO_ROOT / d for d in mod.DEFAULT_SCAN_PATHS if (REPO_ROOT / d).exists()
    ]
    assert paths, "no default scan paths exist — bootstrap a run first"
    res = mod.scan_paths(paths, base=REPO_ROOT)
    assert res.files_scanned > 0
    assert (
        res.reportable == []
    ), f"existing fixtures contain reportable secrets: {[str(f) for f in res.reportable[:5]]}"


def test_existing_repo_outputs_pass_with_email_scan() -> None:
    """All emails in fixtures are @example.com — should be allowlisted."""
    mod = _load_module()
    paths = [
        REPO_ROOT / d for d in mod.DEFAULT_SCAN_PATHS if (REPO_ROOT / d).exists()
    ]
    res = mod.scan_paths(paths, base=REPO_ROOT, scan_emails=True)
    assert (
        res.reportable == []
    ), f"existing fixtures contain non-example.com emails: {[str(f) for f in res.reportable[:5]]}"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


@pytest.mark.slow
def test_cli_clean_dir_exits_zero(tmp_path: Path) -> None:
    (tmp_path / "ok.md").write_text("nothing to see\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--paths", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


@pytest.mark.slow
def test_cli_dirty_dir_exits_one_and_redacts(tmp_path: Path) -> None:
    (tmp_path / "leak.md").write_text(f"AWS_KEY={FAKE_AWS_KEY_NO_MARKER}\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--paths", str(tmp_path)],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1
    assert "leak.md" in proc.stdout
    assert "aws_access_key_id" in proc.stdout
    # Full secret tail must NOT print.
    assert FAKE_AWS_KEY_NO_MARKER[4:] not in proc.stdout
    assert "***[redacted len=20]" in proc.stdout


@pytest.mark.slow
def test_cli_json_output_contains_redacted_findings(tmp_path: Path) -> None:
    (tmp_path / "leak.md").write_text(f"AWS_KEY={FAKE_AWS_KEY_NO_MARKER}\n", encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--paths", str(tmp_path), "--json"],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert proc.returncode == 1
    body = json.loads(proc.stdout)
    assert body["ok"] is False
    assert body["reportable"]
    f0 = body["reportable"][0]
    assert f0["category"] == "aws_access_key_id"
    assert "[redacted" in f0["preview"]
    # The raw secret must NOT appear anywhere in the JSON output.
    assert FAKE_AWS_KEY_NO_MARKER[4:] not in proc.stdout
    # Schema fields the consumer relies on.
    for k in ("file", "line", "column", "category", "preview"):
        assert k in f0


@pytest.mark.slow
def test_cli_default_paths_existing_repo_passes() -> None:
    """ACCEPTANCE: ``python scripts/scan_generated_outputs.py`` against the repo
    must pass on the bundled fixtures + freshly generated outputs."""
    proc = subprocess.run(
        [sys.executable, str(SCRIPT), "--quiet"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr


# ---------------------------------------------------------------------------
# Make target
# ---------------------------------------------------------------------------


def test_makefile_exposes_scan_outputs_target() -> None:
    mk = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "scan-outputs:" in mk
    assert "scripts/scan_generated_outputs.py" in mk
    assert "scan-outputs" in mk.split(".PHONY:", 1)[1].splitlines()[0]


# ---------------------------------------------------------------------------
# validate_everything wiring
# ---------------------------------------------------------------------------


def test_validate_everything_imports_scanner_module() -> None:
    src = (REPO_ROOT / "scripts" / "validate_everything.py").read_text(encoding="utf-8")
    assert "from scripts import scan_generated_outputs as scanner" in src
    assert "scanner.scan_paths" in src
