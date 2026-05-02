#!/usr/bin/env python3
"""Generated-output safety scanner.

Walks the directories produced by the assessment pipeline and looks for
secret-shaped values, common token formats, and high-risk PII. Findings are
emitted with **redacted** previews — the full secret value is never printed.

Default scan paths (anything that does not exist is silently skipped)::

    output/
    output_tracker/
    output_agent_run/
    evidence/
    reports/
    web/sample-data/

Override with ``--paths`` (one or more).

Detection categories::

    aws_access_key_id        AKIA / ASIA + 16 alnum
    aws_secret_access_key    "aws_secret_access_key = ..."  (40 base64 chars)
    aws_session_token        "AWS_SESSION_TOKEN = ..."      (40+ base64 chars)
    private_key_block        "-----BEGIN ... PRIVATE KEY-----"
    bearer_token             "Bearer <token>" / "Authorization: Bearer ..."
    api_key                  api_key / x-api-key / apikey assignment
    password                 password / passwd / secret assignment
    github_pat               ghp_, gho_, ghs_, github_pat_
    slack_token              xoxa-/xoxb-/xoxp-/xoxr-/xoxs-...
    stripe_key               sk_live_...
    google_api_key           AIza...
    jwt                      eyJ...eyJ...sig
    email                    real-looking emails (only when --scan-emails)
    ssn                      US Social Security number (xxx-xx-xxxx)
    pii_credit_card_like     Luhn-valid 13-19 digit run

Allowlists (case-insensitive)::

    Default emails:
        fixture@example.com
        alice@example.com
        bob@example.com
        security@example.com

    Domain allowlist for emails: ``example.com``, ``example.org``, ``example.net``,
    ``localhost`` and ``invalid`` (per RFC 2606 / 6761).

    Marker allowlist for any finding: any value containing
    ``FAKE`` / ``FIXTURE`` / ``EXAMPLE`` / ``DUMMY`` / ``REDACTED`` (case-
    insensitive); or a per-line marker like ``# fixture-only`` /
    ``<fixture-only>``.

CLI exit codes::

    0   no findings (or only allowlisted matches)
    1   one or more findings remain after allowlisting
    2   bad arguments
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import re
import sys
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]


# ---------------------------------------------------------------------------
# Default paths and allowlists
# ---------------------------------------------------------------------------

DEFAULT_SCAN_PATHS: tuple[str, ...] = (
    "output",
    "output_tracker",
    "output_agent_run",
    "evidence",
    "reports",
    "web/sample-data",
)

DEFAULT_ALLOWLISTED_EMAILS: frozenset[str] = frozenset(
    {
        "fixture@example.com",
        "alice@example.com",
        "bob@example.com",
        "security@example.com",
    }
)

# Reserved per RFC 2606 / 6761 — safe to use everywhere as fixture data.
ALLOWLISTED_EMAIL_DOMAINS: frozenset[str] = frozenset(
    {"example.com", "example.org", "example.net", "localhost", "invalid"}
)

# Markers that prove a value is a deliberate non-secret. Case-insensitive
# substring match against either the matched value OR the surrounding line.
ALLOWLIST_MARKERS: tuple[str, ...] = (
    "FAKE",
    "FIXTURE",
    "EXAMPLE",
    "DUMMY",
    "REDACTED",
    "PLACEHOLDER",
    "TEST_ONLY",
    "TESTONLY",
)

# Per-line markers that downgrade ANY match on that line to allowlisted.
LINE_MARKER_RE = re.compile(r"#\s*fixture[-_]?only\b|<fixture-only>", re.I)

# Lines that obviously contain only a content hash (md5/sha1/sha256/sha512)
# at the start, optionally followed by whitespace + filename, are not credible
# secrets — they are integrity checksums. We skip the entire line for the
# numeric-only PII categories.
HASH_LINE_RE = re.compile(r"^\s*[0-9a-fA-F]{32,128}(?:\s|$)")

SKIP_SUFFIXES: frozenset[str] = frozenset(
    {
        ".pyc",
        ".so",
        ".dylib",
        ".png",
        ".jpg",
        ".jpeg",
        ".gif",
        ".pdf",
        ".zip",
        ".tar",
        ".gz",
        ".tgz",
        ".bz2",
        ".xz",
        ".whl",
        ".lock",
    }
)
SKIP_DIR_NAMES: frozenset[str] = frozenset({"__pycache__", ".git"})

MAX_FILE_BYTES = 8 * 1024 * 1024


# ---------------------------------------------------------------------------
# Pattern catalog
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SecretPattern:
    """One detection rule."""

    category: str  # short stable id used in JSON output / allowlist keys
    label: str  # human readable
    regex: re.Pattern[str]
    secret_group: int = 0
    severity: str = "high"  # high | medium | low
    requires_opt_in: bool = False


def _C(p: str, *, flags: int = 0) -> re.Pattern[str]:
    return re.compile(p, flags)


PATTERN_CATALOG: tuple[SecretPattern, ...] = (
    SecretPattern(
        "aws_access_key_id",
        "AWS access key id",
        _C(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    SecretPattern(
        "aws_secret_access_key",
        "AWS secret access key (env-style assignment)",
        _C(
            r"(?:aws[_-]?secret[_-]?access[_-]?key|AWS_SECRET_ACCESS_KEY)"
            r"\s*[=:]\s*['\"]?(?P<sec>[A-Za-z0-9/+=]{40})['\"]?",
            flags=re.I,
        ),
        secret_group=1,
    ),
    SecretPattern(
        "aws_session_token",
        "AWS session / security token (env-style assignment)",
        _C(
            r"(?:aws[_-]?session[_-]?token|x-amz-security-token|AWS_SESSION_TOKEN)"
            r"\s*[=:]\s*['\"]?(?P<sec>[A-Za-z0-9/+=]{40,})['\"]?",
            flags=re.I,
        ),
        secret_group=1,
    ),
    SecretPattern(
        "private_key_block",
        "Private key block",
        _C(
            r"-----BEGIN\s+(?:RSA|EC|DSA|OPENSSH|ENCRYPTED|PRIVATE)\s+PRIVATE\s+KEY-----"
        ),
    ),
    SecretPattern(
        "bearer_token",
        "Bearer token (HTTP authorization header)",
        _C(
            r"(?<![\w-])(?:Authorization\s*:\s*)?[Bb]earer\s+(?P<sec>[A-Za-z0-9._~+/=-]{20,})"
        ),
        secret_group=1,
    ),
    SecretPattern(
        "api_key",
        "API key (env-style assignment)",
        _C(
            # Optional prefix (e.g. "x-", "GOOGLE_") then the api-key-like keyword.
            r"(?:(?<=^)|(?<=[\s,;{(\[]))"
            r"(?P<keyname>[A-Za-z0-9_-]{0,30}(?:api[_-]?key|apikey|x-api-key|access[_-]?key|secret[_-]?key))"
            r"\s*[=:]\s*['\"]?(?P<sec>[A-Za-z0-9_\-./+=]{20,})['\"]?",
            flags=re.I,
        ),
        secret_group="sec",
    ),
    SecretPattern(
        "password",
        "Password / secret (env-style assignment)",
        _C(
            r"(?:(?<=^)|(?<=[\s,;{(\[]))"
            r"(?P<keyname>[A-Za-z0-9_-]{0,30}(?:password|passwd|secret))"
            r"\s*[=:]\s*['\"](?P<sec>[^\s'\"]{6,})['\"]",
            flags=re.I,
        ),
        secret_group="sec",
    ),
    SecretPattern(
        "github_pat_classic",
        "GitHub PAT (classic)",
        _C(r"\bghp_[A-Za-z0-9]{36}\b"),
    ),
    SecretPattern(
        "github_pat_fine_grained",
        "GitHub PAT (fine-grained)",
        _C(r"\bgithub_pat_[A-Za-z0-9_]{82,}\b"),
    ),
    SecretPattern(
        "github_oauth",
        "GitHub OAuth token",
        _C(r"\bgho_[A-Za-z0-9]{36}\b"),
    ),
    SecretPattern(
        "github_user_server",
        "GitHub user-server token",
        _C(r"\bghs_[A-Za-z0-9]{36}\b"),
    ),
    SecretPattern(
        "slack_token",
        "Slack token",
        _C(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    SecretPattern(
        "stripe_live_key",
        "Stripe live key",
        _C(r"\bsk_live_[A-Za-z0-9]{24,}\b"),
    ),
    SecretPattern(
        "google_api_key",
        "Google API key",
        _C(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    ),
    SecretPattern(
        "jwt",
        "JWT-shaped token",
        _C(
            r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
        ),
    ),
    SecretPattern(
        "email",
        "Real-looking email address",
        _C(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        severity="medium",
        requires_opt_in=True,  # only fires when --scan-emails is set
    ),
    SecretPattern(
        "ssn",
        "US Social Security number (xxx-xx-xxxx)",
        # Avoid 000-xx-xxxx, 666-xx-xxxx, 9xx-xx-xxxx, and the all-zero areas
        # which the SSA never issues; reduces false positives on dummy IDs.
        _C(r"(?<!\d)(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?!\d)"),
    ),
    SecretPattern(
        "pii_credit_card_like",
        "Possible credit-card number (Luhn-valid, separator-delimited)",
        # Require at least one space or dash between groups so we do not
        # match arbitrary 13-19 digit runs inside hex hashes / IDs.
        _C(
            r"(?<![\w-])"
            r"(?:\d{4}[ -]\d{4}[ -]\d{4}[ -]\d{1,4}|\d{4}[ -]\d{6}[ -]\d{4,5})"
            r"(?![\w-])"
        ),
        severity="medium",
    ),
)


# ---------------------------------------------------------------------------
# Findings + scanning
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    """A single scan hit. The ``preview`` is redacted; ``raw`` is intentionally
    NOT stored so a leaked Finding cannot leak the underlying secret."""

    category: str
    label: str
    severity: str
    file: str  # relative to whatever the caller chose as the base
    line: int
    column: int
    preview: str  # redacted snippet, safe to print and log
    allowlisted: bool = False
    allowlist_reason: str = ""

    def to_dict(self) -> dict[str, object]:
        return dataclasses.asdict(self)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    paths_scanned: list[str] = field(default_factory=list)

    @property
    def reportable(self) -> list[Finding]:
        return [f for f in self.findings if not f.allowlisted]

    @property
    def allowlisted(self) -> list[Finding]:
        return [f for f in self.findings if f.allowlisted]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def redact(value: str, *, keep: int = 4) -> str:
    """Return a safe-to-print redaction of *value*.

    Keeps the first ``keep`` characters when the value is longer than
    ``keep + 3``; otherwise returns ``"***[redacted len=N]"``.
    """
    n = len(value)
    if n <= keep + 3:
        return f"***[redacted len={n}]"
    head = value[:keep]
    return f"{head}***[redacted len={n}]"


def _line_and_column(text: str, offset: int) -> tuple[int, int, str]:
    """Return 1-based (line_no, column, full_line) for ``text[offset]``."""
    line_start = text.rfind("\n", 0, offset) + 1
    line_end = text.find("\n", offset)
    if line_end == -1:
        line_end = len(text)
    line_no = text.count("\n", 0, offset) + 1
    column = offset - line_start + 1
    return line_no, column, text[line_start:line_end]


def _surrounding_context(text: str, offset: int, *, lines: int = 2) -> str:
    """Return ``lines`` lines before + the match line + ``lines`` lines after.

    Used for marker-based allowlisting so that a header comment like
    ``# FAKE — fixture only`` immediately above the assignment also
    counts as a marker for the line that follows.
    """
    if not text:
        return ""
    # Walk back N newlines.
    start = offset
    for _ in range(lines):
        nl = text.rfind("\n", 0, max(0, start - 1))
        if nl < 0:
            start = 0
            break
        start = nl
    # Walk forward N newlines past the line containing offset.
    end = offset
    for _ in range(lines + 1):
        nl = text.find("\n", end)
        if nl < 0:
            end = len(text)
            break
        end = nl + 1
    return text[max(0, start) : end]


def _is_allowlisted_email(value: str, extra_emails: Iterable[str]) -> tuple[bool, str]:
    v = value.lower()
    if v in DEFAULT_ALLOWLISTED_EMAILS or v in {e.lower() for e in extra_emails}:
        return True, "allowlisted email address"
    domain = v.rsplit("@", 1)[-1]
    if domain in ALLOWLISTED_EMAIL_DOMAINS:
        return True, f"allowlisted email domain ({domain})"
    return False, ""


def _has_marker(text: str) -> bool:
    upper = text.upper()
    return any(m in upper for m in ALLOWLIST_MARKERS)


def _luhn_valid(digits: str) -> bool:
    digits = re.sub(r"\D", "", digits)
    if not (13 <= len(digits) <= 19):
        return False
    s = 0
    parity = len(digits) % 2
    for i, ch in enumerate(digits):
        n = int(ch)
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        s += n
    return s % 10 == 0


def _matched_value(match: re.Match[str], pattern: SecretPattern) -> str:
    g = pattern.secret_group
    if isinstance(g, str):
        try:
            return match.group(g)
        except (IndexError, error := IndexError) as _e:  # noqa: F841
            return match.group(0)
    if g and g <= len(match.groups()):
        return match.group(g)
    return match.group(0)


# ---------------------------------------------------------------------------
# Scan core
# ---------------------------------------------------------------------------


def scan_text(
    text: str,
    *,
    file_label: str = "<text>",
    scan_emails: bool = False,
    extra_allowlist_emails: Iterable[str] = (),
) -> list[Finding]:
    """Scan a single in-memory string."""
    findings: list[Finding] = []
    extra_emails = list(extra_allowlist_emails)
    for pattern in PATTERN_CATALOG:
        if pattern.requires_opt_in and not scan_emails:
            continue
        for match in pattern.regex.finditer(text):
            value = _matched_value(match, pattern)
            if not value:
                continue
            # Pattern-specific filters and Luhn.
            if pattern.category == "pii_credit_card_like" and not _luhn_valid(value):
                continue
            line_no, col, line_text = _line_and_column(text, match.start())
            # Hash digests in checksum files are not credible secrets — they
            # are integrity values. Skip purely numeric-style PII matches in
            # such lines so a SHA256 hex run does not masquerade as a CC.
            if pattern.category in ("pii_credit_card_like", "ssn") and HASH_LINE_RE.match(line_text):
                continue
            context = _surrounding_context(text, match.start(), lines=2)
            allowlisted = False
            reason = ""
            # Email allowlist.
            if pattern.category == "email":
                allowlisted, reason = _is_allowlisted_email(value, extra_emails)
            # Marker-based allowlist.
            if not allowlisted:
                if _has_marker(value) or _has_marker(line_text) or _has_marker(context):
                    allowlisted = True
                    reason = "value, line, or nearby context carries explicit FAKE/FIXTURE/EXAMPLE marker"
                elif LINE_MARKER_RE.search(line_text) or LINE_MARKER_RE.search(context):
                    allowlisted = True
                    reason = "line carries explicit fixture-only marker"
            preview = redact(value)
            findings.append(
                Finding(
                    category=pattern.category,
                    label=pattern.label,
                    severity=pattern.severity,
                    file=file_label,
                    line=line_no,
                    column=col,
                    preview=preview,
                    allowlisted=allowlisted,
                    allowlist_reason=reason,
                )
            )
    return findings


def _iter_files(root: Path) -> Iterable[Path]:
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIR_NAMES]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.suffix.lower() in SKIP_SUFFIXES:
                continue
            try:
                size = p.stat().st_size
            except OSError:
                continue
            if size > MAX_FILE_BYTES:
                continue
            yield p


def scan_path(
    path: Path,
    *,
    base: Path | None = None,
    scan_emails: bool = False,
    extra_allowlist_emails: Iterable[str] = (),
) -> list[Finding]:
    """Scan a single file or recurse a directory."""
    findings: list[Finding] = []
    base = base or path
    if path.is_file():
        files: Iterable[Path] = [path]
    elif path.is_dir():
        files = _iter_files(path)
    else:
        return findings
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        try:
            rel = str(f.relative_to(base))
        except ValueError:
            rel = str(f)
        findings.extend(
            scan_text(
                text,
                file_label=rel,
                scan_emails=scan_emails,
                extra_allowlist_emails=extra_allowlist_emails,
            )
        )
    return findings


def scan_paths(
    paths: Sequence[Path],
    *,
    base: Path | None = None,
    scan_emails: bool = False,
    extra_allowlist_emails: Iterable[str] = (),
) -> ScanResult:
    """Top-level entry point used by both the CLI and ``validate_everything``.

    ``base`` controls how relative file paths are reported in findings.
    """
    base = (base or REPO_ROOT).resolve()
    result = ScanResult()
    for raw in paths:
        p = raw.resolve()
        if not p.exists():
            continue
        result.paths_scanned.append(_safe_rel(p, base))
        if p.is_file():
            result.files_scanned += 1
            try:
                result.bytes_scanned += p.stat().st_size
            except OSError:
                pass
            try:
                text = p.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            result.findings.extend(
                scan_text(
                    text,
                    file_label=_safe_rel(p, base),
                    scan_emails=scan_emails,
                    extra_allowlist_emails=extra_allowlist_emails,
                )
            )
        else:
            for f in _iter_files(p):
                result.files_scanned += 1
                try:
                    result.bytes_scanned += f.stat().st_size
                except OSError:
                    pass
                try:
                    text = f.read_text(encoding="utf-8", errors="ignore")
                except Exception:
                    continue
                rel = _safe_rel(f, base)
                result.findings.extend(
                    scan_text(
                        text,
                        file_label=rel,
                        scan_emails=scan_emails,
                        extra_allowlist_emails=extra_allowlist_emails,
                    )
                )
    return result


def _safe_rel(p: Path, base: Path) -> str:
    try:
        return str(p.relative_to(base))
    except ValueError:
        return str(p)


# ---------------------------------------------------------------------------
# Pretty printing
# ---------------------------------------------------------------------------


def format_finding(f: Finding, *, color: bool = False) -> str:
    """One-line, redacted, human-readable finding."""
    bar = "·"
    if color and sys.stdout.isatty():
        red = "\033[31m"
        yellow = "\033[33m"
        reset = "\033[0m"
        sev_color = red if f.severity == "high" else yellow
        sev = f"{sev_color}{f.severity.upper():6}{reset}"
    else:
        sev = f"{f.severity.upper():6}"
    suffix = " [allowlisted: " + f.allowlist_reason + "]" if f.allowlisted else ""
    return f"{sev} {f.file}:{f.line}:{f.column} {bar} {f.category} {bar} {f.preview}{suffix}"


def render_summary_text(result: ScanResult) -> str:
    rep = result.reportable
    al = result.allowlisted
    lines: list[str] = []
    lines.append(
        f"scan_generated_outputs: scanned {result.files_scanned} file(s) "
        f"across {len(result.paths_scanned)} path(s)"
    )
    for p in result.paths_scanned:
        lines.append(f"  - {p}")
    if al:
        lines.append(f"\n{len(al)} allowlisted match(es) (informational):")
        for f in al[:30]:
            lines.append("  " + format_finding(f))
        if len(al) > 30:
            lines.append(f"  ... +{len(al) - 30} more")
    if rep:
        lines.append(f"\n{len(rep)} REPORTABLE finding(s):")
        for f in rep:
            lines.append("  " + format_finding(f, color=True))
    else:
        lines.append("\nNo reportable findings — outputs are clean.")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Scan generated assessment outputs for secrets and high-risk PII.",
    )
    p.add_argument(
        "--paths",
        nargs="+",
        type=Path,
        help=(
            "Paths to scan (files or directories). Defaults to: "
            + ", ".join(DEFAULT_SCAN_PATHS)
        ),
    )
    p.add_argument(
        "--repo-root",
        type=Path,
        default=REPO_ROOT,
        help="Repo root used to resolve default paths and report relative paths.",
    )
    p.add_argument(
        "--scan-emails",
        action="store_true",
        help="Also flag real-looking emails (default: off; emails categorically allowlisted).",
    )
    p.add_argument(
        "--allow-email",
        action="append",
        default=[],
        help="Additional email allowlist entry (may be repeated).",
    )
    p.add_argument(
        "--allowlist-file",
        type=Path,
        help="Optional file with extra allowlisted emails (one per line, '#' comments).",
    )
    p.add_argument("--json", dest="emit_json", action="store_true", help="Emit JSON instead of text.")
    p.add_argument(
        "--quiet",
        action="store_true",
        help="Only print the rollup line + reportable findings (suppress informational).",
    )
    return p.parse_args(argv)


def _load_allowlist_file(path: Path | None) -> list[str]:
    if path is None:
        return []
    out: list[str] = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = raw.split("#", 1)[0].strip()
        if s:
            out.append(s)
    return out


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    repo_root = args.repo_root.resolve()
    paths: list[Path] = (
        list(args.paths)
        if args.paths
        else [repo_root / d for d in DEFAULT_SCAN_PATHS]
    )
    extra_emails = list(args.allow_email) + _load_allowlist_file(args.allowlist_file)

    result = scan_paths(
        paths,
        base=repo_root,
        scan_emails=args.scan_emails,
        extra_allowlist_emails=extra_emails,
    )

    if args.emit_json:
        out = {
            "schema_version": "1.0",
            "tool": "scan_generated_outputs",
            "files_scanned": result.files_scanned,
            "bytes_scanned": result.bytes_scanned,
            "paths_scanned": result.paths_scanned,
            "reportable": [f.to_dict() for f in result.reportable],
            "allowlisted": [f.to_dict() for f in result.allowlisted],
            "ok": not result.reportable,
        }
        json.dump(out, sys.stdout, indent=2)
        sys.stdout.write("\n")
    elif args.quiet:
        rep = result.reportable
        print(
            f"scan_generated_outputs: {result.files_scanned} file(s); "
            f"{len(rep)} reportable, {len(result.allowlisted)} allowlisted"
        )
        for f in rep:
            print("  " + format_finding(f))
    else:
        print(render_summary_text(result))

    return 0 if not result.reportable else 1


if __name__ == "__main__":
    raise SystemExit(main())
