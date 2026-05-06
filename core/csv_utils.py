"""Dialect-aware CSV helpers for evidence imports.

The agent consumes CSVs from hand-authored fixtures, assessment trackers, AWS
credential exports, and scanner tools. Real exports are not always comma-only:
Prowler examples may be semicolon-delimited, spreadsheets may include BOMs and
blank rows, and tracker comments often contain quoted newlines. Keep those
rules in one place so evidence loaders do not quietly drop columns.
"""

from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class CsvReadResult:
    rows: list[dict[str, Any]]
    headers: list[str]
    delimiter: str
    warnings: list[str] = field(default_factory=list)


def _detect_dialect(text: str) -> csv.Dialect:
    sample = text[:8192]
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        class _Default(csv.Dialect):
            delimiter = ","
            quotechar = '"'
            escapechar = None
            doublequote = True
            skipinitialspace = True
            lineterminator = "\n"
            quoting = csv.QUOTE_MINIMAL
            strict = False

        return _Default()


def read_csv_dicts(path: Path, *, skip_blank_rows: bool = True) -> CsvReadResult:
    """Read a CSV-like file into dictionaries with dialect detection.

    Returns rows plus non-fatal warnings. The function does not raise for row
    width drift because operators need diagnostics on imperfect exports; callers
    that require strictness can fail on ``warnings``.
    """
    text = path.read_text(encoding="utf-8-sig")
    if not text.strip():
        return CsvReadResult(rows=[], headers=[], delimiter=",")

    dialect = _detect_dialect(text)
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    headers = [str(h or "").strip() for h in (reader.fieldnames or [])]
    rows: list[dict[str, Any]] = []
    warnings: list[str] = []

    for line_no, row in enumerate(reader, start=2):
        if row is None:
            continue
        extras = row.pop(None, None)
        normalized = {str(k or "").replace("\ufeff", "").strip(): (v if v is not None else "") for k, v in row.items()}
        if skip_blank_rows and not any(str(v or "").strip() for v in normalized.values()):
            continue
        if extras:
            warnings.append(f"{path}: row {line_no} has {len(extras)} extra field(s)")
        if len(normalized) < len(headers):
            warnings.append(f"{path}: row {line_no} has fewer fields than header")
        rows.append(normalized)

    return CsvReadResult(rows=rows, headers=headers, delimiter=str(getattr(dialect, "delimiter", ",")), warnings=warnings)


def load_csv_rows(path: Path) -> list[dict[str, Any]]:
    """Compatibility wrapper for callers that only need row dictionaries."""
    return read_csv_dicts(path).rows
