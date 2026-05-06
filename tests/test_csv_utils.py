from __future__ import annotations

from pathlib import Path

from core.csv_utils import read_csv_dicts


def test_read_csv_dicts_handles_bom_and_semicolon(tmp_path: Path) -> None:
    p = tmp_path / "prowler.csv"
    p.write_text("\ufeffCheckID;Status;Severity\nec2_public;FAIL;high\n", encoding="utf-8")

    result = read_csv_dicts(p)

    assert result.delimiter == ";"
    assert result.headers == ["CheckID", "Status", "Severity"]
    assert result.rows == [{"CheckID": "ec2_public", "Status": "FAIL", "Severity": "high"}]
    assert result.warnings == []


def test_read_csv_dicts_preserves_multiline_cells_and_skips_blank_rows(tmp_path: Path) -> None:
    p = tmp_path / "tracker.csv"
    p.write_text(
        'control,comment\n'
        'CM-8,"line one\nline two"\n'
        ",\n"
        "RA-5,plain\n",
        encoding="utf-8",
    )

    result = read_csv_dicts(p)

    assert len(result.rows) == 2
    assert result.rows[0]["comment"] == "line one\nline two"
    assert result.rows[1]["control"] == "RA-5"


def test_read_csv_dicts_reports_malformed_extra_fields(tmp_path: Path) -> None:
    p = tmp_path / "bad.csv"
    p.write_text("a,b\n1,2,3\n", encoding="utf-8")

    result = read_csv_dicts(p)

    assert result.rows == [{"a": "1", "b": "2"}]
    assert any("extra field" in warning for warning in result.warnings)
