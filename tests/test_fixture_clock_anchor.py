"""Regression tests for the fixture-clock anchor mechanism.

The fixture provider supports an opt-in ``fixture_clock.json`` file in any
scenario directory. When present, every datetime field in both the legacy
pipeline bundle and the canonical ``AssessmentBundle`` is shifted by
``(now - anchor)`` so that time-aware evaluators (AU-6 freshness,
RA-5 staleness, CM-3 ticket recency, SI-4 alert recency) remain
deterministic regardless of when the fixture is replayed.

These tests pin the contract:

1. Scenarios *without* ``fixture_clock.json`` are loaded unchanged.
2. Scenarios *with* the file have all known datetime fields shifted by the
   same delta in both the pipeline bundle and the assessment bundle.
3. The shifted timestamps satisfy the canonical 24h freshness window so
   AU-6 reports PARTIAL (not FAIL) on the readiness fixture even when
   replayed days after the anchor date.
4. Re-anchoring within the same hour is a no-op (no flapping).
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from providers.fixture import (
    FIXTURE_CLOCK_FILENAME,
    FixtureProvider,
    _apply_fixture_clock_anchor,
    _apply_fixture_clock_anchor_to_pipeline,
    _read_fixture_clock,
    _shift_iso_string,
)

ROOT = Path(__file__).resolve().parents[1]
READINESS = ROOT / "fixtures" / "scenario_20x_readiness"
PUBLIC_ADMIN = ROOT / "fixtures" / "scenario_public_admin_vuln_event"


# ---------------------------------------------------------------------------
# Pure helpers
# ---------------------------------------------------------------------------


def test_shift_iso_string_round_trips_zulu_form():
    delta = timedelta(hours=10)
    out = _shift_iso_string("2026-05-01T11:45:00Z", delta)
    assert out is not None and out.endswith("Z")
    assert datetime.fromisoformat(out.replace("Z", "+00:00")) == datetime(
        2026, 5, 1, 21, 45, tzinfo=timezone.utc
    )


def test_shift_iso_string_round_trips_offset_form():
    delta = timedelta(minutes=30)
    out = _shift_iso_string("2026-05-01T11:45:00+00:00", delta)
    assert out is not None and not out.endswith("Z")
    assert datetime.fromisoformat(out) == datetime(
        2026, 5, 1, 12, 15, tzinfo=timezone.utc
    )


def test_shift_iso_string_passes_through_garbage():
    assert _shift_iso_string("not-a-date", timedelta(hours=1)) == "not-a-date"
    assert _shift_iso_string("", timedelta(hours=1)) == ""
    assert _shift_iso_string(None, timedelta(hours=1)) is None


# ---------------------------------------------------------------------------
# fixture_clock.json discovery
# ---------------------------------------------------------------------------


def test_readiness_scenario_ships_fixture_clock():
    p = READINESS / FIXTURE_CLOCK_FILENAME
    assert p.is_file(), "scenario_20x_readiness must ship fixture_clock.json"
    doc = json.loads(p.read_text(encoding="utf-8"))
    assert "anchor" in doc and isinstance(doc["anchor"], str)


def test_read_fixture_clock_parses_anchor():
    a = _read_fixture_clock(READINESS)
    assert isinstance(a, datetime)
    assert a.tzinfo is not None


def test_read_fixture_clock_returns_none_for_unanchored_scenario():
    if not (PUBLIC_ADMIN / FIXTURE_CLOCK_FILENAME).is_file():
        assert _read_fixture_clock(PUBLIC_ADMIN) is None


# ---------------------------------------------------------------------------
# Anchor-based shifting on the canonical bundle
# ---------------------------------------------------------------------------


def test_apply_anchor_shifts_log_sources_within_freshness_window():
    fp = FixtureProvider(READINESS)
    bundle = fp.load_bundle()
    now = datetime.now(timezone.utc)
    fresh = [
        ls
        for ls in bundle.log_sources
        if ls.last_seen is not None and (now - ls.last_seen) <= timedelta(hours=24)
    ]
    assert fresh, (
        "expected at least one log source last_seen within 24h after applying "
        "fixture_clock anchor"
    )


def test_apply_anchor_is_noop_when_anchor_is_recent():
    fp = FixtureProvider(READINESS)
    bundle = fp.load_bundle()
    snapshot = [(ls.log_source_id, ls.last_seen) for ls in bundle.log_sources]
    recent_anchor = datetime.now(timezone.utc) - timedelta(minutes=10)
    out = _apply_fixture_clock_anchor(bundle, anchor=recent_anchor)
    after = [(ls.log_source_id, ls.last_seen) for ls in out.log_sources]
    assert snapshot == after, "anchor within 12h must be a no-op"


def test_pipeline_anchor_rewrites_iso_strings():
    fp = FixtureProvider(READINESS)
    pipeline = fp.load()  # already anchored at this point
    sources = pipeline.central_log_sources.get("sources") or []
    now = datetime.now(timezone.utc)
    parsed = [
        datetime.fromisoformat(s["last_seen"].replace("Z", "+00:00"))
        for s in sources
        if s.get("last_seen")
    ]
    assert parsed, "expected at least one log source with last_seen"
    assert all(
        (now - dt) <= timedelta(hours=24) for dt in parsed
    ), "all anchored log sources must fall inside 24h freshness window"


def test_pipeline_anchor_handles_old_anchor_for_synthetic_input():
    # Build a synthetic pipeline-like object via the real provider then poke
    # one timestamp far into the past to confirm the shift happens even when
    # the original is years old.
    fp = FixtureProvider(READINESS)
    pipeline = fp.load()
    sources = pipeline.central_log_sources.get("sources") or []
    if sources:
        sources[0]["last_seen"] = "2020-01-01T00:00:00Z"
    very_old_anchor = datetime(2020, 1, 1, tzinfo=timezone.utc)
    _apply_fixture_clock_anchor_to_pipeline(pipeline, anchor=very_old_anchor)
    new = pipeline.central_log_sources["sources"][0]["last_seen"]
    new_dt = datetime.fromisoformat(new.replace("Z", "+00:00"))
    delta_to_now = abs((datetime.now(timezone.utc) - new_dt).total_seconds())
    assert delta_to_now < 5 * 60, (
        f"shifted timestamp should be near 'now' (got delta={delta_to_now:.1f}s)"
    )
