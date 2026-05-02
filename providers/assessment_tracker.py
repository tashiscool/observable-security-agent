"""Read-only provider for an importer-generated assessment tracker scenario.

The tracker is the assessor's evidence-request worksheet — not observed cloud state — so
this provider deliberately does **not** implement the full :class:`CloudProviderAdapter`
interface. It exposes:

* :meth:`tracker_items` — every parsed row (machine-readable),
* :meth:`evidence_gaps` — open requests still missing supporting evidence files,
* :meth:`requested_controls` — the union of NIST 800-53 controls referenced,
* :meth:`category_counts` — count of rows per classified category,
* :meth:`auditor_questions_markdown` — assessor follow-up questions text,
* :meth:`fixture_root` — same path; once the user populates the missing evidence files
  (real ``cloud_events.json``, ``discovered_assets.json``, etc.), this directory can be
  consumed by :class:`providers.fixture.FixtureProvider` end-to-end.

If you also passed ``--with-meta-event`` to the importer, ``cloud_events.json`` already
contains a single synthesized ``assessment.tracker_loaded`` event, so the existing
``FixtureProvider`` minimum-bundle gate will load the directory immediately for pipeline
demonstration.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


__all__ = ["AssessmentTrackerProvider", "TrackerLoadError"]


class TrackerLoadError(ValueError):
    """Raised when the tracker scenario directory is missing or malformed."""


@dataclass(frozen=True)
class _Loaded:
    items: list[dict[str, Any]]
    gaps: list[dict[str, Any]]
    auditor_md: str
    raw_items_envelope: dict[str, Any]


class AssessmentTrackerProvider:
    """Loads a directory written by ``normalization.assessment_tracker_import``."""

    REQUIRED_FILES = ("tracker_items.json",)

    def __init__(self, scenario_root: Path | str) -> None:
        self._root = Path(scenario_root).resolve()
        self._loaded: _Loaded | None = None

    @property
    def fixture_root(self) -> Path:
        return self._root

    def provider_name(self) -> str:
        return "assessment_tracker"

    def validate_layout(self) -> None:
        for name in self.REQUIRED_FILES:
            if not (self._root / name).is_file():
                raise TrackerLoadError(
                    f"Tracker scenario at {self._root} is missing required file: {name}. "
                    f"Run `agent.py import-assessment-tracker --input <csv> --output {self._root}` first."
                )

    def _ensure_loaded(self) -> _Loaded:
        if self._loaded is not None:
            return self._loaded
        self.validate_layout()
        items_envelope = self._read_json("tracker_items.json")
        if not isinstance(items_envelope, dict) or "rows" not in items_envelope:
            raise TrackerLoadError(
                f"tracker_items.json at {self._root} is not in the expected envelope shape "
                f"(missing 'rows' key)."
            )
        rows = list(items_envelope.get("rows") or [])
        gaps_envelope = self._read_json_optional("evidence_gaps.json") or {}
        # Schema 2.0 uses `evidence_gaps`; older schema 1.0 used `gaps`. Support both.
        gaps = list(
            gaps_envelope.get("evidence_gaps") or gaps_envelope.get("gaps") or []
        )
        auditor_md_path = self._root / "auditor_questions.md"
        auditor_md = auditor_md_path.read_text(encoding="utf-8") if auditor_md_path.is_file() else ""
        self._loaded = _Loaded(items=rows, gaps=gaps, auditor_md=auditor_md, raw_items_envelope=items_envelope)
        return self._loaded

    def tracker_items(self) -> list[dict[str, Any]]:
        return list(self._ensure_loaded().items)

    def evidence_gaps(self) -> list[dict[str, Any]]:
        return list(self._ensure_loaded().gaps)

    def auditor_questions_markdown(self) -> str:
        return self._ensure_loaded().auditor_md

    def requested_controls(self) -> list[str]:
        seen: set[str] = set()
        out: list[str] = []
        for r in self._ensure_loaded().items:
            for c in r.get("controls") or []:
                if c not in seen:
                    seen.add(c)
                    out.append(c)
        return out

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for r in self._ensure_loaded().items:
            cat = r.get("category") or "other"
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def items_by_category(self, category: str) -> list[dict[str, Any]]:
        return [r for r in self._ensure_loaded().items if (r.get("category") or "other") == category]

    def open_items(self) -> list[dict[str, Any]]:
        out = []
        closed = {"closed", "complete", "completed", "satisfied", "accepted", "resolved", "n/a", "na"}
        for r in self._ensure_loaded().items:
            s = (r.get("status") or "").strip().lower()
            if not s or s not in closed:
                out.append(r)
        return out

    def has_meta_event(self) -> bool:
        env = self._ensure_loaded().raw_items_envelope
        return bool(env.get("with_meta_event"))

    def to_summary_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider_name(),
            "fixture_root": str(self._root),
            "row_count": len(self.tracker_items()),
            "open_count": len(self.open_items()),
            "open_gap_count": len(self.evidence_gaps()),
            "requested_controls": self.requested_controls(),
            "category_counts": self.category_counts(),
            "has_meta_event": self.has_meta_event(),
        }

    def _read_json(self, name: str) -> Any:
        path = self._root / name
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            raise TrackerLoadError(f"Invalid JSON in {path}: {e}") from e

    def _read_json_optional(self, name: str) -> Any | None:
        path = self._root / name
        if not path.is_file():
            return None
        return self._read_json(name)
