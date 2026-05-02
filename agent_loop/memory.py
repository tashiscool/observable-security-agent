"""Workflow memory: per-task input/output store passed between :mod:`agent_loop.actions`.

This is intentionally a small, in-process key/value store rather than a database.
The memory is what makes the workflow auditable — every task records the
declarative inputs it consumed, the outputs it produced, and the artifact paths
it wrote so the trace can be replayed.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


__all__ = ["WorkflowMemory", "_now_iso"]


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class WorkflowMemory:
    """Bounded, in-process memory shared across workflow tasks.

    The memory holds:

    * ``globals`` — workflow-wide configuration (input path, output dir, etc.).
    * ``per_task`` — keyed by ``task_id``; each value is a dict containing
      ``inputs``, ``outputs``, and ``artifacts`` recorded at execution time.

    The memory is SAFE to serialize to JSON and is included in
    ``agent_run_trace.json``. ``Path`` values are coerced to strings on
    write so the trace stays portable.
    """

    workflow_name: str
    started_at: str = field(default_factory=_now_iso)
    globals: dict[str, Any] = field(default_factory=dict)
    per_task: dict[str, dict[str, Any]] = field(default_factory=dict)

    # ---- globals --------------------------------------------------------

    def set_global(self, key: str, value: Any) -> None:
        self.globals[key] = _coerce_value(value)

    def get_global(self, key: str, default: Any = None) -> Any:
        return self.globals.get(key, default)

    # ---- per-task -------------------------------------------------------

    def record_inputs(self, task_id: str, inputs: Mapping[str, Any]) -> None:
        bucket = self.per_task.setdefault(task_id, {})
        bucket["inputs"] = {k: _coerce_value(v) for k, v in inputs.items()}

    def record_outputs(self, task_id: str, outputs: Mapping[str, Any]) -> None:
        bucket = self.per_task.setdefault(task_id, {})
        bucket["outputs"] = {k: _coerce_value(v) for k, v in outputs.items()}

    def record_artifact(self, task_id: str, name: str, path: Path | str) -> None:
        bucket = self.per_task.setdefault(task_id, {})
        artifacts = bucket.setdefault("artifacts", [])
        artifacts.append({"name": name, "path": str(path)})

    def get_outputs(self, task_id: str) -> dict[str, Any]:
        return dict((self.per_task.get(task_id) or {}).get("outputs") or {})

    def get_inputs(self, task_id: str) -> dict[str, Any]:
        return dict((self.per_task.get(task_id) or {}).get("inputs") or {})

    def get_artifacts(self, task_id: str) -> list[dict[str, str]]:
        return list((self.per_task.get(task_id) or {}).get("artifacts") or [])

    # ---- serialization --------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        return {
            "workflow_name": self.workflow_name,
            "started_at": self.started_at,
            "globals": dict(self.globals),
            "per_task": {tid: dict(rec) for tid, rec in self.per_task.items()},
        }


def _coerce_value(value: Any) -> Any:
    """Coerce Path → str (and recurse into containers) so the memory is JSON-safe."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {k: _coerce_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_coerce_value(v) for v in value]
    return value
