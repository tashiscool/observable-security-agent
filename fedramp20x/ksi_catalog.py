"""YAML-based KSI catalog: Pydantic models and strict loaders."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

ValidationMode = Literal["automated", "manual", "hybrid"]
ValidationType = Literal["automated", "manual", "hybrid"]
SeverityIfFailed = Literal["critical", "high", "medium", "low"]


class KsiCatalogLoadError(ValueError):
    """Raised when the KSI catalog file is missing, invalid YAML, or fails validation."""

    def __init__(self, message: str, *, path: Path | None = None, cause: Exception | None = None) -> None:
        self.path = path
        self.__cause__ = cause
        loc = f" ({path})" if path else ""
        super().__init__(f"{message}{loc}")


class LegacyControls(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    rev4: list[str] = Field(default_factory=list)
    rev5: list[str] = Field(default_factory=list)


class ReportingSections(BaseModel):
    model_config = ConfigDict(extra="forbid")

    assessor: str | None = None
    executive: str | None = None
    ao: str | None = None


class Criterion(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    criteria_id: str = Field(..., min_length=1)
    description: str = Field(..., min_length=1)
    validation_type: ValidationType
    expected_result: str | None = None
    severity_if_failed: SeverityIfFailed
    eval_refs: list[str] = Field(default_factory=list)
    evidence_required: list[str] = Field(default_factory=list)


class Ksi(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    ksi_id: str = Field(..., min_length=1)
    theme: str = Field(..., min_length=1)
    title: str = Field(..., min_length=1)
    objective: str = Field(..., min_length=1)
    legacy_controls: LegacyControls
    validation_mode: ValidationMode
    automation_target: bool
    evidence_sources: list[str] = Field(default_factory=list)
    pass_fail_criteria: list[Criterion] = Field(default_factory=list)
    reporting_sections: ReportingSections | None = None

    @model_validator(mode="after")
    def _criteria_non_empty(self) -> Ksi:
        if not self.pass_fail_criteria:
            raise ValueError(f"KSI {self.ksi_id!r} must define at least one pass_fail_criterion")
        return self

    @model_validator(mode="after")
    def _legacy_non_empty(self) -> Ksi:
        lc = self.legacy_controls
        if not lc.rev4 and not lc.rev5:
            raise ValueError(f"KSI {self.ksi_id!r} must map to at least one legacy rev4 or rev5 control")
        return self


class KsiCatalog(BaseModel):
    """Root document for ``config/ksi-catalog.yaml``."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: str = Field(default="1.0")
    catalog_version: str = Field(default="1.0.0", min_length=1)
    catalog: list[Ksi] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ksi_ids(self) -> KsiCatalog:
        seen: set[str] = set()
        for k in self.catalog:
            if k.ksi_id in seen:
                raise ValueError(f"Duplicate ksi_id: {k.ksi_id!r}")
            seen.add(k.ksi_id)
        return self


def load_ksi_catalog(path: Path) -> KsiCatalog:
    """
    Load and validate ``ksi-catalog.yaml``.

    :raises KsiCatalogLoadError: on missing file, YAML errors, or validation failure.
    """
    if not path.is_file():
        raise KsiCatalogLoadError("KSI catalog file not found", path=path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise KsiCatalogLoadError("Invalid YAML in KSI catalog", path=path, cause=e) from e
    if raw is None:
        raise KsiCatalogLoadError("KSI catalog is empty or null", path=path)
    if not isinstance(raw, dict):
        raise KsiCatalogLoadError("KSI catalog root must be a mapping", path=path)
    try:
        return KsiCatalog.model_validate(raw)
    except Exception as e:
        raise KsiCatalogLoadError(f"KSI catalog validation failed: {e}", path=path, cause=e) from e


def ksi_catalog_to_package_payload(catalog: KsiCatalog) -> list[dict[str, Any]]:
    """Serialize catalog entries for ``fedramp20x-package.json`` (JSON-safe dicts)."""
    return [k.model_dump(mode="json") for k in catalog.catalog]
