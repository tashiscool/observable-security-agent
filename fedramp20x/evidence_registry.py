"""Evidence source registry: typed models, validation, and YAML loader."""

from __future__ import annotations

from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

EvidenceCategory = Literal[
    "identity",
    "logging",
    "vulnerability_management",
    "change_management",
    "inventory",
    "incident_response",
    "recovery",
    "supply_chain",
    "training",
    "configuration",
    "network",
]
CollectionMethod = Literal["api", "file", "manual", "hybrid"]
Frequency = Literal[
    "continuous",
    "daily",
    "weekly",
    "monthly",
    "quarterly",
    "annual",
    "event_driven",
    "manual",
]
EvidenceFormat = Literal["json", "csv", "yaml", "markdown", "pdf", "screenshot", "mixed"]


class EvidenceRegistryLoadError(ValueError):
    """Raised when the evidence source registry is missing, invalid YAML, or fails validation."""

    def __init__(self, message: str, *, path: Path | None = None, cause: Exception | None = None) -> None:
        self.path = path
        self.__cause__ = cause
        loc = f" ({path})" if path else ""
        super().__init__(f"{message}{loc}")


class EvidenceSource(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    id: str = Field(..., min_length=1)
    name: str = Field(..., min_length=1)
    category: EvidenceCategory
    collection_method: CollectionMethod
    collector: str | None = None
    frequency: Frequency
    owner: str = Field(..., min_length=1)
    evidence_format: EvidenceFormat
    authoritative_for: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    automation_score: int = Field(default=0, ge=0, le=5)
    # Optional Nisify-aligned hint: how this source is usually collected (not used in scoring logic).
    typical_channel: str | None = Field(
        default=None,
        description=(
            "Optional lifecycle hint, e.g. saas_api_readonly | periodic_file_export | "
            "manual_governance_attestation — for registry documentation only."
        ),
    )

    @model_validator(mode="after")
    def _api_or_hybrid_needs_collector_or_limitation(self) -> EvidenceSource:
        if self.collection_method in ("api", "hybrid"):
            has_collector = bool((self.collector or "").strip())
            has_lim = bool(self.limitations)
            if not has_collector and not has_lim:
                raise ValueError(
                    f"Evidence source {self.id!r}: collection_method is {self.collection_method!r} "
                    "but neither collector nor limitations are provided (at least one is required)."
                )
        return self


class EvidenceRegistry(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    schema_version: str = Field(default="1.0")
    sources: list[EvidenceSource] = Field(default_factory=list)

    @model_validator(mode="after")
    def _unique_ids_and_required_fields(self) -> EvidenceRegistry:
        seen: set[str] = set()
        for s in self.sources:
            if s.id in seen:
                raise ValueError(f"Duplicate evidence source id: {s.id!r}")
            seen.add(s.id)
            if not (s.owner or "").strip():
                raise ValueError(f"Evidence source {s.id!r} must have a non-empty owner")
        return self


def load_evidence_source_registry(path: Path) -> EvidenceRegistry:
    """
    Load and validate ``evidence-source-registry.yaml``.

    :raises EvidenceRegistryLoadError: on missing file, YAML errors, or validation failure.
    """
    if not path.is_file():
        raise EvidenceRegistryLoadError("Evidence source registry file not found", path=path)
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as e:
        raise EvidenceRegistryLoadError("Invalid YAML in evidence source registry", path=path, cause=e) from e
    if raw is None:
        raise EvidenceRegistryLoadError("Evidence source registry is empty or null", path=path)
    if not isinstance(raw, dict):
        raise EvidenceRegistryLoadError("Evidence source registry root must be a mapping", path=path)
    try:
        return EvidenceRegistry.model_validate(raw)
    except Exception as e:
        raise EvidenceRegistryLoadError(
            f"Evidence source registry validation failed: {e}", path=path, cause=e
        ) from e


def evidence_registry_to_package_dict(registry: EvidenceRegistry) -> dict:
    """Serialize registry for ``fedramp20x-package.json`` (JSON-safe)."""
    return registry.model_dump(mode="json")
