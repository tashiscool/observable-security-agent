"""Config normalization and JSON Schema validation for core YAML."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from fedramp20x.config_normalize import (
    normalize_authorization_scope,
    normalize_system_boundary,
    validate_against_schema,
)

ROOT = Path(__file__).resolve().parents[1]
SCHEMAS = ROOT / "schemas"
CONFIG = ROOT / "config"


def test_repo_system_boundary_passes_schema() -> None:
    raw = yaml.safe_load((CONFIG / "system-boundary.yaml").read_text(encoding="utf-8"))
    merged = normalize_system_boundary(raw)
    assert merged.get("system_id") == raw["system"]["id"]
    assert merged.get("short_name") == raw["system"]["name"]
    validate_against_schema(merged, SCHEMAS / "config-system-boundary.schema.json")


def test_repo_authorization_scope_passes_schema() -> None:
    raw = yaml.safe_load((CONFIG / "authorization-scope.yaml").read_text(encoding="utf-8"))
    merged = normalize_authorization_scope(raw)
    assert merged.get("in_scope_services")
    assert merged.get("out_of_scope")
    validate_against_schema(merged, SCHEMAS / "config-authorization-scope.schema.json")


def test_load_poam_policy_merged_passes_schema() -> None:
    from fedramp20x.poam_builder import load_poam_policy

    pol = load_poam_policy(CONFIG / "poam-policy.yaml")
    validate_against_schema(pol, SCHEMAS / "config-poam-policy.schema.json")


def test_reporting_and_validation_policy_schemas() -> None:
    val = yaml.safe_load((CONFIG / "validation-policy.yaml").read_text(encoding="utf-8"))
    rep = yaml.safe_load((CONFIG / "reporting-policy.yaml").read_text(encoding="utf-8"))
    validate_against_schema(val, SCHEMAS / "config-validation-policy.schema.json")
    validate_against_schema(rep, SCHEMAS / "config-reporting-policy.schema.json")
