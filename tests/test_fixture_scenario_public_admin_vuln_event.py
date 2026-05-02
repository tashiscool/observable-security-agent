"""Loader and content checks for `fixtures/scenario_public_admin_vuln_event/`."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.normalizer import load_normalized_primary_event
from core.pipeline_models import PipelineSemanticEvent as SemanticEvent
from core.utils import (
    build_asset_evidence,
    discovered_ids,
    inventory_ids,
    load_evidence_bundle_from_directory,
    scanner_target_ids,
    validate_evidence_bundle_minimum,
)
from providers.fixture import FixtureProvider


@pytest.fixture
def scenario_root() -> Path:
    return Path(__file__).resolve().parents[1] / "fixtures" / "scenario_public_admin_vuln_event"


def test_fixture_provider_validates_and_loads(scenario_root: Path) -> None:
    p = FixtureProvider(scenario_root)
    p.validate_layout()
    bundle = p.load()
    validate_evidence_bundle_minimum(bundle)
    assert bundle.source_root == scenario_root.resolve()


def test_declared_inventory_story_rows(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    rows = bundle.declared_inventory_rows
    asset_ids = {r["asset_id"] for r in rows if r.get("asset_id")}
    assert "prod-api-01" in asset_ids
    assert "prod-db-01" in asset_ids
    assert "prod-lb-01" in asset_ids
    assert "prod-storage-01" in asset_ids
    assert "prod-api-standby-02" in asset_ids
    # Stale / duplicate-name narrative: two rows reference prod-api-01 (primary + stale CMDB)
    prod_api_rows = [r for r in rows if r.get("asset_id") == "prod-api-01"]
    assert len(prod_api_rows) >= 2
    ips = {r.get("expected_private_ip") for r in prod_api_rows}
    assert "10.0.1.50" in ips
    assert "10.254.0.99" in ips


def test_discovered_includes_rogue_not_in_declared_inventory_ids(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    disc = discovered_ids(bundle)
    inv = inventory_ids(bundle)
    assert "prod-api-01" in disc
    assert "rogue-prod-worker-99" in disc
    assert "rogue-prod-worker-99" not in inv


def test_prod_api_01_missing_from_scanner_targets(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    targets = scanner_target_ids(bundle)
    assert "prod-db-01" in targets
    assert "prod-lb-01" in targets
    assert "prod-storage-01" in targets
    assert "prod-api-01" not in targets


def test_primary_event_is_public_admin_on_prod_api_01(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    sem, raw = load_normalized_primary_event(bundle)
    assert isinstance(sem, SemanticEvent)
    assert sem.event_type == "network.public_admin_port_opened"
    assert sem.asset_id == "prod-api-01"
    assert sem.provider == "aws"
    assert "alice" in (sem.actor or "").lower()
    assert sem.port == 22
    assert sem.source_cidr == "0.0.0.0/0"
    assert len(raw) >= 7
    assert raw[0].get("_primary") is True


def test_cloud_events_include_supporting_provider_samples(scenario_root: Path) -> None:
    path = scenario_root / "cloud_events.json"
    events = json.loads(path.read_text(encoding="utf-8"))
    names = []
    for e in events:
        if "detail" in e and isinstance(e["detail"], dict):
            names.append(e["detail"].get("eventName"))
        if e.get("event_type"):
            names.append(e.get("event_type"))
    flat = [n for n in names if n]
    assert "AuthorizeSecurityGroupIngress" in flat
    assert "AttachUserPolicy" in flat
    assert "RunInstances" in flat
    assert "StopLogging" in flat
    assert "identity.admin_role_granted" in flat
    assert "logging.audit_disabled" in flat
    assert "compute.untracked_asset_created" in flat


def test_central_logs_stale_for_prod_api_01(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    ae = build_asset_evidence(bundle, "prod-api-01")
    assert ae.central_log_seen_last_24h is False
    ae_db = build_asset_evidence(bundle, "prod-db-01")
    assert ae_db.central_log_seen_last_24h is True


def test_scanner_findings_high_open_without_exploitation_review(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    findings = bundle.scanner_findings.get("findings", [])
    api_high = next(f for f in findings if f.get("asset_id") == "prod-api-01" and f.get("severity") == "high")
    assert api_high.get("status") == "open"
    assert not (api_high.get("exploitation_review") or {}).get("log_review_performed")
    db_med = next(f for f in findings if f.get("asset_id") == "prod-db-01")
    assert db_med.get("severity") == "medium"
    lb = next(f for f in findings if f.get("asset_id") == "prod-lb-01")
    assert lb.get("status") == "closed"


def test_poam_seed_excludes_correlated_issue(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    seeds = bundle.poam_seed_rows
    assert len(seeds) >= 1
    # No POA&M row yet for the prod-api-01 SG / High-finding correlated storyline
    for row in seeds:
        aid = (row.get("asset_identifier") or "").lower()
        wn = (row.get("weakness_name") or "").lower()
        assert not (aid == "prod-api-01" and ("ssh" in wn or "security group" in wn or "ingress" in wn))
    assert any("poam-2025" in str(r.get("poam_id", "")).lower() for r in seeds)


def test_alert_rules_no_enabled_public_admin_rule(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    rules = bundle.alert_rules.get("rules", [])
    pub = [r for r in rules if r.get("matches_event_type") == "network.public_admin_port_opened"]
    assert len(pub) == 1
    assert pub[0].get("enabled") is False
    id_admin = [r for r in rules if "identity.admin_role_granted" in (r.get("event_types") or [])]
    assert any(r.get("enabled") for r in id_admin)


def test_tickets_no_link_to_primary_sg_event(scenario_root: Path) -> None:
    bundle = load_evidence_bundle_from_directory(scenario_root)
    sem, _ = load_normalized_primary_event(bundle)
    ref = sem.raw_event_ref
    tix = bundle.tickets.get("tickets", [])
    linked = [t for t in tix if t.get("links_event_ref") == ref or t.get("links_asset_id") == sem.asset_id]
    assert linked == []
