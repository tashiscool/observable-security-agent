from __future__ import annotations

from pathlib import Path

from core.evidence_graph import evidence_graph_from_assessment_bundle
from core.models import Asset, AssessmentBundle, DeclaredInventoryRecord
from core.normalizer import normalize_cloud_event
from core.utils import build_asset_evidence, load_evidence_bundle_from_directory
from evals.inventory_coverage import eval_cm8_inventory_reconciliation, eval_inventory_coverage


def _decl(**kw: object) -> DeclaredInventoryRecord:
    base = dict(
        inventory_id="inv-1",
        name="n1",
        asset_type="compute",
        in_boundary=True,
        scanner_required=True,
        log_required=True,
    )
    base.update(kw)
    return DeclaredInventoryRecord(**base)  # type: ignore[arg-type]


def _asset(**kw: object) -> Asset:
    base = dict(
        asset_id="a1",
        provider="aws",
        asset_type="compute",
        name="n1",
        criticality="moderate",
        environment="dev",
    )
    base.update(kw)
    return Asset(**base)  # type: ignore[arg-type]


def _minimal_bundle(tmp_path: Path):
    inv = tmp_path / "declared_inventory.csv"
    inv.write_text("asset_id,env\na1,prod\n", encoding="utf-8")
    disc = tmp_path / "discovered_assets.json"
    disc.write_text('{"assets":[{"asset_id":"a1"}]}', encoding="utf-8")
    ev = tmp_path / "cloud_events.json"
    ev.write_text('[{"_format":"aws_cloudtrail","_asset_id":"a1","detail":{"eventName":"AuthorizeSecurityGroupIngress","eventTime":"2026-01-01T00:00:00Z","userIdentity":{"userName":"u"},"requestParameters":{"groupId":"sg-1","ipPermissions":{"items":[{"fromPort":22,"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]}}]}}}}]', encoding="utf-8")

    return load_evidence_bundle_from_directory(tmp_path)


def test_cm8_fail_when_in_boundary_declared_has_no_discovered_asset() -> None:
    inv = _decl(inventory_id="inv-prod-api", name="prod-api-01", asset_id="prod-api-01")
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_cm8_inventory_reconciliation(bundle, graph)
    assert r.result == "FAIL"
    assert any("no matching discovered cloud asset" in g for g in r.gaps)


def test_cm8_partial_on_duplicate_inventory_names() -> None:
    inv1 = _decl(inventory_id="inv-a", name="shared-name", asset_id="asset-a")
    inv2 = _decl(inventory_id="inv-b", name="shared-name", asset_id="asset-b")
    a1 = _asset(asset_id="asset-a", name="asset-a", environment="dev")
    a2 = _asset(asset_id="asset-b", name="asset-b", environment="dev")
    bundle = AssessmentBundle(declared_inventory=[inv1, inv2], assets=[a1, a2])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_cm8_inventory_reconciliation(bundle, graph)
    assert r.result == "PARTIAL"
    assert any("Duplicate declared inventory names" in g for g in r.gaps)


def test_cm8_pass_when_declared_matches_discovered() -> None:
    inv = _decl(inventory_id="inv-1", name="api", asset_id="api")
    ast = _asset(asset_id="api", name="api", environment="dev")
    bundle = AssessmentBundle(declared_inventory=[inv], assets=[ast])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_cm8_inventory_reconciliation(bundle, graph)
    assert r.result == "PASS"


def test_cm8_rogue_prod_evidence_string() -> None:
    rogue = _asset(asset_id="rogue-prod-worker-99", name="rogue", environment="prod")
    bundle = AssessmentBundle(declared_inventory=[], assets=[rogue])
    graph = evidence_graph_from_assessment_bundle(bundle)
    r = eval_cm8_inventory_reconciliation(bundle, graph)
    assert r.result == "FAIL"
    assert any("Discovered asset rogue-prod-worker-99 is not present in declared inventory." in e for e in r.evidence)


def test_inventory_pass_when_declared_and_discovered(tmp_path: Path) -> None:
    b = _minimal_bundle(tmp_path)
    sem = normalize_cloud_event(
        {
            "_format": "aws_cloudtrail",
            "_asset_id": "a1",
            "detail": {
                "eventName": "AuthorizeSecurityGroupIngress",
                "eventTime": "2026-01-01T00:00:00Z",
                "userIdentity": {"userName": "u"},
                "requestParameters": {
                    "groupId": "sg-1",
                    "ipPermissions": {
                        "items": [
                            {
                                "fromPort": 22,
                                "ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]},
                            }
                        ]
                    },
                },
            },
        },
        "ref",
    )
    ae = build_asset_evidence(b, "a1")
    r = eval_inventory_coverage(b, sem, ae)
    assert r.result.value == "PASS"
