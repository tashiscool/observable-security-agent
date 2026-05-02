"""Reference-sample-backed regression tests (fixtures under ``tests/fixtures/`` only)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from jsonschema import validate

from core.evidence_graph import evidence_graph_dict_to_cypher
from core.models import ScannerFinding
from normalization.ocsf_export import read_semantic_type_from_ocsf_like_export, security_event_to_ocsf_like_export
from providers.auditkit import validate_auditkit_inspired_evidence_shape
from providers.electriceye import import_electriceye
from providers.ocsf import import_ocsf
from providers.prowler import import_prowler, iter_prowler_records

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "tests" / "fixtures"


def test_prowler_representative_fixture_imports_scanner_finding() -> None:
    path = FIX / "prowler" / "prowler_sample_results.json"
    findings, events = import_prowler(path)
    assert len(findings) == 1
    assert isinstance(findings[0], ScannerFinding)
    assert findings[0].scanner_name == "prowler"
    assert findings[0].metadata.get("prowler_check_id") == "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
    assert any(e.semantic_type == "network.public_admin_port_opened" for e in events)
    schema = json.loads((ROOT / "schemas" / "scanner-finding.schema.json").read_text(encoding="utf-8"))
    validate(instance=findings[0].model_dump(mode="json"), schema=schema)


def test_ocsf_representative_fixture_imports_scanner_finding() -> None:
    path = FIX / "ocsf" / "sample_detection.json"
    findings, events = import_ocsf(path)
    assert len(findings) == 1
    assert isinstance(findings[0], ScannerFinding)
    assert findings[0].scanner_name == "ocsf"
    assert "SSH" in findings[0].title or "ssh" in findings[0].title.lower()
    assert len(events) == 1
    schema = json.loads((ROOT / "schemas" / "scanner-finding.schema.json").read_text(encoding="utf-8"))
    validate(instance=findings[0].model_dump(mode="json"), schema=schema)


def test_ocsf_like_export_preserves_semantic_event_type() -> None:
    path = FIX / "ocsf" / "sample_detection.json"
    _, events = import_ocsf(path)
    sem = events[0].semantic_type
    exported = security_event_to_ocsf_like_export(events[0])
    assert read_semantic_type_from_ocsf_like_export(exported) == sem
    assert exported.get("class_uid") == 2004


def test_cartography_inspired_graph_cypher_represents_account_to_poam_chain() -> None:
    path = FIX / "cartography" / "account_asset_finding_eval_poam.graph.json"
    graph = json.loads(path.read_text(encoding="utf-8"))
    cy = evidence_graph_dict_to_cypher(graph)
    assert "HAS_FINDING" in cy
    assert "TRACKED_BY_POAM" in cy
    assert "BELONGS_TO_ACCOUNT" in cy
    assert "cloud_account::aws:111122223333" in cy
    assert "scanner_finding::finding-carto-1" in cy
    assert "evaluation::eval-ksi-1" in cy


def test_auditkit_inspired_package_fixture_validates() -> None:
    path = FIX / "auditkit" / "minimal_inspired_nested_package.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    assert validate_auditkit_inspired_evidence_shape(doc) == []


def test_auditkit_shape_flags_incomplete_docs() -> None:
    assert validate_auditkit_inspired_evidence_shape({}) != []


def test_electriceye_style_fixture_maps_via_public_exposure_policy() -> None:
    path = FIX / "electriceye" / "sample_failed_checks.json"
    findings, events = import_electriceye(path)
    assert findings[0].scanner_name == "electriceye"
    assert findings[0].metadata.get("public_exposure_policy_semantic_hint") == "network.public_admin_port_opened"
    assert events and events[0].semantic_type == "network.public_admin_port_opened"


def test_reference_prowler_generic_compliance_fixture_rejected() -> None:
    p = ROOT / "reference_samples" / "prowler" / "outputs" / "generic_compliance_fixture.json"
    with pytest.raises(ValueError, match="compliance framework"):
        iter_prowler_records(p)


def test_reference_prowler_check_metadata_not_scan_rows() -> None:
    p = ROOT / "reference_samples" / "prowler" / "checks" / "aws_iam_user_accesskey_unused.metadata.json"
    with pytest.raises(ValueError, match="check metadata"):
        iter_prowler_records(p)


def test_reference_prowler_output_metadata_template_rejected() -> None:
    p = ROOT / "reference_samples" / "prowler" / "schemas" / "output_metadata_fixture.json"
    with pytest.raises(ValueError, match="check metadata"):
        iter_prowler_records(p)


def test_prowler_wrapped_results_object(tmp_path: Path) -> None:
    doc = {
        "results": [
            {
                "CheckID": "x",
                "CheckTitle": "t",
                "Status": "PASS",
                "ResourceId": "arn:aws:s3:::bucket-a",
            }
        ]
    }
    p = tmp_path / "prowler_wrapped.json"
    p.write_text(json.dumps(doc), encoding="utf-8")
    rows = iter_prowler_records(p)
    assert len(rows) == 1
