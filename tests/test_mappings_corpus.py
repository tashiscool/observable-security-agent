"""Cross-mapping corpus consistency: KSI catalog, crosswalk CSVs, evidence registry, YAML maps."""

from __future__ import annotations

import csv
import re
from pathlib import Path

import pytest
import yaml

from fedramp20x.crosswalk_normalize import normalize_rev4_rev5_table, normalize_rev5_ksi_table
from fedramp20x.evidence_registry import load_evidence_source_registry
from fedramp20x.ksi_catalog import load_ksi_catalog
from fedramp20x.mappings_corpus import iter_evidence_source_ids_from_ksi_evidence, load_ksi_to_evidence_map

ROOT = Path(__file__).resolve().parents[1]
MAPPINGS = ROOT / "mappings"
CONFIG = ROOT / "config"

# NIST SP 800-53 / FedRAMP style control identifiers (base + enhancements).
_CONTROL_ID_RE = re.compile(
    r"^[A-Z]{2}-\d{1,2}(?:\([0-9a-zA-Z][a-zA-Z0-9(), .-]*\))*$"
)


def _load_csv_rows(path: Path) -> list[dict[str, str]]:
    text = path.read_text(encoding="utf-8")
    return list(csv.DictReader(text.splitlines()))


def test_every_catalog_ksi_appears_in_rev5_crosswalk() -> None:
    cat = load_ksi_catalog(CONFIG / "ksi-catalog.yaml")
    catalog_ksi = {k.ksi_id for k in cat.catalog}
    rows = normalize_rev5_ksi_table(_load_csv_rows(MAPPINGS / "rev5-to-20x-ksi-crosswalk.csv"))
    mapped = {r["ksi_id"] for r in rows}
    missing = catalog_ksi - mapped
    assert not missing, f"KSI ids in catalog but not in rev5 crosswalk: {sorted(missing)}"


def test_secondary_rev5_crosswalk_blank_trace_note_normalized() -> None:
    rows = normalize_rev5_ksi_table(
        [
            {
                "rev5_control": "CM-8",
                "ksi_id": "KSI-CM-01",
                "mapping_type": "secondary",
                "trace_note": "",
            }
        ]
    )

    assert rows[0]["trace_note"] == "Secondary mapping; source row did not provide trace_note."


def test_evidence_sources_in_ksi_map_exist_in_registry() -> None:
    reg = load_evidence_source_registry(CONFIG / "evidence-source-registry.yaml")
    reg_ids = {s.id for s in reg.sources}
    doc = load_ksi_to_evidence_map(MAPPINGS / "fedramp20x-ksi-to-evidence-map.yaml")
    referenced = iter_evidence_source_ids_from_ksi_evidence(doc)
    unknown = referenced - reg_ids
    assert not unknown, f"Evidence source ids in ksi map not in registry: {sorted(unknown)}"


def test_shared_responsibility_lists_reference_registry_ids() -> None:
    reg = load_evidence_source_registry(CONFIG / "evidence-source-registry.yaml")
    reg_ids = {s.id for s in reg.sources}
    raw = yaml.safe_load((MAPPINGS / "shared-responsibility-map.yaml").read_text(encoding="utf-8"))
    assert isinstance(raw, dict)
    cr = raw.get("customer_responsibility")
    assert isinstance(cr, list)
    unknown = {str(x) for x in cr if str(x) not in reg_ids}
    assert not unknown, f"customer_responsibility entries not in registry: {sorted(unknown)}"


@pytest.mark.parametrize(
    "path,normalizer",
    [
        ("rev4-to-rev5-crosswalk.csv", normalize_rev4_rev5_table),
        ("rev5-to-20x-ksi-crosswalk.csv", normalize_rev5_ksi_table),
    ],
)
def test_crosswalk_control_ids_well_formed(path: str, normalizer) -> None:
    rows = normalizer(_load_csv_rows(MAPPINGS / path))
    bad: list[str] = []
    for r in rows:
        if path.startswith("rev4"):
            for k in ("rev4_control_id", "rev5_control_id"):
                cid = r.get(k, "")
                if cid and not _CONTROL_ID_RE.match(cid):
                    bad.append(f"{k}={cid!r}")
        else:
            cid = r.get("rev5_control_id", "")
            if cid and not _CONTROL_ID_RE.match(cid):
                bad.append(f"rev5_control_id={cid!r}")
    assert not bad, "Invalid control ids:\n" + "\n".join(bad[:50])


def test_catalog_legacy_control_ids_well_formed() -> None:
    cat = load_ksi_catalog(CONFIG / "ksi-catalog.yaml")
    bad: list[str] = []
    for k in cat.catalog:
        for fam, label in (("rev4", k.legacy_controls.rev4), ("rev5", k.legacy_controls.rev5)):
            for cid in label:
                if not _CONTROL_ID_RE.match(cid):
                    bad.append(f"{k.ksi_id} {fam} {cid!r}")
    assert not bad, "\n".join(bad)


def test_inherited_responsibility_yaml_shape() -> None:
    raw = yaml.safe_load((MAPPINGS / "inherited-responsibility-map.yaml").read_text(encoding="utf-8"))
    assert raw.get("schema_version") == "1.0"
    services = raw.get("inherited_services")
    assert isinstance(services, list) and len(services) >= 3
    for s in services:
        assert isinstance(s, dict)
        for req in (
            "service_name",
            "responsibility_type",
            "evidence_needed",
            "inherited_authorization_status",
            "customer_responsibility_notes",
        ):
            assert req in s, f"missing {req} in {s.get('service_name')}"
        ev = s["evidence_needed"]
        assert isinstance(ev, list) and ev
        unknown = {x for x in ev if x not in {sid.id for sid in load_evidence_source_registry(CONFIG / "evidence-source-registry.yaml").sources}}
        assert not unknown, f"inherited evidence_needed not in registry: {unknown}"


def test_ksi_evidence_map_has_all_catalog_ksis() -> None:
    cat = load_ksi_catalog(CONFIG / "ksi-catalog.yaml")
    doc = load_ksi_to_evidence_map(MAPPINGS / "fedramp20x-ksi-to-evidence-map.yaml")
    kmap = doc.get("ksi_evidence")
    assert isinstance(kmap, dict)
    for k in cat.catalog:
        assert k.ksi_id in kmap, f"missing ksi_evidence block for {k.ksi_id}"
        block = kmap[k.ksi_id]
        for fld in (
            "required_evidence_sources",
            "optional_evidence_sources",
            "machine_evidence",
            "human_evidence",
            "validation_outputs",
            "report_sections",
        ):
            assert fld in block, f"{k.ksi_id} missing {fld}"


def test_shared_responsibility_has_ksi_splits() -> None:
    raw = yaml.safe_load((MAPPINGS / "shared-responsibility-map.yaml").read_text(encoding="utf-8"))
    kr = raw.get("ksi_responsibility")
    assert isinstance(kr, dict)
    cat = load_ksi_catalog(CONFIG / "ksi-catalog.yaml")
    for k in cat.catalog:
        assert k.ksi_id in kr
        entry = kr[k.ksi_id]
        for key in (
            "cloud_provider_inherited",
            "csp_responsible",
            "customer_agency_responsible",
            "shared",
        ):
            assert key in entry and str(entry[key]).strip(), f"{k.ksi_id} missing {key}"
