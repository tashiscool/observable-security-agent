"""Tests for ``fedramp20x.evidence_links``."""

from __future__ import annotations

import json
from pathlib import Path

from fedramp20x.evidence_links import (
    build_evidence_links,
    collect_artifact_file_specs,
    finalize_evidence_link_tracking,
    prepare_stable_evidence_ref_attachments,
    render_checksums_sha256,
    sha256_file,
    stable_evidence_id,
    validate_evidence_refs_resolve,
    write_package_checksums,
)
from fedramp20x.evidence_registry import EvidenceRegistry, EvidenceSource


def _minimal_registry() -> EvidenceRegistry:
    return EvidenceRegistry(
        sources=[
            EvidenceSource(
                id="src1",
                name="S",
                category="inventory",
                collection_method="api",
                collector="http://x",
                frequency="daily",
                owner="o",
                evidence_format="json",
            )
        ]
    )


def test_checksums_generated(tmp_path: Path) -> None:
    a = tmp_path / "a.txt"
    a.write_text("hello", encoding="utf-8")
    text = render_checksums_sha256([(a, "raw/a.txt")])
    lines = text.strip().split("\n")
    assert len(lines) == 1
    h, _, path = lines[0].partition("  ")
    assert path == "raw/a.txt"
    assert h == sha256_file(a)


def test_stable_evidence_id_is_deterministic() -> None:
    assert stable_evidence_id("raw/eval_results.json") == stable_evidence_id("raw/eval_results.json")
    assert stable_evidence_id("raw/eval_results.json") != stable_evidence_id("raw/other.json")


def test_ksi_evidence_refs_resolve(tmp_path: Path) -> None:
    ao = tmp_path / "assess"
    ao.mkdir()
    ev = ao / "eval_results.json"
    ev.write_text('{"evaluations":[]}', encoding="utf-8")
    pkgd = tmp_path / "evidence" / "package"
    pkgd.mkdir(parents=True)
    pkg = pkgd / "fedramp20x-package.json"
    pkg.write_text("{}", encoding="utf-8")
    po = tmp_path / "evidence" / "package"
    graph = ao / "evidence_graph.json"
    graph.write_text("{}", encoding="utf-8")

    er = tmp_path
    ksi = [{"ksi_id": "K1", "status": "PASS", "summary": "s", "evidence_refs": []}]
    findings: list[dict] = []
    package = {"ksi_validation_results": ksi, "findings": findings}

    prepare_stable_evidence_ref_attachments(
        evidence_root=er,
        assessment_output=ao,
        pkg_path=pkg,
        package=package,
        ksi_results=ksi,
        findings=findings,
    )
    eid = stable_evidence_id("raw/eval_results.json")
    assert ksi[0]["evidence_refs"][0]["evidence_id"] == eid

    specs = collect_artifact_file_specs(
        evidence_root=er, assessment_output=ao, package_output=po, graph_path=graph
    )
    links = build_evidence_links(
        file_specs=specs, evidence_registry=_minimal_registry(), ksi_results=ksi, findings=findings
    )
    assert validate_evidence_refs_resolve(ksi_results=ksi, findings=findings, links=links) == []


def test_missing_required_artifact_strict_failure(tmp_path: Path) -> None:
    ao = tmp_path / "assess"
    ao.mkdir()
    (ao / "eval_results.json").write_text("{}", encoding="utf-8")
    pkgd = tmp_path / "evidence" / "package"
    pkgd.mkdir(parents=True)
    pkg = pkgd / "fedramp20x-package.json"
    pkg.write_text("{}", encoding="utf-8")
    po = tmp_path / "evidence" / "package"
    graph = ao / "evidence_graph.json"
    graph.write_text("{}", encoding="utf-8")

    ksi = [{"ksi_id": "K1", "status": "PASS", "summary": "s", "evidence_refs": []}]
    findings: list[dict] = []
    package: dict = {"ksi_validation_results": ksi, "findings": findings}
    policy = {
        "strict_evidence_links": True,
        "evidence_artifacts": {"required_raw_paths": ["raw/does-not-exist.json"]},
    }
    _warn, errs = finalize_evidence_link_tracking(
        evidence_root=tmp_path,
        assessment_output=ao,
        package_output=po,
        graph_path=graph,
        pkg_path=pkg,
        package=package,
        ksi_results=ksi,
        findings=findings,
        evidence_registry=_minimal_registry(),
        validation_policy=policy,
        mirror_roots=(),
    )
    assert errs
    assert any("does-not-exist" in e for e in errs)


def test_write_package_checksums_includes_evidence_links(tmp_path: Path) -> None:
    el = tmp_path / "evidence" / "validation-results" / "evidence-links.json"
    el.parent.mkdir(parents=True, exist_ok=True)
    el.write_text('{"evidence_links":[]}', encoding="utf-8")
    a = tmp_path / "a.bin"
    a.write_bytes(b"x")
    ck = write_package_checksums(
        evidence_root=tmp_path,
        file_specs=[(a, "raw/a.bin")],
        evidence_links_path=el,
    )
    body = ck.read_text(encoding="utf-8")
    assert "raw/a.bin" in body
    assert "evidence/validation-results/evidence-links.json" in body
