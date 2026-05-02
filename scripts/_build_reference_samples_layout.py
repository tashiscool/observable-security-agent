#!/usr/bin/env python3
"""One-off helper: populate reference_samples layout from local reference/ clones.

Not imported by runtime. Run from repo root:
  python scripts/_build_reference_samples_layout.py
"""

from __future__ import annotations

import json
import re
import shutil
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REF = ROOT / "reference"
RS = ROOT / "reference_samples"


def head_text(src: Path, n: int) -> str:
    lines = src.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    return "".join(lines[:n])


def write_head(dest: Path, src: Path, n: int) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(head_text(src, n), encoding="utf-8")


@dataclass(frozen=True)
class CopySpec:
    """Manifest row fields for one copied file."""

    source_project: str
    source_repo_url: str
    source_license: str
    original_path: str
    copied_path: str
    category: str
    reason_copied: str
    how_we_use_it: str
    direct_code_reuse_allowed: str
    notes: str


def main() -> None:
    rows: list[CopySpec] = []

    def cp_license(
        slug: str,
        project: str,
        url: str,
        lic: str,
        ref_file: str,
    ) -> None:
        src = REF / ref_file
        if not src.is_file():
            return
        dest = RS / "licenses" / f"{slug}.LICENSE"
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        rel = dest.relative_to(ROOT).as_posix()
        rows.append(
            CopySpec(
                source_project=project,
                source_repo_url=url,
                source_license=lic,
                original_path=ref_file,
                copied_path=rel,
                category="license",
                reason_copied="Upstream license text for attribution and redistribution compliance.",
                how_we_use_it="Legal reference only; informs NOTICE and third-party attribution if we ship excerpts.",
                direct_code_reuse_allowed="false",
                notes="Copied verbatim from local reference/ shallow clone.",
            )
        )

    # --- New license files ---
    cp_license(
        "cloudsploit",
        "cloudsploit",
        "https://github.com/aquasecurity/cloudsploit",
        "GPL-3.0",
        "cloudsploit/LICENSE",
    )
    cp_license(
        "cloudgraph-cli",
        "cloudgraph-cli",
        "https://github.com/cloudgraphdev/cli",
        "MPL-2.0",
        "cloudgraph-cli/LICENSE",
    )
    cp_license(
        "fixinventory",
        "fixinventory",
        "https://github.com/someengineering/fixinventory",
        "Apache-2.0",
        "fixinventory/LICENSE",
    )
    cp_license(
        "aurelian",
        "aurelian",
        "https://github.com/praetorian-inc/aurelian",
        "Apache-2.0",
        "aurelian/LICENSE",
    )
    cp_license(
        "nisify",
        "nisify",
        "https://github.com/clay-good/nisify",
        "MIT",
        "nisify/LICENSE",
    )
    cp_license(
        "FedRAMP20xMCP",
        "FedRAMP20xMCP",
        "https://github.com/KevinRabun/FedRAMP20xMCP",
        "MIT",
        "FedRAMP20xMCP/LICENSE",
    )

    # --- cloudsploit ---
    cs_plugin_src = REF / "cloudsploit/plugins/aws/ec2/publicIpAddress.js"
    if cs_plugin_src.is_file():
        dst = RS / "cloudsploit" / "checks" / "publicIpAddress.js"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cs_plugin_src, dst)
        rows.append(
            CopySpec(
                source_project="cloudsploit",
                source_repo_url="https://github.com/aquasecurity/cloudsploit",
                source_license="GPL-3.0",
                original_path="plugins/aws/ec2/publicIpAddress.js",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="scanner_check",
                reason_copied="Representative EC2 public exposure check: metadata, APIs, and addResult usage.",
                how_we_use_it="Study CloudSploit check shape for a future adapter; run CloudSploit externally—do not import this file.",
                direct_code_reuse_allowed="false",
                notes="GPL-3.0 upstream — no incorporation into non-GPL products; excerpt for study only.",
            )
        )
    cs_readme = REF / "cloudsploit/README.md"
    if cs_readme.is_file():
        dst = RS / "cloudsploit" / "docs" / "README_excerpt.md"
        write_head(dst, cs_readme, 45)
        rows.append(
            CopySpec(
                source_project="cloudsploit",
                source_repo_url="https://github.com/aquasecurity/cloudsploit",
                source_license="GPL-3.0",
                original_path="README.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="Top-of-README excerpt: CSPM scope and positioning.",
                how_we_use_it="Human-readable comparison vs. our evidence-correlation agent; not parsed at runtime.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt.",
            )
        )
    dst_note = RS / "cloudsploit" / "outputs" / "result_object_semantics_excerpt.md"
    dst_note.parent.mkdir(parents=True, exist_ok=True)
    dst_note.write_text(
        head_text(cs_plugin_src, 20)
        + "\n# ...\n"
        + "".join(cs_plugin_src.read_text(encoding="utf-8").splitlines(keepends=True)[76:91]),
        encoding="utf-8",
    )
    rows.append(
        CopySpec(
            source_project="cloudsploit",
            source_repo_url="https://github.com/aquasecurity/cloudsploit",
            source_license="GPL-3.0",
            original_path="plugins/aws/ec2/publicIpAddress.js (excerpt)",
            copied_path=dst_note.relative_to(ROOT).as_posix(),
            category="scanner_output",
            reason_copied="Tiny excerpt showing addResult lines for PASS/FAIL messaging.",
            how_we_use_it="Illustrates typical CloudSploit result rows (status code + region + resource ARN) for adapter design.",
            direct_code_reuse_allowed="false",
            notes="Derived excerpt from same plugin file; GPL-3.0.",
        )
    )

    # --- cloudgraph ---
    cg_ex = REF / "cloudgraph-cli/examples/examples.txt"
    if cg_ex.is_file():
        dst = RS / "cloudgraph" / "graph_models" / "examples_entrypoint.txt"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cg_ex, dst)
        rows.append(
            CopySpec(
                source_project="cloudgraph-cli",
                source_repo_url="https://github.com/cloudgraphdev/cli",
                source_license="MPL-2.0",
                original_path="examples/examples.txt",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="Official pointer to CloudGraph documentation and query examples.",
                how_we_use_it="Reminder that graph schema and queries are documentation-driven; informs adapter boundaries.",
                direct_code_reuse_allowed="false",
                notes="",
            )
        )
    cg_pkg = REF / "cloudgraph-cli/package.json"
    if cg_pkg.is_file():
        pkg = json.loads(cg_pkg.read_text(encoding="utf-8"))
        slim = {
            k: pkg.get(k)
            for k in ("name", "description", "version", "license", "bin", "bugs")
            if k in pkg
        }
        dst = RS / "cloudgraph" / "schemas" / "cli_package_identity.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(slim, indent=2) + "\n", encoding="utf-8")
        rows.append(
            CopySpec(
                source_project="cloudgraph-cli",
                source_repo_url="https://github.com/cloudgraphdev/cli",
                source_license="MPL-2.0",
                original_path="package.json (subset)",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="schema",
                reason_copied="Non-secret package identity: GraphQL CLI name, binary, license.",
                how_we_use_it="Ground truth for naming and license when documenting optional CloudGraph integration.",
                direct_code_reuse_allowed="true",
                notes="Subset JSON extracted from package.json; MPL-2.0 applies to upstream.",
            )
        )
    cg_readme = REF / "cloudgraph-cli/README.md"
    if cg_readme.is_file():
        dst = RS / "cloudgraph" / "docs" / "README_excerpt.md"
        write_head(dst, cg_readme, 42)
        rows.append(
            CopySpec(
                source_project="cloudgraph-cli",
                source_repo_url="https://github.com/cloudgraphdev/cli",
                source_license="MPL-2.0",
                original_path="README.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="README excerpt: multi-cloud GraphQL CSPM positioning.",
                how_we_use_it="Compare graph-query UX vs. our evidence graph and FedRAMP package outputs.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt (upstream README is large).",
            )
        )

    # --- fixinventory ---
    fi_flow = (
        REF
        / "fixinventory/plugins/aws/test/resources/files/ec2/describe-flow-logs.json"
    )
    if fi_flow.is_file():
        dst = RS / "fixinventory" / "collectors" / "aws_ec2_describe_flow_logs_fixture.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fi_flow, dst)
        rows.append(
            CopySpec(
                source_project="fixinventory",
                source_repo_url="https://github.com/someengineering/fixinventory",
                source_license="Apache-2.0",
                original_path="plugins/aws/test/resources/files/ec2/describe-flow-logs.json",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="collector_output",
                reason_copied="Small AWS API-shaped fixture: resource metadata a collector normalizes into the asset graph.",
                how_we_use_it="Study raw cloud API blob → graph node edge cases for inventory adapters.",
                direct_code_reuse_allowed="false",
                notes="Test fixture from upstream; Apache-2.0.",
            )
        )
    fi_fixlib_readme = REF / "fixinventory/fixlib/README.md"
    if fi_fixlib_readme.is_file():
        dst = RS / "fixinventory" / "graph_models" / "fixlib_readme_excerpt.md"
        write_head(dst, fi_fixlib_readme, 55)
        rows.append(
            CopySpec(
                source_project="fixinventory",
                source_repo_url="https://github.com/someengineering/fixinventory",
                source_license="Apache-2.0",
                original_path="fixlib/README.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="graph_model",
                reason_copied="fixlib README excerpt: shared graph/utilities layer description.",
                how_we_use_it="Informs how Fix Inventory thinks about shared modeling utilities vs. plugins.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt.",
            )
        )
    fi_security = REF / "fixinventory/SECURITY.md"
    if fi_security.is_file():
        dst = RS / "fixinventory" / "docs" / "SECURITY_excerpt.md"
        write_head(dst, fi_security, 35)
        rows.append(
            CopySpec(
                source_project="fixinventory",
                source_repo_url="https://github.com/someengineering/fixinventory",
                source_license="Apache-2.0",
                original_path="SECURITY.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="SECURITY policy excerpt for responsible integration patterns.",
                how_we_use_it="Reference if we document third-party Fix Inventory adjacency.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt.",
            )
        )

    # --- aurelian ---
    au_pub = REF / "aurelian/docs/aurelian_aws_recon_public-resources.md"
    if au_pub.is_file():
        dst = RS / "aurelian" / "recon_patterns" / "aws_recon_public_resources.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(au_pub, dst)
        rows.append(
            CopySpec(
                source_project="aurelian",
                source_repo_url="https://github.com/praetorian-inc/aurelian",
                source_license="Apache-2.0",
                original_path="docs/aurelian_aws_recon_public-resources.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="recon_pattern",
                reason_copied="Auto-generated CLI doc for public-exposure recon module (flags + behavior summary).",
                how_we_use_it="Maps public exposure recon concepts to our public_exposure_policy / semantic event vocabulary.",
                direct_code_reuse_allowed="false",
                notes="Documentation-only file from upstream.",
            )
        )
    au_recon_idx = REF / "aurelian/docs/aurelian_aws_recon.md"
    if au_recon_idx.is_file():
        dst = RS / "aurelian" / "docs" / "aurelian_aws_recon_excerpt.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(au_recon_idx, dst)
        rows.append(
            CopySpec(
                source_project="aurelian",
                source_repo_url="https://github.com/praetorian-inc/aurelian",
                source_license="Apache-2.0",
                original_path="docs/aurelian_aws_recon.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="Module listing for AWS recon surface (graph, IAM, public resources, etc.).",
                how_we_use_it="Breadth check for recon-vs-compliance boundary when scoping adapters.",
                direct_code_reuse_allowed="false",
                notes="",
            )
        )
    au_readme = REF / "aurelian/README.md"
    if au_readme.is_file():
        dst = RS / "aurelian" / "outputs" / "README_excerpt.md"
        write_head(dst, au_readme, 38)
        rows.append(
            CopySpec(
                source_project="aurelian",
                source_repo_url="https://github.com/praetorian-inc/aurelian",
                source_license="Apache-2.0",
                original_path="README.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="Top-of-README excerpt: framework positioning.",
                how_we_use_it="Human-readable contrast vs. FedRAMP evidence lifecycle agent.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt.",
            )
        )

    # --- nisify ---
    for name in ("aws_mfa_status.json", "aws_security_findings.json"):
        src = REF / "nisify/examples/sample_evidence" / name
        if src.is_file():
            dst = RS / "nisify" / "evidence_model" / name
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            rows.append(
                CopySpec(
                    source_project="nisify",
                    source_repo_url="https://github.com/clay-good/nisify",
                    source_license="MIT",
                    original_path=f"examples/sample_evidence/{name}",
                    copied_path=dst.relative_to(ROOT).as_posix(),
                    category="evidence_sample",
                    reason_copied="Representative normalized evidence JSON for NIST CSF-style maturity tooling.",
                    how_we_use_it="Compare evidence envelope fields to our AssessmentBundle / fixture scenarios.",
                    direct_code_reuse_allowed="true",
                    notes="MIT sample evidence; safe to use as structural inspiration.",
                )
            )
    nis_map_src = REF / "nisify/data/control_evidence_mappings.json"
    if nis_map_src.is_file():
        data = json.loads(nis_map_src.read_text(encoding="utf-8"))
        excerpt = {
            "version": data.get("version"),
            "description": data.get("description"),
            "mappings_sample": (data.get("mappings") or [])[:5],
        }
        dst = RS / "nisify" / "mappings" / "control_evidence_mappings_excerpt.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(json.dumps(excerpt, indent=2) + "\n", encoding="utf-8")
        rows.append(
            CopySpec(
                source_project="nisify",
                source_repo_url="https://github.com/clay-good/nisify",
                source_license="MIT",
                original_path="data/control_evidence_mappings.json (truncated)",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="compliance_mapping",
                reason_copied="First five control↔evidence mappings illustrate mapping list shape.",
                how_we_use_it="Contrast NIST CSF mapping density with our FedRAMP 20x KSI / control crosswalk YAML.",
                direct_code_reuse_allowed="true",
                notes="Truncated from upstream JSON; MIT.",
            )
        )
    nm = REF / "nisify/docs/nist-mapping.md"
    if nm.is_file():
        dst = RS / "nisify" / "mappings" / "nist_mapping_doc_excerpt.md"
        write_head(dst, nm, 52)
        rows.append(
            CopySpec(
                source_project="nisify",
                source_repo_url="https://github.com/clay-good/nisify",
                source_license="MIT",
                original_path="docs/nist-mapping.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="compliance_mapping",
                reason_copied="NIST mapping documentation excerpt.",
                how_we_use_it="Human study for evidence-to-control narrative patterns (CSF, not FedRAMP 20x).",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt.",
            )
        )
    cfg = REF / "nisify/examples/config.example.yaml"
    if cfg.is_file():
        dst = RS / "nisify" / "docs" / "config.example.yaml"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(cfg, dst)
        rows.append(
            CopySpec(
                source_project="nisify",
                source_repo_url="https://github.com/clay-good/nisify",
                source_license="MIT",
                original_path="examples/config.example.yaml",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="config",
                reason_copied="Example connector/evidence configuration shape.",
                how_we_use_it="Inform multi-connector policy when designing provider configs.",
                direct_code_reuse_allowed="true",
                notes="MIT.",
            )
        )
    nis_readme = REF / "nisify/README.md"
    if nis_readme.is_file():
        dst = RS / "nisify" / "reports" / "README_product_excerpt.md"
        write_head(dst, nis_readme, 35)
        rows.append(
            CopySpec(
                source_project="nisify",
                source_repo_url="https://github.com/clay-good/nisify",
                source_license="MIT",
                original_path="README.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="evidence_reporting",
                reason_copied="Product README excerpt: dashboards and maturity positioning.",
                how_we_use_it="Compare reporting tone to assessor/executive reports in our pipeline.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt.",
            )
        )

    # --- fedramp20xmcp ---
    mcp_server = REF / "FedRAMP20xMCP/server.json"
    if mcp_server.is_file():
        dst = RS / "fedramp20xmcp" / "requirements" / "server.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(mcp_server, dst)
        rows.append(
            CopySpec(
                source_project="FedRAMP20xMCP",
                source_repo_url="https://github.com/KevinRabun/FedRAMP20xMCP",
                source_license="MIT",
                original_path="server.json",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="requirement_lookup",
                reason_copied="MCP server manifest snippet (tooling surface).",
                how_we_use_it="Compare to our static `config/ksi-catalog.yaml` and eval IDs; optional MCP adjacency.",
                direct_code_reuse_allowed="true",
                notes="MIT.",
            )
        )
    ksi_pat = REF / "FedRAMP20xMCP/data/patterns/ksi_patterns.yaml"
    if ksi_pat.is_file():
        dst = RS / "fedramp20xmcp" / "mappings" / "ksi_patterns.yaml"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ksi_pat, dst)
        rows.append(
            CopySpec(
                source_project="FedRAMP20xMCP",
                source_repo_url="https://github.com/KevinRabun/FedRAMP20xMCP",
                source_license="MIT",
                original_path="data/patterns/ksi_patterns.yaml",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="compliance_mapping",
                reason_copied="Compact FedRAMP 20x KSI pattern YAML (lookup / keyword patterns).",
                how_we_use_it="Study upstream KSI pattern list vs. our classifier and KSI rollup logic.",
                direct_code_reuse_allowed="true",
                notes="MIT.",
            )
        )
    adv = REF / "FedRAMP20xMCP/docs/ADVANCED-SETUP.md"
    if adv.is_file():
        dst = RS / "fedramp20xmcp" / "docs" / "ADVANCED-SETUP.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(adv, dst)
        rows.append(
            CopySpec(
                source_project="FedRAMP20xMCP",
                source_repo_url="https://github.com/KevinRabun/FedRAMP20xMCP",
                source_license="MIT",
                original_path="docs/ADVANCED-SETUP.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="Operator-focused setup documentation (short file).",
                how_we_use_it="Document sidecar MCP deployment if we reference this project.",
                direct_code_reuse_allowed="false",
                notes="",
            )
        )
    ps = REF / "FedRAMP20xMCP/docs/PATTERN_SCHEMA_V2.md"
    if ps.is_file():
        dst = RS / "fedramp20xmcp" / "requirements" / "PATTERN_SCHEMA_V2_excerpt.md"
        write_head(dst, ps, 75)
        rows.append(
            CopySpec(
                source_project="FedRAMP20xMCP",
                source_repo_url="https://github.com/KevinRabun/FedRAMP20xMCP",
                source_license="MIT",
                original_path="docs/PATTERN_SCHEMA_V2.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="schema",
                reason_copied="Pattern schema documentation excerpt (how requirements are encoded).",
                how_we_use_it="Cross-check pattern DSL vs. our YAML configs and eval hooks.",
                direct_code_reuse_allowed="false",
                notes="Truncated excerpt from large doc.",
            )
        )

    # --- knox 20x pilot ---
    knox_base = REF / "knox-fedramp-20x-pilot"
    for fn in ("evidence-mappings.json", "ksi-validation-results.json"):
        src = knox_base / "machine-readable-assessment" / fn
        if src.is_file():
            dst = RS / "knox_20x_pilot" / "package_examples" / fn
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            rows.append(
                CopySpec(
                    source_project="knox-fedramp-20x-pilot",
                    source_repo_url="https://github.com/Knox-Gov/fedramp_20x_pilot",
                    source_license="unknown",
                    original_path=f"machine-readable-assessment/{fn}",
                    copied_path=dst.relative_to(ROOT).as_posix(),
                    category="fedramp_package_example",
                    reason_copied="Machine-readable pilot assessment fragments (KSI validation + evidence mapping list shape).",
                    how_we_use_it="Structural reference for FedRAMP 20x package JSON we emit under evidence/package/.",
                    direct_code_reuse_allowed="unknown",
                    notes="No LICENSE file at repo root in shallow clone; confirm Knox/Adobe terms before redistribution.",
                )
            )
    schema_js = knox_base / "schemas" / "fedramp-output-schema.json"
    if schema_js.is_file():
        dst = RS / "knox_20x_pilot" / "schemas" / "fedramp-output-schema.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(schema_js, dst)
        rows.append(
            CopySpec(
                source_project="knox-fedramp-20x-pilot",
                source_repo_url="https://github.com/Knox-Gov/fedramp_20x_pilot",
                source_license="unknown",
                original_path="schemas/fedramp-output-schema.json",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="schema",
                reason_copied="FedRAMP output JSON Schema from public pilot materials.",
                how_we_use_it="Optional cross-check vs. our schemas/ when aligning package fields.",
                direct_code_reuse_allowed="unknown",
                notes="Confirm redistribution terms; pilot artifact.",
            )
        )
    d1 = knox_base / "documentation/cloud-service-summary.md"
    if d1.is_file():
        dst = RS / "knox_20x_pilot" / "docs" / "cloud-service-summary.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(d1, dst)
        rows.append(
            CopySpec(
                source_project="knox-fedramp-20x-pilot",
                source_repo_url="https://github.com/Knox-Gov/fedramp_20x_pilot",
                source_license="unknown",
                original_path="documentation/cloud-service-summary.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="docs",
                reason_copied="CSP boundary summary narrative from pilot documentation.",
                how_we_use_it="Compare system-boundary prose to `config/system-boundary.yaml` narratives.",
                direct_code_reuse_allowed="unknown",
                notes="",
            )
        )
    d2 = knox_base / "documentation/machine-readable-assessment.md"
    if d2.is_file():
        dst = RS / "knox_20x_pilot" / "reports" / "machine-readable-assessment_overview.md"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(d2, dst)
        rows.append(
            CopySpec(
                source_project="knox-fedramp-20x-pilot",
                source_repo_url="https://github.com/Knox-Gov/fedramp_20x_pilot",
                source_license="unknown",
                original_path="documentation/machine-readable-assessment.md",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="evidence_reporting",
                reason_copied="Explains machine-readable assessment packaging in the pilot.",
                how_we_use_it="Narrative alignment for assessor-facing machine-readable outputs.",
                direct_code_reuse_allowed="unknown",
                notes="",
            )
        )

    fi_small = (
        REF
        / "fixinventory/plugins/aws/test/resources/files/eks/list-clusters.json"
    )
    if fi_small.is_file():
        dst = RS / "fixinventory" / "schemas" / "aws_eks_list_clusters_minimal_fixture.json"
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(fi_small, dst)
        rows.append(
            CopySpec(
                source_project="fixinventory",
                source_repo_url="https://github.com/someengineering/fixinventory",
                source_license="Apache-2.0",
                original_path="plugins/aws/test/resources/files/eks/list-clusters.json",
                copied_path=dst.relative_to(ROOT).as_posix(),
                category="schema_fixture",
                reason_copied="Minimal AWS ListClusters API response blob (inventory collector raw JSON).",
                how_we_use_it="Illustrates smallest API list response shape normalized into graph resources.",
                direct_code_reuse_allowed="false",
                notes="Test fixture; Apache-2.0.",
            )
        )

    # --- merge with existing tracked samples (everything except README + manifest) ---
    manifest_path = RS / "manifest.json"
    prior = json.loads(manifest_path.read_text(encoding="utf-8"))
    ref_inv = prior.get("reference_directory_inventory")
    existing_files = prior.get("files") or []

    by_path: dict[str, dict] = {e["copied_path"]: e for e in existing_files}
    for spec in rows:
        by_path[spec.copied_path] = {
            "source_project": spec.source_project,
            "source_repo_url": spec.source_repo_url,
            "source_license": spec.source_license,
            "original_path": spec.original_path,
            "copied_path": spec.copied_path,
            "category": spec.category,
            "reason_copied": spec.reason_copied,
            "how_we_use_it": spec.how_we_use_it,
            "direct_code_reuse_allowed": spec.direct_code_reuse_allowed,
            "notes": spec.notes,
        }

    new_manifest = {
        "schema_version": prior.get("schema_version", "1.0"),
        "description": prior.get(
            "description",
            "Reference samples copied from upstream OSS repos (not vendored).",
        ),
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": sorted(by_path.values(), key=lambda e: e["copied_path"]),
    }
    if ref_inv is not None:
        new_manifest["reference_directory_inventory"] = ref_inv

    manifest_path.write_text(json.dumps(new_manifest, indent=2) + "\n", encoding="utf-8")

    # Verify parity: every file on disk (except README, manifest) is in manifest
    on_disk = {
        p.relative_to(ROOT).as_posix()
        for p in RS.rglob("*")
        if p.is_file() and p.name not in ("README.md", "manifest.json")
    }
    manifest_paths = {e["copied_path"] for e in new_manifest["files"]}
    if on_disk != manifest_paths:
        missing = sorted(on_disk - manifest_paths)
        extra = sorted(manifest_paths - on_disk)
        raise SystemExit(
            f"Manifest/disk mismatch.\nOnly on disk: {missing}\nOnly in manifest: {extra}"
        )
    print(f"OK: {len(on_disk)} tracked files, manifest synced.")


if __name__ == "__main__":
    main()
