"""AuditKit-inspired *structural* checks against evidence bundles (no AuditKit runtime dependency)."""

from __future__ import annotations

from typing import Any


def validate_auditkit_inspired_evidence_shape(doc: dict[str, Any]) -> list[str]:
    """
    Return human-readable gaps when a document does not mirror concepts stressed in
    AuditKit's evidence-package examples (findings, machine-readable artifacts, linkage).

    Intended for tests and CI against our ``fedramp20x-package`` nested bundle, not for
    validating upstream AuditKit output.
    """
    errs: list[str] = []
    if not isinstance(doc, dict):
        return ["root must be an object"]
    if doc.get("schema_version") != "1.0":
        errs.append("expected schema_version 1.0 (parallel to versioned audit bundles)")
    pm = doc.get("package_metadata")
    if not isinstance(pm, dict):
        errs.append("missing package_metadata (program / generator context)")
    elif not str(pm.get("generator_id") or "").strip():
        errs.append("package_metadata.generator_id should identify the generator")

    findings = doc.get("findings")
    if not isinstance(findings, list) or not findings:
        errs.append("findings[] should list assessed issues (AuditKit examples emphasize failed controls)")

    el = doc.get("evidence_links")
    if not isinstance(el, list) or not el:
        errs.append("evidence_links[] should tie findings to artifacts (auditor-ready traceability)")

    poam = doc.get("poam_items")
    if not isinstance(poam, list) or not poam:
        errs.append("poam_items[] should capture remediation tracking")

    return errs


__all__ = ["validate_auditkit_inspired_evidence_shape"]
