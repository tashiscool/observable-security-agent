"""Load ancillary FedRAMP 20x mapping YAML under ``mappings/`` (evidence map, responsibility)."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml_mapping(path: Path) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(path)
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def load_ksi_to_evidence_map(path: Path) -> dict[str, Any]:
    """Load ``fedramp20x-ksi-to-evidence-map.yaml``."""
    return load_yaml_mapping(path)


def load_shared_responsibility_map(path: Path) -> dict[str, Any]:
    """Load ``shared-responsibility-map.yaml``."""
    return load_yaml_mapping(path)


def load_inherited_responsibility_map(path: Path) -> dict[str, Any]:
    """Load ``inherited-responsibility-map.yaml``."""
    return load_yaml_mapping(path)


def iter_evidence_source_ids_from_ksi_evidence(doc: dict[str, Any]) -> set[str]:
    """Collect evidence source ids from ``ksi_evidence`` blocks (list-valued fields)."""
    out: set[str] = set()
    kmap = doc.get("ksi_evidence")
    if not isinstance(kmap, dict):
        return out
    list_keys = (
        "required_evidence_sources",
        "optional_evidence_sources",
        "machine_evidence",
        "human_evidence",
    )
    for _ksi, block in kmap.items():
        if not isinstance(block, dict):
            continue
        for lk in list_keys:
            seq = block.get(lk)
            if isinstance(seq, list):
                for x in seq:
                    if isinstance(x, str) and x.strip():
                        out.add(x.strip())
    return out
