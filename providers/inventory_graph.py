"""Normalize graph/inventory exports from graph-first tools into OSA shapes."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from core.models import Asset


def _node_id(node: dict[str, Any]) -> str:
    return str(node.get("id") or node.get("uid") or node.get("key") or node.get("arn") or node.get("name") or "asset-unknown")


def _provider(node: dict[str, Any]) -> str:
    raw = str(node.get("provider") or node.get("cloud") or node.get("cloudProvider") or "").lower()
    if raw in {"aws", "azure", "gcp"}:
        return raw
    rid = _node_id(node).lower()
    if rid.startswith("arn:aws"):
        return "aws"
    if "/subscriptions/" in rid:
        return "azure"
    if rid.startswith("//") or "googleapis" in rid:
        return "gcp"
    return "unknown"


def _asset_type(node: dict[str, Any]) -> str:
    raw = str(node.get("asset_type") or node.get("type") or node.get("label") or "unknown").lower()
    if any(x in raw for x in ("instance", "compute", "vm")):
        return "compute"
    if any(x in raw for x in ("database", "rds", "sql")):
        return "database"
    if any(x in raw for x in ("bucket", "storage", "s3")):
        return "storage"
    if any(x in raw for x in ("lb", "load_balancer", "load balancer")):
        return "load_balancer"
    if "network" in raw or "security_group" in raw:
        return "network"
    return "unknown"


def graph_node_to_asset(node: dict[str, Any]) -> Asset:
    tags = node.get("tags") if isinstance(node.get("tags"), dict) else {}
    env = str(tags.get("Environment") or node.get("environment") or "unknown").lower()
    if env not in {"prod", "staging", "dev", "test", "unknown"}:
        env = "unknown"
    crit = str(node.get("criticality") or "moderate").lower()
    if crit == "medium":
        crit = "moderate"
    if crit not in {"low", "moderate", "high"}:
        crit = "moderate"
    return Asset(
        asset_id=_node_id(node)[:120],
        provider=_provider(node),
        account_id=str(node.get("account_id") or node.get("accountId") or "") or None,
        project_id=str(node.get("project_id") or "") or None,
        subscription_id=str(node.get("subscription_id") or "") or None,
        region=str(node.get("region") or "") or None,
        asset_type=_asset_type(node),  # type: ignore[arg-type]
        name=str(node.get("name") or _node_id(node))[:200],
        private_ips=[str(x) for x in (node.get("private_ips") or node.get("privateIps") or [])],
        public_ips=[str(x) for x in (node.get("public_ips") or node.get("publicIps") or [])],
        tags={str(k): str(v) for k, v in tags.items()},
        criticality=crit,  # type: ignore[arg-type]
        environment=env,  # type: ignore[arg-type]
        raw_ref=_node_id(node),
    )


def iter_graph_nodes(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [x for x in data if isinstance(x, dict)]
    if isinstance(data, dict):
        nodes = data.get("nodes")
        if isinstance(nodes, list):
            return [x for x in nodes if isinstance(x, dict)]
        if isinstance(nodes, dict):
            out: list[dict[str, Any]] = []
            for group, rows in nodes.items():
                if isinstance(rows, list):
                    for row in rows:
                        if isinstance(row, dict):
                            copy = dict(row)
                            copy.setdefault("type", group)
                            out.append(copy)
            return out
        for key in ("assets", "resources", "items"):
            if isinstance(data.get(key), list):
                return [x for x in data[key] if isinstance(x, dict)]
        return [data]
    raise ValueError("Unsupported graph/inventory JSON shape")


def import_graph_assets(path: Path) -> list[Asset]:
    return [graph_node_to_asset(n) for n in iter_graph_nodes(path)]


def import_graph_assets_to_file(input_path: Path, output_path: Path) -> Path:
    assets = import_graph_assets(input_path)
    dest = output_path if output_path.suffix.lower() == ".json" else output_path / "discovered_assets.json"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps({"assets": [a.model_dump(mode="json") for a in assets]}, indent=2), encoding="utf-8")
    return dest


__all__ = ["import_graph_assets", "import_graph_assets_to_file", "graph_node_to_asset"]
