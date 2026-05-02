"""Directed evidence graph (JSON in / out) — no Neo4j required for BuildLab.

v3 uses singular node labels (``asset``, ``cloud_account``, …) and UPPER_SNAKE
relationships aligned with Cartography / Fix Inventory / CloudGraph *concepts*
(account scoping, resource topology, findings, exposure) without importing their
Neo4j or GraphQL stacks.

Structural edges beyond the FedRAMP chain (inventory match, event resolution,
event typing) use ``INVENTORY_DESCRIBES_ASSET``, ``EVENT_TARGETS_ASSET``,
``INSTANCE_OF_EVENT_TYPE``.
"""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel

from core.models import (
    AlertRule,
    AssessmentBundle,
    Asset,
    DeclaredInventoryRecord,
    EvalResult,
    LogSource,
    ScannerTarget,
    SecurityEvent,
)
from fedramp20x.crosswalk_normalize import normalize_rev5_ksi_table
from fedramp20x.eval_ksi_mapping import eval_to_ksi_ids

_PKG_ROOT = Path(__file__).resolve().parents[1]

# --- Node kinds (singular labels) ---
NodeType = Literal[
    "cloud_account",
    "asset",
    "declared_inventory_record",
    "event",
    "scanner_target",
    "scanner_finding",
    "log_source",
    "alert_rule",
    "ticket",
    "poam_item",
    "control",
    "evaluation",
    "event_mtype",
    "network_exposure",
    "ksi",
    "evidence_artifact",
]

# FedRAMP / assessment chain (user vocabulary)
REL_BELONGS_TO_ACCOUNT = "BELONGS_TO_ACCOUNT"
REL_HAS_PUBLIC_EXPOSURE = "HAS_PUBLIC_EXPOSURE"
REL_HAS_FINDING = "HAS_FINDING"
REL_COVERED_BY_SCANNER_TARGET = "COVERED_BY_SCANNER_TARGET"
REL_MISSING_SCANNER_TARGET = "MISSING_SCANNER_TARGET"
REL_EMITS_LOGS_TO = "EMITS_LOGS_TO"
REL_MISSING_CENTRAL_LOGGING = "MISSING_CENTRAL_LOGGING"
REL_COVERED_BY_ALERT = "COVERED_BY_ALERT"
REL_MISSING_ALERT = "MISSING_ALERT"
REL_LINKED_TO_TICKET = "LINKED_TO_TICKET"
REL_MISSING_TICKET = "MISSING_TICKET"
REL_TRACKED_BY_POAM = "TRACKED_BY_POAM"
REL_MAPS_TO_CONTROL = "MAPS_TO_CONTROL"
REL_MAPS_TO_KSI = "MAPS_TO_KSI"
REL_SUPPORTED_BY_EVIDENCE = "SUPPORTED_BY_EVIDENCE"

# Structural (topology / typing)
REL_INVENTORY_DESCRIBES_ASSET = "INVENTORY_DESCRIBES_ASSET"
REL_EVENT_TARGETS_ASSET = "EVENT_TARGETS_ASSET"
REL_INSTANCE_OF_EVENT_TYPE = "INSTANCE_OF_EVENT_TYPE"

# Backward aliases for lowercase v2 labels in tests / fixtures
LEGACY_REL_TO_CANONICAL: dict[str, str] = {
    "inventory_describes_asset": REL_INVENTORY_DESCRIBES_ASSET,
    "event_affects_asset": REL_EVENT_TARGETS_ASSET,
    "scanner_target_covers_asset": REL_COVERED_BY_SCANNER_TARGET,
    "finding_affects_asset": REL_HAS_FINDING,
    "asset_emits_log_source": REL_EMITS_LOGS_TO,
    "alert_rule_covers_event_type": REL_COVERED_BY_ALERT,
    "ticket_links_event": REL_LINKED_TO_TICKET,
    "ticket_links_finding": REL_LINKED_TO_TICKET,
    "ticket_links_asset": REL_LINKED_TO_TICKET,
    "poam_tracks_eval": REL_TRACKED_BY_POAM,
    "poam_references_asset": REL_TRACKED_BY_POAM,
    "eval_impacts_control": REL_MAPS_TO_CONTROL,
    "event_instance_of_type": REL_INSTANCE_OF_EVENT_TYPE,
}


def _node_key(node_type: str, node_id: str) -> str:
    return f"{node_type}::{node_id}"


def node_key(node_type: str, node_id: str) -> str:
    """Stable external id ``{type}::{natural_id}`` (natural id must not contain ``::``)."""
    return _node_key(node_type, node_id)


def _model_dump(m: BaseModel) -> dict[str, Any]:
    return m.model_dump(mode="json")


@lru_cache
def _ksi_crosswalk_bundle() -> tuple[tuple[dict[str, Any], ...], dict[str, str], dict[str, Any]]:
    csv_path = _PKG_ROOT / "mappings" / "rev5-to-20x-ksi-crosswalk.csv"
    raw = list(csv.DictReader(csv_path.read_text(encoding="utf-8").splitlines()))
    rows = normalize_rev5_ksi_table(raw)
    cfg = yaml.safe_load((_PKG_ROOT / "config" / "control-crosswalk.yaml").read_text(encoding="utf-8"))
    defaults = {str(k): str(v) for k, v in (cfg.get("eval_id_default_ksi") or {}).items()}
    agent = dict(cfg.get("eval_id_agent_ksi") or {})
    return tuple(rows), defaults, agent


def _cloud_scope_id(asset: Asset) -> str | None:
    if asset.account_id and str(asset.account_id).strip():
        return f"{asset.provider}:{str(asset.account_id).strip()}"
    if asset.project_id and str(asset.project_id).strip():
        return f"{asset.provider}:project:{str(asset.project_id).strip()}"
    if asset.subscription_id and str(asset.subscription_id).strip():
        return f"{asset.provider}:sub:{str(asset.subscription_id).strip()}"
    return None


def _exposure_semantic(sem: str) -> bool:
    return sem in (
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
    )


@dataclass
class GraphEdge:
    from_id: str
    to_id: str
    relationship: str
    data: dict[str, Any] = field(default_factory=dict)


class EvidenceGraph:
    """Directed graph with typed nodes (``node_type::node_id`` keys)."""

    def __init__(self, *, version: str = "3.0") -> None:
        self.version = version
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: list[GraphEdge] = []

    def add_node(self, node_type: str, node_id: str, data: dict[str, Any] | None = None) -> str:
        key = _node_key(node_type, node_id)
        payload = {"type": node_type, "id": node_id, "data": dict(data or {})}
        self._nodes[key] = payload
        return key

    def add_edge(
        self,
        from_id: str,
        to_id: str,
        relationship: str,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._edges.append(GraphEdge(from_id=from_id, to_id=to_id, relationship=relationship, data=dict(data or {})))

    def get_node(self, node_id: str) -> dict[str, Any] | None:
        return self._nodes.get(node_id)

    def find_edges(
        self,
        *,
        from_id: str | None = None,
        to_id: str | None = None,
        relationship: str | None = None,
    ) -> list[dict[str, Any]]:
        rels = {relationship} if relationship is not None else None
        if relationship is not None:
            rels = {relationship, LEGACY_REL_TO_CANONICAL.get(relationship, relationship)}
        out: list[dict[str, Any]] = []
        for e in self._edges:
            if from_id is not None and e.from_id != from_id:
                continue
            if to_id is not None and e.to_id != to_id:
                continue
            if rels is not None and e.relationship not in rels:
                continue
            out.append(
                {
                    "from": e.from_id,
                    "to": e.to_id,
                    "relationship": e.relationship,
                    "data": dict(e.data),
                }
            )
        return out

    def neighbors(self, node_id: str, relationship: str | None = None) -> list[str]:
        seen: set[str] = set()
        order: list[str] = []
        rels: set[str] | None = None
        if relationship is not None:
            rels = {relationship, LEGACY_REL_TO_CANONICAL.get(relationship, relationship)}
        for e in self._edges:
            if rels is not None and e.relationship not in rels:
                continue
            if e.from_id == node_id and e.to_id not in seen:
                seen.add(e.to_id)
                order.append(e.to_id)
            if e.to_id == node_id and e.from_id not in seen:
                seen.add(e.from_id)
                order.append(e.from_id)
        return order

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "nodes": list(self._nodes.values()),
            "edges": [
                {"from": e.from_id, "to": e.to_id, "relationship": e.relationship, "data": dict(e.data)}
                for e in self._edges
            ],
        }

    def write_json(self, path: Path | str) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=2, default=str), encoding="utf-8")


# --- Asset resolution (exact asset_id → name → private IP → public IP) ---


def _match_asset_for_identifier(
    *,
    asset_id: str | None,
    name: str | None,
    private_ip: str | None,
    public_ip: str | None,
    assets: list[Asset],
) -> tuple[Asset | None, str | None]:
    if asset_id and str(asset_id).strip():
        aid = str(asset_id).strip()
        for a in assets:
            if a.asset_id == aid:
                return a, "asset_id"
    if name and str(name).strip():
        nm = str(name).strip()
        for a in assets:
            if a.name == nm or a.asset_id == nm:
                return a, "name"
    if private_ip and str(private_ip).strip():
        pip = str(private_ip).strip()
        for a in assets:
            if pip in a.private_ips:
                return a, "private_ip"
    if public_ip and str(public_ip).strip():
        pub = str(public_ip).strip()
        for a in assets:
            if pub in a.public_ips:
                return a, "public_ip"
    return None, None


def _match_asset_for_event(ev: SecurityEvent, assets: list[Asset]) -> tuple[Asset | None, str | None]:
    if ev.asset_id and str(ev.asset_id).strip():
        aid = str(ev.asset_id).strip()
        for a in assets:
            if a.asset_id == aid:
                return a, "event.asset_id"
    rid = (ev.resource_id or "").strip()
    if rid:
        for a in assets:
            if a.asset_id == rid or (a.raw_ref and rid == a.raw_ref) or a.name == rid:
                return a, "event.resource_id"
    return None, None


def _match_asset_for_scanner_target(st: ScannerTarget, assets: list[Asset]) -> tuple[Asset | None, str | None]:
    if getattr(st, "asset_id", None) and str(st.asset_id).strip():
        for a in assets:
            if a.asset_id == str(st.asset_id).strip():
                return a, "scanner_target.asset_id"
    if getattr(st, "hostname", None) and str(st.hostname).strip():
        a, _ = _match_asset_for_identifier(
            asset_id=None,
            name=str(st.hostname).strip(),
            private_ip=None,
            public_ip=None,
            assets=assets,
        )
        if a is not None:
            return a, "scanner_target.hostname"
    if getattr(st, "ip", None) and str(st.ip).strip():
        ip = str(st.ip).strip()
        for a in assets:
            if ip in a.private_ips or ip in a.public_ips:
                return a, "scanner_target.ip"
    return None, None


def _log_active_central(ls: LogSource, *, now: datetime, hours: float) -> bool:
    if ls.status != "active":
        return False
    if ls.central_destination is None:
        return False
    if ls.last_seen is None:
        return True
    return (now - ls.last_seen) <= timedelta(hours=hours)


def evidence_graph_from_assessment_bundle(
    bundle: AssessmentBundle,
    *,
    eval_results: list[EvalResult] | None = None,
    source_root: Path | None = None,
) -> EvidenceGraph:
    """
    Populate graph from :class:`AssessmentBundle`.

    When ``eval_results`` is set, adds ``evaluation`` nodes, ``MAPS_TO_CONTROL`` /
    ``MAPS_TO_KSI``, ``TRACKED_BY_POAM`` (evaluation → poam_item), and wires KSI /
    evidence artifact stubs.

    ``source_root`` optionally adds ``evidence_artifact`` nodes for standard fixture filenames.
    """
    g = EvidenceGraph()
    assets = list(bundle.assets)
    eval_results = list(eval_results or [])
    now = datetime.now(timezone.utc)

    accounts: dict[str, dict[str, Any]] = {}
    for a in assets:
        sid = _cloud_scope_id(a)
        if sid and sid not in accounts:
            accounts[sid] = {
                "scope_id": sid,
                "provider": a.provider,
                "account_id": a.account_id,
                "project_id": a.project_id,
                "subscription_id": a.subscription_id,
            }
    for sid, data in sorted(accounts.items()):
        g.add_node("cloud_account", sid, data)

    for a in assets:
        g.add_node("asset", a.asset_id, _model_dump(a))
        sid = _cloud_scope_id(a)
        if sid and g.get_node(_node_key("cloud_account", sid)):
            g.add_edge(_node_key("asset", a.asset_id), _node_key("cloud_account", sid), REL_BELONGS_TO_ACCOUNT, {})

    for inv in bundle.declared_inventory:
        g.add_node("declared_inventory_record", inv.inventory_id, _model_dump(inv))

    for ev in bundle.events:
        g.add_node("event", ev.event_id, _model_dump(ev))
    for st in bundle.scanner_targets:
        g.add_node("scanner_target", f"{st.scanner_name}::{st.target_id}", _model_dump(st))
    for sf in bundle.scanner_findings:
        g.add_node("scanner_finding", sf.finding_id, _model_dump(sf))
    for ls in bundle.log_sources:
        g.add_node("log_source", ls.log_source_id, _model_dump(ls))
    for ar in bundle.alert_rules:
        g.add_node("alert_rule", ar.rule_id, _model_dump(ar))
    for t in bundle.tickets:
        g.add_node("ticket", t.ticket_id, _model_dump(t))
    for p in bundle.poam_items:
        g.add_node("poam_item", p.poam_id, _model_dump(p))

    control_ids: set[str] = set()
    for evr in eval_results:
        control_ids.update(str(c).strip() for c in evr.controls if str(c).strip())
    for ar in bundle.alert_rules:
        control_ids.update(str(c).strip() for c in ar.controls if str(c).strip())
    for p in bundle.poam_items:
        control_ids.update(str(c).strip() for c in p.controls if str(c).strip())
    for cid in sorted(control_ids):
        g.add_node("control", cid, {"control_id": cid})

    event_types_seen: set[str] = set()
    for ev in bundle.events:
        event_types_seen.add(str(ev.semantic_type))
    for ar in bundle.alert_rules:
        for t in ar.mapped_semantic_types:
            if str(t).strip():
                event_types_seen.add(str(t).strip())
    for et in sorted(event_types_seen):
        g.add_node("event_mtype", et, {"semantic_type": et})

    for evr in eval_results:
        g.add_node("evaluation", evr.eval_id, _model_dump(evr))

    rev5_rows, default_ksi, agent_ksi = _ksi_crosswalk_bundle()
    rev5_list = list(rev5_rows)
    ksi_seen: set[str] = set()
    for evr in eval_results:
        for kid in eval_to_ksi_ids(
            {"eval_id": evr.eval_id, "control_refs": evr.controls},
            rev5_list,
            default_ksi,
            agent_ksi,
        ):
            ksi_seen.add(kid)
    for kid in sorted(ksi_seen):
        g.add_node("ksi", kid, {"ksi_id": kid})

    if source_root is not None:
        root = source_root.resolve()
        for name in (
            "cloud_events.json",
            "scanner_findings.json",
            "declared_inventory.csv",
            "scanner_targets.csv",
            "central_log_sources.json",
            "alert_rules.json",
            "tickets.json",
            "discovered_assets.json",
        ):
            fp = root / name
            if fp.is_file():
                eid = f"file:{name}"
                g.add_node("evidence_artifact", eid, {"path": str(fp), "basename": name})
                for kid in sorted(ksi_seen):
                    g.add_edge(
                        _node_key("ksi", kid),
                        _node_key("evidence_artifact", eid),
                        REL_SUPPORTED_BY_EVIDENCE,
                        {"role": "ksi_evidence_pool"},
                    )

    inv: DeclaredInventoryRecord
    for inv in bundle.declared_inventory:
        a, how = _match_asset_for_identifier(
            asset_id=inv.asset_id,
            name=inv.name,
            private_ip=inv.expected_private_ip,
            public_ip=inv.expected_public_ip,
            assets=assets,
        )
        if a is not None:
            g.add_edge(
                _node_key("declared_inventory_record", inv.inventory_id),
                _node_key("asset", a.asset_id),
                REL_INVENTORY_DESCRIBES_ASSET,
                {"match": how},
            )

    for st in bundle.scanner_targets:
        sk = _node_key("scanner_target", f"{st.scanner_name}::{st.target_id}")
        a, how = _match_asset_for_scanner_target(st, assets)
        if a is not None:
            g.add_edge(_node_key("asset", a.asset_id), sk, REL_COVERED_BY_SCANNER_TARGET, {"match": how})

    for sf in bundle.scanner_findings:
        fk = _node_key("scanner_finding", sf.finding_id)
        a, how = None, None
        if sf.asset_id:
            a, how = _match_asset_for_identifier(asset_id=sf.asset_id, name=None, private_ip=None, public_ip=None, assets=assets)
        if a is None and sf.target_id:
            a, how = _match_asset_for_identifier(
                asset_id=sf.target_id, name=sf.target_id, private_ip=None, public_ip=None, assets=assets
            )
        if a is not None:
            g.add_edge(_node_key("asset", a.asset_id), fk, REL_HAS_FINDING, {"match": how})

    for ev in bundle.events:
        ek = _node_key("event", ev.event_id)
        a, how = _match_asset_for_event(ev, assets)
        if a is not None:
            g.add_edge(ek, _node_key("asset", a.asset_id), REL_EVENT_TARGETS_ASSET, {"match": how})
        g.add_edge(
            ek,
            _node_key("event_mtype", str(ev.semantic_type)),
            REL_INSTANCE_OF_EVENT_TYPE,
            {},
        )
        if a is not None and _exposure_semantic(str(ev.semantic_type)):
            nx_id = f"{a.asset_id}:{ev.event_id}"
            g.add_node(
                "network_exposure",
                nx_id,
                {
                    "semantic_type": str(ev.semantic_type),
                    "event_id": ev.event_id,
                    "asset_id": a.asset_id,
                    "port": ev.port,
                },
            )
            g.add_edge(_node_key("asset", a.asset_id), _node_key("network_exposure", nx_id), REL_HAS_PUBLIC_EXPOSURE, {})

    for ls in bundle.log_sources:
        if ls.asset_id and str(ls.asset_id).strip():
            aid = str(ls.asset_id).strip()
            if g.get_node(_node_key("asset", aid)):
                g.add_edge(
                    _node_key("asset", aid),
                    _node_key("log_source", ls.log_source_id),
                    REL_EMITS_LOGS_TO,
                    {},
                )

    for ar in bundle.alert_rules:
        rk = _node_key("alert_rule", ar.rule_id)
        for t in ar.mapped_semantic_types:
            ts = str(t).strip()
            if not ts:
                continue
            tk = _node_key("event_mtype", ts)
            if g.get_node(tk):
                g.add_edge(rk, tk, REL_COVERED_BY_ALERT, {})

    asset_et: dict[str, set[str]] = {a.asset_id: set() for a in assets}
    for ev in bundle.events:
        a, _ = _match_asset_for_event(ev, assets)
        if a is not None:
            asset_et[a.asset_id].add(str(ev.semantic_type))
    rule_types: set[str] = set()
    for ar in bundle.alert_rules:
        if not ar.enabled:
            continue
        for t in ar.mapped_semantic_types:
            if str(t).strip():
                rule_types.add(str(t).strip())

    for aid, types in asset_et.items():
        ak = _node_key("asset", aid)
        for sem in types:
            if sem not in rule_types:
                tk = _node_key("event_mtype", sem)
                if g.get_node(tk):
                    g.add_edge(ak, tk, REL_MISSING_ALERT, {})

    for t in bundle.tickets:
        tk = _node_key("ticket", t.ticket_id)
        for aid in t.linked_asset_ids:
            if aid and g.get_node(_node_key("asset", str(aid).strip())):
                g.add_edge(tk, _node_key("asset", str(aid).strip()), REL_LINKED_TO_TICKET, {"target": "asset"})
        for eid in t.linked_event_ids:
            if eid and g.get_node(_node_key("event", str(eid).strip())):
                g.add_edge(tk, _node_key("event", str(eid).strip()), REL_LINKED_TO_TICKET, {"target": "event"})
        for fid in t.linked_finding_ids:
            if fid and g.get_node(_node_key("scanner_finding", str(fid).strip())):
                g.add_edge(tk, _node_key("scanner_finding", str(fid).strip()), REL_LINKED_TO_TICKET, {"target": "finding"})

    for p in bundle.poam_items:
        pk = _node_key("poam_item", p.poam_id)
        a, how = _match_asset_for_identifier(
            asset_id=p.asset_identifier,
            name=p.asset_identifier,
            private_ip=None,
            public_ip=None,
            assets=assets,
        )
        if a is not None:
            g.add_edge(_node_key("asset", a.asset_id), pk, REL_TRACKED_BY_POAM, {"match": how, "role": "asset"})
        if p.source_eval_id:
            ek = _node_key("evaluation", str(p.source_eval_id).strip())
            if g.get_node(ek):
                g.add_edge(ek, pk, REL_TRACKED_BY_POAM, {"role": "evaluation"})

    for evr in eval_results:
        ek = _node_key("evaluation", evr.eval_id)
        for c in evr.controls:
            cid = str(c).strip()
            if cid and g.get_node(_node_key("control", cid)):
                g.add_edge(ek, _node_key("control", cid), REL_MAPS_TO_CONTROL, {})
        for kid in eval_to_ksi_ids(
            {"eval_id": evr.eval_id, "control_refs": evr.controls},
            rev5_list,
            default_ksi,
            agent_ksi,
        ):
            if g.get_node(_node_key("ksi", kid)):
                g.add_edge(ek, _node_key("ksi", kid), REL_MAPS_TO_KSI, {})

    # --- Gap synthesis: scanner / logging (inventory-driven) ---
    for inv in bundle.declared_inventory:
        if not (inv.scanner_required and inv.in_boundary):
            continue
        a = _match_asset_for_identifier(
            asset_id=inv.asset_id,
            name=inv.name,
            private_ip=inv.expected_private_ip,
            public_ip=inv.expected_public_ip,
            assets=assets,
        )[0]
        if a is None:
            continue
        ak = _node_key("asset", a.asset_id)
        has_cov = bool(g.find_edges(from_id=ak, relationship=REL_COVERED_BY_SCANNER_TARGET))
        if not has_cov:
            sid = _cloud_scope_id(a)
            if sid and g.get_node(_node_key("cloud_account", sid)):
                g.add_edge(ak, _node_key("cloud_account", sid), REL_MISSING_SCANNER_TARGET, {"inventory_id": inv.inventory_id})

    for inv in bundle.declared_inventory:
        if not (inv.log_required and inv.in_boundary):
            continue
        a = _match_asset_for_identifier(
            asset_id=inv.asset_id,
            name=inv.name,
            private_ip=inv.expected_private_ip,
            public_ip=inv.expected_public_ip,
            assets=assets,
        )[0]
        if a is None:
            continue
        ak = _node_key("asset", a.asset_id)
        sources = [ls for ls in bundle.log_sources if (ls.asset_id or "").strip() == a.asset_id]
        ok = any(_log_active_central(ls, now=now, hours=24.0) for ls in sources)
        if not ok:
            sid = _cloud_scope_id(a)
            if sid and g.get_node(_node_key("cloud_account", sid)):
                g.add_edge(ak, _node_key("cloud_account", sid), REL_MISSING_CENTRAL_LOGGING, {"inventory_id": inv.inventory_id})

    return g


# --- Legacy v1 graph (agent historical bundle shape) ---


def build_evidence_graph(
    *,
    semantic_event: Any,
    inventory_nodes: list[dict[str, Any]],
    scanner_nodes: list[dict[str, Any]],
    log_nodes: list[dict[str, Any]],
    alert_nodes: list[dict[str, Any]],
    ticket_nodes: list[dict[str, Any]],
    vuln_nodes: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "version": "1.0",
        "root_event": semantic_event.model_dump(mode="json"),
        "nodes": {
            "inventory": inventory_nodes,
            "scanner": scanner_nodes,
            "logs": log_nodes,
            "alerts": alert_nodes,
            "tickets": ticket_nodes,
            "vulnerabilities": vuln_nodes,
        },
        "edges": edges,
    }


def edge(
    source_type: str,
    source_id: str,
    rel: str,
    target_type: str,
    target_id: str,
    attrs: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "source": {"type": source_type, "id": source_id},
        "relationship": rel,
        "target": {"type": target_type, "id": target_id},
        "attributes": attrs or {},
    }


def _cypher_escape_literal(s: str) -> str:
    return s.replace("\\", "\\\\").replace("'", "\\'")


def evidence_graph_dict_to_cypher(graph: dict[str, Any]) -> str:
    """Render graph JSON (v3 ``from``/``to``/``relationship``) as Cypher ``MERGE`` fragments."""
    lines: list[str] = [
        "// Observable Security Agent — evidence graph Cypher export",
        "// BuildLab uses JSON only; Cypher is optional downstream.",
    ]
    for n in graph.get("nodes") or []:
        if not isinstance(n, dict):
            continue
        ntype = str(n.get("type") or "unknown")
        nid = str(n.get("id") or "")
        gk = _cypher_escape_literal(_node_key(ntype, nid))
        nt_esc = _cypher_escape_literal(ntype)
        id_esc = _cypher_escape_literal(nid)
        lines.append(
            f"MERGE (n:ObservableGraphNode {{graph_key: '{gk}'}}) "
            f"SET n.node_type = '{nt_esc}', n.natural_id = '{id_esc}';"
        )
    for e in graph.get("edges") or []:
        if not isinstance(e, dict):
            continue
        fr = str(e.get("from") or "")
        to = str(e.get("to") or "")
        rel = str(e.get("relationship") or "")
        rt = LEGACY_REL_TO_CANONICAL.get(rel, rel)
        if not rt or not all(c.isalnum() or c == "_" for c in rt):
            rt = "EVIDENCE_RELATED"
        fr_esc = _cypher_escape_literal(fr)
        to_esc = _cypher_escape_literal(to)
        lines.append(
            f"MATCH (a:ObservableGraphNode {{graph_key: '{fr_esc}'}}), "
            f"(b:ObservableGraphNode {{graph_key: '{to_esc}'}}) "
            f"MERGE (a)-[:{rt}]->(b);"
        )
    return "\n".join(lines) + "\n"


__all__ = [
    "EvidenceGraph",
    "node_key",
    "REL_BELONGS_TO_ACCOUNT",
    "REL_COVERED_BY_ALERT",
    "REL_COVERED_BY_SCANNER_TARGET",
    "REL_EMITS_LOGS_TO",
    "REL_EVENT_TARGETS_ASSET",
    "REL_HAS_FINDING",
    "REL_HAS_PUBLIC_EXPOSURE",
    "REL_INVENTORY_DESCRIBES_ASSET",
    "REL_INSTANCE_OF_EVENT_TYPE",
    "REL_LINKED_TO_TICKET",
    "REL_MAPS_TO_CONTROL",
    "REL_MAPS_TO_KSI",
    "REL_MISSING_ALERT",
    "REL_MISSING_CENTRAL_LOGGING",
    "REL_MISSING_SCANNER_TARGET",
    "REL_MISSING_TICKET",
    "REL_SUPPORTED_BY_EVIDENCE",
    "REL_TRACKED_BY_POAM",
    "build_evidence_graph",
    "edge",
    "evidence_graph_dict_to_cypher",
    "evidence_graph_from_assessment_bundle",
]
