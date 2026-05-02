"""Load ``config/public-exposure-policy.yaml`` for ElectricEye/Aurelian-inspired exposure semantics."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

import yaml

from core.models import SemanticType

_AGENT_ROOT = Path(__file__).resolve().parents[1]

ALLOWED_PUBLIC_EXPOSURE_SEMANTICS: frozenset[str] = frozenset(
    {
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
    }
)


@lru_cache(maxsize=8)
def load_public_exposure_policy(*, config_root: Path | None = None) -> dict[str, Any]:
    root = config_root or (_AGENT_ROOT / "config")
    path = root / "public-exposure-policy.yaml"
    if not path.is_file():
        return {}
    raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    return raw if isinstance(raw, dict) else {}


def exposure_rank_for_semantic(semantic: str, *, policy: dict[str, Any] | None = None) -> int:
    pol = policy if policy is not None else load_public_exposure_policy()
    ranks = pol.get("exposure_rank")
    if isinstance(ranks, dict):
        v = ranks.get(semantic)
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, str) and v.strip().isdigit():
            return int(v.strip())
    # Defaults if YAML omits block
    return {
        "network.public_admin_port_opened": 50,
        "network.public_database_port_opened": 40,
        "network.public_sensitive_service_opened": 35,
        "network.firewall_rule_changed": 10,
    }.get(semantic, 0)


def _protocol_matches(svc: dict[str, Any], protocol: str | None) -> bool:
    protos = svc.get("protocols")
    if not protos or not isinstance(protos, list):
        return True
    praw = (protocol or "tcp").lower().strip()
    if praw in ("-1", "all", "any", ""):
        return True
    allowed = {str(x).lower() for x in protos}
    return praw in allowed or "-1" in allowed


def semantic_type_for_exposed_port(port: int, protocol: str | None = None) -> SemanticType:
    """
    Map a single exposed listener port to a ``SemanticType`` using the policy ``services`` list.

    First matching service wins (YAML order). Unknown ports fall back to ``network.firewall_rule_changed``.
    """
    pol = load_public_exposure_policy()
    for svc in pol.get("services") or []:
        if not isinstance(svc, dict):
            continue
        ports = svc.get("ports") or []
        if not isinstance(ports, list):
            continue
        try:
            port_ints = {int(x) for x in ports}
        except (TypeError, ValueError):
            continue
        if int(port) not in port_ints:
            continue
        if not _protocol_matches(svc, protocol):
            continue
        st = str(svc.get("semantic_type") or "")
        if st in ALLOWED_PUBLIC_EXPOSURE_SEMANTICS:
            return st  # type: ignore[return-value]
    return "network.firewall_rule_changed"


def iter_canonical_exposure_probe_ports(*, policy: dict[str, Any] | None = None) -> list[int]:
    """Sorted unique ports from all policy services (used when SG allows all protocols, e.g. ``-1``)."""
    pol = policy if policy is not None else load_public_exposure_policy()
    seen: set[int] = set()
    out: list[int] = []
    for svc in pol.get("services") or []:
        if not isinstance(svc, dict):
            continue
        for p in svc.get("ports") or []:
            try:
                pi = int(p)
            except (TypeError, ValueError):
                continue
            if pi not in seen:
                seen.add(pi)
                out.append(pi)
    return sorted(out)


def merged_query_keywords_for_semantic(semantic_type: str, *, policy: dict[str, Any] | None = None) -> list[str]:
    """Union of ``generated_query_keywords`` from all services sharing a ``semantic_type``."""
    pol = policy if policy is not None else load_public_exposure_policy()
    seen: set[str] = set()
    out: list[str] = []
    for svc in pol.get("services") or []:
        if not isinstance(svc, dict):
            continue
        if str(svc.get("semantic_type") or "") != semantic_type:
            continue
        for kw in svc.get("generated_query_keywords") or []:
            ks = str(kw).strip()
            if ks and ks not in seen:
                seen.add(ks)
                out.append(ks)
    return out


def semantic_type_from_public_exposure_policy(
    *,
    check_id: str,
    title: str,
    policy: dict[str, Any] | None = None,
) -> SemanticType | None:
    """Return a semantic type when a service rule or legacy ``rules`` entry matches; otherwise ``None``."""
    pol = policy if policy is not None else load_public_exposure_policy()
    cid = check_id.lower()
    ttl = title.lower()
    blob = f"{cid} {ttl}"

    for svc in pol.get("services") or []:
        if not isinstance(svc, dict):
            continue
        sem = svc.get("semantic_type")
        if str(sem) not in ALLOWED_PUBLIC_EXPOSURE_SEMANTICS:
            continue
        subs = svc.get("match_check_id_substrings") or []
        if isinstance(subs, list) and any(str(s).lower() in cid for s in subs if str(s).strip()):
            return sem  # type: ignore[return-value]
        pat = svc.get("match_title_regex")
        if isinstance(pat, str) and pat.strip():
            try:
                if re.search(pat, blob):
                    return sem  # type: ignore[return-value]
            except re.error:
                continue

    rules = pol.get("rules")
    if not isinstance(rules, list):
        return None
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        sem = rule.get("semantic_type")
        if str(sem) not in ALLOWED_PUBLIC_EXPOSURE_SEMANTICS:
            continue
        subs = rule.get("match_check_id_substrings") or []
        if isinstance(subs, list) and any(str(s).lower() in cid for s in subs if str(s).strip()):
            return sem  # type: ignore[return-value]
        pat = rule.get("match_title_regex")
        if isinstance(pat, str) and pat.strip():
            try:
                if re.search(pat, blob):
                    return sem  # type: ignore[return-value]
            except re.error:
                continue
    return None
