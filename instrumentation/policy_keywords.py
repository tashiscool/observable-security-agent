"""Enrich generated queries using ``config/public-exposure-policy.yaml`` keywords."""

from __future__ import annotations

from providers.exposure_policy import merged_query_keywords_for_semantic

_PUBLIC_SEM = frozenset(
    {
        "network.public_admin_port_opened",
        "network.public_database_port_opened",
        "network.public_sensitive_service_opened",
    }
)


def splunk_policy_keyword_pipe(semantic_type: str) -> str:
    if semantic_type not in _PUBLIC_SEM:
        return ""
    kws = merged_query_keywords_for_semantic(semantic_type)
    if not kws:
        return ""
    parts: list[str] = []
    for k in kws[:20]:
        kk = str(k).strip()
        if not kk:
            continue
        if any(c in kk for c in (' ', '"', "'", ":")) and not (kk.startswith('"') and kk.endswith('"')):
            parts.append(f'"{kk}"')
        else:
            parts.append(kk)
    if not parts:
        return ""
    return "\n| search (" + " OR ".join(parts) + ")"


def sentinel_policy_where_has_any(semantic_type: str) -> str:
    if semantic_type not in _PUBLIC_SEM:
        return ""
    kws = merged_query_keywords_for_semantic(semantic_type)
    if not kws:
        return ""
    quoted = ", ".join(f'"{str(k).strip()}"' for k in kws[:18] if str(k).strip())
    if not quoted:
        return ""
    return f"\n| where * has_any ({quoted})\n"


def gcp_policy_keyword_or_block(semantic_type: str) -> str:
    if semantic_type not in _PUBLIC_SEM:
        return ""
    kws = merged_query_keywords_for_semantic(semantic_type)
    if not kws:
        return ""
    frags: list[str] = []
    for k in kws[:14]:
        kk = str(k).strip()
        if not kk:
            continue
        frags.append(f'(textPayload:"{kk}" OR protoPayload.request:"{kk}")')
    if not frags:
        return ""
    return "\nAND (" + "\n  OR ".join(frags) + "\n)"


def aws_narrative_policy_footer(semantic_type: str) -> str:
    if semantic_type not in _PUBLIC_SEM:
        return ""
    kws = merged_query_keywords_for_semantic(semantic_type)
    if not kws:
        return ""
    return "\n- Policy keyword hints (config/public-exposure-policy.yaml): " + ", ".join(kws[:24])
