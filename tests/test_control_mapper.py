from __future__ import annotations

import pytest

from core.control_mapper import (
    controls_for_eval,
    get_controls_for_asset_gap,
    get_controls_for_eval,
    get_controls_for_event,
)


def test_get_controls_for_eval_inventory() -> None:
    c = get_controls_for_eval("CM8_INVENTORY_RECONCILIATION")
    assert c == ["CM-8", "CM-8(1)", "CM-8(3)"]


def test_get_controls_for_eval_scanner_full_list() -> None:
    c = get_controls_for_eval("RA5_SCANNER_SCOPE_COVERAGE")
    assert "RA-5(3)" in c
    assert "CA-7" in c
    assert "SI-2" in c


def test_get_controls_for_eval_central_logging_full_list() -> None:
    c = get_controls_for_eval("AU6_CENTRALIZED_LOG_COVERAGE")
    assert "AU-3(1)" in c
    assert "AU-9(2)" in c
    assert "AU-12" in c


def test_get_controls_for_eval_alert_instrumentation() -> None:
    c = get_controls_for_eval("SI4_ALERT_INSTRUMENTATION")
    assert "SI-4(16)" in c
    assert "CM-11" in c


def test_get_controls_for_eval_change_linkage() -> None:
    c = get_controls_for_eval("CM3_CHANGE_EVIDENCE_LINKAGE")
    assert "SA-10" in c
    assert "MA-5" in c


def test_get_controls_for_eval_poam() -> None:
    assert get_controls_for_eval("CA5_POAM_STATUS") == ["CA-5", "CA-7", "RA-5", "CP-9", "CP-10"]


def test_get_controls_for_eval_unknown() -> None:
    assert get_controls_for_eval("NOT-A-REAL-EVAL") == []


def test_get_controls_for_agent_evals() -> None:
    assert "AC-6" in get_controls_for_eval("AGENT_TOOL_GOVERNANCE")
    assert "SC-28" in get_controls_for_eval("AGENT_MEMORY_CONTEXT_SAFETY")
    assert "AU-2" in get_controls_for_eval("AGENT_AUDITABILITY")


def test_controls_for_eval_alias() -> None:
    assert controls_for_eval("CM8_INVENTORY_RECONCILIATION") == get_controls_for_eval(
        "CM8_INVENTORY_RECONCILIATION"
    )


@pytest.mark.parametrize(
    "semantic,expected_subset",
    [
        ("identity.user_created", ("AC-2", "IA-5")),
        ("network.public_admin_port_opened", ("SC-7", "CM-7")),
        ("network.public_sensitive_service_opened", ("SC-7", "CM-7")),
        ("logging.central_ingestion_missing", ("AU-12", "AU-6(3)")),
        ("scanner.asset_missing_from_scope", ("RA-5(6)",)),
        ("change.no_ticket_linked", ("CM-3",)),
        ("unknown", ()),
    ],
)
def test_get_controls_for_event(semantic: str, expected_subset: tuple[str, ...]) -> None:
    c = get_controls_for_event(semantic)
    for x in expected_subset:
        assert x in c or (not expected_subset and c == [])


def test_get_controls_for_event_firewall_merges_boundary_and_change() -> None:
    c = get_controls_for_event("network.firewall_rule_changed")
    assert "SC-7" in c and "CM-3" in c
    # deterministic dedupe: CM-7 appears once
    assert c.count("CM-7") == 1


def test_get_controls_for_event_unknown_semantic() -> None:
    assert get_controls_for_event("not.in.schema") == []


def test_get_controls_for_asset_gap_aliases() -> None:
    assert get_controls_for_asset_gap("inventory") == get_controls_for_asset_gap(
        "inventory_completeness"
    )
    assert get_controls_for_asset_gap("central_logging") == get_controls_for_asset_gap(
        "centralized_audit_logging"
    )


def test_get_controls_for_asset_gap_normalizes_key() -> None:
    assert get_controls_for_asset_gap("  Scanner_Scope ") == get_controls_for_asset_gap(
        "scanner_scope"
    )


def test_get_controls_for_asset_gap_unknown() -> None:
    assert get_controls_for_asset_gap("no_such_gap") == []
