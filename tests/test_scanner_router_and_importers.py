"""Universal import routers for scanner, ticket, and inventory evidence."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from providers.inventory_graph import import_graph_assets
from providers.scanner_router import detect_scanner_format, import_scanner
from providers.ticket_export import import_tickets

ROOT = Path(__file__).resolve().parents[1]
AGENT = ROOT / "agent.py"


def test_auto_detects_and_imports_prowler_reference_sample() -> None:
    path = ROOT / "reference_samples" / "prowler" / "outputs" / "scan_result_sample.json"
    assert detect_scanner_format(path) == "prowler"
    fmt, findings, events = import_scanner(path, source_format="auto")
    assert fmt == "prowler"
    assert findings
    assert any(e.semantic_type == "network.public_admin_port_opened" for e in events)


def test_imports_nessus_like_csv(tmp_path: Path) -> None:
    p = tmp_path / "nessus.csv"
    p.write_text(
        "Plugin ID,Risk,Host,Port,Name,CVE,Status\n"
        "19506,High,prod-api-01,443,Nessus Scan Information,CVE-2024-0001,Open\n",
        encoding="utf-8",
    )
    fmt, findings, events = import_scanner(p, source_format="auto")
    assert fmt == "nessus"
    assert events == []
    assert findings[0].scanner_name == "nessus"
    assert findings[0].severity == "high"
    assert findings[0].cve_ids == ["CVE-2024-0001"]


def test_import_tickets_handles_jira_and_servicenow_like_fields(tmp_path: Path) -> None:
    p = tmp_path / "tickets.csv"
    p.write_text(
        "issue_key,summary,state,assets,findings,sia,testing,approval,deployment,verification,source\n"
        "CHG-100,Patch production API,Done,prod-api-01,FIND-1,yes,yes,yes,yes,no,Jira\n"
        "INC0002,Investigate alert,Closed,prod-api-02,,no,no,yes,no,yes,ServiceNow\n",
        encoding="utf-8",
    )
    tickets = import_tickets(p)
    assert [t.system for t in tickets] == ["jira", "servicenow"]
    assert tickets[0].has_security_impact_analysis is True
    assert tickets[0].has_verification_evidence is False
    assert tickets[1].linked_asset_ids == ["prod-api-02"]


def test_inventory_graph_import_normalizes_assets(tmp_path: Path) -> None:
    p = tmp_path / "graph.json"
    p.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "id": "arn:aws:ec2:us-east-1:111122223333:instance/i-abc",
                        "type": "Instance",
                        "name": "prod-api-01",
                        "account_id": "111122223333",
                        "region": "us-east-1",
                        "tags": {"Environment": "prod"},
                        "public_ips": ["203.0.113.10"],
                    }
                ],
                "edges": [],
            }
        ),
        encoding="utf-8",
    )
    assets = import_graph_assets(p)
    assert len(assets) == 1
    assert assets[0].provider == "aws"
    assert assets[0].asset_type == "compute"
    assert assets[0].environment == "prod"


def test_cli_import_findings_auto_and_import_tickets_and_inventory_graph(tmp_path: Path) -> None:
    scanner_out = tmp_path / "scanner"
    rc = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "import-findings",
            "--format",
            "auto",
            "--input",
            str(ROOT / "reference_samples" / "cloudsploit" / "outputs" / "scan_result_sample.csv"),
            "--output",
            str(scanner_out),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert rc.returncode == 0, rc.stderr
    assert json.loads((scanner_out / "scanner_findings.json").read_text(encoding="utf-8"))["scanner"] == "cloudsploit"

    ticket_csv = tmp_path / "tickets.csv"
    ticket_csv.write_text("key,title,status,asset_id,approval\nCHG-1,Change,Closed,prod-api-01,yes\n", encoding="utf-8")
    rc2 = subprocess.run(
        [sys.executable, str(AGENT), "import-tickets", "--input", str(ticket_csv), "--output", str(tmp_path / "scenario")],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert rc2.returncode == 0, rc2.stderr
    assert (tmp_path / "scenario" / "tickets.json").is_file()

    graph_json = tmp_path / "graph.json"
    graph_json.write_text(json.dumps({"assets": [{"id": "asset-1", "type": "bucket", "name": "storage"}]}), encoding="utf-8")
    rc3 = subprocess.run(
        [
            sys.executable,
            str(AGENT),
            "import-inventory-graph",
            "--input",
            str(graph_json),
            "--output",
            str(tmp_path / "scenario"),
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
    )
    assert rc3.returncode == 0, rc3.stderr
    assert (tmp_path / "scenario" / "discovered_assets.json").is_file()
