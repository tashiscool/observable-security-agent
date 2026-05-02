"""``secure_agent_architecture.md`` generator and CLI."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from core.secure_agent_architecture import build_secure_agent_architecture_markdown, write_secure_agent_architecture

ROOT = Path(__file__).resolve().parents[1]


def test_build_markdown_references_agentic_fixture() -> None:
    md = build_secure_agent_architecture_markdown(ROOT)
    assert "scenario_agentic_risk" in md
    assert "support-ticket-agent" in md
    assert "cloud_admin_tool" in md or "blocked" in md
    assert "```" in md


def test_secure_agent_arch_cli(tmp_path: Path) -> None:
    r = subprocess.run(
        [sys.executable, str(ROOT / "agent.py"), "secure-agent-arch", "--output-dir", str(tmp_path)],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    assert r.returncode == 0, r.stderr + r.stdout
    out = tmp_path / "secure_agent_architecture.md"
    assert out.is_file()
    assert "Policy engine" in out.read_text(encoding="utf-8")


def test_write_sample_data_shape(tmp_path: Path) -> None:
    write_secure_agent_architecture(tmp_path / "secure_agent_architecture.md", repo_root=ROOT)
    assert "Observability" in (tmp_path / "secure_agent_architecture.md").read_text(encoding="utf-8")
