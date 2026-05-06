import asyncio
import os
import subprocess
import sys
from playwright.async_api import async_playwright

OUTPUT_DIR = os.path.join("docs", "competition")
BASE_URL = os.environ.get("OSA_WEB_URL", "http://127.0.0.1:8080/web/index.html")
os.makedirs(OUTPUT_DIR, exist_ok=True)

def ensure_golden_path_artifacts():
    print("Generating golden path artifacts for browser UI panels...")
    subprocess.run(
        [
            sys.executable,
            "agent.py",
            "golden-path-demo",
            "--output-dir",
            os.path.join("build", "assurance-package-demo"),
        ],
        check=True,
    )

async def capture_panel(page, panel_id, filename):
    print(f"Capturing {panel_id} to {filename}...")
    await page.click(f"a.nav-item[data-panel='{panel_id}']")
    await page.wait_for_timeout(1000)  # Wait for animation and render
    await page.screenshot(path=os.path.join(OUTPUT_DIR, filename), full_page=False)

async def main():
    ensure_golden_path_artifacts()
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={'width': 1280, 'height': 800})
        page = await context.new_page()

        print("Navigating to Evidence Explorer...")
        await page.goto(BASE_URL)
        await page.wait_for_timeout(2000)  # Wait for initial data load

        # Original ConMon ones
        print("Capturing ConMon scenarios...")
        await page.click("a.nav-item[data-panel='evals']")
        await page.wait_for_selector("#eval-table tbody tr", state="visible")
        
        await page.locator("#eval-table tbody tr", has_text="CM8_INVENTORY_RECONCILIATION").click()
        await page.wait_for_timeout(500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "conmon_cm8_inventory_reconciliation.png"))

        await page.locator("#eval-table tbody tr", has_text="RA5_SCANNER_SCOPE_COVERAGE").click()
        await page.wait_for_timeout(500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "conmon_ra5_vulnerability_scanning.png"))

        await page.locator("#eval-table tbody tr", has_text="SI4_ALERT_INSTRUMENTATION").click()
        await page.wait_for_timeout(500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "conmon_si4_system_monitoring.png"))

        await page.click("a.nav-item[data-panel='poam']")
        await page.wait_for_timeout(500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "conmon_ca5_poam_updates.png"))

        await page.click("a.nav-item[data-panel='agent-run']")
        await page.wait_for_selector("#agent-run-summary")
        await page.evaluate("window.scrollBy(0, 300)")
        await page.wait_for_timeout(500)
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "conmon_threat_hunt_agentic_risk.png"))

        # Core Panels
        print("Capturing Core Panels...")
        await page.evaluate("window.scrollTo(0, 0)")
        await capture_panel(page, 'graph', 'feature_evidence_graph.png')
        await capture_panel(page, 'correlations', 'feature_correlation_timelines.png')
        await capture_panel(page, 'controls', 'feature_control_view.png')
        await capture_panel(page, 'assets', 'feature_asset_view.png')

        # Agent Capabilities
        print("Capturing Agent Capabilities...")
        await capture_panel(page, 'instrumentation', 'feature_instrumentation.png')
        await capture_panel(page, 'secure-agent', 'feature_secure_agent_architecture.png')
        await capture_panel(page, 'auditor', 'feature_auditor_questions.png')

        # Golden path assurance package panels
        print("Capturing Golden Path Assurance Package Panels...")
        await capture_panel(page, 'golden-path', 'feature_golden_path_pipeline.png')
        await capture_panel(page, 'assurance-package', 'feature_assurance_package_manifest.png')
        await capture_panel(page, 'assurance-evidence', 'feature_assurance_evidence_findings.png')
        await capture_panel(page, 'human-review', 'feature_human_review_decisions.png')
        await capture_panel(page, 'metrics-evals', 'feature_metrics_evals.png')
        await capture_panel(page, 'reports-log', 'feature_reports_run_log.png')
        
        # AI Explain
        await capture_panel(page, 'ai', 'feature_ai_explain.png')

        # FedRAMP 20x
        print("Capturing FedRAMP 20x Panels...")
        await capture_panel(page, '20x-dashboard', 'feature_20x_dashboard.png')
        await capture_panel(page, '20x-ksi', 'feature_20x_ksi_explorer.png')
        await capture_panel(page, '20x-crosswalk', 'feature_20x_crosswalk.png')
        await capture_panel(page, '20x-findings', 'feature_20x_findings.png')
        await capture_panel(page, '20x-recon', 'feature_20x_reconciliation.png')

        # Tracker → 20x
        print("Capturing Tracker -> 20x Panels...")
        await capture_panel(page, 'tracker-import', 'feature_tracker_import.png')
        await capture_panel(page, 'tracker-gaps', 'feature_tracker_evidence_gaps.png')
        await capture_panel(page, 'tracker-trace', 'feature_tracker_agent_run_trace.png')
        await capture_panel(page, 'tracker-llm', 'feature_tracker_llm_reasoning.png')
        await capture_panel(page, 'tracker-package', 'feature_tracker_20x_package.png')
        await capture_panel(page, 'tracker-derivation', 'feature_tracker_derivation_trace.png')
        
        # Capture 3PAO Remediation in the LLM panel explicitly
        print("Capturing 3PAO Remediation Panel...")
        await page.click("a.nav-item[data-panel='tracker-llm']")
        await page.wait_for_timeout(500)
        # In a real run, you'd select the gap and click "Evaluate 3PAO Remediation"
        # We will take a screenshot of the panel itself to show the capability exists.
        await page.screenshot(path=os.path.join(OUTPUT_DIR, "feature_tracker_3pao_remediation.png"))

        print("Done capturing ALL screenshots.")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
