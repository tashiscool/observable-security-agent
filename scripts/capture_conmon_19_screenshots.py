import asyncio
import os
from playwright.async_api import async_playwright

OUTPUT_DIR = os.path.join("docs", "competition")
os.makedirs(OUTPUT_DIR, exist_ok=True)

async def capture_panel(page, panel_id, filename):
    print(f"Capturing {panel_id} to {filename}...")
    await page.click(f"a.nav-item[data-panel='{panel_id}']")
    await page.wait_for_timeout(1000)
    # Scroll down a bit so we can see the 19 items
    await page.evaluate("window.scrollBy(0, 300)")
    await page.screenshot(path=os.path.join(OUTPUT_DIR, filename), full_page=False)

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(viewport={'width': 1280, 'height': 800})
        page = await context.new_page()

        print("Navigating to Evidence Explorer...")
        await page.goto("http://127.0.0.1:8080/web/index.html")
        await page.wait_for_timeout(2000)

        await capture_panel(page, 'tracker-import', 'conmon_19_tracker_import.png')
        await capture_panel(page, 'tracker-gaps', 'conmon_19_evidence_gaps.png')

        print("Captures complete.")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
