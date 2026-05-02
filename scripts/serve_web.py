#!/usr/bin/env python3
"""Serve the repo root over HTTP so /web/index.html and /output/* load in the browser."""

from __future__ import annotations

import argparse
import functools
import http.server
import os
import socketserver
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser(description="Serve Security Evidence Explorer (static web + output/).")
    parser.add_argument("--host", default="127.0.0.1", help="Bind address (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port (default 8080)")
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    os.chdir(root)

    class Handler(http.server.SimpleHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path in ("/", "/index.html"):
                self.path = "/web/index.html"
            return super().do_GET()

        def log_message(self, fmt: str, *log_args: object) -> None:
            print(f"[serve_web] {fmt % log_args}")

    handler = functools.partial(Handler, directory=str(root))
    with socketserver.ThreadingTCPServer((args.host, args.port), handler) as httpd:
        url = f"http://{args.host}:{args.port}/web/index.html"
        print("Security Evidence Explorer")
        print(f"  Serving directory: {root}")
        print(f"  Open in browser:   {url}")
        print()
        print("  Existing tabs (cloud / fixture-driven assessment):")
        print("    Assess → build-20x-package with --package-output evidence/package so")
        print("    ../evidence/package/ exists, or rely on web/sample-data/ for eval-only demo.")
        print()
        print("  Tracker → 20x tabs (Tracker Import / Evidence Gaps / Agent Run Trace /")
        print("  LLM Reasoning / 20x Package / Derivation Trace) read from, in order:")
        print("    1. ./output_agent_run/")
        print("    2. ./output_tracker/")
        print("    3. ./web/sample-data/tracker/   (always present)")
        print("  Generate fresh artifacts with:")
        print("    python agent.py run-agent --workflow tracker-to-20x \\")
        print("      --input fixtures/assessment_tracker/sample_tracker.csv \\")
        print("      --output-dir output_agent_run")
        print()
        print("  Optional API for the LLM Reasoning tab (deterministic fallback otherwise):")
        print("    uvicorn api.server:app --host 127.0.0.1 --port 8081")
        print("  Ctrl+C to stop.")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    main()
