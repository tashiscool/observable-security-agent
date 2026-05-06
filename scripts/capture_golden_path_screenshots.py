"""Render golden-path assurance artifacts into competition PNGs.

The screenshots are generated from real offline demo outputs, not hand-written
mockups. They are intended for README/gallery use when judges want to see the
agentic compliance operations flow without running the app.
"""

from __future__ import annotations

import json
import textwrap
from pathlib import Path
from typing import Any

from PIL import Image, ImageDraw, ImageFont

from core.golden_path import DEFAULT_FIXTURE_DIR, run_golden_path_demo


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_DIR = ROOT / "docs" / "competition"
DEMO_OUTPUT_DIR = ROOT / "build" / "assurance-package-demo"
WIDTH = 1440
HEIGHT = 960
MARGIN = 56
BG = "#f7f8fb"
INK = "#162033"
MUTED = "#56657a"
BLUE = "#2454d6"
GREEN = "#127c55"
RED = "#ba2b2b"
AMBER = "#9a6700"
CARD = "#ffffff"
BORDER = "#d9e0ec"


def _font(size: int, *, bold: bool = False) -> ImageFont.FreeTypeFont | ImageFont.ImageFont:
    candidates = [
        "/System/Library/Fonts/Supplemental/Arial Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Arial.ttf",
        "/System/Library/Fonts/Supplemental/Helvetica Bold.ttf" if bold else "/System/Library/Fonts/Supplemental/Helvetica.ttf",
        "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf" if bold else "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
    ]
    for path in candidates:
        if Path(path).is_file():
            return ImageFont.truetype(path, size=size)
    return ImageFont.load_default()


TITLE = _font(38, bold=True)
H2 = _font(26, bold=True)
BODY = _font(21)
BODY_BOLD = _font(21, bold=True)
SMALL = _font(17)
SMALL_BOLD = _font(17, bold=True)


def _wrap(text: str, width: int) -> list[str]:
    return textwrap.wrap(str(text), width=width, break_long_words=False, replace_whitespace=False) or [""]


def _new(title: str, subtitle: str) -> tuple[Image.Image, ImageDraw.ImageDraw, int]:
    image = Image.new("RGB", (WIDTH, HEIGHT), BG)
    draw = ImageDraw.Draw(image)
    draw.text((MARGIN, 34), title, fill=INK, font=TITLE)
    draw.text((MARGIN, 88), subtitle, fill=MUTED, font=BODY)
    draw.line((MARGIN, 128, WIDTH - MARGIN, 128), fill=BORDER, width=2)
    return image, draw, 158


def _card(draw: ImageDraw.ImageDraw, xy: tuple[int, int, int, int], title: str | None = None) -> None:
    draw.rounded_rectangle(xy, radius=8, fill=CARD, outline=BORDER, width=2)
    if title:
        draw.text((xy[0] + 22, xy[1] + 18), title, fill=INK, font=H2)


def _save(image: Image.Image, filename: str) -> None:
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    image.save(OUTPUT_DIR / filename)


def _status_color(status: str) -> str:
    if status in {"COMPLIANT", "PASS", "READY_FOR_REVIEW", "ACCEPTED"}:
        return GREEN
    if status in {"NON_COMPLIANT", "FAIL", "FALSE_POSITIVE"}:
        return RED
    if status in {"INSUFFICIENT_EVIDENCE", "NEEDS_MORE_EVIDENCE", "RISK_ACCEPTED", "WARN"}:
        return AMBER
    return BLUE


def _pill(draw: ImageDraw.ImageDraw, x: int, y: int, text: str, *, color: str | None = None) -> int:
    fill = color or _status_color(text)
    width = max(95, int(draw.textlength(text, font=SMALL_BOLD)) + 28)
    draw.rounded_rectangle((x, y, x + width, y + 32), radius=16, fill=fill)
    draw.text((x + 14, y + 7), text, fill="white", font=SMALL_BOLD)
    return x + width + 10


def _bullets(draw: ImageDraw.ImageDraw, x: int, y: int, rows: list[str], *, wrap: int = 72, line_gap: int = 9) -> int:
    for row in rows:
        lines = _wrap(row, wrap)
        draw.text((x, y), "-", fill=BLUE, font=BODY_BOLD)
        for i, line in enumerate(lines):
            draw.text((x + 28, y + i * 27), line, fill=INK, font=BODY)
        y += len(lines) * 27 + line_gap
    return y


def _load_demo() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    result = run_golden_path_demo(fixture_dir=DEFAULT_FIXTURE_DIR, output_dir=DEMO_OUTPUT_DIR)
    package = json.loads((DEMO_OUTPUT_DIR / "assurance-package.json").read_text(encoding="utf-8"))
    metrics = json.loads((DEMO_OUTPUT_DIR / "metrics.json").read_text(encoding="utf-8"))
    evals = json.loads((DEMO_OUTPUT_DIR / "eval_results.json").read_text(encoding="utf-8"))
    assert result["schemaValid"] and result["evalsPassed"]
    return package, metrics, evals


def render_pipeline(package: dict[str, Any]) -> None:
    image, draw, y = _new(
        "Golden Path: Agentic Assurance Pipeline",
        "Raw telemetry and scanner evidence becomes a human-reviewed assurance package.",
    )
    steps = [
        ("1", "Ingest", "ECR findings, CloudTrail, IAM, cloud config"),
        ("2", "Normalize", "EvidenceArtifact + NormalizedFinding schemas"),
        ("3", "Map", "Controls RA-5, SI-2, AC-2, AU-6, CM-6, SC-13, CP-4"),
        ("4", "Validate", "presence, freshness, unresolved high findings"),
        ("5", "Reason", "bounded RAG context and deterministic recommendations"),
        ("6", "Review", "false positive, risk accepted, missing evidence"),
        ("7", "Package", "OSCAL-inspired JSON + Markdown reports + metrics"),
    ]
    x = MARGIN
    box_w = 178
    for i, (num, title, desc) in enumerate(steps):
        top = y + (i % 2) * 255
        left = x + (i // 2) * 365
        _card(draw, (left, top, left + box_w, top + 190))
        draw.ellipse((left + 20, top + 20, left + 62, top + 62), fill=BLUE)
        draw.text((left + 34, top + 30), num, fill="white", font=BODY_BOLD)
        draw.text((left + 20, top + 80), title, fill=INK, font=H2)
        for j, line in enumerate(_wrap(desc, 16)):
            draw.text((left + 20, top + 120 + j * 22), line, fill=MUTED, font=SMALL)
        if i < len(steps) - 1:
            arrow_y = top + 95
            draw.line((left + box_w + 8, arrow_y, left + box_w + 142, arrow_y), fill=BLUE, width=4)
            draw.polygon([(left + box_w + 142, arrow_y), (left + box_w + 124, arrow_y - 10), (left + box_w + 124, arrow_y + 10)], fill=BLUE)
    manifest = package["manifest"]
    _card(draw, (MARGIN, 718, WIDTH - MARGIN, 890), "Demo package outcome")
    x = MARGIN + 24
    y = 770
    for label, value in [
        ("Package", manifest["packageStatus"]),
        ("Evidence", str(manifest["evidenceCount"])),
        ("Findings", str(manifest["findingCount"])),
        ("Human reviews", str(manifest["humanReviewedRecommendations"])),
        ("Insufficient", ", ".join(manifest["controlsWithInsufficientEvidence"])),
    ]:
        draw.text((x, y), label, fill=MUTED, font=SMALL_BOLD)
        _pill(draw, x, y + 28, value, color=_status_color(value))
        x += 250
    _save(image, "feature_golden_path_pipeline.png")


def render_assurance_package(package: dict[str, Any]) -> None:
    image, draw, y = _new(
        "Machine-Readable Assurance Package",
        "The package is schema-validated, evidence-linked, and ready for human review.",
    )
    manifest = package["manifest"]
    _card(draw, (MARGIN, y, 680, 520), "Manifest")
    rows = [
        ("Package ID", manifest["packageId"]),
        ("System", manifest["system"]),
        ("Framework", f"{manifest['framework']} / {manifest['baseline']}"),
        ("Status", manifest["packageStatus"]),
        ("Schema", manifest["schemaValidation"]),
        ("Insufficient controls", ", ".join(manifest["controlsWithInsufficientEvidence"])),
    ]
    yy = y + 76
    for label, value in rows:
        draw.text((MARGIN + 24, yy), label, fill=MUTED, font=SMALL_BOLD)
        draw.text((MARGIN + 250, yy), str(value), fill=INK, font=BODY)
        yy += 44
    _card(draw, (720, y, WIDTH - MARGIN, 520), "Package sections")
    sections = [
        f"controls: {len(package['controls'])}",
        f"evidence: {len(package['evidence'])}",
        f"findings: {len(package['findings'])}",
        f"controlMappings: {len(package['controlMappings'])}",
        f"validationResults: {len(package['validationResults'])}",
        f"agentRecommendations: {len(package['agentRecommendations'])}",
        f"humanReviewDecisions: {len(package['humanReviewDecisions'])}",
        f"audit: {len(package['audit'])}",
    ]
    _bullets(draw, 744, y + 76, sections, wrap=38)
    _card(draw, (MARGIN, 560, WIDTH - MARGIN, 888), "Evidence-linked control examples")
    controls = {row["controlId"]: row for row in package["assessmentResults"]}
    examples = [
        f"RA-5: {controls['RA-5']['status']} with findings {', '.join(controls['RA-5']['findingIds'])}",
        f"SI-2: {controls['SI-2']['status']} with findings {', '.join(controls['SI-2']['findingIds'])}",
        f"CP-4: {controls['CP-4']['status']} because no fresh selected evidence exists",
        f"Every finding, validation result, recommendation, and review carries evidenceIds.",
    ]
    _bullets(draw, MARGIN + 24, 636, examples, wrap=100)
    _save(image, "feature_assurance_package_manifest.png")


def render_human_review(package: dict[str, Any]) -> None:
    image, draw, y = _new(
        "Human Review Is Preserved",
        "The agent recommends; humans decide. Review records do not auto-certify controls.",
    )
    decisions = package["humanReviewDecisions"]
    _card(draw, (MARGIN, y, WIDTH - MARGIN, 890), "Reviewer decisions")
    headers = ["Decision", "Recommendation", "Evidence IDs / Finding IDs", "Justification"]
    xs = [MARGIN + 24, 310, 595, 850]
    yy = y + 72
    for x, header in zip(xs, headers):
        draw.text((x, yy), header, fill=MUTED, font=SMALL_BOLD)
    yy += 36
    featured = []
    for wanted in ("FALSE_POSITIVE", "RISK_ACCEPTED", "NEEDS_MORE_EVIDENCE"):
        featured.extend([row for row in decisions if row["decision"] == wanted][:1])
    for row in featured:
        x_next = _pill(draw, xs[0], yy - 5, row["decision"])
        _ = x_next
        draw.text((xs[1], yy), row["recommendationId"], fill=INK, font=SMALL)
        refs = ", ".join((row.get("evidenceIds") or [])[:2] + (row.get("findingIds") or [])[:1])
        for j, line in enumerate(_wrap(refs, 28)[:3]):
            draw.text((xs[2], yy + j * 21), line, fill=INK, font=SMALL)
        for j, line in enumerate(_wrap(row["justification"], 55)[:4]):
            draw.text((xs[3], yy + j * 21), line, fill=INK, font=SMALL)
        yy += 112
        draw.line((MARGIN + 24, yy - 18, WIDTH - MARGIN - 24, yy - 18), fill=BORDER, width=1)
    _bullets(
        draw,
        MARGIN + 24,
        720,
        [
            "Review decisions are stored in the package and reviewer-decisions.md.",
            "False positives and risk acceptances require justification and cited evidence.",
            "Human review does not automatically approve controls or close remediation.",
        ],
        wrap=110,
    )
    _save(image, "feature_human_review_decisions.png")


def render_metrics_evals(package: dict[str, Any], metrics: dict[str, Any], evals: dict[str, Any]) -> None:
    image, draw, y = _new(
        "Observability Metrics And Offline Evals",
        "The demo proves the workflow is testable, measurable, and repeatable without cloud credentials.",
    )
    _card(draw, (MARGIN, y, 680, 890), "Metrics")
    metric_rows = [
        ("retrieval_hit_rate", f"{metrics['retrieval_hit_rate']:.2f}"),
        ("stale_evidence_count", metrics["stale_evidence_count"]),
        ("missing_evidence_count", metrics["missing_evidence_count"]),
        ("high_findings_open", metrics["high_findings_open"]),
        ("critical_findings_open", metrics["critical_findings_open"]),
        ("schema_validation_failure_count", metrics["schema_validation_failure_count"]),
        ("controls_without_evidence", ", ".join(metrics["controls_without_evidence"])),
    ]
    yy = y + 76
    for label, value in metric_rows:
        draw.text((MARGIN + 24, yy), label, fill=MUTED, font=SMALL_BOLD)
        draw.text((MARGIN + 350, yy), str(value), fill=INK, font=BODY)
        yy += 48
    _card(draw, (720, y, WIDTH - MARGIN, 500), "Eval harness")
    summary = evals["summary"]
    _pill(draw, 744, y + 78, f"{summary['passed']}/{summary['total']} PASSED", color=GREEN)
    _bullets(
        draw,
        744,
        y + 140,
        [
            "Control supported by fresh evidence",
            "Insufficient evidence remains insufficient",
            "Stale scan evidence is flagged",
            "Prompt injection and unsupported claims are blocked",
            "Human reviewer accepts with edits",
        ],
        wrap=44,
    )
    _card(draw, (720, 540, WIDTH - MARGIN, 890), "Guardrails")
    _bullets(
        draw,
        744,
        616,
        [
            "No external services or real cloud credentials required for this demo.",
            "Compliance-impacting recommendations require human review.",
            "Missing evidence is never treated as passing evidence.",
            "Generated JSON validates before reports are written.",
        ],
        wrap=46,
    )
    _save(image, "feature_metrics_evals.png")


def main() -> None:
    package, metrics, evals = _load_demo()
    render_pipeline(package)
    render_assurance_package(package)
    render_human_review(package)
    render_metrics_evals(package, metrics, evals)
    print(f"Wrote golden path screenshots to {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
