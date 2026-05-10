"""Screenshot capture and annotation tools for Analyzer."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any

import structlog

from server.core.tool import tool
from ..config import (
    SCREENSHOT_TIMEOUT,
    SCREENSHOT_VIEWPORT_WIDTH,
    SCREENSHOT_VIEWPORT_HEIGHT,
    SCREENSHOT_FORMAT,
    SCREENSHOT_STORAGE_PATH,
    REDACT_URL_PARAMS,
    BROWSER_TYPE,
    BROWSER_HEADLESS,
    BROWSER_IGNORE_HTTPS_ERRORS,
    BROWSER_USER_AGENT,
    ANNOTATION_COLOR,
    ANNOTATION_BORDER_WIDTH,
    EVIDENCE_HASH_ALGORITHM,
)

log = structlog.get_logger(__name__)


def _ensure_storage_dir() -> Path:
    """Ensure screenshot storage directory exists."""
    path = Path(SCREENSHOT_STORAGE_PATH)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _hash_content(content: bytes) -> str:
    """Generate SHA-256 hash of content."""
    return hashlib.sha256(content).hexdigest()


def _redact_url(url: str) -> str:
    """Redact sensitive parameters from URL."""
    if not REDACT_URL_PARAMS:
        return url

    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    # Redact known sensitive params
    sensitive_params = ["password", "token", "key", "secret", "auth", "session", "payload"]
    for param in params:
        if any(s in param.lower() for s in sensitive_params):
            params[param] = ["[REDACTED]"]

    # Redact anything that looks like a payload
    for param, values in params.items():
        for i, value in enumerate(values):
            if any(c in value for c in ["<", ">", "'", '"', ";", "|", "&"]):
                params[param][i] = "[PAYLOAD_REDACTED]"

    new_query = urlencode(params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))


@tool(
    name="capture_screenshot",
    description=(
        "Capture a screenshot of a web page using Playwright. "
        "Automatically redacts sensitive URL parameters and payloads."
    ),
)
async def capture_screenshot(
    url: str,
    label: str = "screenshot",
    wait_for: str = "networkidle",
    cookie: str = "",
    full_page: bool = False,
) -> str:
    """
    Capture screenshot of a URL.

    Args:
        url: URL to screenshot (sensitive params will be redacted)
        label: Label for the screenshot file
        wait_for: Wait condition - load, domcontentloaded, networkidle
        cookie: Cookie string for authenticated access
        full_page: Capture full scrollable page
    """
    try:
        from playwright.async_api import async_playwright
    except ImportError:
        return json.dumps({"error": "Playwright not installed. Run: pip install playwright && playwright install"})

    if not url:
        return json.dumps({"error": "URL is required"})

    storage_dir = _ensure_storage_dir()
    timestamp = int(time.time() * 1000)
    filename = f"{label}_{timestamp}.{SCREENSHOT_FORMAT}"
    filepath = storage_dir / filename

    redacted_url = _redact_url(url)

    try:
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=BROWSER_HEADLESS)
            context = await browser.new_context(
                viewport={"width": SCREENSHOT_VIEWPORT_WIDTH, "height": SCREENSHOT_VIEWPORT_HEIGHT},
                ignore_https_errors=BROWSER_IGNORE_HTTPS_ERRORS,
                user_agent=BROWSER_USER_AGENT,
            )

            # Set cookies if provided
            if cookie:
                # Parse cookie string
                cookies_list = []
                for c in cookie.split(";"):
                    if "=" in c:
                        name, value = c.strip().split("=", 1)
                        cookies_list.append({
                            "name": name,
                            "value": value,
                            "url": url,
                        })
                if cookies_list:
                    await context.add_cookies(cookies_list)

            page = await context.new_page()

            # Navigate
            await page.goto(url, wait_until=wait_for, timeout=SCREENSHOT_TIMEOUT)

            # Inject URL and Timestamp overlay for "Best Practices" reporting
            formatted_time = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            await page.evaluate(
                """([url, time]) => {
                    const banner = document.createElement('div');
                    banner.id = 'pentaforge-evidence-banner';
                    banner.style.cssText = `
                        position: fixed;
                        top: 0;
                        left: 0;
                        width: 100%;
                        background: rgba(0, 0, 0, 0.85);
                        color: #00ff00;
                        font-family: 'Courier New', Courier, monospace;
                        font-size: 13px;
                        padding: 8px 15px;
                        z-index: 2147483647;
                        border-bottom: 2px solid #00ff00;
                        display: flex;
                        justify-content: space-between;
                        pointer-events: none;
                        box-sizing: border-box;
                    `;
                    banner.innerHTML = `
                        <span><strong>URL:</strong> ${url}</span>
                        <span><strong>TIMESTAMP:</strong> ${time}</span>
                    `;
                    document.body.prepend(banner);
                    // Shift body down if needed, or just let it overlay
                    document.body.style.paddingTop = '35px';
                }""",
                [redacted_url, formatted_time],
            )

            # Capture screenshot
            screenshot_bytes = await page.screenshot(
                path=str(filepath),
                full_page=full_page,
                type=SCREENSHOT_FORMAT,
            )

            await browser.close()

        # Calculate hash
        content_hash = _hash_content(filepath.read_bytes())

        return json.dumps({
            "success": True,
            "path": str(filepath),
            "hash": f"sha256:{content_hash}",
            "redacted_url": redacted_url,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "viewport": f"{SCREENSHOT_VIEWPORT_WIDTH}x{SCREENSHOT_VIEWPORT_HEIGHT}",
            "evidence_overlay": True,
        })

    except Exception as e:
        log.error("screenshot_capture_failed", url=redacted_url, error=str(e))
        return json.dumps({
            "success": False,
            "error": str(e),
            "redacted_url": redacted_url,
        })


@tool(
    name="annotate_screenshot",
    description="Add bounding box annotations to a screenshot highlighting vulnerability indicators.",
)
async def annotate_screenshot(
    screenshot_path: str,
    bounding_boxes: list[dict[str, Any]],
    output_suffix: str = "_annotated",
) -> str:
    """
    Annotate screenshot with bounding boxes.

    Args:
        screenshot_path: Path to the screenshot file
        bounding_boxes: List of boxes: [{"x": 0, "y": 0, "width": 100, "height": 50, "label": "..."}]
        output_suffix: Suffix for the annotated output file
    """
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return json.dumps({"error": "Pillow not installed. Run: pip install Pillow"})

    if not screenshot_path or not os.path.exists(screenshot_path):
        return json.dumps({"error": f"Screenshot not found: {screenshot_path}"})

    try:
        # Load image
        img = Image.open(screenshot_path)
        draw = ImageDraw.Draw(img)

        # Try to load font, fall back to default
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 14)
        except Exception:
            font = ImageFont.load_default()

        # Draw bounding boxes
        for box in bounding_boxes:
            x = box.get("x", 0)
            y = box.get("y", 0)
            w = box.get("width", 100)
            h = box.get("height", 50)
            label = box.get("label", "")

            # Draw rectangle
            draw.rectangle(
                [(x, y), (x + w, y + h)],
                outline=ANNOTATION_COLOR,
                width=ANNOTATION_BORDER_WIDTH,
            )

            # Draw label background and text
            if label:
                text_bbox = draw.textbbox((0, 0), label, font=font)
                text_width = text_bbox[2] - text_bbox[0]
                text_height = text_bbox[3] - text_bbox[1]

                # Label background
                draw.rectangle(
                    [(x, y - text_height - 4), (x + text_width + 8, y)],
                    fill=ANNOTATION_COLOR,
                )
                # Label text
                draw.text((x + 4, y - text_height - 2), label, fill="white", font=font)

        # Save annotated image
        base, ext = os.path.splitext(screenshot_path)
        output_path = f"{base}{output_suffix}{ext}"
        img.save(output_path)

        # Calculate hash
        content_hash = _hash_content(Path(output_path).read_bytes())

        return json.dumps({
            "success": True,
            "original_path": screenshot_path,
            "annotated_path": output_path,
            "hash": f"sha256:{content_hash}",
            "annotations_count": len(bounding_boxes),
        })

    except Exception as e:
        log.error("screenshot_annotation_failed", error=str(e))
        return json.dumps({"error": str(e)})


@tool(
    name="capture_before_after",
    description="Capture before and after screenshots for exploitation verification.",
)
async def capture_before_after(
    url: str,
    exploit_url: str = "",
    label: str = "verification",
    cookie: str = "",
    wait_between_ms: int = 1000,
) -> str:
    """
    Capture before and after screenshots.

    Args:
        url: Base URL (for "before" screenshot)
        exploit_url: URL with exploitation result (for "after" screenshot). If empty, uses same URL.
        label: Label prefix for screenshots
        cookie: Cookie string for authentication
        wait_between_ms: Wait time between captures
    """
    # Capture "before"
    before_result = await capture_screenshot(
        url=url,
        label=f"{label}_before",
        cookie=cookie,
    )
    before_data = json.loads(before_result)

    if not before_data.get("success"):
        return json.dumps({
            "success": False,
            "error": f"Failed to capture 'before' screenshot: {before_data.get('error')}",
        })

    # Wait
    await asyncio.sleep(wait_between_ms / 1000)

    # Capture "after"
    after_url = exploit_url or url
    after_result = await capture_screenshot(
        url=after_url,
        label=f"{label}_after",
        cookie=cookie,
    )
    after_data = json.loads(after_result)

    if not after_data.get("success"):
        return json.dumps({
            "success": False,
            "error": f"Failed to capture 'after' screenshot: {after_data.get('error')}",
            "before": before_data,
        })

    return json.dumps({
        "success": True,
        "before": {
            "path": before_data["path"],
            "hash": before_data["hash"],
        },
        "after": {
            "path": after_data["path"],
            "hash": after_data["hash"],
        },
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    })


@tool(
    name="create_evidence_chain",
    description="Create a SHA-256 signed evidence chain linking screenshots and findings.",
)
async def create_evidence_chain(
    finding_id: str,
    before_hash: str,
    after_hash: str,
    verification_result: str,
    metadata: dict[str, Any] | None = None,
) -> str:
    """
    Create signed evidence chain.

    Args:
        finding_id: ID of the finding being verified
        before_hash: SHA-256 hash of before screenshot
        after_hash: SHA-256 hash of after screenshot
        verification_result: Result of verification (confirmed/rejected/inconclusive)
        metadata: Additional metadata to include
    """
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    chain = {
        "version": "1.0",
        "finding_id": finding_id,
        "before_evidence_hash": before_hash,
        "after_evidence_hash": after_hash,
        "verification_result": verification_result,
        "timestamp": timestamp,
        "metadata": metadata or {},
    }

    # Create chain hash
    chain_content = json.dumps(chain, sort_keys=True)
    chain_hash = hashlib.sha256(chain_content.encode()).hexdigest()

    # Sign the chain (simplified - in production use proper signing)
    chain["chain_hash"] = f"sha256:{chain_hash}"
    chain["signature"] = f"sig:{_hash_content(chain_content.encode())[:32]}"

    return json.dumps({
        "evidence_chain": chain,
        "chain_hash": chain["chain_hash"],
        "created_at": timestamp,
    })
