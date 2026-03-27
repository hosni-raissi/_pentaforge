"""
Target Validation Middleware Integration Test
=============================================
Probes your live server to verify middleware target validation is enforced
for URL/IP fields (using safety target_validation layer).

What it checks:
  - Middleware marker is present.
  - Valid target payloads are accepted.
  - Invalid IP payloads are denied with 422.
  - Invalid URL payloads are denied with 422.
  - Mixed invalid payloads report multiple errors.
  - Non-target text fields are ignored.

Usage:
    python -u server/test/test_target_validation_layer.py

Requirements:
    - Server running at BASE (default http://127.0.0.1:8000)
    - stdlib only
"""

from __future__ import annotations

import json
import sys
import uuid
from typing import Any, Optional
from urllib import error, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE = "http://127.0.0.1:8000"
TIMEOUT = 8
RESET_ENDPOINT = "/api/debug/rate-limit/reset"   # Optional


# ---------------------------------------------------------------------------
# HTTP helpers
# ---------------------------------------------------------------------------

def _header_get(headers: dict, name: str) -> Optional[str]:
    needle = name.lower()
    for k, v in headers.items():
        if k.lower() == needle:
            return v
    return None


def call(
    method: str,
    path: str,
    payload: Any = None,
    headers: Optional[dict] = None,
) -> tuple[int, dict, str]:
    req_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        req_headers.setdefault("Content-Type", "application/json")
    req = request.Request(BASE + path, data=data, headers=req_headers, method=method)
    try:
        with request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read().decode()
    except error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()
    except error.URLError as e:
        print(f"\n  ✗ Connection error: {e.reason}")
        print(f"    Is the server running at {BASE}?")
        sys.exit(1)


def _json(body: str) -> dict:
    try:
        value = json.loads(body)
        if isinstance(value, dict):
            return value
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Runner utilities
# ---------------------------------------------------------------------------

PASS = 0
FAIL = 0
SKIP = 0


def _section(title: str) -> None:
    print(f"\n{'─' * 60}")
    print(f"  {title}")
    print(f"{'─' * 60}")


def _ok(msg: str) -> None:
    print(f"  ✓  {msg}")


def _fail(msg: str) -> None:
    global FAIL
    FAIL += 1
    print(f"  ✗  FAIL: {msg}")


def _skip(msg: str) -> None:
    global SKIP
    SKIP += 1
    print(f"  –  SKIP: {msg}")


def _check(cond: bool, pass_msg: str, fail_msg: str) -> bool:
    global PASS
    if cond:
        PASS += 1
        _ok(pass_msg)
        return True
    _fail(fail_msg)
    return False


def _reset_limiter() -> None:
    code, _, _ = call("POST", RESET_ENDPOINT)
    if code in (200, 204):
        print(f"  ↺  reset via {RESET_ENDPOINT}")
    else:
        _skip(f"reset endpoint unavailable ({code}); continuing")


def _new_project_payload(**extra: Any) -> dict[str, Any]:
    payload = {
        "id": f"tv-{uuid.uuid4()}",
        "name": "target-validation-test",
    }
    payload.update(extra)
    return payload


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_reachability_and_marker() -> bool:
    _section("Phase 0 — Reachability + Middleware Marker")
    code, _, _ = call("GET", "/api/health")
    if not _check(code == 200, "/api/health returned 200", f"/api/health returned {code}"):
        return False

    _reset_limiter()
    code, headers, _ = call("GET", "/api/projects")
    rl_marker = _header_get(headers, "X-PentaForge-Rate-Limiter")
    if not _check(
        rl_marker == "active",
        f"Rate-limiter marker present (status {code})",
        f"Missing rate-limiter marker on /api/projects (status {code})",
    ):
        return False

    tv_marker = _header_get(headers, "X-PentaForge-Target-Validation")
    if tv_marker == "active":
        _ok(f"Target-validation marker present (status {code})")
    else:
        _skip(
            "Target-validation marker missing on GET /api/projects. "
            "Will verify functional behavior with invalid payload checks."
        )

    # Functional preflight for target validation layer (truth source).
    payload = _new_project_payload(targetConfig={"target_ip": "999.1.1.1"})
    code, headers, body = call("POST", "/api/projects", payload)
    data = _json(body)
    component = data.get("component")
    return _check(
        code == 422 and component == "target_validation",
        "Functional preflight passed: invalid target is blocked by target_validation",
        (
            f"Functional preflight failed (status={code}, component={component!r}). "
            "You are likely hitting an older server instance; restart uvicorn and retry."
        ),
    )


def test_valid_payloads() -> None:
    _section("Phase 1 — Valid Payloads Accepted")
    _reset_limiter()

    payload = _new_project_payload(target="127.0.0.1")
    code, _, body = call("POST", "/api/projects", payload)
    _check(code == 200, "Top-level valid IP accepted", f"Expected 200, got {code}: {body}")

    _reset_limiter()
    payload = _new_project_payload(
        targetConfig={
            "target_ip": "127.0.0.1",
            "base_url": "http://127.0.0.1:8000/api/health",
        }
    )
    code, _, body = call("POST", "/api/projects", payload)
    _check(code == 200, "Nested valid IP+URL accepted", f"Expected 200, got {code}: {body}")


def test_invalid_ip_rejected() -> None:
    _section("Phase 2 — Invalid IP Rejected")
    _reset_limiter()

    payload = _new_project_payload(targetConfig={"target_ip": "999.1.1.1"})
    code, headers, body = call("POST", "/api/projects", payload)
    data = _json(body)
    errors = data.get("errors", [])
    has_ip_error = any(
        isinstance(item, dict)
        and item.get("type") == "ip"
        and "target_ip" in str(item.get("field", ""))
        for item in errors
    )
    marker = _header_get(headers, "X-PentaForge-Target-Validation")

    _check(code == 422, "Invalid IP returned 422", f"Expected 422, got {code}: {body}")
    _check(marker == "active", "Validation marker present on deny", "Missing validation marker on deny")
    _check(has_ip_error, "IP error details present", f"Expected IP error in body, got: {body}")


def test_invalid_url_rejected() -> None:
    _section("Phase 3 — Invalid URL Rejected")
    _reset_limiter()

    payload = _new_project_payload(targetConfig={"base_url": "not-a-url"})
    code, _, body = call("POST", "/api/projects", payload)
    data = _json(body)
    errors = data.get("errors", [])
    has_url_error = any(
        isinstance(item, dict)
        and item.get("type") == "url"
        and "base_url" in str(item.get("field", ""))
        for item in errors
    )

    _check(code == 422, "Invalid URL returned 422", f"Expected 422, got {code}: {body}")
    _check(has_url_error, "URL error details present", f"Expected URL error in body, got: {body}")


def test_mixed_errors() -> None:
    _section("Phase 4 — Mixed Invalid Payload Returns Multiple Errors")
    _reset_limiter()

    payload = _new_project_payload(
        targetConfig={
            "target_ip": "999.1.1.1",
            "base_url": "not-a-url",
        }
    )
    code, _, body = call("POST", "/api/projects", payload)
    data = _json(body)
    errors = data.get("errors", [])
    error_types = {
        item.get("type")
        for item in errors
        if isinstance(item, dict)
    }

    _check(code == 422, "Mixed invalid payload returned 422", f"Expected 422, got {code}: {body}")
    _check(
        {"ip", "url"}.issubset(error_types),
        "Both IP and URL errors reported",
        f"Expected both ip/url errors, got {sorted(error_types)}; body={body}",
    )


def test_non_target_fields_ignored() -> None:
    _section("Phase 5 — Non-target Fields Ignored")
    _reset_limiter()

    payload = _new_project_payload(description="not-a-url-and-should-not-be-validated")
    code, _, body = call("POST", "/api/projects", payload)
    _check(
        code == 200,
        "Non-target description field did not trigger validation",
        f"Expected 200 for non-target fields, got {code}: {body}",
    )


def summary() -> None:
    total = PASS + FAIL + SKIP
    print(f"\n{'═' * 60}")
    print(f"  Results: {PASS} passed  {FAIL} failed  {SKIP} skipped  ({total} total)")
    print(f"{'═' * 60}")

    if FAIL > 0:
        sys.exit(1)
    print("\n  ALL TARGET VALIDATION CHECKS PASSED ✅\n")


if __name__ == "__main__":
    print("\nTarget Validation Middleware Integration Test")
    print(f"Target server: {BASE}")

    if not test_reachability_and_marker():
        print("\nServer/middleware preflight failed — aborting.")
        sys.exit(1)

    test_valid_payloads()
    test_invalid_ip_rejected()
    test_invalid_url_rejected()
    test_mixed_errors()
    test_non_target_fields_ignored()
    summary()
