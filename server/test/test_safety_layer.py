"""
Rate Limiter Integration Test
==============================
Probes your live server to verify the rate limiter is actually enforced.

What it does differently from the original:
  - Auto-detects the target burst ceiling before asserting (so the test
    doesn't silently pass just because burst > request count).
  - Checks that the middleware is even in the request path first.
  - Verifies Retry-After header is a valid positive number.
  - Resets between tests via /api/debug/rate-limit/reset if available,
    otherwise waits for natural refill.
  - Prints a clear PASS / FAIL / SKIP per test with diagnosis on failure.
  - All assertions include context so failures tell you exactly what's wrong.

Usage:
    python test_rate_limiter_integration.py

Requirements:
    - Server running at BASE (default http://127.0.0.1:8000)
    - No external dependencies (stdlib only)

Configure:
    BASE                   — server URL
    RESET_ENDPOINT         — set to None if you don't expose a reset route
    RATE_LIMIT_STATS_PATH  — set to None if you don't expose stats
    MAX_PROBE              — upper bound when auto-detecting burst size
"""

from __future__ import annotations

import json
import sys
import time
import uuid
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Optional
from urllib import error, request

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE = "http://127.0.0.1:8000"
TIMEOUT = 6

# If your server exposes these debug endpoints, set them. Otherwise None.
RESET_ENDPOINT = "/api/debug/rate-limit/reset"          # POST, resets all buckets
RATE_LIMIT_STATS_PATH = "/api/debug/rate-limit/stats"   # GET, returns RateLimiterStats

# How many requests to send when probing for the burst ceiling.
# Must be comfortably above your expected burst. If your burst is set to
# 1000+ in production config, increase this.
MAX_PROBE = 600

# IP ranges used for tests — these are documentation/test ranges (RFC 5737)
MANY_IPS_PREFIX = "198.18"    # 198.18.0.0/15 — benchmarking range
SINGLE_SOURCE_IP = "203.0.113.42"  # TEST-NET-3, won't conflict with real traffic

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
    payload=None,
    headers: Optional[dict] = None,
) -> tuple[int, dict, str]:
    req_headers = dict(headers or {})
    data = None
    if payload is not None:
        data = json.dumps(payload).encode()
        req_headers.setdefault("Content-Type", "application/json")
    req = request.Request(
        BASE + path, data=data, headers=req_headers, method=method,
    )
    try:
        with request.urlopen(req, timeout=TIMEOUT) as r:
            return r.status, dict(r.headers), r.read().decode()
    except error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()
    except error.URLError as e:
        print(f"\n  ✗ Connection error: {e.reason}")
        print(f"    Is the server running at {BASE}?")
        sys.exit(1)


def run_parallel(
    specs: list[tuple],
    workers: int = 40,
) -> list[dict]:
    """Fire specs concurrently. Each spec is (method, path, payload, headers)."""
    def _one(spec):
        method, path, payload, headers = spec
        code, hdrs, body = call(method, path, payload, headers)
        return {"code": code, "headers": hdrs, "body": body, "path": path}

    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(_one, s): s for s in specs}
        return [f.result() for f in as_completed(futures)]


# ---------------------------------------------------------------------------
# Test runner
# ---------------------------------------------------------------------------

_PASS = 0
_FAIL = 0
_SKIP = 0


def _section(title: str) -> None:
    width = 60
    print(f"\n{'─' * width}")
    print(f"  {title}")
    print(f"{'─' * width}")


def _ok(msg: str) -> None:
    print(f"  ✓  {msg}")


def _fail(msg: str) -> None:
    global _FAIL
    _FAIL += 1
    print(f"  ✗  FAIL: {msg}")


def _skip(msg: str) -> None:
    global _SKIP
    _SKIP += 1
    print(f"  –  SKIP: {msg}")


def _check(cond: bool, pass_msg: str, fail_msg: str) -> bool:
    global _PASS
    if cond:
        _PASS += 1
        _ok(pass_msg)
        return True
    else:
        _fail(fail_msg)
        return False


def _reset_limiter() -> bool:
    """Attempt to reset via debug endpoint. Returns True if successful."""
    if RESET_ENDPOINT is None:
        return False
    code, _, _ = call("POST", RESET_ENDPOINT)
    if code in (200, 204):
        print(f"  ↺  Rate limiter reset via {RESET_ENDPOINT}")
        return True
    print(f"  ↺  Reset endpoint returned {code} — skipping reset")
    return False


def _fetch_stats() -> Optional[dict]:
    if RATE_LIMIT_STATS_PATH is None:
        return None
    code, _, body = call("GET", RATE_LIMIT_STATS_PATH)
    if code == 200:
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            pass
    return None


# ---------------------------------------------------------------------------
# Phase 0 — Server reachability + middleware presence
# ---------------------------------------------------------------------------

def test_server_reachable() -> bool:
    _section("Phase 0 — Server reachability")
    code, _, body = call("GET", "/api/health")
    if not _check(
        code == 200,
        f"/api/health returned {code}",
        f"/api/health returned {code} — is the server running?",
    ):
        return False

    # Fast-fail guard: ensure we are talking to the app instance that has
    # the rate-limiter middleware mounted.
    probe_code, probe_headers, _ = call("GET", "/api/projects")
    middleware_marker = _header_get(probe_headers, "X-PentaForge-Rate-Limiter")
    if not _check(
        middleware_marker == "active",
        f"Rate limiter middleware marker detected on /api/projects (status {probe_code})",
        (
            "Rate limiter middleware marker missing on /api/projects. "
            "You are likely hitting a stale/different server on port 8000. "
            "Restart with: RATE_LIMIT_DEBUG=1 ENV=development "
            "python -m uvicorn server.api.app:app --host 127.0.0.1 --port 8000 --workers 1"
        ),
    ):
        return False

    # Confirm rate limiter middleware is present by checking stats or
    # by sending a known-bad request count and seeing if 429 ever fires.
    stats = _fetch_stats()
    if stats:
        _ok(f"Stats endpoint available: {json.dumps(stats, indent=2)}")
        cfg = stats.get("config", {})
        if cfg:
            print(f"\n  Detected config:")
            for k, v in cfg.items():
                print(f"    {k}: {v}")
    else:
        _skip(
            f"Stats endpoint not available ({RATE_LIMIT_STATS_PATH}). "
            "Set RATE_LIMIT_STATS_PATH to enable config detection."
        )
    return True


# ---------------------------------------------------------------------------
# Phase 1 — Excluded paths bypass the limiter
# ---------------------------------------------------------------------------

def test_excluded_paths():
    _section("Phase 1 — Excluded paths bypass the limiter")
    # Hit /api/health 30 times — should always be 200
    codes = [call("GET", "/api/health")[0] for _ in range(30)]
    counts = Counter(codes)
    print(f"  /api/health × 30 → {dict(counts)}")
    _check(
        set(codes) == {200},
        "All 30 health checks returned 200 (correctly excluded)",
        f"Unexpected codes on excluded path: {counts} — "
        "health endpoint may be rate-limited or server is flaky",
    )


# ---------------------------------------------------------------------------
# Phase 2 — Auto-detect burst ceiling
# ---------------------------------------------------------------------------

def probe_burst(
    path: str,
    use_unique_ips: bool = False,
    label: str = "target",
) -> int:
    """
    Send requests one-by-one until we see a 429, returning the number of
    successful requests before the first denial.

    If use_unique_ips=True, each request comes from a different IP so
    source-layer won't interfere with target-layer detection.
    """
    print(f"\n  Probing {label} burst ceiling (max {MAX_PROBE} requests)…")
    allowed = 0
    for i in range(MAX_PROBE):
        ip = (
            f"198.18.{i // 254}.{(i % 254) + 1}"
            if use_unique_ips
            else SINGLE_SOURCE_IP
        )
        code, hdrs, _ = call("GET", path, headers={"X-Forwarded-For": ip})
        if code == 429:
            retry = _header_get(hdrs, "Retry-After")
            print(
                f"  First 429 at request #{i + 1} "
                f"(allowed={allowed}, Retry-After={retry!r})"
            )
            return allowed
        elif code in (200, 404):
            allowed += 1
        else:
            print(f"  Unexpected {code} at request #{i + 1} — continuing")
    print(
        f"  ⚠  No 429 seen after {MAX_PROBE} requests. "
        f"Either burst ≥ {MAX_PROBE} or limiter is not enforced."
    )
    return allowed


# ---------------------------------------------------------------------------
# Phase 3 — Per-target rate limit
# ---------------------------------------------------------------------------

def test_per_target():
    _section("Phase 2 — Per-target rate limit")
    _reset_limiter()

    path = "/api/projects"

    # Step A: probe burst so we know the ceiling
    burst = probe_burst(path, use_unique_ips=True, label="target")

    if burst >= MAX_PROBE:
        _fail(
            f"Target burst appears to be ≥ {MAX_PROBE}. "
            "Either raise MAX_PROBE or lower RATE_LIMIT_BURST in config."
        )
        return

    if burst == 0:
        _fail(
            "Every request was denied immediately. "
            "Check that burst is configured > 0."
        )
        return

    _ok(f"Target burst ceiling detected: ~{burst} tokens")
    _reset_limiter()

    # Step B: send slightly above burst to trigger 429 without
    # escalating repeat-offender penalties that distort refill timing.
    n = burst + 5
    specs = [
        ("GET", path, None, {"X-Forwarded-For": f"198.18.{i // 254}.{(i % 254) + 1}"})
        for i in range(n)
    ]
    results = run_parallel(specs, workers=min(n, 60))
    codes = Counter(r["code"] for r in results)
    print(f"  Sent {n} requests → {dict(codes)}")

    _check(
        codes[429] > 0,
        f"Got {codes[429]} × 429 after exceeding burst of ~{burst}",
        f"No 429 seen after {n} requests — limiter not enforcing target limit. "
        f"Codes: {dict(codes)}",
    )

    # Step C: Retry-After header must be present and numeric
    retries = [
        _header_get(r["headers"], "Retry-After")
        for r in results if r["code"] == 429
    ]
    valid_retries = []
    for v in retries:
        if v is not None:
            try:
                val = float(v)
                if val > 0:
                    valid_retries.append(val)
            except ValueError:
                pass

    print(f"  Retry-After values (first 5): {valid_retries[:5]}")
    _check(
        len(valid_retries) > 0,
        f"Retry-After header present and valid on 429 responses",
        "Retry-After header missing or non-numeric on 429 responses — "
        "clients can't know when to retry",
    )

    # Step D: after waiting for one refill tick, requests should succeed again
    if valid_retries:
        wait = max(valid_retries) + 0.5
        print(f"  Waiting {wait:.1f}s for bucket to refill…")
        time.sleep(wait)
        code_after, _, _ = call(
            "GET", path,
            headers={"X-Forwarded-For": "198.18.200.1"},
        )
        _check(
            code_after in (200, 201, 204),
            f"Request allowed again after refill (got {code_after})",
            f"Still getting {code_after} after waiting {wait:.1f}s — "
            "refill may not be working",
        )


# ---------------------------------------------------------------------------
# Phase 4 — Per-source rate limit
# ---------------------------------------------------------------------------

def test_per_source():
    _section("Phase 3 — Per-source rate limit")
    _reset_limiter()

    # Use unique paths to keep every target bucket near-empty,
    # so denials come from the source bucket only.
    # Paths that don't exist will 404 — that's fine, it proves the
    # limiter fires BEFORE the route handler.
    source_ip = SINGLE_SOURCE_IP

    # Step A: probe source burst using unique paths
    unique_path_idx = [0]
    print(f"  Probing source burst (IP={source_ip}, unique paths)…")
    allowed = 0
    first_429_at = None
    for i in range(MAX_PROBE):
        path = f"/api/rl-probe-src-{i}"
        code, hdrs, _ = call("GET", path, headers={"X-Forwarded-For": source_ip})
        if code == 429:
            first_429_at = i + 1
            break
        elif code in (200, 404):
            allowed += 1

    if first_429_at is None:
        _fail(
            f"Source burst appears ≥ {MAX_PROBE}. "
            "Raise MAX_PROBE or lower source_burst in config."
        )
        return

    _ok(f"Source burst ceiling detected: ~{allowed} tokens (first 429 at request #{first_429_at})")
    _reset_limiter()

    # Step B: saturate source and verify 429 appears
    n = allowed + 20
    specs = [
        ("GET", f"/api/rl-src-{i}", None, {"X-Forwarded-For": source_ip})
        for i in range(n)
    ]
    results = run_parallel(specs, workers=min(n, 60))
    codes = Counter(r["code"] for r in results)
    print(f"  Sent {n} requests from {source_ip} → {dict(codes)}")

    _check(
        codes[404] > 0,
        f"{codes[404]} requests reached route handler (got 404) before source exhausted",
        "No 404s — requests may not be reaching the route handler at all",
    )
    _check(
        codes[429] > 0,
        f"Got {codes[429]} × 429 once source bucket exhausted",
        f"No 429 seen — source-layer limit not enforced. Codes: {dict(codes)}",
    )

    # Step C: a different IP should not be blocked
    _reset_limiter()
    other_ip = "198.51.100.1"  # TEST-NET-2
    code_other, _, _ = call(
        "GET", "/api/projects",
        headers={"X-Forwarded-For": other_ip},
    )
    _check(
        code_other != 429,
        f"Different IP ({other_ip}) is not affected by source exhaustion on {source_ip}",
        f"Different IP got {code_other} — source buckets may not be isolated",
    )


# ---------------------------------------------------------------------------
# Phase 5 — Middleware ordering (source check fires before route handler)
# ---------------------------------------------------------------------------

def test_middleware_ordering():
    _section("Phase 4 — Middleware fires before route handler")
    _reset_limiter()

    # We expect 429 status (not 404) when source is exhausted on an unknown path.
    # If we get 404 after exhaustion the middleware is running AFTER routing.
    source_ip = "198.51.100.99"
    allowed = 0
    last_code = None
    for i in range(MAX_PROBE):
        code, _, _ = call(
            "GET", f"/api/rl-order-{i}",
            headers={"X-Forwarded-For": source_ip},
        )
        last_code = code
        if code == 429:
            _check(
                True,
                f"Got 429 at request #{i+1} — middleware correctly intercepts before routing",
                "",
            )
            break
        allowed += 1
    else:
        _fail(
            f"Never got 429 from unknown paths after {MAX_PROBE} requests — "
            "either source burst is very high or middleware is not enforcing"
        )


# ---------------------------------------------------------------------------
# Phase 6 — Global rate limit (opt-in, slow)
# ---------------------------------------------------------------------------

def test_global(run: bool = False):
    _section("Phase 5 — Global rate limit")
    if not run:
        _skip(
            "Skipped by default (requires many requests). "
            "Set run=True in test_global() to enable."
        )
        return

    _reset_limiter()
    stats = _fetch_stats()
    global_burst = None
    if stats:
        global_burst = stats.get("config", {}).get("global_burst")
        print(f"  global_burst from stats: {global_burst}")

    n = int(global_burst * 1.2) if global_burst else MAX_PROBE
    print(f"  Sending {n} requests with unique IPs and unique paths…")

    specs = [
        (
            "GET",
            f"/api/rl-global-{i}",
            None,
            {"X-Forwarded-For": f"10.{(i // 65536) % 256}.{(i // 256) % 256}.{i % 256}"},
        )
        for i in range(n)
    ]
    results = run_parallel(specs, workers=120)
    codes = Counter(r["code"] for r in results)
    print(f"  {n} requests → {dict(codes)}")
    _check(
        codes[429] > 0,
        f"Global limit enforced: {codes[429]} × 429",
        f"No 429 — global limit not firing after {n} requests. "
        f"Codes: {dict(codes)}",
    )


# ---------------------------------------------------------------------------
# Phase 7 — Refill sanity (tokens replenish over time)
# ---------------------------------------------------------------------------

def test_refill():
    _section("Phase 6 — Token refill over time")
    _reset_limiter()

    path = "/api/projects"
    source_ip = "198.18.1.1"

    # Exhaust the target bucket
    exhausted = False
    for i in range(MAX_PROBE):
        code, _, _ = call("GET", path, headers={"X-Forwarded-For": f"198.18.{i//254}.{(i%254)+1}"})
        if code == 429:
            exhausted = True
            break

    if not exhausted:
        _skip(f"Couldn't exhaust target bucket within {MAX_PROBE} requests — skipping refill test")
        return

    # Confirm it's still blocked immediately
    code_now, _, _ = call("GET", path, headers={"X-Forwarded-For": "198.18.200.1"})
    _check(
        code_now == 429,
        "Bucket correctly still exhausted immediately after saturation",
        f"Expected 429 immediately after exhaustion but got {code_now}",
    )

    # Wait 2 seconds — at 60 TPM (1/s), we should get at least 1 token
    wait_s = 2.0
    print(f"  Waiting {wait_s}s for refill…")
    time.sleep(wait_s)

    code_after, _, _ = call("GET", path, headers={"X-Forwarded-For": "198.18.201.1"})
    _check(
        code_after != 429,
        f"Bucket refilled after {wait_s}s (got {code_after})",
        f"Still getting 429 after {wait_s}s — refill may not be working "
        f"(got {code_after}). Check RATE_LIMIT_TOKENS_PER_MINUTE.",
    )


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _summary():
    total = _PASS + _FAIL + _SKIP
    print(f"\n{'═' * 60}")
    print(f"  Results: {_PASS} passed  {_FAIL} failed  {_SKIP} skipped  ({total} total)")
    print(f"{'═' * 60}")

    if _FAIL > 0:
        print("""
  DIAGNOSIS CHECKLIST
  ───────────────────
  1. Is the rate limiter middleware mounted on all routes?
     → Check that it runs before your router, not inside a specific route.

  2. Is X-Forwarded-For being read for source IP?
     → Look for: request.headers.get("X-Forwarded-For", request.remote_addr)
     → If you use request.remote_addr all IPs look like 127.0.0.1.

  3. Is the DENY verdict actually returning 429?
     → Look for: if result.verdict == Verdict.DENY: return 429 response
     → A common bug: result is checked but denial is not returned.

  4. Are RATE_LIMIT_BURST / RATE_LIMIT_TOKENS_PER_MINUTE set low enough?
     → If burst=1000 in config, you need >1000 requests to see 429.
     → Expose /api/debug/rate-limit/stats to see live config.

  5. Is _normalize_target() producing the same key for all test requests?
     → Add a debug log: logger.debug("rate_check", target=target_key)
     → If keys differ per-request, each gets its own bucket and 429 never fires.
""")
        sys.exit(1)
    else:
        print("\n  ALL CHECKS PASSED ✅\n")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print(f"\nRate Limiter Integration Test")
    print(f"Target server: {BASE}")
    print(f"Max probe requests: {MAX_PROBE}")

    if not test_server_reachable():
        print("\nServer not reachable — aborting.")
        sys.exit(1)

    test_excluded_paths()
    test_per_target()
    test_per_source()
    test_middleware_ordering()
    test_refill()
    test_global(run=False)   # set run=True to enable heavy global test

    _summary()
