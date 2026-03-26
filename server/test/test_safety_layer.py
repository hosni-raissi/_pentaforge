
"""Tests for the multi-layer token-bucket rate limiter.

Covers:
    - Basic allow / deny flow
    - Global, source, and target layers independently
    - Two-phase atomic consumption (no token waste)
    - Escalating penalties with exponential backoff
    - Violation decay after clean behaviour
    - LRU eviction under memory pressure
    - IP normalization edge cases
    - Target URL normalization
    - Cost validation
    - Thread safety under concurrent load
    - Injectable clock for deterministic timing
    - Metrics hook callbacks
    - Reset operations
    - is_blocked non-consuming check
    - Retry-after accuracy
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock

import pytest

from server.layers.safety.rate_limiter import (
    Clock,
    MetricsHook,
    RateLimiter,
    _Bucket,
    _BoundedBucketStore,
    _ShardedLock,
    _acquire_ordered,
    _normalize_source_ip,
    _normalize_target,
    _DEFAULT_BASE_PENALTY_DURATION,
    _DEFAULT_MAX_PENALTY_DURATION,
    _DEFAULT_PENALTY_FLOOR,
    _REPEAT_OFFENDER_THRESHOLD,
    _VIOLATION_DECAY_AMOUNT,
    _VIOLATION_DECAY_INTERVAL,
)
from .models import ActionRequest, Verdict


# ---------------------------------------------------------------------------
# Fake Clock — deterministic, no real sleeps
# ---------------------------------------------------------------------------

class FakeClock:
    """Injectable clock that advances only when told to."""

    def __init__(self, start: float = 1000.0) -> None:
        self._now = start

    def monotonic(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


# ---------------------------------------------------------------------------
# Fake Metrics — records all hook calls
# ---------------------------------------------------------------------------

@dataclass
class FakeMetrics:
    allows: list[dict] = field(default_factory=list)
    denies: list[dict] = field(default_factory=list)
    penalties: list[dict] = field(default_factory=list)

    def on_allow(self, *, target: str, source_ip: Optional[str]) -> None:
        self.allows.append({"target": target, "source_ip": source_ip})

    def on_deny(
        self,
        *,
        layer: str,
        target: str,
        source_ip: Optional[str],
        retry_after: float,
    ) -> None:
        self.denies.append({
            "layer": layer,
            "target": target,
            "source_ip": source_ip,
            "retry_after": retry_after,
        })

    def on_penalty(
        self,
        *,
        layer: str,
        identifier: str,
        duration: float,
        violation_count: int,
    ) -> None:
        self.penalties.append({
            "layer": layer,
            "identifier": identifier,
            "duration": duration,
            "violation_count": violation_count,
        })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_request(target: str = "api.example.com") -> ActionRequest:
    """Create a minimal ActionRequest for testing."""
    return ActionRequest(target=target)


def _make_limiter(
    clock: Optional[FakeClock] = None,
    metrics: Optional[FakeMetrics] = None,
    **kwargs,
) -> tuple[RateLimiter, FakeClock, FakeMetrics]:
    """Create a rate limiter with fake clock and metrics."""
    clk = clock or FakeClock()
    met = metrics or FakeMetrics()
    defaults = dict(
        tokens_per_minute=60,       # 1 token/sec per target
        burst=10,
        source_tokens_per_minute=30,  # 0.5 token/sec per source
        source_burst=5,
        global_tokens_per_minute=120,  # 2 tokens/sec global
        global_burst=20,
        clock=clk,
        metrics=met,
    )
    defaults.update(kwargs)
    limiter = RateLimiter(**defaults)
    return limiter, clk, met


# ===========================================================================
# BASIC ALLOW / DENY
# ===========================================================================

class TestBasicFlow:
    """Fundamental allow/deny behaviour."""

    def test_first_request_allowed(self):
        limiter, clk, met = _make_limiter()
        result = limiter.check(_make_request(), source_ip="10.0.0.1")

        assert result.verdict == Verdict.ALLOW
        assert "rate_limiter" in result.component
        assert len(met.allows) == 1

    def test_requests_within_burst_all_allowed(self):
        limiter, clk, met = _make_limiter(burst=5, source_burst=5)

        for i in range(5):
            result = limiter.check(_make_request(), source_ip="10.0.0.1")
            assert result.verdict == Verdict.ALLOW

        assert len(met.allows) == 5
        assert len(met.denies) == 0

    def test_exceeding_burst_denied(self):
        limiter, clk, met = _make_limiter(burst=3, source_burst=10)

        for _ in range(3):
            result = limiter.check(_make_request(), source_ip="10.0.0.1")
            assert result.verdict == Verdict.ALLOW

        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY
        assert len(met.denies) == 1

    def test_tokens_refill_over_time(self):
        limiter, clk, met = _make_limiter(
            tokens_per_minute=60,  # 1/sec
            burst=2,
            source_burst=10,
            global_burst=100,
        )

        # Exhaust burst
        limiter.check(_make_request(), source_ip="10.0.0.1")
        limiter.check(_make_request(), source_ip="10.0.0.1")
        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY

        # Advance time to refill 1 token
        clk.advance(1.0)
        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

    def test_deny_includes_retry_after(self):
        limiter, clk, met = _make_limiter(burst=1, source_burst=10)

        limiter.check(_make_request(), source_ip="10.0.0.1")
        result = limiter.check(_make_request(), source_ip="10.0.0.1")

        assert result.verdict == Verdict.DENY
        assert "Retry after" in result.reason


# ===========================================================================
# LAYER ISOLATION
# ===========================================================================

class TestLayerIsolation:
    """Each layer (global, source, target) limits independently."""

    def test_global_limit_blocks_all_sources(self):
        limiter, clk, met = _make_limiter(
            global_burst=3,
            source_burst=100,
            burst=100,
        )

        # Three different sources exhaust global
        for i in range(3):
            result = limiter.check(
                _make_request(), source_ip=f"10.0.0.{i + 1}",
            )
            assert result.verdict == Verdict.ALLOW

        # 4th from new source denied by global
        result = limiter.check(_make_request(), source_ip="10.0.0.99")
        assert result.verdict == Verdict.DENY
        assert "global" in result.component

    def test_source_limit_blocks_single_ip(self):
        limiter, clk, met = _make_limiter(
            source_burst=2,
            burst=100,
            global_burst=100,
        )

        # Source exhausts its limit
        limiter.check(_make_request(), source_ip="10.0.0.1")
        limiter.check(_make_request(), source_ip="10.0.0.1")
        result = limiter.check(_make_request(), source_ip="10.0.0.1")

        assert result.verdict == Verdict.DENY
        assert "source" in result.component

        # Different source still works
        result = limiter.check(_make_request(), source_ip="10.0.0.2")
        assert result.verdict == Verdict.ALLOW

    def test_target_limit_blocks_single_endpoint(self):
        limiter, clk, met = _make_limiter(
            burst=2,            # per-target burst
            source_burst=100,
            global_burst=100,
        )

        target_a = _make_request("api.example.com/a")

        limiter.check(target_a, source_ip="10.0.0.1")
        limiter.check(target_a, source_ip="10.0.0.2")
        result = limiter.check(target_a, source_ip="10.0.0.3")

        assert result.verdict == Verdict.DENY
        assert "target" in result.component

        # Different target still works
        target_b = _make_request("api.example.com/b")
        result = limiter.check(target_b, source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

    def test_no_source_ip_skips_source_layer(self):
        limiter, clk, met = _make_limiter(burst=5, global_burst=100)

        # Should work without source_ip
        for _ in range(5):
            result = limiter.check(_make_request())
            assert result.verdict == Verdict.ALLOW


# ===========================================================================
# TWO-PHASE ATOMIC CONSUMPTION
# ===========================================================================

class TestAtomicConsumption:
    """Phase 1 checks all layers; Phase 2 subtracts only if all pass.
    No tokens are wasted on partial denials.
    """

    def test_no_global_tokens_wasted_on_target_denial(self):
        limiter, clk, met = _make_limiter(
            global_burst=10,
            burst=2,          # target will exhaust first
            source_burst=100,
        )

        # Exhaust target
        limiter.check(_make_request("target-x"), source_ip="10.0.0.1")
        limiter.check(_make_request("target-x"), source_ip="10.0.0.1")

        # This should be denied by target layer
        result = limiter.check(_make_request("target-x"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY
        assert "target" in result.component

        # Global should still have 8 tokens (10 - 2, not 10 - 3)
        stats = limiter.get_stats()
        assert stats["global_tokens_remaining"] == pytest.approx(8.0, abs=0.5)

    def test_no_source_tokens_wasted_on_target_denial(self):
        limiter, clk, met = _make_limiter(
            global_burst=100,
            source_burst=10,
            burst=2,
        )

        limiter.check(_make_request("ep-1"), source_ip="10.0.0.1")
        limiter.check(_make_request("ep-1"), source_ip="10.0.0.1")

        # Denied by target — source should not lose a token
        result = limiter.check(_make_request("ep-1"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY

        # Source bucket should have 8 tokens remaining (10 - 2)
        # Verify by making requests to a fresh target
        for _ in range(8):
            result = limiter.check(
                _make_request(f"fresh-target"), source_ip="10.0.0.1",
            )
            assert result.verdict == Verdict.ALLOW


# ===========================================================================
# PENALTIES — ESCALATING
# ===========================================================================

class TestEscalatingPenalties:
    """Repeat offenders get exponentially longer refill slowdowns."""

    def test_penalty_applied_after_threshold(self):
        limiter, clk, met = _make_limiter(
            burst=1,
            source_burst=100,
            global_burst=1000,
            base_penalty_duration=60.0,
        )

        # Generate enough violations to trigger repeat offender
        for i in range(_REPEAT_OFFENDER_THRESHOLD + 1):
            limiter.check(_make_request(), source_ip="10.0.0.1")
            clk.advance(0.01)  # tiny advance so refill is negligible

        assert len(met.penalties) >= 1

    def test_penalty_escalates_exponentially(self):
        limiter, clk, met = _make_limiter(
            burst=1,
            source_burst=100,
            global_burst=10000,
            base_penalty_duration=10.0,
            max_penalty_duration=1000.0,
            penalty_multiplier=2.0,
        )

        # Trigger multiple penalty rounds
        for _ in range(30):
            limiter.check(_make_request(), source_ip="10.0.0.1")
            clk.advance(0.001)

        # Penalties should grow: 10, 20, 40, 80, ...
        durations = [p["duration"] for p in met.penalties]
        if len(durations) >= 2:
            assert durations[1] > durations[0]

    def test_penalty_capped_at_max(self):
        limiter, clk, met = _make_limiter(
            burst=1,
            source_burst=100,
            global_burst=10000,
            base_penalty_duration=100.0,
            max_penalty_duration=500.0,
            penalty_multiplier=3.0,
        )

        for _ in range(50):
            limiter.check(_make_request(), source_ip="10.0.0.1")
            clk.advance(0.001)

        durations = [p["duration"] for p in met.penalties]
        assert all(d <= 500.0 for d in durations)

    def test_penalty_slows_refill_rate(self):
        limiter, clk, met = _make_limiter(
            tokens_per_minute=600,  # 10/sec normally
            burst=1,
            source_burst=100,
            global_burst=10000,
            base_penalty_duration=300.0,
        )

        # Exhaust and trigger penalty
        for _ in range(_REPEAT_OFFENDER_THRESHOLD + 2):
            limiter.check(_make_request(), source_ip="10.0.0.1")
            clk.advance(0.001)

        # Under penalty, refill is 10% of normal (1/sec instead of 10/sec)
        # Wait 1 second — should get ~1 token, not ~10
        clk.advance(1.0)
        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        # Should get at most 1 token back
        assert result.verdict == Verdict.ALLOW

        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY


# ===========================================================================
# VIOLATION DECAY
# ===========================================================================

class TestViolationDecay:
    """Violations decay after sustained good behaviour."""

    def test_violations_decay_after_clean_period(self):
        clk = FakeClock()
        bucket = _Bucket(
            tokens=0.0,
            max_tokens=10.0,
            refill_rate=1.0,
            _clock=clk,
        )

        # Accumulate violations
        for _ in range(8):
            bucket.record_violation()

        assert bucket.violation_count == 8

        # Advance past decay interval
        clk.advance(_VIOLATION_DECAY_INTERVAL + 1.0)
        bucket.refill()

        assert bucket.violation_count == 8 - _VIOLATION_DECAY_AMOUNT

    def test_violations_dont_go_negative(self):
        clk = FakeClock()
        bucket = _Bucket(
            tokens=10.0,
            max_tokens=10.0,
            refill_rate=1.0,
            _clock=clk,
        )

        bucket.record_violation()
        bucket.record_violation()
        assert bucket.violation_count == 2

        clk.advance(_VIOLATION_DECAY_INTERVAL + 1.0)
        bucket.refill()

        assert bucket.violation_count == 0

    def test_penalty_count_resets_when_below_threshold(self):
        clk = FakeClock()
        bucket = _Bucket(
            tokens=0.0,
            max_tokens=10.0,
            refill_rate=1.0,
            _clock=clk,
        )

        # Become repeat offender
        for _ in range(_REPEAT_OFFENDER_THRESHOLD + 5):
            bucket.record_violation()
        bucket.apply_penalty()

        assert bucket.is_repeat_offender
        assert bucket._penalty_count > 0

        # Decay until below threshold
        for _ in range(10):
            clk.advance(_VIOLATION_DECAY_INTERVAL + 1.0)
            bucket.refill()

        if bucket.violation_count < _REPEAT_OFFENDER_THRESHOLD:
            assert bucket._penalty_count == 0


# ===========================================================================
# LRU EVICTION
# ===========================================================================

class TestLRUEviction:
    """Bounded memory prevents OOM from attacker-generated keys."""

    def test_eviction_at_capacity(self):
        store = _BoundedBucketStore(max_size=3)

        for i in range(5):
            store.get_or_create(f"key-{i}", burst=10.0, refill_rate=1.0)

        assert len(store) == 3
        # First two should be evicted
        assert store.get("key-0") is None
        assert store.get("key-1") is None
        # Last three should remain
        assert store.get("key-2") is not None
        assert store.get("key-3") is not None
        assert store.get("key-4") is not None

    def test_access_refreshes_lru_position(self):
        store = _BoundedBucketStore(max_size=3)

        store.get_or_create("a", burst=10.0, refill_rate=1.0)
        store.get_or_create("b", burst=10.0, refill_rate=1.0)
        store.get_or_create("c", burst=10.0, refill_rate=1.0)

        # Touch "a" — moves it to most-recently-used
        store.get("a")

        # Add "d" — should evict "b" (now the LRU)
        store.get_or_create("d", burst=10.0, refill_rate=1.0)

        assert store.get("a") is not None
        assert store.get("b") is None
        assert store.get("c") is not None
        assert store.get("d") is not None

    def test_rate_limiter_survives_many_unique_keys(self):
        limiter, clk, met = _make_limiter(max_buckets=100)

        for i in range(500):
            result = limiter.check(
                _make_request(f"target-{i}"),
                source_ip=f"10.0.{i // 256}.{i % 256}",
            )
            # Should never crash — eviction handles memory

        stats = limiter.get_stats()
        assert stats["target_buckets_active"] <= 100
        assert stats["source_buckets_active"] <= 100


# ===========================================================================
# IP NORMALIZATION
# ===========================================================================

class TestIPNormalization:
    """IP validation, normalization, and edge cases."""

    def test_ipv4_passthrough(self):
        assert _normalize_source_ip("192.168.1.1") == "192.168.1.1"

    def test_ipv4_whitespace_stripped(self):
        assert _normalize_source_ip("  10.0.0.1  ") == "10.0.0.1"

    def test_ipv6_normalized(self):
        result = _normalize_source_ip("::1")
        assert result == "::1"

    def test_ipv6_mapped_ipv4_converted(self):
        result = _normalize_source_ip("::ffff:192.168.1.1")
        assert result == "192.168.1.1"

    def test_invalid_ip_hashed(self):
        result = _normalize_source_ip("not-an-ip")
        assert result.startswith("invalid:")
        assert len(result) > len("invalid:")

    def test_invalid_ip_deterministic(self):
        a = _normalize_source_ip("garbage-input")
        b = _normalize_source_ip("garbage-input")
        assert a == b

    def test_different_invalid_ips_different_hashes(self):
        a = _normalize_source_ip("attacker-1")
        b = _normalize_source_ip("attacker-2")
        assert a != b

    def test_same_ip_same_bucket(self):
        """Ensure normalized IPs share a rate-limit bucket."""
        limiter, clk, met = _make_limiter(source_burst=2, burst=100, global_burst=100)

        limiter.check(_make_request(), source_ip="::ffff:10.0.0.1")
        limiter.check(_make_request(), source_ip="10.0.0.1")

        # Both should have consumed from the same bucket
        result = limiter.check(_make_request(), source_ip="  10.0.0.1  ")
        assert result.verdict == Verdict.DENY
        assert "source" in result.component


# ===========================================================================
# TARGET NORMALIZATION
# ===========================================================================

class TestTargetNormalization:
    """URL and hostname normalization for consistent bucket keys."""

    def test_case_insensitive(self):
        assert _normalize_target("API.Example.COM") == "api.example.com"

    def test_whitespace_stripped(self):
        assert _normalize_target("  example.com  ") == "example.com"

    def test_trailing_slash_stripped(self):
        assert _normalize_target("example.com/api/") == "example.com/api"

    def test_empty_string(self):
        assert _normalize_target("") == ""
        assert _normalize_target("   ") == ""

    def test_url_default_port_stripped(self):
        result = _normalize_target("http://example.com:80/path")
        assert ":80" not in result
        assert "example.com" in result

    def test_url_non_default_port_kept(self):
        result = _normalize_target("http://example.com:8080/path")
        assert ":8080" in result

    def test_https_default_port_stripped(self):
        result = _normalize_target("https://example.com:443/path")
        assert ":443" not in result

    def test_url_fragment_stripped(self):
        result = _normalize_target("http://example.com/page#section")
        assert "#" not in result
        assert "section" not in result

    def test_url_query_params_sorted(self):
        a = _normalize_target("http://example.com/api?z=1&a=2&m=3")
        b = _normalize_target("http://example.com/api?a=2&m=3&z=1")
        assert a == b

    def test_url_full_normalization(self):
        raw = "  HTTP://Example.COM:80/api/users/?b=2&a=1#section  "
        expected_base = "http://example.com/api/users?a=1&b=2"
        result = _normalize_target(raw)
        assert result == expected_base

    def test_normalized_targets_share_bucket(self):
        limiter, clk, met = _make_limiter(burst=2, source_burst=100, global_burst=100)

        limiter.check(
            _make_request("HTTP://Example.COM:80/api?b=2&a=1"),
            source_ip="10.0.0.1",
        )
        limiter.check(
            _make_request("http://example.com/api?a=1&b=2"),
            source_ip="10.0.0.2",
        )

        # Same normalized target — third request should be denied
        result = limiter.check(
            _make_request("http://example.com/api/?a=1&b=2#frag"),
            source_ip="10.0.0.3",
        )
        assert result.verdict == Verdict.DENY
        assert "target" in result.component


# ===========================================================================
# COST VALIDATION
# ===========================================================================

class TestCostValidation:
    """Invalid cost values are rejected."""

    def test_zero_cost_rejected(self):
        limiter, clk, met = _make_limiter()
        with pytest.raises(ValueError, match="positive"):
            limiter.check(_make_request(), cost=0)

    def test_negative_cost_rejected(self):
        limiter, clk, met = _make_limiter()
        with pytest.raises(ValueError, match="positive"):
            limiter.check(_make_request(), cost=-5.0)

    def test_nan_cost_rejected(self):
        limiter, clk, met = _make_limiter()
        with pytest.raises(ValueError):
            limiter.check(_make_request(), cost=float("nan"))

    def test_string_cost_rejected(self):
        limiter, clk, met = _make_limiter()
        with pytest.raises(ValueError):
            limiter.check(_make_request(), cost="ten")  # type: ignore

    def test_large_cost_allowed_but_denied(self):
        limiter, clk, met = _make_limiter(burst=5)
        result = limiter.check(_make_request(), cost=100.0, source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY

    def test_fractional_cost_works(self):
        limiter, clk, met = _make_limiter(burst=10, source_burst=10, global_burst=100)
        result = limiter.check(
            _make_request(), cost=0.5, source_ip="10.0.0.1",
        )
        assert result.verdict == Verdict.ALLOW


# ===========================================================================
# METRICS HOOK
# ===========================================================================

class TestMetricsHook:
    """Metrics callbacks fire correctly."""

    def test_allow_fires_on_allow(self):
        limiter, clk, met = _make_limiter()
        limiter.check(_make_request("svc-a"), source_ip="10.0.0.1")

        assert len(met.allows) == 1
        assert met.allows[0]["target"] == "svc-a"
        assert met.allows[0]["source_ip"] == "10.0.0.1"

    def test_deny_fires_on_deny(self):
        limiter, clk, met = _make_limiter(burst=1, source_burst=100, global_burst=100)

        limiter.check(_make_request(), source_ip="10.0.0.1")
        limiter.check(_make_request(), source_ip="10.0.0.1")

        assert len(met.denies) == 1
        assert met.denies[0]["layer"] == "rate_limiter.target"

    def test_penalty_fires_for_repeat_offender(self):
        limiter, clk, met = _make_limiter(
            burst=1, source_burst=100, global_burst=10000,
        )

        for _ in range(_REPEAT_OFFENDER_THRESHOLD + 2):
            limiter.check(_make_request(), source_ip="10.0.0.1")
            clk.advance(0.001)

        assert len(met.penalties) >= 1
        assert met.penalties[0]["violation_count"] >= _REPEAT_OFFENDER_THRESHOLD


# ===========================================================================
# RESET OPERATIONS
# ===========================================================================

class TestReset:
    """Reset clears state correctly."""

    def test_reset_all(self):
        limiter, clk, met = _make_limiter(burst=2, source_burst=2, global_burst=100)

        limiter.check(_make_request(), source_ip="10.0.0.1")
        limiter.check(_make_request(), source_ip="10.0.0.1")
        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY

        limiter.reset()

        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

        stats = limiter.get_stats()
        assert stats["global_violations"] == 0

    def test_reset_specific_target(self):
        limiter, clk, met = _make_limiter(
            burst=1, source_burst=100, global_burst=100,
        )

        limiter.check(_make_request("target-a"), source_ip="10.0.0.1")
        result = limiter.check(_make_request("target-a"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY

        limiter.reset(target="target-a")

        result = limiter.check(_make_request("target-a"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

    def test_reset_source(self):
        limiter, clk, met = _make_limiter(
            source_burst=1, burst=100, global_burst=100,
        )

        limiter.check(_make_request(), source_ip="10.0.0.1")
        result = limiter.check(_make_request("other"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY

        limiter.reset_source("10.0.0.1")

        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

    def test_reset_target_doesnt_affect_others(self):
        limiter, clk, met = _make_limiter(
            burst=1, source_burst=100, global_burst=100,
        )

        limiter.check(_make_request("a"), source_ip="10.0.0.1")
        limiter.check(_make_request("b"), source_ip="10.0.0.1")

        limiter.reset(target="a")

        # "a" is reset — should allow
        result = limiter.check(_make_request("a"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

        # "b" is not reset — should deny
        result = limiter.check(_make_request("b"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.DENY


# ===========================================================================
# IS_BLOCKED (non-consuming)
# ===========================================================================

class TestIsBlocked:
    """Non-consuming check doesn't consume tokens."""

    def test_not_blocked_initially(self):
        limiter, clk, met = _make_limiter()
        assert limiter.is_blocked(target="x", source_ip="10.0.0.1") is False

    def test_blocked_when_exhausted(self):
        limiter, clk, met = _make_limiter(burst=1, source_burst=100, global_burst=100)

        limiter.check(_make_request("x"), source_ip="10.0.0.1")

        assert limiter.is_blocked(target="x") is True

    def test_is_blocked_doesnt_consume(self):
        limiter, clk, met = _make_limiter(burst=2, source_burst=100, global_burst=100)

        limiter.check(_make_request("x"), source_ip="10.0.0.1")

        # Call is_blocked many times — should not consume
        for _ in range(100):
            limiter.is_blocked(target="x", source_ip="10.0.0.1")

        # Should still have 1 token left
        result = limiter.check(_make_request("x"), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW

    def test_global_block_detected(self):
        limiter, clk, met = _make_limiter(global_burst=1)
        limiter.check(_make_request(), source_ip="10.0.0.1")

        assert limiter.is_blocked() is True


# ===========================================================================
# GET_STATS
# ===========================================================================

class TestGetStats:
    """Stats endpoint returns correct typed data."""

    def test_initial_stats(self):
        limiter, clk, met = _make_limiter()
        stats = limiter.get_stats()

        assert stats["target_buckets_active"] == 0
        assert stats["source_buckets_active"] == 0
        assert stats["global_tokens_remaining"] == 20.0
        assert stats["global_max_tokens"] == 20.0
        assert stats["global_violations"] == 0
        assert stats["config"]["target_tpm"] == 60
        assert stats["config"]["source_tpm"] == 30
        assert stats["config"]["global_tpm"] == 120

    def test_stats_after_activity(self):
        limiter, clk, met = _make_limiter()

        limiter.check(_make_request("a"), source_ip="10.0.0.1")
        limiter.check(_make_request("b"), source_ip="10.0.0.2")

        stats = limiter.get_stats()
        assert stats["target_buckets_active"] == 2
        assert stats["source_buckets_active"] == 2
        assert stats["global_tokens_remaining"] == pytest.approx(18.0, abs=0.5)


# ===========================================================================
# BUCKET UNIT TESTS
# ===========================================================================

class TestBucketInternals:
    """Direct tests on the _Bucket dataclass."""

    def test_refill_does_not_exceed_max(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=10.0, max_tokens=10.0, refill_rate=100.0, _clock=clk)

        clk.advance(1000.0)
        bucket.refill()

        assert bucket.tokens == 10.0

    def test_consume_success(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=5.0, max_tokens=10.0, refill_rate=1.0, _clock=clk)

        assert bucket.consume(3.0) is True
        assert bucket.tokens == pytest.approx(2.0, abs=0.1)

    def test_consume_failure_records_violation(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=1.0, max_tokens=10.0, refill_rate=0.0, _clock=clk)

        assert bucket.consume(5.0) is False
        assert bucket.violation_count == 1
        assert bucket.tokens == pytest.approx(1.0, abs=0.1)  # not consumed

    def test_subtract_floors_at_zero(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=2.0, max_tokens=10.0, refill_rate=1.0, _clock=clk)

        bucket.subtract(5.0)
        assert bucket.tokens == 0.0

    def test_has_tokens_does_not_mutate(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=5.0, max_tokens=10.0, refill_rate=1.0, _clock=clk)

        initial_tokens = bucket.tokens
        initial_refill = bucket.last_refill

        result = bucket.has_tokens(3.0)

        assert result is True
        assert bucket.tokens == initial_tokens
        assert bucket.last_refill == initial_refill

    def test_time_until_available(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=0.0, max_tokens=10.0, refill_rate=2.0, _clock=clk)

        wait = bucket.time_until_available(4.0)
        assert wait == pytest.approx(2.0, abs=0.1)  # 4 tokens / 2 per sec

    def test_time_until_available_zero_when_sufficient(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=10.0, max_tokens=10.0, refill_rate=1.0, _clock=clk)

        assert bucket.time_until_available(5.0) == 0.0

    def test_penalty_reduces_effective_rate(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=0.0, max_tokens=100.0, refill_rate=10.0, _clock=clk)

        bucket.apply_penalty(base_duration=100.0)

        clk.advance(10.0)
        bucket.refill()

        # 10 seconds × (10.0 × 0.1) = 10 tokens (penalised)
        # vs 10 seconds × 10.0 = 100 tokens (normal)
        assert bucket.tokens == pytest.approx(10.0, abs=1.0)

    def test_penalty_expires(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=0.0, max_tokens=100.0, refill_rate=10.0, _clock=clk)

        bucket.apply_penalty(base_duration=10.0)

        # Advance past penalty
        clk.advance(20.0)
        bucket.refill()

        # First 10s at 10%: 10 × 10 × 0.1 = 10
        # Next 10s at 100%: 10 × 10 = 100
        # Total: 110, capped at 100
        assert bucket.tokens == pytest.approx(100.0, abs=5.0)

    def test_repeat_offender_threshold(self):
        clk = FakeClock()
        bucket = _Bucket(tokens=10.0, max_tokens=10.0, refill_rate=1.0, _clock=clk)

        for _ in range(_REPEAT_OFFENDER_THRESHOLD - 1):
            bucket.record_violation()
        assert not bucket.is_repeat_offender

        bucket.record_violation()
        assert bucket.is_repeat_offender


# ===========================================================================
# BOUNDED BUCKET STORE
# ===========================================================================

class TestBoundedBucketStore:
    """LRU store unit tests."""

    def test_get_nonexistent_returns_none(self):
        store = _BoundedBucketStore(max_size=10)
        assert store.get("nope") is None

    def test_contains(self):
        store = _BoundedBucketStore(max_size=10)
        store.get_or_create("k", burst=10.0, refill_rate=1.0)
        assert "k" in store
        assert "other" not in store

    def test_pop_removes(self):
        store = _BoundedBucketStore(max_size=10)
        store.get_or_create("k", burst=10.0, refill_rate=1.0)
        bucket = store.pop("k")
        assert bucket is not None
        assert "k" not in store

    def test_pop_nonexistent_returns_none(self):
        store = _BoundedBucketStore(max_size=10)
        assert store.pop("nope") is None

    def test_clear(self):
        store = _BoundedBucketStore(max_size=10)
        for i in range(5):
            store.get_or_create(f"k-{i}", burst=10.0, refill_rate=1.0)
        store.clear()
        assert len(store) == 0

    def test_keys_snapshot(self):
        store = _BoundedBucketStore(max_size=10)
        store.get_or_create("a", burst=10.0, refill_rate=1.0)
        store.get_or_create("b", burst=10.0, refill_rate=1.0)
        keys = store.keys()
        assert set(keys) == {"a", "b"}


# ===========================================================================
# SHARDED LOCK
# ===========================================================================

class TestShardedLock:
    """Shard lock determinism and distribution."""

    def test_same_key_same_lock(self):
        sl = _ShardedLock(shards=16)
        lock_a = sl.get("key-1")
        lock_b = sl.get("key-1")
        assert lock_a is lock_b

    def test_different_keys_can_differ(self):
        sl = _ShardedLock(shards=64)
        locks = {id(sl.get(f"key-{i}")) for i in range(1000)}
        # With 1000 keys and 64 shards, we should hit multiple shards
        assert len(locks) > 1

    def test_all_locks_returns_all_shards(self):
        sl = _ShardedLock(shards=8)
        assert len(sl.all_locks()) == 8


# ===========================================================================
# ORDERED LOCK ACQUISITION
# ===========================================================================

class TestAcquireOrdered:
    """Deadlock-free multi-lock acquisition."""

    def test_acquires_and_releases(self):
        lock_a = threading.Lock()
        lock_b = threading.Lock()

        with _acquire_ordered(lock_a, lock_b):
            # Both should be held
            assert not lock_a.acquire(blocking=False)
            assert not lock_b.acquire(blocking=False)

        # Both released
        assert lock_a.acquire(blocking=False)
        lock_a.release()
        assert lock_b.acquire(blocking=False)
        lock_b.release()

    def test_deduplicates_same_lock(self):
        lock = threading.Lock()

        # Should not deadlock despite duplicate
        with _acquire_ordered(lock, lock, lock):
            assert not lock.acquire(blocking=False)

        assert lock.acquire(blocking=False)
        lock.release()

    def test_no_deadlock_with_reversed_order(self):
        """Two threads acquiring same locks in different argument order."""
        lock_a = threading.Lock()
        lock_b = threading.Lock()

        results = []
        barrier = threading.Barrier(2, timeout=5)

        def worker(first, second, label):
            barrier.wait()
            with _acquire_ordered(first, second):
                results.append(label)
                # Small delay to increase chance of contention
                time.sleep(0.01)

        t1 = threading.Thread(target=worker, args=(lock_a, lock_b, "t1"))
        t2 = threading.Thread(target=worker, args=(lock_b, lock_a, "t2"))

        t1.start()
        t2.start()
        t1.join(timeout=5)
        t2.join(timeout=5)

        assert not t1.is_alive(), "Thread 1 deadlocked"
        assert not t2.is_alive(), "Thread 2 deadlocked"
        assert set(results) == {"t1", "t2"}


# ===========================================================================
# THREAD SAFETY — CONCURRENT LOAD
# ===========================================================================

class TestConcurrency:
    """Verify thread safety under parallel load."""

    def test_concurrent_same_target(self):
        """Many threads hammering the same target — no crashes, correct limiting."""
        limiter, clk, met = _make_limiter(
            burst=50,
            source_burst=100,
            global_burst=1000,
        )

        results = {"allow": 0, "deny": 0}
        lock = threading.Lock()

        def worker(thread_id: int):
            local_allow = 0
            local_deny = 0
            for _ in range(20):
                result = limiter.check(
                    _make_request("shared-target"),
                    source_ip=f"10.0.{thread_id // 256}.{thread_id % 256}",
                )
                if result.verdict == Verdict.ALLOW:
                    local_allow += 1
                else:
                    local_deny += 1
            with lock:
                results["allow"] += local_allow
                results["deny"] += local_deny

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        for t in threads:
            assert not t.is_alive(), f"Thread {t.name} hung"

        total = results["allow"] + results["deny"]
        assert total == 200  # 10 threads × 20 requests
        # With burst=50, at most 50 allows for the target
        assert results["allow"] <= 55  # small tolerance for refill during test

    def test_concurrent_different_targets(self):
        """Different targets should not interfere with each other."""
        limiter, clk, met = _make_limiter(
            burst=10,
            source_burst=1000,
            global_burst=10000,
        )

        per_thread_allows = {}
        lock = threading.Lock()

        def worker(thread_id: int):
            allows = 0
            target = f"target-{thread_id}"
            for _ in range(10):
                result = limiter.check(
                    _make_request(target),
                    source_ip="10.0.0.1",
                )
                if result.verdict == Verdict.ALLOW:
                    allows += 1
            with lock:
                per_thread_allows[thread_id] = allows

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        # Each thread has its own target with burst=10, sending 10 requests
        for tid, allows in per_thread_allows.items():
            assert allows == 10, (
                f"Thread {tid} got {allows} allows, expected 10"
            )

    def test_no_deadlock_under_mixed_load(self):
        """Mix of operations: check, reset, stats, is_blocked."""
        limiter, clk, met = _make_limiter(
            burst=5,
            source_burst=5,
            global_burst=10000,
            max_buckets=50,
        )

        stop = threading.Event()
        errors: list[str] = []

        def checker(thread_id: int):
            try:
                while not stop.is_set():
                    limiter.check(
                        _make_request(f"t-{thread_id % 5}"),
                        source_ip=f"10.0.0.{thread_id}",
                    )
            except Exception as e:
                errors.append(f"checker-{thread_id}: {e}")

        def resetter():
            try:
                while not stop.is_set():
                    limiter.reset(target="t-0")
                    time.sleep(0.001)
            except Exception as e:
                errors.append(f"resetter: {e}")

        def stats_reader():
            try:
                while not stop.is_set():
                    limiter.get_stats()
                    limiter.is_blocked(target="t-1", source_ip="10.0.0.1")
            except Exception as e:
                errors.append(f"stats: {e}")

        threads = []
        for i in range(8):
            threads.append(threading.Thread(target=checker, args=(i,)))
        threads.append(threading.Thread(target=resetter))
        threads.append(threading.Thread(target=stats_reader))

        for t in threads:
            t.start()

        time.sleep(0.5)  # Let them run
        stop.set()

        for t in threads:
            t.join(timeout=5)

        for t in threads:
            assert not t.is_alive(), f"Thread {t.name} hung (possible deadlock)"
        assert errors == [], f"Errors during concurrent test: {errors}"


# ===========================================================================
# RETRY-AFTER ACCURACY
# ===========================================================================

class TestRetryAfter:
    """Retry-after timing matches actual token availability."""

    def test_retry_after_matches_refill_time(self):
        limiter, clk, met = _make_limiter(
            tokens_per_minute=60,  # 1 token/sec
            burst=1,
            source_burst=100,
            global_burst=100,
        )

        limiter.check(_make_request(), source_ip="10.0.0.1")
        result = limiter.check(_make_request(), source_ip="10.0.0.1")

        assert result.verdict == Verdict.DENY

        # Parse retry-after from reason
        reason = result.reason
        # Extract number after "Retry after "
        retry_str = reason.split("Retry after ")[1].split("s")[0]
        retry_after = float(retry_str)

        # Should be approximately 1 second (1 token / 1 token per sec)
        assert 0.5 <= retry_after <= 2.0

        # Actually wait that long and verify
        clk.advance(retry_after + 0.1)
        result = limiter.check(_make_request(), source_ip="10.0.0.1")
        assert result.verdict == Verdict.ALLOW


# ===========================================================================
# REPR
# ===========================================================================

class TestRepr:
    """String representations are informative."""

    def test_rate_limiter_repr(self):
        limiter, clk, met = _make_limiter()
        r = repr(limiter)
        assert "RateLimiter" in r
        assert "target=" in r
        assert "source=" in r
        assert "global=" in r

    def test_bucket_repr(self):
        clk = FakeClock()
        bucket = _Bucket(
            tokens=5.0, max_tokens=10.0, refill_rate=1.0, _clock=clk,
        )
        r = repr(bucket)
        assert "5.0" in r
        assert "10" in r

    def test_store_repr(self):
        store = _BoundedBucketStore(max_size=100)
        r = repr(store)
        assert "size=0" in r
        assert "max=100" in r