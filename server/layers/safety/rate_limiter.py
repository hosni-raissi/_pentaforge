"""Rate Limiter — multi-layer token bucket to prevent DoS/DDoS.

Layers:
    1. Global    — absolute ceiling across all requests.
    2. Per-source — prevents a single caller/IP from flooding.
    3. Per-target — prevents hammering a single endpoint/host.

Protections:
    - Bounded memory via LRU eviction.
    - Escalating time-based penalties for repeat offenders.
    - Atomic consumption (no token waste on partial denials).
    - Retry-after calculation for client guidance.
    - IP validation and normalization.
    - Sharded locks for high-throughput concurrency (deadlock-free).
    - Thread-safe throughout.

Note:
    This is an in-memory, single-process rate limiter. If deployed
    across multiple instances (e.g. Kubernetes pods), each instance
    maintains independent state. A global limit of 10,000 TPM becomes
    N × 10,000 TPM across N pods. For distributed rate limiting,
    back this with Redis or a shared store.
"""

from __future__ import annotations

import hashlib
import ipaddress
import time
from collections import OrderedDict
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from threading import Lock
from typing import (
    Callable,
    Iterator,
    Optional,
    Protocol,
    TypedDict,
)
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode

import structlog

from .config import (
    RATE_LIMIT_BURST,
    RATE_LIMIT_TOKENS_PER_MINUTE,
)
from .models import ActionRequest, CheckResult, Verdict

logger = structlog.get_logger(__name__)


# ---------------------------------------------------------------------------
# Clock Protocol (injectable for testing)
# ---------------------------------------------------------------------------

class Clock(Protocol):
    """Protocol for injectable time source."""

    def monotonic(self) -> float: ...


class _SystemClock:
    """Default clock backed by time.monotonic."""

    __slots__ = ()

    def monotonic(self) -> float:
        return time.monotonic()


_DEFAULT_CLOCK = _SystemClock()


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DEFAULT_SOURCE_TPM: int = 300
_DEFAULT_SOURCE_BURST: int = 50
_DEFAULT_GLOBAL_TPM: int = 10_000
_DEFAULT_GLOBAL_BURST: int = 500
_DEFAULT_MAX_BUCKETS: int = 100_000
_DEFAULT_BASE_PENALTY_DURATION: float = 60.0       # seconds
_DEFAULT_MAX_PENALTY_DURATION: float = 3600.0       # 1 hour cap
_DEFAULT_PENALTY_MULTIPLIER: float = 2.0            # exponential backoff
_DEFAULT_PENALTY_FLOOR: float = 0.1                 # 10 % of normal refill
_REPEAT_OFFENDER_THRESHOLD: int = 10
_VIOLATION_DECAY_INTERVAL: float = 600.0            # 10 min of clean behaviour
_VIOLATION_DECAY_AMOUNT: int = 5
_LOCK_SHARDS: int = 64
_LOG_SUPPRESSION_INTERVAL: float = 1.0              # min seconds between identical log msgs


# ---------------------------------------------------------------------------
# Metrics Hook
# ---------------------------------------------------------------------------

class MetricsHook(Protocol):
    """Optional callback for external metrics systems (Prometheus, StatsD…)."""

    def on_allow(self, *, target: str, source_ip: Optional[str]) -> None: ...

    def on_deny(
        self,
        *,
        layer: str,
        target: str,
        source_ip: Optional[str],
        retry_after: float,
    ) -> None: ...

    def on_penalty(
        self,
        *,
        layer: str,
        identifier: str,
        duration: float,
        violation_count: int,
    ) -> None: ...


class _NoOpMetrics:
    """Default no-op metrics hook."""

    __slots__ = ()

    def on_allow(self, **_kw: object) -> None:
        pass

    def on_deny(self, **_kw: object) -> None:
        pass

    def on_penalty(self, **_kw: object) -> None:
        pass


_NOOP_METRICS = _NoOpMetrics()


# ---------------------------------------------------------------------------
# Stats TypedDict
# ---------------------------------------------------------------------------

class RateLimiterConfig(TypedDict):
    target_tpm: int
    target_burst: float
    source_tpm: int
    source_burst: float
    global_tpm: int
    global_burst: float
    base_penalty_duration_s: float
    max_penalty_duration_s: float


class RateLimiterStats(TypedDict):
    target_buckets_active: int
    source_buckets_active: int
    global_tokens_remaining: float
    global_max_tokens: float
    global_violations: int
    config: RateLimiterConfig


# ---------------------------------------------------------------------------
# Token Bucket
# ---------------------------------------------------------------------------

@dataclass
class _Bucket:
    """Single token bucket with automatic refill and escalating penalties.

    Violation tracking is centralised in ``record_violation()`` —
    callers must not increment ``violation_count`` directly.
    """

    tokens: float
    max_tokens: float
    refill_rate: float                              # tokens / second (base)
    _clock: Clock = field(default=_DEFAULT_CLOCK, repr=False)
    last_refill: float = field(default=0.0)
    violation_count: int = 0
    penalty_until: float = 0.0                      # monotonic timestamp
    _last_violation_time: float = 0.0
    _base_refill_rate: float = field(init=False, repr=False)
    _penalty_count: int = 0                         # for exponential backoff

    def __post_init__(self) -> None:
        self._base_refill_rate = self.refill_rate
        if self.last_refill == 0.0:
            self.last_refill = self._clock.monotonic()

    # ---- Public API ----

    def refill(self) -> None:
        """Refill tokens based on elapsed time. Call once per check cycle."""
        now = self._clock.monotonic()
        elapsed = now - self.last_refill
        self.last_refill = now
        if elapsed > 0:
            self.tokens = min(
                self.max_tokens,
                self.tokens + elapsed * self._effective_refill_rate(now),
            )
        self._maybe_decay_violations(now)

    def has_tokens(self, cost: float) -> bool:
        """Check capacity WITHOUT refilling or mutating state."""
        return self.tokens >= cost

    def subtract(self, cost: float) -> None:
        """Subtract tokens unconditionally (post-refill, post-check)."""
        self.tokens = max(0.0, self.tokens - cost)

    def consume(self, cost: float = 1.0) -> bool:
        """Refill, check, and consume atomically. Records violation on denial."""
        self.refill()
        if self.tokens >= cost:
            self.tokens -= cost
            return True
        self.record_violation()
        return False

    def record_violation(self) -> None:
        """Single source of truth for violation counting."""
        now = self._clock.monotonic()
        self.violation_count += 1
        self._last_violation_time = now

    def apply_penalty(
        self,
        base_duration: float = _DEFAULT_BASE_PENALTY_DURATION,
        max_duration: float = _DEFAULT_MAX_PENALTY_DURATION,
        multiplier: float = _DEFAULT_PENALTY_MULTIPLIER,
    ) -> float:
        """Apply escalating penalty. Returns actual duration applied."""
        self._penalty_count += 1
        duration = min(
            base_duration * (multiplier ** (self._penalty_count - 1)),
            max_duration,
        )
        now = self._clock.monotonic()
        # Extend from current penalty end or from now, whichever is later
        self.penalty_until = max(self.penalty_until, now) + duration
        return duration

    def time_until_available(self, cost: float = 1.0) -> float:
        """Seconds until the bucket has enough tokens for *cost*."""
        if self.tokens >= cost:
            return 0.0
        deficit = cost - self.tokens
        now = self._clock.monotonic()
        rate = self._effective_refill_rate(now)
        if rate <= 0:
            return float("inf")
        return deficit / rate

    @property
    def is_repeat_offender(self) -> bool:
        return self.violation_count >= _REPEAT_OFFENDER_THRESHOLD

    def _effective_refill_rate(self, now: float) -> float:
        if now < self.penalty_until:
            return self._base_refill_rate * _DEFAULT_PENALTY_FLOOR
        return self._base_refill_rate

    def _maybe_decay_violations(self, now: float) -> None:
        """Decay violations after sustained good behaviour."""
        if (
            self.violation_count > 0
            and self._last_violation_time > 0
            and (now - self._last_violation_time) > _VIOLATION_DECAY_INTERVAL
        ):
            old = self.violation_count
            self.violation_count = max(
                0, self.violation_count - _VIOLATION_DECAY_AMOUNT,
            )
            if self.violation_count < _REPEAT_OFFENDER_THRESHOLD:
                self._penalty_count = 0     # reset escalation ladder
            if old != self.violation_count:
                self._last_violation_time = now     # reset decay window

    def __repr__(self) -> str:
        now = self._clock.monotonic()
        return (
            f"_Bucket(tokens={self.tokens:.1f}/{self.max_tokens:.0f}, "
            f"rate={self._effective_refill_rate(now):.2f}/s, "
            f"violations={self.violation_count}, "
            f"penalties={self._penalty_count})"
        )


# ---------------------------------------------------------------------------
# LRU Bounded Dict
# ---------------------------------------------------------------------------

class _BoundedBucketStore:
    """LRU-evicting dictionary to prevent unbounded memory growth.

    NOT thread-safe on its own — callers must hold appropriate locks.
    """

    __slots__ = ("_store", "_max_size")

    def __init__(self, max_size: int = _DEFAULT_MAX_BUCKETS) -> None:
        self._store: OrderedDict[str, _Bucket] = OrderedDict()
        self._max_size = max_size

    def get(self, key: str) -> Optional[_Bucket]:
        """Retrieve bucket and mark as recently used."""
        if key in self._store:
            self._store.move_to_end(key)
            return self._store[key]
        return None

    def get_or_create(
        self,
        key: str,
        burst: float,
        refill_rate: float,
        clock: Clock = _DEFAULT_CLOCK,
    ) -> _Bucket:
        bucket = self.get(key)
        if bucket is None:
            bucket = _Bucket(
                tokens=burst,
                max_tokens=burst,
                refill_rate=refill_rate,
                _clock=clock,
            )
            self._put(key, bucket)
        return bucket

    def _put(self, key: str, bucket: _Bucket) -> None:
        if key in self._store:
            self._store.move_to_end(key)
        self._store[key] = bucket
        while len(self._store) > self._max_size:
            evicted_key, _ = self._store.popitem(last=False)
            logger.debug("bucket_evicted", key=evicted_key)

    def pop(self, key: str) -> Optional[_Bucket]:
        return self._store.pop(key, None)

    def clear(self) -> None:
        self._store.clear()

    def keys(self) -> list[str]:
        return list(self._store.keys())

    def __len__(self) -> int:
        return len(self._store)

    def __contains__(self, key: str) -> bool:
        return key in self._store

    def __repr__(self) -> str:
        return f"_BoundedBucketStore(size={len(self)}, max={self._max_size})"


# ---------------------------------------------------------------------------
# Sharded Lock — Actually Used
# ---------------------------------------------------------------------------

class _ShardedLock:
    """Reduces lock contention by sharding across N independent locks.

    Uses Python's built-in ``hash()`` for fast shard selection
    (cryptographic hashing is unnecessary for load distribution).
    """

    __slots__ = ("_locks", "_shards")

    def __init__(self, shards: int = _LOCK_SHARDS) -> None:
        self._locks = [Lock() for _ in range(shards)]
        self._shards = shards

    def get(self, key: str) -> Lock:
        """Return the lock shard for a given key."""
        idx = hash(key) % self._shards
        return self._locks[idx]

    def all_locks(self) -> list[Lock]:
        """Return all shard locks (for global operations)."""
        return list(self._locks)


# ---------------------------------------------------------------------------
# Ordered Multi-Lock Acquisition (Deadlock-Free)
# ---------------------------------------------------------------------------

@contextmanager
def _acquire_ordered(*locks: Lock) -> Iterator[None]:
    """Acquire multiple locks in a consistent order to prevent deadlocks.

    Ordering by ``id()`` ensures all threads agree on acquisition
    sequence regardless of the order arguments are passed in.
    Duplicate locks are acquired only once.
    """
    unique = sorted(set(locks), key=id)
    stack = ExitStack()
    try:
        for lock in unique:
            stack.enter_context(lock)      # calls lock.acquire()
        yield
    finally:
        stack.close()                       # releases in reverse order


# ---------------------------------------------------------------------------
# IP Utilities
# ---------------------------------------------------------------------------

def _normalize_source_ip(ip: str) -> str:
    """Validate and normalize an IP address string.

    - Strips whitespace.
    - Converts IPv6-mapped IPv4 to plain IPv4.
    - Hashes invalid inputs to prevent key-injection attacks.
    """
    cleaned = ip.strip()
    try:
        addr = ipaddress.ip_address(cleaned)
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
            addr = addr.ipv4_mapped
        return str(addr)
    except ValueError:
        hashed = hashlib.sha256(cleaned.encode()).hexdigest()[:16]
        logger.warning("invalid_source_ip", raw=cleaned, hashed_key=hashed)
        return f"invalid:{hashed}"


# ---------------------------------------------------------------------------
# Target Key Normalization
# ---------------------------------------------------------------------------

def _normalize_target(target: str) -> str:
    """Normalize target key for consistent bucket lookup.

    Handles hostnames, paths, and full URLs:
      - Strips whitespace, lowercases.
      - For URLs: strips fragments, normalises default ports,
        sorts query parameters.
      - Strips trailing slashes.
    """
    cleaned = target.strip().lower()
    if not cleaned:
        return cleaned

    # Attempt URL parse — only apply URL logic if scheme is present
    parsed = urlparse(cleaned)
    if parsed.scheme in ("http", "https", "ftp", "ftps"):
        # Strip fragment
        # Normalize default ports
        netloc = parsed.hostname or ""
        port = parsed.port
        if port:
            default_ports = {"http": 80, "https": 443, "ftp": 21, "ftps": 990}
            if port != default_ports.get(parsed.scheme):
                netloc = f"{netloc}:{port}"

        # Sort query parameters for consistency
        query_params = parse_qsl(parsed.query, keep_blank_values=True)
        sorted_query = urlencode(sorted(query_params))

        path = parsed.path.rstrip("/") or "/"

        normalized = urlunparse((
            parsed.scheme,
            netloc,
            path,
            parsed.params,
            sorted_query,
            "",  # no fragment
        ))
        return normalized

    # Plain hostname or path
    return cleaned.rstrip("/")


# ---------------------------------------------------------------------------
# Rate-Limited Logger
# ---------------------------------------------------------------------------

class _RateLimitedLogger:
    """Suppresses duplicate log messages within a time window.

    During a DDoS, thousands of denial messages per second would
    overwhelm the log pipeline. This ensures at most one message
    per (event, key) pair within ``interval`` seconds.
    """

    __slots__ = ("_last_logged", "_interval", "_lock")

    def __init__(self, interval: float = _LOG_SUPPRESSION_INTERVAL) -> None:
        self._last_logged: dict[str, float] = {}
        self._interval = interval
        self._lock = Lock()

    def should_log(self, key: str) -> bool:
        now = time.monotonic()
        with self._lock:
            last = self._last_logged.get(key, 0.0)
            if now - last >= self._interval:
                self._last_logged[key] = now
                # Prevent unbounded growth of the suppression dict
                if len(self._last_logged) > 10_000:
                    cutoff = now - self._interval * 2
                    self._last_logged = {
                        k: v
                        for k, v in self._last_logged.items()
                        if v > cutoff
                    }
                return True
            return False


_rate_limited_logger = _RateLimitedLogger()


# ---------------------------------------------------------------------------
# Rate Limiter
# ---------------------------------------------------------------------------

class RateLimiter:
    """Multi-layer token-bucket rate limiter.

    Architecture::

        Request
          │
          ▼
        ┌──────────────────┐
        │  Global Limit    │ ── DENY ──▶ Response
        └────────┬─────────┘
                 │ OK
                 ▼
        ┌──────────────────┐
        │  Source IP Limit  │ ── DENY ──▶ Response
        └────────┬─────────┘
                 │ OK
                 ▼
        ┌──────────────────┐
        │  Target Limit    │ ── DENY ──▶ Response
        └────────┬─────────┘
                 │ OK
                 ▼
              ALLOW

    Concurrency model:
        - Each bucket layer uses sharded locks for parallel access.
        - Multi-bucket operations acquire locks in ``id()`` order
          to prevent deadlocks.
        - Global operations (reset, stats) acquire all shard locks.
    """

    def __init__(
        self,
        # Per-target limits
        tokens_per_minute: int = RATE_LIMIT_TOKENS_PER_MINUTE,
        burst: int = RATE_LIMIT_BURST,
        # Per-source limits
        source_tokens_per_minute: int = _DEFAULT_SOURCE_TPM,
        source_burst: int = _DEFAULT_SOURCE_BURST,
        # Global limits
        global_tokens_per_minute: int = _DEFAULT_GLOBAL_TPM,
        global_burst: int = _DEFAULT_GLOBAL_BURST,
        # Memory bounds
        max_buckets: int = _DEFAULT_MAX_BUCKETS,
        # Penalty config
        base_penalty_duration: float = _DEFAULT_BASE_PENALTY_DURATION,
        max_penalty_duration: float = _DEFAULT_MAX_PENALTY_DURATION,
        penalty_multiplier: float = _DEFAULT_PENALTY_MULTIPLIER,
        # Extensibility
        clock: Optional[Clock] = None,
        metrics: Optional[MetricsHook] = None,
    ) -> None:
        self._clock: Clock = clock or _DEFAULT_CLOCK

        # Per-target config
        self._target_tpm = tokens_per_minute
        self._target_burst = float(burst)
        self._target_refill = tokens_per_minute / 60.0

        # Per-source config
        self._source_tpm = source_tokens_per_minute
        self._source_burst = float(source_burst)
        self._source_refill = source_tokens_per_minute / 60.0

        # Global config
        self._global_tpm = global_tokens_per_minute
        self._global_burst = float(global_burst)
        self._global_bucket = _Bucket(
            tokens=float(global_burst),
            max_tokens=float(global_burst),
            refill_rate=global_tokens_per_minute / 60.0,
            _clock=self._clock,
        )
        self._global_lock = Lock()

        # Penalty
        self._base_penalty_duration = base_penalty_duration
        self._max_penalty_duration = max_penalty_duration
        self._penalty_multiplier = penalty_multiplier

        # Stores
        self._target_buckets = _BoundedBucketStore(max_buckets)
        self._source_buckets = _BoundedBucketStore(max_buckets)

        # Concurrency — sharded locks for source and target stores
        self._source_shard = _ShardedLock()
        self._target_shard = _ShardedLock()

        # Metrics
        self._metrics: MetricsHook = metrics or _NOOP_METRICS

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(
        self,
        action: ActionRequest,
        cost: float = 1.0,
        source_ip: Optional[str] = None,
    ) -> CheckResult:
        """Check all rate-limit layers. Any layer can deny.

        Uses two-phase checking:
            Phase 1 — refill and pre-check all layers (one refill each).
            Phase 2 — if all pass, subtract from all layers.

        Locks are acquired in deterministic ``id()`` order to prevent
        deadlocks while allowing parallel throughput for unrelated keys.
        """
        # ── Validate cost ──
        if not isinstance(cost, (int, float)) or cost != cost:  # NaN
            raise ValueError(f"cost must be a positive number, got {cost!r}")
        if cost <= 0:
            raise ValueError(f"cost must be positive, got {cost}")

        target_key = _normalize_target(action.target)
        source_key = _normalize_source_ip(source_ip) if source_ip else None

        # ── Determine which locks we need ──
        locks_needed: list[Lock] = [self._global_lock]
        if source_key:
            locks_needed.append(self._source_shard.get(source_key))
        locks_needed.append(self._target_shard.get(target_key))

        with _acquire_ordered(*locks_needed):
            # ── Phase 1: Refill all buckets once, then pre-check ──

            # Layer 1: Global
            self._global_bucket.refill()
            if not self._global_bucket.has_tokens(cost):
                self._global_bucket.record_violation()
                retry_after = self._global_bucket.time_until_available(cost)

                self._metrics.on_deny(
                    layer="global",
                    target=action.target,
                    source_ip=source_ip,
                    retry_after=retry_after,
                )
                log_key = "global_rate_limit"
                if _rate_limited_logger.should_log(log_key):
                    logger.critical(
                        "global_rate_limit_exceeded",
                        target=action.target,
                        source_ip=source_ip,
                        retry_after=round(retry_after, 1),
                    )

                return CheckResult(
                    verdict=Verdict.DENY,
                    component="rate_limiter.global",
                    reason=(
                        f"Global rate limit exceeded. "
                        f"Limit: {self._global_tpm}/min, "
                        f"burst: {self._global_burst:.0f}. "
                        f"Retry after {retry_after:.1f}s."
                    ),
                )

            # Layer 2: Per-source
            source_bucket: Optional[_Bucket] = None
            if source_key:
                source_bucket = self._source_buckets.get_or_create(
                    key=source_key,
                    burst=self._source_burst,
                    refill_rate=self._source_refill,
                    clock=self._clock,
                )
                source_bucket.refill()
                if not source_bucket.has_tokens(cost):
                    return self._deny_bucket(
                        bucket=source_bucket,
                        cost=cost,
                        layer_name="rate_limiter.source",
                        limit_label=f"{self._source_tpm}/min per source",
                        identifier=source_ip or source_key,
                        target=action.target,
                        source_ip=source_ip,
                    )

            # Layer 3: Per-target
            target_bucket = self._target_buckets.get_or_create(
                key=target_key,
                burst=self._target_burst,
                refill_rate=self._target_refill,
                clock=self._clock,
            )
            target_bucket.refill()
            if not target_bucket.has_tokens(cost):
                return self._deny_bucket(
                    bucket=target_bucket,
                    cost=cost,
                    layer_name="rate_limiter.target",
                    limit_label=f"{self._target_tpm}/min per target",
                    identifier=action.target,
                    target=action.target,
                    source_ip=source_ip,
                )

            # ── Phase 2: All passed — subtract atomically ──
            self._global_bucket.subtract(cost)
            if source_bucket is not None:
                source_bucket.subtract(cost)
            target_bucket.subtract(cost)

        # Metrics (outside lock)
        self._metrics.on_allow(target=action.target, source_ip=source_ip)

        return CheckResult(
            verdict=Verdict.ALLOW,
            component="rate_limiter",
            reason=(
                f"All rate-limit checks passed. "
                f"Global: {self._global_bucket.tokens:.0f} remaining, "
                f"Target: {target_bucket.tokens:.0f} remaining."
            ),
        )

    def reset(self, target: Optional[str] = None) -> None:
        """Reset rate-limit state for a target, or everything if None."""
        if target is None:
            # Acquire ALL locks to ensure no in-flight checks
            all_locks: list[Lock] = (
                [self._global_lock]
                + self._source_shard.all_locks()
                + self._target_shard.all_locks()
            )
            with _acquire_ordered(*all_locks):
                self._target_buckets.clear()
                self._source_buckets.clear()
                self._global_bucket = _Bucket(
                    tokens=self._global_burst,
                    max_tokens=self._global_burst,
                    refill_rate=self._global_tpm / 60.0,
                    _clock=self._clock,
                )
                logger.info("rate_limiter_reset", scope="all")
        else:
            key = _normalize_target(target)
            lock = self._target_shard.get(key)
            with lock:
                self._target_buckets.pop(key)
                logger.info(
                    "rate_limiter_reset", scope="target", target=target,
                )

    def reset_source(self, source_ip: str) -> None:
        """Reset rate-limit state for a specific source IP."""
        key = _normalize_source_ip(source_ip)
        lock = self._source_shard.get(key)
        with lock:
            self._source_buckets.pop(key)
            logger.info(
                "rate_limiter_reset", scope="source", source_ip=source_ip,
            )

    def get_stats(self) -> RateLimiterStats:
        """Return current rate limiter statistics."""
        with self._global_lock:
            self._global_bucket.refill()
            return RateLimiterStats(
                target_buckets_active=len(self._target_buckets),
                source_buckets_active=len(self._source_buckets),
                global_tokens_remaining=round(
                    self._global_bucket.tokens, 1,
                ),
                global_max_tokens=self._global_bucket.max_tokens,
                global_violations=self._global_bucket.violation_count,
                config=RateLimiterConfig(
                    target_tpm=self._target_tpm,
                    target_burst=self._target_burst,
                    source_tpm=self._source_tpm,
                    source_burst=self._source_burst,
                    global_tpm=self._global_tpm,
                    global_burst=self._global_burst,
                    base_penalty_duration_s=self._base_penalty_duration,
                    max_penalty_duration_s=self._max_penalty_duration,
                ),
            )

    def is_blocked(
        self,
        target: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> bool:
        """Quick check: would a request be denied right now? (Non-consuming.)"""
        locks_needed: list[Lock] = [self._global_lock]
        if source_ip:
            source_key = _normalize_source_ip(source_ip)
            locks_needed.append(self._source_shard.get(source_key))
        if target:
            target_key = _normalize_target(target)
            locks_needed.append(self._target_shard.get(target_key))

        with _acquire_ordered(*locks_needed):
            self._global_bucket.refill()
            if not self._global_bucket.has_tokens(1.0):
                return True

            if source_ip:
                bucket = self._source_buckets.get(source_key)  # type: ignore[possibly-undefined]
                if bucket is not None:
                    bucket.refill()
                    if not bucket.has_tokens(1.0):
                        return True

            if target:
                bucket = self._target_buckets.get(target_key)  # type: ignore[possibly-undefined]
                if bucket is not None:
                    bucket.refill()
                    if not bucket.has_tokens(1.0):
                        return True

        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _deny_bucket(
        self,
        bucket: _Bucket,
        cost: float,
        layer_name: str,
        limit_label: str,
        identifier: str,
        target: str,
        source_ip: Optional[str],
    ) -> CheckResult:
        """Build a DENY result for a specific bucket layer.

        Violation counting happens here — the single source of truth.
        """
        bucket.record_violation()
        retry_after = bucket.time_until_available(cost)

        # ── Metrics ──
        self._metrics.on_deny(
            layer=layer_name,
            target=target,
            source_ip=source_ip,
            retry_after=retry_after,
        )

        # ── Rate-limited logging ──
        log_key = f"{layer_name}:{identifier}"
        if _rate_limited_logger.should_log(log_key):
            log_fn = (
                logger.critical if bucket.is_repeat_offender
                else logger.warning
            )
            log_fn(
                "rate_limited",
                layer=layer_name,
                identifier=identifier,
                tokens_remaining=round(bucket.tokens, 2),
                violation_count=bucket.violation_count,
                retry_after=round(retry_after, 1),
                is_repeat_offender=bucket.is_repeat_offender,
            )

        # ── Escalating penalty for repeat offenders ──
        if bucket.is_repeat_offender:
            actual_duration = bucket.apply_penalty(
                base_duration=self._base_penalty_duration,
                max_duration=self._max_penalty_duration,
                multiplier=self._penalty_multiplier,
            )

            self._metrics.on_penalty(
                layer=layer_name,
                identifier=identifier,
                duration=actual_duration,
                violation_count=bucket.violation_count,
            )

            if _rate_limited_logger.should_log(f"penalty:{log_key}"):
                logger.warning(
                    "penalty_applied",
                    layer=layer_name,
                    identifier=identifier,
                    penalty_duration=round(actual_duration, 1),
                    penalty_count=bucket._penalty_count,
                    violation_count=bucket.violation_count,
                )

            # Recalculate retry_after with penalty applied
            retry_after = bucket.time_until_available(cost)

        return CheckResult(
            verdict=Verdict.DENY,
            component=layer_name,
            reason=(
                f"Rate limit exceeded for '{identifier}'. "
                f"Limit: {limit_label}. "
                f"Violations: {bucket.violation_count}. "
                f"Retry after {retry_after:.1f}s."
            ),
        )

    def __repr__(self) -> str:
        return (
            f"RateLimiter("
            f"target={self._target_tpm}/min burst={self._target_burst:.0f}, "
            f"source={self._source_tpm}/min burst={self._source_burst:.0f}, "
            f"global={self._global_tpm}/min burst={self._global_burst:.0f}, "
            f"targets={len(self._target_buckets)}, "
            f"sources={len(self._source_buckets)}"
            f")"
        )