"""Resilient HTTP Engine, TokenBucket Rate Limiter, Circuit Breaker & Performance Telemetry."""

import asyncio
import contextlib
import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import httpx

with contextlib.suppress(Exception):
    import truststore

    truststore.inject_into_ssl()

RETRYABLE_STATUS_CODES: frozenset[int] = frozenset({408, 429, 500, 502, 503, 504})
REPLAY_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD", "OPTIONS", "PUT", "DELETE"})


class TerminalHttpError(RuntimeError):
    """Raised when an HTTP request fails with a non-retryable status code (e.g., 400, 401, 403, 404)."""

    def __init__(self, status_code: int, message: str) -> None:
        super().__init__(f"Terminal HTTP error {status_code}: {message}")
        self.status_code = status_code


class CircuitOpenError(RuntimeError):
    """Raised when a source's circuit breaker is open due to sustained upstream failures."""


class TokenBucket:
    """Proactive asynchronous Token Bucket rate limiter (api-rate-limit-handler skill)."""

    def __init__(self, max_tokens: float, refill_rate_per_sec: float) -> None:
        self.max_tokens = max(1.0, float(max_tokens))
        self.refill_rate = max(0.01, float(refill_rate_per_sec))
        self.tokens = self.max_tokens
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = max(0.0, now - self.last_refill)
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    async def acquire(self) -> float:
        """Acquire a single request token, waiting if necessary. Returns wait time in seconds."""
        waited = 0.0
        async with self._lock:
            self._refill()
            if self.tokens < 1.0:
                wait_seconds = (1.0 - self.tokens) / self.refill_rate
                waited = wait_seconds
                await asyncio.sleep(wait_seconds)
                self._refill()
            self.tokens -= 1.0
        return waited


class CircuitBreaker:
    """Per-source circuit breaker (opens after `failure_threshold` failures in window)."""

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout_sec: float = 30.0,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout_sec = recovery_timeout_sec
        self.failure_count = 0
        self.opened_at: float | None = None
        self.state: str = "closed"  # closed, open, half_open

    def allow_request(self) -> bool:
        """Check whether a call is permitted through the circuit breaker."""
        if self.state == "closed":
            return True
        if self.state == "open" and self.opened_at is not None:
            if (time.monotonic() - self.opened_at) >= self.recovery_timeout_sec:
                self.state = "half_open"
                return True
            return False
        return self.state == "half_open"

    def record_success(self) -> None:
        """Reset failure count and close the circuit."""
        self.failure_count = 0
        self.opened_at = None
        self.state = "closed"

    def record_failure(self) -> None:
        """Increment failure count and trip the circuit if threshold is reached."""
        self.failure_count += 1
        if self.failure_count >= self.failure_threshold:
            self.state = "open"
            self.opened_at = time.monotonic()


def parse_retry_delay(
    headers: httpx.Headers | dict[str, str],
    attempt: int,
    max_delay_sec: float = 60.0,
) -> float:
    """Parse upstream `Retry-After` or `x-ratelimit-reset` headers, or compute full-jitter backoff."""
    normalized = {k.lower(): v for k, v in headers.items()}

    # 1. Standard Retry-After (numeric seconds or HTTP-date)
    retry_after = normalized.get("retry-after")
    if retry_after is not None and retry_after.strip() != "":
        try:
            seconds = float(retry_after.strip())
            if math.isfinite(seconds) and seconds >= 0.0:
                return seconds
        except ValueError:
            try:
                retry_dt = parsedate_to_datetime(retry_after.strip())
                if retry_dt.tzinfo is None:
                    retry_dt = retry_dt.replace(tzinfo=UTC)
                delta = (retry_dt - datetime.now(UTC)).total_seconds()
                return max(0.0, delta)
            except (ValueError, TypeError, OverflowError):
                pass

    # 2. GitHub / standard Unix epoch seconds reset header
    reset_val = normalized.get("x-ratelimit-reset")
    if reset_val is not None and reset_val.strip() != "":
        try:
            epoch_sec = float(reset_val.strip())
            if math.isfinite(epoch_sec) and epoch_sec > 1_000_000_000:
                return max(0.0, epoch_sec - time.time())
        except ValueError:
            pass

    # 3. Fallback: capped exponential backoff with full jitter
    cap = min(1.0 * (2**attempt), max_delay_sec)
    return random.uniform(0.05, max(0.1, cap))


@dataclass
class SourceMetrics:
    """Telemetry metrics for a single OSINT source."""

    requests: int = 0
    successes: int = 0
    failures: int = 0
    retries: int = 0
    cache_hits: int = 0
    latencies_ms: list[float] = field(default_factory=list)


class PerformanceTelemetry:
    """Observability and performance metrics tracker (performance-engineer skill)."""

    def __init__(self) -> None:
        self._sources: dict[str, SourceMetrics] = defaultdict(SourceMetrics)
        self._started_at = time.monotonic()

    def record_call(
        self,
        source_id: str,
        latency_ms: float,
        success: bool,
        retries: int = 0,
        cached: bool = False,
    ) -> None:
        """Record metrics for an OSINT source invocation."""
        m = self._sources[source_id]
        m.requests += 1
        if cached:
            m.cache_hits += 1
        if success:
            m.successes += 1
        else:
            m.failures += 1
        m.retries += retries
        m.latencies_ms.append(latency_ms)
        if len(m.latencies_ms) > 500:
            m.latencies_ms = m.latencies_ms[-500:]

    @staticmethod
    def _percentile(values: list[float], pct: float) -> float:
        if not values:
            return 0.0
        sorted_vals = sorted(values)
        idx = min(len(sorted_vals) - 1, max(0, int(math.ceil((pct / 100.0) * len(sorted_vals)) - 1)))
        return round(sorted_vals[idx], 2)

    def snapshot(self) -> dict[str, Any]:
        """Return aggregated performance metrics (p50, p95, p99, cache hit ratio, throughput)."""
        all_latencies: list[float] = []
        total_requests = 0
        total_success = 0
        total_failures = 0
        total_retries = 0
        total_cache_hits = 0
        per_source: dict[str, Any] = {}

        for src, m in self._sources.items():
            total_requests += m.requests
            total_success += m.successes
            total_failures += m.failures
            total_retries += m.retries
            total_cache_hits += m.cache_hits
            all_latencies.extend(m.latencies_ms)
            per_source[src] = {
                "requests": m.requests,
                "successes": m.successes,
                "failures": m.failures,
                "retries": m.retries,
                "cache_hits": m.cache_hits,
                "p50_ms": self._percentile(m.latencies_ms, 50),
                "p95_ms": self._percentile(m.latencies_ms, 95),
                "p99_ms": self._percentile(m.latencies_ms, 99),
            }

        uptime_s = max(0.001, time.monotonic() - self._started_at)
        cache_hit_ratio = (
            round((total_cache_hits / total_requests) * 100.0, 2) if total_requests > 0 else 0.0
        )
        return {
            "uptime_seconds": round(uptime_s, 2),
            "total_requests": total_requests,
            "total_successes": total_success,
            "total_failures": total_failures,
            "total_retries": total_retries,
            "total_cache_hits": total_cache_hits,
            "cache_hit_rate_pct": cache_hit_ratio,
            "p50_latency_ms": self._percentile(all_latencies, 50),
            "p95_latency_ms": self._percentile(all_latencies, 95),
            "p99_latency_ms": self._percentile(all_latencies, 99),
            "sources": per_source,
        }


class ResilientHttpClient:
    """Connection-pooled async HTTP client with TokenBucket, CircuitBreaker, and Retry-After."""

    def __init__(
        self,
        timeout_sec: float = 12.0,
        max_retries: int = 3,
        max_elapsed_sec: float = 45.0,
        telemetry: PerformanceTelemetry | None = None,
    ) -> None:
        self.timeout_sec = timeout_sec
        self.max_retries = max_retries
        self.max_elapsed_sec = max_elapsed_sec
        self.telemetry = telemetry or PerformanceTelemetry()
        self._limiters: dict[str, TokenBucket] = {}
        self._breakers: dict[str, CircuitBreaker] = {}
        self._client: httpx.AsyncClient | None = None

    def configure_source(
        self,
        source_id: str,
        rate_limit_per_min: int = 30,
        failure_threshold: int = 5,
    ) -> None:
        """Register rate limit and circuit breaker parameters for a specific source."""
        refill_per_sec = max(0.1, rate_limit_per_min / 60.0)
        burst = max(2.0, min(20.0, float(rate_limit_per_min)))
        self._limiters[source_id] = TokenBucket(max_tokens=burst, refill_rate_per_sec=refill_per_sec)
        self._breakers[source_id] = CircuitBreaker(failure_threshold=failure_threshold)

    def _get_limiter(self, source_id: str) -> TokenBucket:
        if source_id not in self._limiters:
            self.configure_source(source_id)
        return self._limiters[source_id]

    def _get_breaker(self, source_id: str) -> CircuitBreaker:
        if source_id not in self._breakers:
            self.configure_source(source_id)
        return self._breakers[source_id]

    async def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            limits = httpx.Limits(max_keepalive_connections=20, max_connections=50)
            self._client = httpx.AsyncClient(
                timeout=httpx.Timeout(self.timeout_sec),
                limits=limits,
                follow_redirects=True,
                headers={
                    "User-Agent": "GodsEye-OSINT-Platform/1.0 (+https://github.com/godseye-osint)"
                },
            )
        return self._client

    async def close(self) -> None:
        """Close underlying HTTP connection pool."""
        if self._client is not None and not self._client.is_closed:
            await self._client.aclose()

    async def fetch_with_retry(
        self,
        source_id: str,
        url: str,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
        max_retries: int | None = None,
        max_elapsed_sec: float | None = None,
        retry_non_idempotent: bool = False,
    ) -> httpx.Response:
        """Execute an HTTP request with proactive rate limiting, circuit breaking, and bounded retry."""
        breaker = self._get_breaker(source_id)
        if not breaker.allow_request():
            raise CircuitOpenError(f"Circuit breaker is OPEN for source '{source_id}'")

        limiter = self._get_limiter(source_id)
        await limiter.acquire()

        client = await self._ensure_client()
        retries_limit = self.max_retries if max_retries is None else max_retries
        elapsed_budget = self.max_elapsed_sec if max_elapsed_sec is None else max_elapsed_sec
        upper_method = method.upper()
        replay_safe = (upper_method in REPLAY_SAFE_METHODS) or retry_non_idempotent

        started_at = time.monotonic()
        retries_used = 0

        for attempt in range(retries_limit + 1):
            try:
                response = await client.request(
                    method=upper_method,
                    url=url,
                    headers=headers,
                    params=params,
                    json=json_body,
                )
            except (httpx.TimeoutException, httpx.NetworkError) as exc:
                if not replay_safe or attempt == retries_limit:
                    breaker.record_failure()
                    latency_ms = (time.monotonic() - started_at) * 1000.0
                    self.telemetry.record_call(
                        source_id, latency_ms, success=False, retries=retries_used
                    )
                    raise
                delay = parse_retry_delay({}, attempt)
                remaining = elapsed_budget - (time.monotonic() - started_at)
                if remaining <= 0 or delay > remaining:
                    breaker.record_failure()
                    raise TimeoutError(
                        f"Retry for {source_id} cannot fit within {elapsed_budget}s budget"
                    ) from exc
                retries_used += 1
                await asyncio.sleep(delay)
                continue

            if response.is_success:
                breaker.record_success()
                latency_ms = (time.monotonic() - started_at) * 1000.0
                self.telemetry.record_call(
                    source_id, latency_ms, success=True, retries=retries_used
                )
                return response

            # Terminal client error (e.g. 400, 401, 403, 404) -> do not retry
            if response.status_code not in RETRYABLE_STATUS_CODES:
                await response.aclose()
                latency_ms = (time.monotonic() - started_at) * 1000.0
                self.telemetry.record_call(
                    source_id, latency_ms, success=False, retries=retries_used
                )
                raise TerminalHttpError(response.status_code, response.reason_phrase or "Client Error")

            if not replay_safe:
                await response.aclose()
                breaker.record_failure()
                raise RuntimeError(
                    f"{upper_method} was not retried because replay safety was not established"
                )

            if attempt == retries_limit:
                status = response.status_code
                await response.aclose()
                breaker.record_failure()
                latency_ms = (time.monotonic() - started_at) * 1000.0
                self.telemetry.record_call(
                    source_id, latency_ms, success=False, retries=retries_used
                )
                raise RuntimeError(f"Failed after {retries_limit} retries with status {status}")

            delay = parse_retry_delay(response.headers, attempt)
            remaining = elapsed_budget - (time.monotonic() - started_at)
            await response.aclose()
            if remaining <= 0 or delay > remaining:
                breaker.record_failure()
                latency_ms = (time.monotonic() - started_at) * 1000.0
                self.telemetry.record_call(
                    source_id, latency_ms, success=False, retries=retries_used
                )
                raise TimeoutError(
                    f"Retry delay ({delay:.2f}s) exceeds remaining operation budget ({remaining:.2f}s)"
                )

            retries_used += 1
            await asyncio.sleep(delay)

        raise RuntimeError("Unreachable retry state")
