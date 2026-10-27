"""Tests for API Rate Limit Handler, Circuit Breaker, Retry-After & Multi-Tier Cache."""

from datetime import UTC, datetime, timedelta
from email.utils import format_datetime

import httpx
import pytest

from godseye.core.cache import MultiTierCache
from godseye.core.resilience import (
    CircuitBreaker,
    CircuitOpenError,
    ResilientHttpClient,
    TerminalHttpError,
    TokenBucket,
    parse_retry_delay,
)


def test_parse_retry_delay_numeric_and_http_date() -> None:
    # 1. Numeric Retry-After
    delay_num = parse_retry_delay({"Retry-After": "4.5"}, attempt=0)
    assert delay_num == 4.5

    # 2. HTTP-date Retry-After
    future_dt = datetime.now(UTC) + timedelta(seconds=10)
    http_date = format_datetime(future_dt, usegmt=True)
    delay_date = parse_retry_delay({"Retry-After": http_date}, attempt=0)
    assert 5.0 <= delay_date <= 12.0

    # 3. GitHub x-ratelimit-reset epoch seconds
    future_epoch = str(int(datetime.now(UTC).timestamp()) + 8)
    delay_gh = parse_retry_delay({"x-ratelimit-reset": future_epoch}, attempt=0)
    assert 4.0 <= delay_gh <= 10.0

    # 4. Fallback exponential backoff with jitter
    fallback = parse_retry_delay({}, attempt=2, max_delay_sec=10.0)
    assert 0.05 <= fallback <= 4.0


@pytest.mark.asyncio
async def test_token_bucket_rate_limiter() -> None:
    bucket = TokenBucket(max_tokens=2.0, refill_rate_per_sec=20.0)
    w1 = await bucket.acquire()
    w2 = await bucket.acquire()
    w3 = await bucket.acquire()
    assert w1 == 0.0
    assert w2 == 0.0
    assert w3 > 0.0


def test_circuit_breaker_transitions() -> None:
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout_sec=0.05)
    assert cb.allow_request() is True
    cb.record_failure()
    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "open"
    assert cb.allow_request() is False


@pytest.mark.asyncio
async def test_resilient_http_client_retry_and_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    client = ResilientHttpClient(timeout_sec=2.0, max_retries=2, max_elapsed_sec=5.0)
    calls = 0

    async def fake_request(method: str, url: str, **kwargs: object) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(429, headers={"Retry-After": "0.02"}, request=httpx.Request(method, url))
        return httpx.Response(200, json={"ok": True}, request=httpx.Request(method, url))

    inner = await client._ensure_client()
    monkeypatch.setattr(inner, "request", fake_request)

    resp = await client.fetch_with_retry("test_src", "https://example.com/api")
    assert resp.status_code == 200
    assert calls == 2

    # Terminal 404 should not retry
    async def fake_404(method: str, url: str, **kwargs: object) -> httpx.Response:
        return httpx.Response(404, request=httpx.Request(method, url))

    monkeypatch.setattr(inner, "request", fake_404)
    with pytest.raises(TerminalHttpError) as exc_info:
        await client.fetch_with_retry("test_src", "https://example.com/missing")
    assert exc_info.value.status_code == 404

    # Circuit breaker open check
    client._get_breaker("broken_src").state = "open"
    client._get_breaker("broken_src").opened_at = 9999999999.0
    with pytest.raises(CircuitOpenError):
        await client.fetch_with_retry("broken_src", "https://example.com")

    await client.close()


def test_multi_tier_cache_l1_and_l2(temp_db_path: str) -> None:
    cache = MultiTierCache(db_path=temp_db_path, l1_max_size=16, default_ttl_sec=60)
    cache.set("k1", {"domain": "example.com"})
    assert cache.get("k1") == {"domain": "example.com"}

    # Evict L1 to verify L2 SQLite persistence
    cache._l1.clear()
    assert cache.get("k1") == {"domain": "example.com"}
    cache.close()
