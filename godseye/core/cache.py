"""Multi-tier Caching (L1 In-Memory LRU + L2 SQLite TTL) for OSINT responses."""

import json
import sqlite3
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any


class MultiTierCache:
    """Two-level cache (L1 memory OrderedDict LRU + L2 SQLite TTL table)."""

    def __init__(
        self,
        db_path: str = ":memory:",
        l1_max_size: int = 512,
        default_ttl_sec: int = 3600,
    ) -> None:
        self.db_path = db_path
        self.l1_max_size = max(16, l1_max_size)
        self.default_ttl_sec = default_ttl_sec
        self._l1: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        if db_path != ":memory:":
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_schema()

    def _init_schema(self) -> None:
        with self._conn:
            self._conn.execute("PRAGMA journal_mode=WAL;")
            self._conn.execute(
                """
                CREATE TABLE IF NOT EXISTS osint_cache (
                    cache_key TEXT PRIMARY KEY,
                    payload_json TEXT NOT NULL,
                    expires_at REAL NOT NULL
                )
                """
            )

    def get(self, key: str) -> Any | None:
        """Retrieve cached item from L1 or L2 if not expired."""
        now = time.time()

        # Check L1 memory cache
        if key in self._l1:
            expires_at, value = self._l1[key]
            if expires_at > now:
                self._l1.move_to_end(key)
                return value
            del self._l1[key]

        # Check L2 SQLite cache
        cur = self._conn.execute(
            "SELECT payload_json, expires_at FROM osint_cache WHERE cache_key = ?",
            (key,),
        )
        row = cur.fetchone()
        if row is None:
            return None

        payload_json, expires_at = row[0], float(row[1])
        if expires_at <= now:
            with self._conn:
                self._conn.execute("DELETE FROM osint_cache WHERE cache_key = ?", (key,))
            return None

        value = json.loads(payload_json)
        self._set_l1(key, value, expires_at)
        return value

    def set(self, key: str, value: Any, ttl_sec: int | None = None) -> None:
        """Store item in both L1 and L2 caches with TTL."""
        ttl = self.default_ttl_sec if ttl_sec is None else ttl_sec
        expires_at = time.time() + max(1, ttl)
        self._set_l1(key, value, expires_at)

        serialized = json.dumps(value, ensure_ascii=False, default=str)
        with self._conn:
            self._conn.execute(
                """
                INSERT INTO osint_cache (cache_key, payload_json, expires_at)
                VALUES (?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    payload_json = excluded.payload_json,
                    expires_at = excluded.expires_at
                """,
                (key, serialized, expires_at),
            )

    def _set_l1(self, key: str, value: Any, expires_at: float) -> None:
        if key in self._l1:
            self._l1.move_to_end(key)
        self._l1[key] = (expires_at, value)
        while len(self._l1) > self.l1_max_size:
            self._l1.popitem(last=False)

    def clear(self) -> None:
        """Clear both L1 and L2 cache tiers."""
        self._l1.clear()
        with self._conn:
            self._conn.execute("DELETE FROM osint_cache")

    def close(self) -> None:
        """Close SQLite connection."""
        self._conn.close()
