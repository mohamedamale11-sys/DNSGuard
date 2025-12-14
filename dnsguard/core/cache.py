from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass
class CacheEntry:
    expires_at: float
    value: Any


class TTLCache:
    """Very small TTL-aware cache.

    Keyed by (server, qname, qtype, dnssec_flag).
    """

    def __init__(self, max_items: int = 2048):
        self._max = max_items
        self._data: Dict[Tuple[str, str, str, bool], CacheEntry] = {}

    def get(self, key: Tuple[str, str, str, bool]) -> Optional[Any]:
        entry = self._data.get(key)
        if not entry:
            return None
        if time.time() >= entry.expires_at:
            self._data.pop(key, None)
            return None
        return entry.value

    def set(self, key: Tuple[str, str, str, bool], value: Any, ttl: int) -> None:
        if ttl <= 0:
            return
        if len(self._data) >= self._max:
            # simple eviction: drop an arbitrary item (good enough for this tool)
            self._data.pop(next(iter(self._data)), None)
        self._data[key] = CacheEntry(expires_at=time.time() + ttl, value=value)

