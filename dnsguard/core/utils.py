from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple


def now_ms() -> int:
    return int(time.time() * 1000)


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def uniq(seq: List[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


@dataclass
class QueryMeta:
    server: str
    qname: str
    qtype: str
    tcp: bool
    rcode: str
    elapsed_ms: int
    truncated: bool = False
    retries: int = 0

