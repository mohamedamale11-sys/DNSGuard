from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..core.resolver import DNSResolver


@dataclass
class CAAResult:
    domain: str
    records: List[str]
    has_caa: bool
    notes: List[str]


def check_caa(domain: str, resolver: DNSResolver, server: str) -> CAAResult:
    notes: List[str] = []
    records: List[str] = []
    try:
        ans = resolver.query(domain, "CAA", server=server)
        records = ans.answers
    except Exception:
        records = []
    has_caa = len(records) > 0
    if not has_caa:
        notes.append("No CAA records found. CAA is optional but can reduce certificate mis-issuance risk.")
    return CAAResult(domain=domain, records=records, has_caa=has_caa, notes=notes)

