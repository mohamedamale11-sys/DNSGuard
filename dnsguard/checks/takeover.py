from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..core.resolver import DNSResolver


@dataclass
class TakeoverIndicator:
    domain: str
    cname_chain: List[str]
    dangling_cname: bool
    notes: List[str]


def check_dangling_cname(domain: str, resolver: DNSResolver, server: str) -> TakeoverIndicator:
    """Safe heuristic: checks if domain resolves to a CNAME target that does not resolve (NXDOMAIN/NoAnswer).
    Does NOT attempt takeover or exploitation.
    """
    notes: List[str] = []
    chain: List[str] = []
    dangling = False

    try:
        cname = resolver.query(domain, "CNAME", server=server)
        if cname.answers:
            target = cname.answers[0]
            chain.append(target)
            # verify target resolves
            try:
                a = resolver.query(target, "A", server=server)
                if not a.answers:
                    dangling = True
            except Exception:
                dangling = True

            if dangling:
                notes.append("CNAME target failed to resolve. This can indicate a dangling DNS entry (potential takeover risk depending on provider).")
    except Exception:
        pass

    return TakeoverIndicator(domain=domain, cname_chain=chain, dangling_cname=dangling, notes=notes)

