from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional

from ..core.resolver import DNSResolver


@dataclass
class DNSSECResult:
    domain: str
    ds_present: bool
    rrsig_present: bool
    notes: List[str]


def check_dnssec_signals(domain: str, resolver: DNSResolver, server: str) -> DNSSECResult:
    notes: List[str] = []
    ds_present = False
    rrsig_present = False

    # DS should exist at parent zone, but querying DS at the domain often works through recursive resolvers.
    try:
        ds = resolver.query(domain, "DS", server=server, want_dnssec=True)
        ds_present = len(ds.answers) > 0
    except Exception:
        ds_present = False

    # RRSIG may appear when requesting DNSSEC with want_dnssec
    try:
        a = resolver.query(domain, "DNSKEY", server=server, want_dnssec=True)
        # Some resolvers include RRSIG in authority/answer sections. We can't perfectly validate chain here,
        # but presence of DNSKEY indicates DNSSEC material exists at zone apex.
        rrsig_present = any("RRSIG" in x for x in (a.authority + a.additional)) or False
        if a.answers:
            # DNSKEY presence alone is meaningful
            rrsig_present = True
    except Exception:
        rrsig_present = False

    if not ds_present:
        notes.append("No DS record detected (DNSSEC may not be enabled for this zone, or resolver did not return DS).")
    if ds_present and not rrsig_present:
        notes.append("DS detected but DNSKEY/RRSIG signals not observed (could be resolver behavior).")

    if ds_present and rrsig_present:
        notes.append("DNSSEC signals detected (DS + DNSKEY/RRSIG). Full validation requires a validating resolver and chain checks.")

    return DNSSECResult(domain=domain, ds_present=ds_present, rrsig_present=rrsig_present, notes=notes)

