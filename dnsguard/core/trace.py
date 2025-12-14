from __future__ import annotations

import json
import random
from dataclasses import dataclass
from typing import List, Optional, Tuple

import dns.flags
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype

from .resolver import DNSResolver
from .utils import is_ip, now_ms, uniq


@dataclass
class TraceStep:
    server: str
    qname: str
    qtype: str
    elapsed_ms: int
    rcode: str
    answers: List[str]
    authority: List[str]
    additional: List[str]
    note: str = ""


@dataclass
class TraceResult:
    qname: str
    qtype: str
    steps: List[TraceStep]
    final_answers: List[str]


def _load_root_hints() -> List[str]:
    """
    Loads root server IPs from packaged data: dnsguard/data/root_hints.json.
    Fallbacks to a small built-in list if not found.
    """
    try:
        from importlib import resources

        p = resources.files("dnsguard").joinpath("data/root_hints.json")
        with p.open("r", encoding="utf-8") as f:
            j = json.load(f)
        ips = [x["ip"] for x in j.get("servers", []) if isinstance(x, dict) and x.get("ip")]
        ips = [ip for ip in ips if is_ip(ip)]
        if ips:
            return ips
    except Exception:
        pass

    # fallback (safe minimal set)
    return ["198.41.0.4", "199.9.14.201", "192.33.4.12"]


def _rrset_to_text(rrsets) -> List[str]:
    out: List[str] = []
    for rrset in rrsets:
        for item in rrset:
            out.append(item.to_text())
    return out


def _extract_referral_ns(resp: dns.message.Message) -> List[str]:
    """
    Extract NS names from AUTHORITY section referrals.
    """
    ns_names: List[str] = []
    for rrset in resp.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for item in rrset:
                # dnspython NS rdata: item.to_text() gives target hostname
                ns_names.append(item.to_text())
    return uniq([n if n.endswith(".") else n + "." for n in ns_names])


def _extract_glue_ips(resp: dns.message.Message) -> List[str]:
    """
    Extract glue A/AAAA IPs from ADDITIONAL section.
    """
    ips: List[str] = []
    for rrset in resp.additional:
        if rrset.rdtype in (dns.rdatatype.A, dns.rdatatype.AAAA):
            for item in rrset:
                t = item.to_text()
                if is_ip(t):
                    ips.append(t)
    return uniq(ips)


def _extract_cname_target(resp: dns.message.Message) -> Optional[str]:
    """
    If the answer contains a CNAME, return the CNAME target.
    """
    for rrset in resp.answer:
        if rrset.rdtype == dns.rdatatype.CNAME:
            for item in rrset:
                target = item.to_text()
                return target if target.endswith(".") else target + "."
    return None


def iterative_trace(
    qname: str,
    qtype: str = "A",
    timeout: float = 2.0,
    max_steps: int = 30,
    ns_resolver_ip: str = "1.1.1.1",
) -> TraceResult:
    """
    Best-effort iterative resolution trace similar to `dig +trace`.

    Strategy:
    - Start at root hints
    - Query current qname/qtype against one server
    - If ANSWER -> done (or follow CNAME)
    - Else follow referral NS:
        - Use glue IPs if present
        - Otherwise resolve NS hostnames to IPs using a recursive resolver (ns_resolver_ip)
    """
    qtype = qtype.upper()
    current = qname.rstrip(".") + "."

    roots = _load_root_hints()
    # Shuffle roots so traces aren't always identical
    random.shuffle(roots)

    resolver = DNSResolver(timeout=timeout, tries=2)
    steps: List[TraceStep] = []
    servers = roots[:]  # start at root

    final_answers: List[str] = []

    # Safety: avoid infinite CNAME loops
    cname_hops = 0
    seen_names = set()

    for _ in range(max_steps):
        if not servers:
            break

        server = servers[0]
        note = ""

        # Build query
        msg = dns.message.make_query(current, qtype, use_edns=True, payload=1232)

        t0 = now_ms()
        resp = dns.query.udp(msg, server, timeout=timeout)
        elapsed = now_ms() - t0

        # TCP fallback if truncated
        if resp.flags & dns.flags.TC:
            note = "udp_truncated->tcp"
            t0 = now_ms()
            resp = dns.query.tcp(msg, server, timeout=timeout)
            elapsed = now_ms() - t0

        rcode_text = dns.rcode.to_text(resp.rcode())

        ans_txt = _rrset_to_text(resp.answer)
        auth_txt = _rrset_to_text(resp.authority)
        addl_txt = _rrset_to_text(resp.additional)

        steps.append(
            TraceStep(
                server=server,
                qname=current,
                qtype=qtype,
                elapsed_ms=elapsed,
                rcode=rcode_text,
                answers=ans_txt,
                authority=auth_txt,
                additional=addl_txt,
                note=note,
            )
        )

        # Stop on errors
        if resp.rcode() != dns.rcode.NOERROR:
            break

        # If we got answers, either finish or follow CNAME
        if resp.answer:
            cname_target = _extract_cname_target(resp)
            if cname_target and qtype != "CNAME":
                # Follow CNAME to resolve final qtype
                cname_hops += 1
                if cname_hops > 8:
                    break
                if cname_target in seen_names:
                    break
                seen_names.add(cname_target)

                current = cname_target
                servers = roots[:]  # restart from root for the new name (simple + reliable)
                continue

            # Otherwise, treat the answer as final
            final_answers = ans_txt
            break

        # No answer: follow referrals
        glue_ips = _extract_glue_ips(resp)
        if glue_ips:
            servers = glue_ips
            continue

        ns_names = _extract_referral_ns(resp)
        if not ns_names:
            # Sometimes you get SOA in authority (negative caching). Stop.
            break

        # Resolve NS names to IPs using a recursive resolver (reliable)
        ns_ips: List[str] = []
        for ns in ns_names[:6]:
            try:
                a = resolver.query(ns, "A", server=ns_resolver_ip)
                ns_ips.extend(a.answers)
            except Exception:
                pass
            try:
                aaaa = resolver.query(ns, "AAAA", server=ns_resolver_ip)
                ns_ips.extend(aaaa.answers)
            except Exception:
                pass

        ns_ips = uniq([ip for ip in ns_ips if is_ip(ip)])
        if not ns_ips:
            break

        servers = ns_ips

    return TraceResult(qname=qname, qtype=qtype, steps=steps, final_answers=final_answers)
