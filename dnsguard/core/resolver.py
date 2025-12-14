from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.exception

from .cache import TTLCache
from .utils import QueryMeta, now_ms


@dataclass
class Answer:
    qname: str
    qtype: str
    ttl: Optional[int]
    answers: List[str]
    authority: List[str]
    additional: List[str]
    meta: QueryMeta


class DNSResolver:
    def __init__(
        self,
        timeout: float = 2.0,
        tries: int = 2,
        udp_payload: int = 1232,
        cache: Optional[TTLCache] = None,
    ):
        self.timeout = timeout
        self.tries = max(1, tries)
        self.udp_payload = udp_payload
        self.cache = cache or TTLCache()

    def query(
        self,
        qname: str,
        qtype: str,
        server: str,
        want_dnssec: bool = False,
        use_tcp_fallback: bool = True,
    ) -> Answer:
        qtype = qtype.upper()
        key = (server, qname.lower().rstrip("."), qtype, bool(want_dnssec))
        cached = self.cache.get(key)
        if cached:
            return cached

        q = dns.message.make_query(qname, qtype, use_edns=True, payload=self.udp_payload)
        if want_dnssec:
            q.want_dnssec(True)

        last_exc: Optional[Exception] = None
        retries = 0

        # UDP first
        for attempt in range(self.tries):
            retries = attempt
            t0 = now_ms()
            try:
                r = dns.query.udp(q, server, timeout=self.timeout)
                elapsed = now_ms() - t0
                truncated = bool(r.flags & dns.flags.TC)
                if truncated and use_tcp_fallback:
                    return self._query_tcp(qname, qtype, server, want_dnssec, retries=retries)
                ans = self._parse_response(qname, qtype, server, tcp=False, resp=r, elapsed=elapsed, retries=retries)
                self._cache_answer(key, ans)
                return ans
            except Exception as e:
                last_exc = e

        # TCP fallback if UDP failed
        if use_tcp_fallback:
            try:
                return self._query_tcp(qname, qtype, server, want_dnssec, retries=retries)
            except Exception as e:
                last_exc = e

        raise last_exc or RuntimeError("DNS query failed")

    def _query_tcp(self, qname: str, qtype: str, server: str, want_dnssec: bool, retries: int) -> Answer:
        q = dns.message.make_query(qname, qtype, use_edns=True, payload=self.udp_payload)
        if want_dnssec:
            q.want_dnssec(True)
        t0 = now_ms()
        r = dns.query.tcp(q, server, timeout=self.timeout)
        elapsed = now_ms() - t0
        ans = self._parse_response(qname, qtype, server, tcp=True, resp=r, elapsed=elapsed, retries=retries)
        key = (server, qname.lower().rstrip("."), qtype.upper(), bool(want_dnssec))
        self._cache_answer(key, ans)
        return ans

    def _parse_response(
        self,
        qname: str,
        qtype: str,
        server: str,
        tcp: bool,
        resp: dns.message.Message,
        elapsed: int,
        retries: int,
    ) -> Answer:
        rcode_text = dns.rcode.to_text(resp.rcode())
        meta = QueryMeta(
            server=server,
            qname=qname,
            qtype=qtype.upper(),
            tcp=tcp,
            rcode=rcode_text,
            elapsed_ms=elapsed,
            truncated=bool(resp.flags & dns.flags.TC),
            retries=retries,
        )

        answers: List[str] = []
        authority: List[str] = []
        additional: List[str] = []
        ttl: Optional[int] = None

        if resp.answer:
            # pick TTL from the first rrset
            ttl = resp.answer[0].ttl if getattr(resp.answer[0], "ttl", None) is not None else None
            for rrset in resp.answer:
                for item in rrset:
                    answers.append(item.to_text())

        for rrset in resp.authority:
            for item in rrset:
                authority.append(item.to_text())

        for rrset in resp.additional:
            for item in rrset:
                additional.append(item.to_text())

        return Answer(
            qname=qname,
            qtype=qtype.upper(),
            ttl=ttl,
            answers=answers,
            authority=authority,
            additional=additional,
            meta=meta,
        )

    def _cache_answer(self, key, ans: Answer) -> None:
        if ans.ttl is None:
            return
        # cap cache TTL to avoid huge retention
        ttl = int(min(max(ans.ttl, 0), 3600))
        self.cache.set(key, ans, ttl)

