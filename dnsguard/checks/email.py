from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from ..core.resolver import DNSResolver


@dataclass
class SPFResult:
    raw: Optional[str]
    policy: Optional[str]
    warnings: List[str]


def _flatten_txt(txt_items: List[str]) -> List[str]:
    # dnspython returns TXT items possibly already quoted; normalize
    out = []
    for t in txt_items:
        t = t.strip()
        if t.startswith('"') and t.endswith('"'):
            t = t[1:-1]
        out.append(t)
    return out


def parse_spf(spf: str) -> SPFResult:
    warnings: List[str] = []
    policy: Optional[str] = None

    s = spf.strip()
    if not s.lower().startswith("v=spf1"):
        return SPFResult(raw=spf, policy=None, warnings=["Not an SPF record (missing v=spf1)"])

    # simple policy extraction: last qualifier all
    m = re.search(r"(\+all|-all|~all|\?all)\b", s)
    if m:
        policy = m.group(1)
        if policy == "+all":
            warnings.append("SPF is overly permissive (+all): anyone can send email as this domain.")
        if policy in ("~all", "?all"):
            warnings.append(f"SPF is weak ({policy}). Consider -all for strict policy when appropriate.")
    else:
        warnings.append("SPF record has no explicit all mechanism; policy unclear.")

    # RFC requires max 10 DNS lookups for mechanisms like include, a, mx, ptr, exists, redirect
    lookup_mechs = re.findall(r"\b(include:|redirect=|exists:|ptr|mx\b|a\b)", s)
    if len(lookup_mechs) > 10:
        warnings.append("SPF likely exceeds 10-DNS-lookup limit (may fail).")

    return SPFResult(raw=spf, policy=policy, warnings=warnings)


@dataclass
class DMARCResult:
    raw: Optional[str]
    policy: Optional[str]
    warnings: List[str]


def parse_dmarc(dmarc: str) -> DMARCResult:
    warnings: List[str] = []
    s = dmarc.strip()
    if not s.lower().startswith("v=dmarc1"):
        return DMARCResult(raw=dmarc, policy=None, warnings=["Not a DMARC record (missing v=DMARC1)"])
    m = re.search(r"\bp=([a-zA-Z]+)", s)
    policy = m.group(1).lower() if m else None
    if not policy:
        warnings.append("DMARC missing p= policy.")
    elif policy == "none":
        warnings.append("DMARC policy is p=none (monitoring only). Consider quarantine/reject when ready.")
    return DMARCResult(raw=dmarc, policy=policy, warnings=warnings)


@dataclass
class EmailPosture:
    domain: str
    mx: List[str]
    mx_null: bool
    spf: SPFResult
    dmarc: DMARCResult
    dkim_selectors_checked: List[str]
    dkim_found: Dict[str, bool]
    findings: List[str]


def check_email_posture(
    domain: str,
    resolver: DNSResolver,
    server: str,
    dkim_selectors: Optional[List[str]] = None,
) -> EmailPosture:
    findings: List[str] = []

    # MX
    mx = []
    mx_null = False
    try:
        mx_ans = resolver.query(domain, "MX", server=server)
        mx = mx_ans.answers
        # Null MX pattern: "0 ."
        if any(x.strip() == "0 ." or x.strip().endswith(" .") for x in mx):
            mx_null = True
            findings.append("Null MX detected: domain is signaling it does not accept email (good for reducing misdirected mail).")
    except Exception:
        pass

    # SPF
    spf_raw = None
    try:
        txt_ans = resolver.query(domain, "TXT", server=server)
        txts = _flatten_txt(txt_ans.answers)
        for t in txts:
            if t.lower().startswith("v=spf1"):
                spf_raw = t
                break
    except Exception:
        pass

    spf_parsed = parse_spf(spf_raw) if spf_raw else SPFResult(raw=None, policy=None, warnings=["No SPF record found."])
    findings.extend(spf_parsed.warnings)

    # DMARC
    dmarc_raw = None
    try:
        dmarc_ans = resolver.query(f"_dmarc.{domain}", "TXT", server=server)
        txts = _flatten_txt(dmarc_ans.answers)
        for t in txts:
            if t.lower().startswith("v=dmarc1"):
                dmarc_raw = t
                break
    except Exception:
        pass

    dmarc_parsed = parse_dmarc(dmarc_raw) if dmarc_raw else DMARCResult(raw=None, policy=None, warnings=["No DMARC record found."])
    findings.extend(dmarc_parsed.warnings)

    # DKIM (optional)
    selectors = dkim_selectors or []
    dkim_found: Dict[str, bool] = {}
    for sel in selectors:
        name = f"{sel}._domainkey.{domain}"
        found = False
        try:
            ans = resolver.query(name, "TXT", server=server)
            txts = _flatten_txt(ans.answers)
            found = any("v=dkim1" in t.lower() for t in txts)
        except Exception:
            found = False
        dkim_found[sel] = found

    if selectors and not any(dkim_found.values()):
        findings.append("No DKIM record found for provided selectors. If the domain sends email, configure DKIM.")

    # Heuristic: if MX exists and DMARC missing -> higher risk
    if mx and not mx_null and dmarc_parsed.raw is None:
        findings.append("Domain appears to accept email (MX exists) but DMARC is missing: higher spoofing/phishing risk.")

    return EmailPosture(
        domain=domain,
        mx=mx,
        mx_null=mx_null,
        spf=spf_parsed,
        dmarc=dmarc_parsed,
        dkim_selectors_checked=selectors,
        dkim_found=dkim_found,
        findings=findings,
    )

