from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .checks.caa import check_caa
from .checks.dnssec import check_dnssec_signals
from .checks.email import check_email_posture
from .checks.takeover import check_dangling_cname
from .core.cache import TTLCache
from .core.resolver import DNSResolver
from .core.trace import iterative_trace
from .report.render_html import render_report_html

DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def _parse_resolvers(s: Optional[str]) -> List[str]:
    if not s:
        return DEFAULT_RESOLVERS
    return [x.strip() for x in s.split(",") if x.strip()]


def cmd_lookup(args: argparse.Namespace) -> int:
    resolver = DNSResolver(timeout=args.timeout, tries=args.tries, cache=TTLCache())
    resolvers = _parse_resolvers(args.resolvers)
    results = []

    for r in resolvers:
        try:
            ans = resolver.query(args.domain, args.type, server=r, want_dnssec=args.dnssec)
            results.append(asdict(ans))
            if not args.json:
                print(
                    f"{args.domain} {args.type} TTL={ans.ttl} via {r} "
                    f"({ans.meta.elapsed_ms}ms, rcode={ans.meta.rcode}, tcp={ans.meta.tcp})"
                )
                for a in ans.answers:
                    print("  ", a)
                if args.show_authority and ans.authority:
                    print("  [authority]")
                    for x in ans.authority:
                        print("   ", x)
        except Exception as e:
            results.append({"server": r, "error": str(e)})
            if not args.json:
                print(f"{args.domain} {args.type} via {r}: ERROR {e}", file=sys.stderr)

    if args.json:
        out = {"domain": args.domain, "type": args.type, "results": results}
        if args.json == "-":
            print(json.dumps(out, indent=2))
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
    return 0


def cmd_trace(args: argparse.Namespace) -> int:
    tr = iterative_trace(
        args.domain,
        qtype=args.type,
        timeout=args.timeout,
        ns_resolver_ip=args.ns_resolver,
    )

    if args.json:
        out = {
            "domain": args.domain,
            "type": args.type,
            "ns_resolver": args.ns_resolver,
            "steps": [asdict(s) for s in tr.steps],
            "final_answers": tr.final_answers,
        }
        if args.json == "-":
            print(json.dumps(out, indent=2))
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
    else:
        for i, s in enumerate(tr.steps, 1):
            print(
                f"[{i}] server={s.server} q={s.qname} {s.qtype} "
                f"rcode={s.rcode} {s.elapsed_ms}ms "
                f"answers={len(s.answers)} authority={len(s.authority)} additional={len(s.additional)}"
                + (f" note={s.note}" if getattr(s, "note", "") else "")
            )
            if s.answers:
                print("  answers:")
                for a in s.answers:
                    print("    ", a)
            if s.authority:
                print("  authority:")
                for a in s.authority[:12]:
                    print("    ", a)

        if tr.final_answers:
            print("\nFINAL:")
            for a in tr.final_answers:
                print("  ", a)
    return 0


def cmd_email(args: argparse.Namespace) -> int:
    resolver = DNSResolver(timeout=args.timeout, tries=args.tries, cache=TTLCache())
    sels = [x.strip() for x in (args.dkim_selectors or "").split(",") if x.strip()]
    res = check_email_posture(args.domain, resolver, server=args.server, dkim_selectors=sels)
    out = asdict(res)
    if args.json:
        if args.json == "-":
            print(json.dumps(out, indent=2))
        else:
            with open(args.json, "w", encoding="utf-8") as f:
                json.dump(out, f, indent=2)
    else:
        print(json.dumps(out, indent=2))
    return 0


def _score_report(findings: List[str]) -> int:
    # simple explainable scoring: start 100, subtract per finding severity keywords
    score = 100
    for f in findings:
        lf = f.lower()
        if "overly permissive" in lf or "takeover" in lf:
            score -= 25
        elif "missing" in lf:
            score -= 15
        elif "weak" in lf or "monitoring" in lf:
            score -= 8
        else:
            score -= 5
    return max(0, min(100, score))


def cmd_scan(args: argparse.Namespace) -> int:
    resolvers = _parse_resolvers(args.resolvers)
    resolver = DNSResolver(timeout=args.timeout, tries=args.tries, cache=TTLCache())

    # Resolver comparison: query a few record types across resolvers
    compare: Dict[str, Any] = {"resolvers": resolvers, "queries": {}}
    record_types = ["A", "AAAA", "CNAME", "MX", "TXT", "NS", "SOA"]
    for t in record_types:
        compare["queries"][t] = []
        for r in resolvers:
            try:
                ans = resolver.query(args.domain, t, server=r)
                compare["queries"][t].append(
                    {
                        "server": r,
                        "ttl": ans.ttl,
                        "answers": ans.answers,
                        "ms": ans.meta.elapsed_ms,
                        "rcode": ans.meta.rcode,
                    }
                )
            except Exception as e:
                compare["queries"][t].append({"server": r, "error": str(e)})

    # Checks (use primary server for posture checks to keep consistent)
    primary = args.server or resolvers[0]
    email = check_email_posture(args.domain, resolver, server=primary, dkim_selectors=_csv(args.dkim_selectors))
    dnssec = check_dnssec_signals(args.domain, resolver, server=primary)
    caa = check_caa(args.domain, resolver, server=primary)
    takeover = check_dangling_cname(args.domain, resolver, server=primary)

    # Trace (can be slow, optional)
    tr = (
        iterative_trace(args.domain, qtype="A", timeout=args.timeout, ns_resolver_ip=args.ns_resolver)
        if args.trace
        else None
    )

    findings: List[str] = []
    findings.extend(email.findings)
    findings.extend(dnssec.notes)
    findings.extend(caa.notes)
    findings.extend(takeover.notes)

    score = _score_report(findings)

    report: Dict[str, Any] = {
        "domain": args.domain,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "score": score,
        "findings": findings,
        "summary": {
            "primary_resolver": primary,
            "resolvers_compared": resolvers,
            "ns_resolver_for_trace": args.ns_resolver,
        },
        "sections": {
            "email": asdict(email),
            "dnssec": asdict(dnssec),
            "caa": asdict(caa),
            "takeover": asdict(takeover),
            "resolver_comparison": compare,
            "trace": {"steps": [asdict(s) for s in tr.steps], "final_answers": tr.final_answers} if tr else {"enabled": False},
        },
    }

    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

    if args.html:
        html_doc = render_report_html(report)
        with open(args.html, "w", encoding="utf-8") as f:
            f.write(html_doc)

    if not args.out and not args.html:
        print(json.dumps(report, indent=2, ensure_ascii=False))

    return 0


def _csv(s: Optional[str]) -> List[str]:
    if not s:
        return []
    return [x.strip() for x in s.split(",") if x.strip()]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="dnsguard", description="DNSGuard: DNS + security posture analyzer")
    p.add_argument("--version", action="version", version="dnsguard 0.1.0")
    sub = p.add_subparsers(dest="cmd", required=True)

    # lookup
    a = sub.add_parser("lookup", help="Lookup DNS records across resolvers")
    a.add_argument("domain")
    a.add_argument("--type", default="A", help="Record type (A, AAAA, CNAME, MX, TXT, NS, SOA, CAA, DS, DNSKEY)")
    a.add_argument("--resolvers", help="Comma-separated resolvers (default: 1.1.1.1,8.8.8.8,9.9.9.9)")
    a.add_argument("--timeout", type=float, default=2.0)
    a.add_argument("--tries", type=int, default=2)
    a.add_argument("--dnssec", action="store_true", help="Request DNSSEC-related data (DO bit)")
    a.add_argument("--show-authority", action="store_true")
    a.add_argument("--json", help="Write JSON output to file (or '-' for stdout)")
    a.set_defaults(func=cmd_lookup)

    # trace
    t = sub.add_parser("trace", help="Iterative trace like dig +trace")
    t.add_argument("domain")
    t.add_argument("--type", default="A")
    t.add_argument("--timeout", type=float, default=2.0)
    t.add_argument("--json", help="Write JSON output to file (or '-' for stdout)")
    t.add_argument(
        "--ns-resolver",
        default="1.1.1.1",
        help="Recursive resolver used to resolve NS hostnames when glue is missing (default: 1.1.1.1)",
    )
    t.set_defaults(func=cmd_trace)

    # email
    e = sub.add_parser("email", help="Email security posture (SPF/DMARC/DKIM selectors)")
    e.add_argument("domain")
    e.add_argument("--server", default="1.1.1.1", help="Resolver to use")
    e.add_argument("--dkim-selectors", help="Comma-separated DKIM selectors to check (optional)")
    e.add_argument("--timeout", type=float, default=2.0)
    e.add_argument("--tries", type=int, default=2)
    e.add_argument("--json", help="Write JSON output to file (or '-' for stdout)")
    e.set_defaults(func=cmd_email)

    # scan
    s = sub.add_parser("scan", help="Full scan + JSON/HTML report")
    s.add_argument("domain")
    s.add_argument("--resolvers", help="Comma-separated resolvers for comparison")
    s.add_argument("--server", help="Primary resolver for checks (default: first resolver)")
    s.add_argument("--dkim-selectors", help="Comma-separated DKIM selectors to check (optional)")
    s.add_argument("--timeout", type=float, default=2.0)
    s.add_argument("--tries", type=int, default=2)
    s.add_argument("--trace", action="store_true", help="Include iterative trace (slower)")
    s.add_argument(
        "--ns-resolver",
        default="1.1.1.1",
        help="Recursive resolver used during trace to resolve NS hostnames when glue is missing",
    )
    s.add_argument("--out", help="Write JSON report to file")
    s.add_argument("--html", help="Write HTML report to file")
    s.set_defaults(func=cmd_scan)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
