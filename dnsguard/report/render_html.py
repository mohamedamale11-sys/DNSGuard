from __future__ import annotations

import html
from typing import Any, Dict, List


def _esc(s: str) -> str:
    return html.escape(s, quote=True)


def render_report_html(report: Dict[str, Any]) -> str:
    domain = report.get("domain", "unknown")
    created = report.get("created_at", "")
    score = report.get("score", None)

    findings = report.get("findings", [])
    sections = report.get("sections", {})

    def li(items: List[str]) -> str:
        if not items:
            return "<p><em>No findings.</em></p>"
        return "<ul>" + "".join(f"<li>{_esc(str(x))}</li>" for x in items) + "</ul>"

    def pre(obj: Any) -> str:
        import json
        return "<pre>" + _esc(json.dumps(obj, indent=2, ensure_ascii=False)) + "</pre>"

    # Simple, clean HTML (no external deps)
    html_doc = f"""<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>DNSGuard Report - {_esc(domain)}</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; line-height: 1.4; }}
    .card {{ border: 1px solid #2a2a2a; border-radius: 14px; padding: 16px; margin-bottom: 16px; }}
    .muted {{ opacity: 0.8; }}
    .grid {{ display: grid; grid-template-columns: 1fr; gap: 16px; }}
    @media (min-width: 900px) {{ .grid {{ grid-template-columns: 1fr 1fr; }} }}
    h1 {{ margin: 0 0 8px 0; }}
    h2 {{ margin: 0 0 8px 0; }}
    code, pre {{ background: #0f0f0f; color: #f2f2f2; padding: 10px; border-radius: 10px; overflow-x: auto; }}
    pre {{ margin: 0; }}
    .pill {{ display:inline-block; padding: 4px 10px; border-radius: 999px; border:1px solid #444; }}
  </style>
</head>
<body>
  <div class="card">
    <h1>DNSGuard Report</h1>
    <div class="muted">Domain: <strong>{_esc(domain)}</strong> · Created: {_esc(created)}</div>
    <div style="margin-top:10px;">
      <span class="pill">Score: {_esc(str(score)) if score is not None else "N/A"}</span>
    </div>
  </div>

  <div class="grid">
    <div class="card">
      <h2>Key Findings</h2>
      {li([str(x) for x in findings])}
    </div>
    <div class="card">
      <h2>Raw Summary</h2>
      {pre(report.get("summary", {}))}
    </div>
  </div>

  <div class="card">
    <h2>Email Security</h2>
    {pre(sections.get("email", {}))}
  </div>

  <div class="card">
    <h2>DNSSEC</h2>
    {pre(sections.get("dnssec", {}))}
  </div>

  <div class="card">
    <h2>CAA</h2>
    {pre(sections.get("caa", {}))}
  </div>

  <div class="card">
    <h2>Takeover Indicators</h2>
    {pre(sections.get("takeover", {}))}
  </div>

  <div class="card">
    <h2>Resolver Comparison</h2>
    {pre(sections.get("resolver_comparison", {}))}
  </div>

  <div class="card">
    <h2>Trace (Iterative Steps)</h2>
    {pre(sections.get("trace", {}))}
  </div>

</body>
</html>"""
    return html_doc

