import html
from veylance.config import LEGAL_NOTICE, REPORT_DISCLAIMER, VERSION
from veylance.core.findings import ScanResult, Severity
from veylance.modules import ADVANCED_MODULES, ADVANCED_MODULE_EXPLAINERS
from veylance.report.base import BaseReporter


TEMPLATE = """<!doctype html>
<html lang="en" class="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Veylance Security Report - {host}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<style>
  :root {{
    --bg-main: #09090b;
    --bg-card: #121215;
    --bg-code: #18181b;
    --border-color: #27272a;
    --border-hover: #3f3f46;
    --text-primary: #f4f4f5;
    --text-muted: #a1a1aa;
    --crimson: #dc2626;
    --crimson-glow: rgba(220, 38, 38, 0.15);
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: "Inter", -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    margin: 0;
    background: var(--bg-main);
    color: var(--text-primary);
    line-height: 1.6;
    -webkit-font-smoothing: antialiased;
  }}
  .wrap {{
    max-width: 1120px;
    margin: 0 auto;
    padding: 40px 24px;
  }}
  
  /* Hero / Header with Veylance Grid Texture */
  .hero-header {{
    background-color: #0c0c0f;
    background-image: 
      linear-gradient(to right, rgba(220, 38, 38, 0.08) 1px, transparent 1px),
      linear-gradient(to bottom, rgba(220, 38, 38, 0.08) 1px, transparent 1px);
    background-size: 32px 32px;
    border: 1px solid rgba(220, 38, 38, 0.25);
    border-radius: 14px;
    padding: 36px 32px;
    margin-bottom: 32px;
    box-shadow: 0 0 45px rgba(220, 38, 38, 0.06);
    position: relative;
    overflow: hidden;
  }}
  .hero-header::before {{
    content: "";
    position: absolute;
    top: -60px;
    right: -60px;
    width: 200px;
    height: 200px;
    background: radial-gradient(circle, rgba(220, 38, 38, 0.2) 0%, transparent 70%);
    pointer-events: none;
  }}
  .brand-bar {{
    display: flex;
    align-items: center;
    gap: 12px;
    margin-bottom: 16px;
  }}
  .pill-badge {{
    background: rgba(220, 38, 38, 0.15);
    border: 1px solid rgba(220, 38, 38, 0.4);
    color: #ef4444;
    font-family: "JetBrains Mono", monospace;
    font-size: 11px;
    font-weight: 700;
    padding: 3px 10px;
    border-radius: 100px;
    letter-spacing: 0.08em;
  }}
  .brand-title {{
    font-size: 14px;
    font-weight: 600;
    color: var(--text-muted);
  }}
  .brand-title b {{
    color: #ffffff;
    font-weight: 700;
  }}
  h1 {{
    color: #ffffff;
    font-size: 32px;
    font-weight: 800;
    letter-spacing: -0.02em;
    margin: 0 0 16px 0;
  }}
  .meta-grid {{
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-top: 20px;
    font-size: 13px;
    border-top: 1px solid rgba(255, 255, 255, 0.08);
    padding-top: 18px;
    color: var(--text-muted);
  }}
  .meta-grid b {{ color: var(--text-primary); }}
  
  /* Section Headings */
  h2 {{
    color: #ffffff;
    font-size: 20px;
    font-weight: 700;
    letter-spacing: -0.01em;
    margin: 40px 0 16px 0;
    display: flex;
    align-items: center;
    gap: 10px;
  }}
  h2::before {{
    content: "";
    display: inline-block;
    width: 4px;
    height: 18px;
    background: var(--crimson);
    border-radius: 2px;
  }}
  h3 {{
    font-size: 15px;
    font-weight: 600;
    color: #ffffff;
    margin: 0 0 6px 0;
  }}
  
  /* Severity Badges matching landing page theme */
  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    font-family: "JetBrains Mono", monospace;
  }}
  .critical {{ background: #dc2626; color: #ffffff; }}
  .high {{ background: rgba(234, 88, 12, 0.18); color: #fb923c; border: 1px solid rgba(234, 88, 12, 0.4); }}
  .medium {{ background: rgba(245, 158, 11, 0.18); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.4); }}
  .low {{ background: rgba(96, 165, 250, 0.18); color: #93c5fd; border: 1px solid rgba(96, 165, 250, 0.4); }}
  .info {{ background: rgba(107, 114, 128, 0.18); color: #a1a1aa; border: 1px solid rgba(107, 114, 128, 0.4); }}
  
  /* Cards */
  .card {{
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 10px;
    padding: 20px;
    margin: 14px 0;
    transition: border-color 0.15s ease;
  }}
  .card:hover {{ border-color: var(--border-hover); }}
  .card.card-crit {{ border-left: 4px solid var(--crimson); }}
  .card.card-high {{ border-left: 4px solid #ea580c; }}
  
  code {{
    background: var(--bg-code);
    color: #f4f4f5;
    padding: 2px 7px;
    border-radius: 4px;
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
    border: 1px solid var(--border-color);
  }}
  pre {{
    background: #08080a;
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 12px 16px;
    overflow-x: auto;
    font-family: "JetBrains Mono", monospace;
    font-size: 12px;
    color: #d4d4d8;
    margin: 10px 0 0 0;
  }}
  pre code {{
    background: transparent;
    border: none;
    padding: 0;
  }}
  
  /* Tables */
  table {{
    border-collapse: collapse;
    width: 100%;
    margin-top: 14px;
    background: var(--bg-card);
    border-radius: 10px;
    overflow: hidden;
    border: 1px solid var(--border-color);
  }}
  th, td {{
    padding: 12px 16px;
    text-align: left;
    font-size: 13px;
    border-bottom: 1px solid var(--border-color);
  }}
  th {{
    background: #16161a;
    color: var(--text-muted);
    font-weight: 600;
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.05em;
  }}
  tr:last-child td {{ border-bottom: none; }}
  
  /* Alert & Notice Boxes */
  .notice-box {{
    background: #141418;
    border-left: 4px solid #f59e0b;
    border-radius: 8px;
    padding: 14px 18px;
    margin: 20px 0;
    font-size: 13px;
    color: #e4e4e7;
    border-top: 1px solid var(--border-color);
    border-right: 1px solid var(--border-color);
    border-bottom: 1px solid var(--border-color);
  }}
  .explainer-box {{
    background: #141418;
    border-left: 4px solid var(--crimson);
    border-radius: 8px;
    padding: 14px 18px;
    margin: 16px 0;
    font-size: 13px;
    border-top: 1px solid var(--border-color);
    border-right: 1px solid var(--border-color);
    border-bottom: 1px solid var(--border-color);
  }}
  .drift-box {{
    background: #141418;
    border-left: 4px solid var(--crimson);
    border-radius: 8px;
    padding: 14px 18px;
    margin: 16px 0;
    font-size: 13px;
    border-top: 1px solid var(--border-color);
    border-right: 1px solid var(--border-color);
    border-bottom: 1px solid var(--border-color);
  }}
  
  details {{
    background: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 14px 18px;
    margin: 14px 0;
  }}
  summary {{
    cursor: pointer;
    font-weight: 600;
    color: #60a5fa;
  }}
  
  footer {{
    margin-top: 60px;
    border-top: 1px solid var(--border-color);
    padding-top: 24px;
    font-size: 12px;
    color: var(--text-muted);
  }}
</style>
</head>
<body>
<div class="wrap">

  <div class="hero-header">
    <div class="brand-bar">
      <span class="pill-badge">AUDIT REPORT</span>
      <span class="brand-title"><b>Veylance</b> <span style="color:#dc2626">/</span> Website Security Audit Engine</span>
    </div>
    <h1>Security Assessment Report</h1>
    <div class="meta-grid">
      <div><b>Target:</b> <span style="color:#60a5fa;text-decoration:underline">{target}</span></div>
      <div><b>Audit Date:</b> {date} UTC</div>
      <div><b>Duration:</b> {duration}s</div>
      <div><b>Engine:</b> 35 Modules Active (v{version})</div>
    </div>
  </div>

  <div class="notice-box">
    <b>Legal Notice &amp; Scope:</b> {legal_banner}
  </div>

  <h2>Audit Summary</h2>
  {summary}

  {combined_section}

  <h2>Standard Security Findings ({n_standard})</h2>
  {standard_findings}

  <h2>Advanced / Hidden Exposure Findings ({n_advanced})</h2>
  {advanced_findings}

  {drift_section}

  {suppressed_section}

  <h2>Detected Technology Stack</h2>
  <ul>{tech}</ul>

  <h2>Scan Context &amp; Information</h2>
  {info}

  <footer>
    <b>Disclaimer:</b> {legal_disclaimer}
  </footer>
</div>
</body>
</html>"""


class HtmlReporter(BaseReporter):
    extension = "html"

    def render(self, r: ScanResult) -> str:
        counts = r.counts()
        summary = "<table><tr><th>Severity</th><th>Discovered Count</th></tr>" + "".join(
            f"<tr><td><span class='badge {s.name.lower()}'>{s.name}</span></td><td style='font-weight:600;font-family:\"JetBrains Mono\", monospace'>{n}</td></tr>"
            for s, n in counts.items()
        ) + "</table>"

        comb_findings = [f for f in r.findings if f.module == "combined_risk_scenarios"]
        std_findings = [f for f in r.findings if f.module not in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]
        adv_findings = [f for f in r.findings if f.module in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]

        def _card(i: int, f) -> str:
            card_cls = "card"
            if f.severity == Severity.CRITICAL:
                card_cls += " card-crit"
            elif f.severity == Severity.HIGH:
                card_cls += " card-high"

            lines = [
                f"<div class='{card_cls}'>",
                f"<div style='display:flex;align-items:center;gap:12px;margin-bottom:10px;flex-wrap:wrap'>",
                f"<span class='badge {f.severity.name.lower()}'>{f.severity.name}</span>",
                f"<b style='font-size:15px;color:#ffffff'>#{i} {html.escape(f.title)}</b>",
                f"<span style='color:#a1a1aa;font-size:12px;margin-left:auto'>module: <code>{html.escape(f.module)}</code></span>",
                f"</div>",
                f"<div style='font-size:13.5px;color:#d4d4d8;margin-bottom:6px'><b>Detail:</b> {html.escape(f.detail)}</div>",
            ]
            if f.url:
                lines.append(f"<div style='font-size:13px;margin-top:6px;color:#a1a1aa'><b>Endpoint:</b> <code>{html.escape(f.url)}</code></div>")
            if f.fix:
                lines.append(f"<div style='font-size:13px;margin-top:8px;color:#4ade80;background:rgba(34,197,94,0.08);padding:8px 12px;border-radius:6px;border:1px solid rgba(34,197,94,0.2)'><b>Remediation:</b> {html.escape(f.fix)}</div>")
            if f.cwe or f.owasp:
                refs = " &nbsp;|&nbsp; ".join(x for x in (f.cwe, f"OWASP {f.owasp}" if f.owasp else None) if x)
                lines.append(f"<div style='font-size:12px;color:#a1a1aa;margin-top:8px'><b>Security Standards:</b> {refs}</div>")
            if f.evidence:
                lines.append(f"<pre><code>{html.escape(f.evidence[:600])}</code></pre>")
            lines.append("</div>")
            return "".join(lines)

        # 1. Combined Risk Scenarios section (above Standard Findings)
        if comb_findings:
            comb_cards = "".join(_card(i, f) for i, f in enumerate(sorted(comb_findings, key=lambda x: x.severity), 1))
            combined_section = (
                f"<h2>Combined Risk Scenarios ({len(comb_findings)})</h2>"
                f"<div class='explainer-box' style='border-left-color:#dc2626;background:rgba(220,38,38,0.08)'>"
                f"<b style='color:#ef4444'>Chained Attack Scenarios:</b> Multi-stage exploit paths formed by dangerous combinations of findings that individually appear low/medium severity but together compromise application boundaries."
                f"</div>"
                f"{comb_cards}"
            )
        else:
            combined_section = ""

        # 2. Standard findings section
        if std_findings:
            std_html = "".join(_card(i, f) for i, f in enumerate(sorted(std_findings, key=lambda x: x.severity), 1))
        else:
            std_html = "<p style='color:#a1a1aa'><em>No standard findings identified.</em></p>"

        # 3. Advanced findings section with incident prevention explainer
        if adv_findings:
            active_adv_mods = sorted(set(f.module for f in adv_findings))
            explainer_items = "".join(
                f"<li style='margin-bottom:4px'><b><code>{html.escape(m)}</code>:</b> {html.escape(ADVANCED_MODULE_EXPLAINERS.get(m, ''))}</li>"
                for m in active_adv_mods if m in ADVANCED_MODULE_EXPLAINERS
            )
            adv_cards = "".join(_card(i, f) for i, f in enumerate(sorted(adv_findings, key=lambda x: x.severity), 1))
            adv_html = (
                f"<div class='explainer-box'>"
                f"<b>Advanced Detection Focus &amp; Incident Prevention:</b>"
                f"<ul style='margin:8px 0 0 16px;padding:0;color:#d4d4d8'>{explainer_items}</ul></div>"
                f"{adv_cards}"
            )
        else:
            adv_html = "<p style='color:#a1a1aa'><em>No advanced or hidden exposures detected.</em></p>"

        # 4. Changes Since Last Scan (Drift) section
        drift = r.info.get("scan_drift")
        if drift and (isinstance(drift, dict) or hasattr(drift, "new_findings")):
            prior_time = drift.get("prior_timestamp", "") if isinstance(drift, dict) else drift.prior_timestamp
            new_f = drift.get("new_findings", []) if isinstance(drift, dict) else drift.new_findings
            res_f = drift.get("resolved_findings", []) if isinstance(drift, dict) else drift.resolved_findings
            new_eps = drift.get("new_js_endpoints", []) if isinstance(drift, dict) else drift.new_js_endpoints
            new_subs = drift.get("new_subdomains", []) if isinstance(drift, dict) else drift.new_subdomains

            drift_parts = [f"<h2>Changes Since Last Scan ({html.escape(prior_time[:16])})</h2>"]
            drift_parts.append("<div class='drift-box'><b>Temporal Attack-Surface Drift:</b> Comparison of current exposures against prior audit state to track remediation progress and new vulnerabilities.</div>")
            if new_f:
                drift_parts.append(f"<h3 style='color:#ef4444'>New Findings ({len(new_f)})</h3><ul>")
                for nf in new_f:
                    t = nf.get("title", "") if isinstance(nf, dict) else getattr(nf, "title", str(nf))
                    s = nf.get("severity", "") if isinstance(nf, dict) else getattr(nf, "severity", "")
                    drift_parts.append(f"<li><span class='badge {s.lower()}'>{html.escape(s)}</span> <b>{html.escape(t)}</b></li>")
                drift_parts.append("</ul>")

            if res_f:
                drift_parts.append(f"<h3 style='color:#4ade80'>Resolved Findings ({len(res_f)})</h3><ul>")
                for rf in res_f:
                    t = rf.get("title", "") if isinstance(rf, dict) else getattr(rf, "title", str(rf))
                    s = rf.get("severity", "") if isinstance(rf, dict) else getattr(rf, "severity", "")
                    drift_parts.append(f"<li><s style='color:#71717a'>[{html.escape(s)}] {html.escape(t)}</s> <span style='color:#4ade80;font-size:12px'>(Remediated)</span></li>")
                drift_parts.append("</ul>")

            if new_eps:
                drift_parts.append(f"<h3>New Discovered JS Endpoints ({len(new_eps)})</h3><ul>")
                for ep in new_eps:
                    drift_parts.append(f"<li><code>{html.escape(ep)}</code></li>")
                drift_parts.append("</ul>")

            if new_subs:
                drift_parts.append(f"<h3>New Discovered Subdomains ({len(new_subs)})</h3><ul>")
                for sb in new_subs:
                    drift_parts.append(f"<li><code>{html.escape(sb)}</code></li>")
                drift_parts.append("</ul>")
            else:
                warn = drift.get("subdomain_warning") if isinstance(drift, dict) else getattr(drift, "subdomain_warning", None)
                if warn:
                    drift_parts.append(f"<div class='drift-box' style='border-left-color:#f59e0b'><b>⚠️ Subdomain Anomaly:</b> {html.escape(warn)}</div>")

            drift_section = "".join(drift_parts)
        else:
            drift_section = ""

        # 5. SPA catch-all suppressed section (if any paths were suppressed)
        suppressed = sorted(set(r.info.get("spa_catchall_suppressed", [])))
        if suppressed:
            list_items = "".join(f"<li><code>{html.escape(p)}</code></li>" for p in suppressed)
            suppressed_section = (
                f"<h2>SPA Catch-All Suppressed ({len(suppressed)})</h2>"
                f"<details>"
                f"<summary>View {len(suppressed)} paths suppressed by baseline diffing</summary>"
                f"<p style='font-size:13px;color:#a1a1aa;margin:8px 0'>These paths returned the SPA catch-all response identical to the baseline route and were suppressed as non-actionable exposures.</p>"
                f"<ul style='font-size:13px;margin:6px 0 0 16px;padding:0'>{list_items}</ul>"
                f"</details>"
            )
        else:
            suppressed_section = ""

        info_html = "<ul>" + "".join(
            f"<li><b>{html.escape(k)}:</b> {html.escape(str(v))}</li>"
            for k, v in r.info.items()
            if k != "spa_catchall_suppressed"
        ) + "</ul>"

        return TEMPLATE.format(
            host=r.target,
            target=r.target,
            date=r.timestamp.strftime("%Y-%m-%d %H:%M"),
            duration=round(r.duration, 1),
            version=VERSION,
            summary=summary,
            combined_section=combined_section,
            n_standard=len(std_findings),
            standard_findings=std_html,
            n_advanced=len(adv_findings),
            advanced_findings=adv_html,
            drift_section=drift_section,
            suppressed_section=suppressed_section,
            tech="".join(f"<li>{html.escape(t)}</li>" for t in sorted(r.tech)) or "<li>-</li>",
            info=info_html,
            legal_banner=html.escape(LEGAL_NOTICE),
            legal_disclaimer=html.escape(REPORT_DISCLAIMER),
        )