import html
from veylance.config import LEGAL_NOTICE, REPORT_DISCLAIMER
from veylance.core.findings import ScanResult, Severity
from veylance.modules import ADVANCED_MODULES, ADVANCED_MODULE_EXPLAINERS
from veylance.report.base import BaseReporter


TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>Veylance - {host}</title>
<style>
 body{{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;margin:0;background:#0d1117;color:#c9d1d9;line-height:1.5}}
 .wrap{{max-width:1100px;margin:0 auto;padding:32px}}
 h1{{color:#58a6ff;font-size:28px;margin-bottom:8px}}
 h2{{color:#e6edf3;border-bottom:1px solid #30363d;padding-bottom:8px;margin-top:36px;font-size:20px}}
 h3{{font-size:16px;margin:0 0 6px 0}}
 .badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;color:#000}}
 .critical{{background:#f85149;color:#fff}} .high{{background:#ff7b72;color:#000}} .medium{{background:#d29922;color:#000}}
 .low{{background:#58a6ff;color:#000}} .info{{background:#8b949e;color:#000}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}}
 code{{background:#21262d;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:12px}}
 pre{{background:#21262d;padding:10px 12px;border-radius:6px;overflow-x:auto;font-size:12px;margin:8px 0 0 0}}
 table{{border-collapse:collapse;width:100%;margin-top:12px}}
 th,td{{border:1px solid #30363d;padding:8px 12px;text-align:left;font-size:13px}}
 th{{background:#161b22;color:#8b949e}}
 .explainer-box{{background:#161b22;border-left:4px solid #58a6ff;padding:12px 16px;margin:14px 0;border-radius:4px;font-size:13px}}
 .drift-box{{background:#161f28;border-left:4px solid #58a6ff;padding:12px 16px;margin:14px 0;border-radius:4px;font-size:13px}}
 details{{background:#161b22;border:1px solid #30363d;border-radius:6px;padding:12px 16px;margin:12px 0}}
 summary{{cursor:pointer;font-weight:600;color:#58a6ff}}
</style></head>
<body><div class="wrap">
<h1>Veylance Security Report</h1>
<div style="background:#21262d;border-left:4px solid #d29922;padding:12px 16px;margin:16px 0;font-size:13px;border-radius:4px;color:#e6edf3">
<b>⚠️ Legal Notice:</b> {legal_banner}
</div>
<p style="font-size:14px"><b>Target:</b> {target}<br>
<b>Date:</b> {date}<br>
<b>Duration:</b> {duration}s<br>
<b>Modules Run:</b> {modules}</p>

<h2>Summary</h2>
{summary}

{combined_section}

<h2>Standard Security Findings ({n_standard})</h2>
{standard_findings}

<h2>Advanced / Hidden Exposure ({n_advanced})</h2>
{advanced_findings}

{drift_section}

{suppressed_section}

<h2>Technology Stack</h2>
<ul>{tech}</ul>

<h2>Scan Context &amp; Information</h2>
{info}

<footer style="margin-top:40px;border-top:1px solid #30363d;padding-top:16px;font-size:12px;color:#8b949e">
<b>Disclaimer:</b> {legal_disclaimer}
</footer>
</div></body></html>"""


class HtmlReporter(BaseReporter):
    extension = "html"

    def render(self, r: ScanResult) -> str:
        counts = r.counts()
        summary = "<table><tr><th>Severity</th><th>Count</th></tr>" + "".join(
            f"<tr><td><span class='badge {s.name.lower()}'>{s.name}</span></td><td>{n}</td></tr>"
            for s, n in counts.items()
        ) + "</table>"

        comb_findings = [f for f in r.findings if f.module == "combined_risk_scenarios"]
        std_findings = [f for f in r.findings if f.module not in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]
        adv_findings = [f for f in r.findings if f.module in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]

        def _card(i: int, f) -> str:
            lines = [
                f"<div class='card'>",
                f"<div style='display:flex;align-items:center;gap:10px;margin-bottom:8px'>",
                f"<span class='badge {f.severity.name.lower()}'>{f.severity.name}</span>",
                f"<b>#{i} {html.escape(f.title)}</b>",
                f"<span style='color:#8b949e;font-size:12px;margin-left:auto'>module: <code>{html.escape(f.module)}</code></span>",
                f"</div>",
                f"<div style='font-size:13px'><b>Detail:</b> {html.escape(f.detail)}</div>",
            ]
            if f.url:
                lines.append(f"<div style='font-size:13px;margin-top:4px'><b>URL:</b> <code>{html.escape(f.url)}</code></div>")
            if f.fix:
                lines.append(f"<div style='font-size:13px;margin-top:4px;color:#7ee787'><b>Remediation:</b> {html.escape(f.fix)}</div>")
            if f.cwe or f.owasp:
                refs = " &nbsp;|&nbsp; ".join(x for x in (f.cwe, f"OWASP {f.owasp}" if f.owasp else None) if x)
                lines.append(f"<div style='font-size:12px;color:#8b949e;margin-top:6px'><b>References:</b> {refs}</div>")
            if f.evidence:
                lines.append(f"<pre><code>{html.escape(f.evidence[:500])}</code></pre>")
            lines.append("</div>")
            return "".join(lines)

        # 1. Combined Risk Scenarios section (above Standard Findings)
        if comb_findings:
            comb_cards = "".join(_card(i, f) for i, f in enumerate(sorted(comb_findings, key=lambda x: x.severity), 1))
            combined_section = (
                f"<h2>Combined Risk Scenarios ({len(comb_findings)})</h2>"
                f"<div class='explainer-box' style='border-left-color:#f85149;background:#1f1315'>"
                f"<b style='color:#ff7b72'>Compounded Attack Scenarios:</b> Multi-stage attack vectors and compounded risk scenarios formed by dangerous combinations of findings that individually appear low/medium severity but together form an actionable breach path."
                f"</div>"
                f"{comb_cards}"
            )
        else:
            combined_section = ""

        # 2. Standard findings section
        if std_findings:
            std_html = "".join(_card(i, f) for i, f in enumerate(sorted(std_findings, key=lambda x: x.severity), 1))
        else:
            std_html = "<p style='color:#8b949e'><em>No standard findings.</em></p>"

        # 3. Advanced findings section with incident prevention explainer
        if adv_findings:
            active_adv_mods = sorted(set(f.module for f in adv_findings))
            explainer_items = "".join(
                f"<li><b><code>{html.escape(m)}</code>:</b> {html.escape(ADVANCED_MODULE_EXPLAINERS.get(m, ''))}</li>"
                for m in active_adv_mods if m in ADVANCED_MODULE_EXPLAINERS
            )
            adv_cards = "".join(_card(i, f) for i, f in enumerate(sorted(adv_findings, key=lambda x: x.severity), 1))
            adv_html = (
                f"<div class='explainer-box'>"
                f"<b>Incident Prevention &amp; Detection Focus:</b>"
                f"<ul style='margin:6px 0 0 16px;padding:0'>{explainer_items}</ul></div>"
                f"{adv_cards}"
            )
        else:
            adv_html = "<p style='color:#8b949e'><em>No advanced or hidden exposures detected.</em></p>"

        # 4. Changes Since Last Scan (Drift) section
        drift = r.info.get("scan_drift")
        if drift and (isinstance(drift, dict) or hasattr(drift, "new_findings")):
            prior_time = drift.get("prior_timestamp", "") if isinstance(drift, dict) else drift.prior_timestamp
            new_f = drift.get("new_findings", []) if isinstance(drift, dict) else drift.new_findings
            res_f = drift.get("resolved_findings", []) if isinstance(drift, dict) else drift.resolved_findings
            new_eps = drift.get("new_js_endpoints", []) if isinstance(drift, dict) else drift.new_js_endpoints
            new_subs = drift.get("new_subdomains", []) if isinstance(drift, dict) else drift.new_subdomains

            drift_parts = [f"<h2>Changes Since Last Scan ({html.escape(prior_time[:16])})</h2>"]
            drift_parts.append("<div class='drift-box'><b>Temporal Drift Analysis:</b> Comparing current attack surface and vulnerabilities with prior audit fingerprint.</div>")
            if new_f:
                drift_parts.append(f"<h3 style='color:#f85149'>New Findings ({len(new_f)})</h3><ul>")
                for nf in new_f:
                    t = nf.get("title", "") if isinstance(nf, dict) else getattr(nf, "title", str(nf))
                    s = nf.get("severity", "") if isinstance(nf, dict) else getattr(nf, "severity", "")
                    drift_parts.append(f"<li><span class='badge {s.lower()}'>{html.escape(s)}</span> <b>{html.escape(t)}</b></li>")
                drift_parts.append("</ul>")

            if res_f:
                drift_parts.append(f"<h3 style='color:#7ee787'>Resolved Findings ({len(res_f)})</h3><ul>")
                for rf in res_f:
                    t = rf.get("title", "") if isinstance(rf, dict) else getattr(rf, "title", str(rf))
                    s = rf.get("severity", "") if isinstance(rf, dict) else getattr(rf, "severity", "")
                    drift_parts.append(f"<li><s style='color:#8b949e'>[{html.escape(s)}] {html.escape(t)}</s> <span style='color:#7ee787;font-size:12px'>(Remediated)</span></li>")
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
                    drift_parts.append(f"<div class='drift-box' style='border-left-color:#d29922'><b>⚠️ Subdomain Anomaly:</b> {html.escape(warn)}</div>")

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
                f"<p style='font-size:13px;color:#8b949e;margin:8px 0'>These paths returned the SPA catch-all response identical to the baseline route and were not flagged as real exposures.</p>"
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
            modules=", ".join(r.modules_run),
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