import html
from sentinelscan.config import LEGAL_NOTICE, REPORT_DISCLAIMER
from sentinelscan.core.findings import ScanResult, Severity
from sentinelscan.report.base import BaseReporter


TEMPLATE = """<!doctype html>
<html><head><meta charset="utf-8"><title>SentinelScan - {host}</title>
<style>
 body{{font-family:system-ui;margin:0;background:#0d1117;color:#c9d1d9}}
 .wrap{{max-width:1100px;margin:0 auto;padding:32px}}
 h1{{color:#58a6ff}} h2{{border-bottom:1px solid #30363d;padding-bottom:6px}}
 .badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;font-weight:600;color:#000}}
 .critical{{background:#f85149}} .high{{background:#ff7b72}} .medium{{background:#d29922}}
 .low{{background:#58a6ff}} .info{{background:#8b949e}}
 .card{{background:#161b22;border:1px solid #30363d;border-radius:8px;padding:16px;margin:12px 0}}
 code{{background:#21262d;padding:2px 6px;border-radius:4px}}
 table{{border-collapse:collapse;width:100%;margin-top:12px}}
 th,td{{border:1px solid #30363d;padding:8px;text-align:left;font-size:13px}}
 th{{background:#161b22}}
</style></head>
<body><div class="wrap">
<h1>🛡️ SentinelScan Report</h1>
<div style="background:#21262d;border-left:4px solid #d29922;padding:12px 16px;margin:16px 0;font-size:13px;border-radius:4px;color:#e6edf3">
<b>⚠️ Legal Notice:</b> {legal_banner}
</div>
<p><b>Target:</b> {target}<br>
<b>Date:</b> {date}<br>
<b>Duration:</b> {duration}s<br>
<b>Modules:</b> {modules}</p>
<h2>Summary</h2>
{summary}
<h2>Findings ({n_findings})</h2>
{findings}
<h2>Technology</h2>
<ul>{tech}</ul>
<h2>Info</h2>
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

        fh = []
        for i, f in enumerate(sorted(r.findings, key=lambda x: x.severity), 1):
            fh.append(
                f"<div class='card'><span class='badge {f.severity.name.lower()}'>{f.severity.name}</span> "
                f"<b>#{i} {html.escape(f.title)}</b> "
                f"<small>module: {f.module}</small><br><br>"
                f"<b>Detail:</b> {html.escape(f.detail)}<br>"
                + (f"<b>URL:</b> <code>{html.escape(f.url)}</code><br>" if f.url else "")
                + (f"<b>Fix:</b> <code>{html.escape(f.fix)}</code><br>" if f.fix else "")
                + (f"<b>CWE:</b> {f.cwe} &nbsp; <b>OWASP:</b> {f.owasp}" if f.cwe or f.owasp else "")
                + "</div>"
            )

        info_html = "<ul>" + "".join(
            f"<li><b>{html.escape(k)}:</b> {html.escape(str(v))}</li>" for k, v in r.info.items()
        ) + "</ul>"

        return TEMPLATE.format(
            host=r.target, target=r.target, date=r.timestamp.strftime("%Y-%m-%d %H:%M"),
            duration=round(r.duration, 1), modules=", ".join(r.modules_run),
            summary=summary, findings="".join(fh) or "<p>No findings.</p>",
            n_findings=len(r.findings),
            tech="".join(f"<li>{html.escape(t)}</li>" for t in sorted(r.tech)) or "<li>-</li>",
            info=info_html,
            legal_banner=html.escape(LEGAL_NOTICE),
            legal_disclaimer=html.escape(REPORT_DISCLAIMER),
        )