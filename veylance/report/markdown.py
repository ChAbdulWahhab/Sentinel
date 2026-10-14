"""Markdown reporter — GitHub / GitLab friendly."""
from __future__ import annotations

from veylance.config import LEGAL_NOTICE, REPORT_DISCLAIMER
from veylance.core.findings import ScanResult, Severity
from veylance.report.base import BaseReporter


class MarkdownReporter(BaseReporter):
    extension = "md"

    def render(self, r: ScanResult) -> str:
        L: list[str] = []
        L.append(f"# Veylance Report - {r.target}")
        L.append("")
        L.append(f"> **Legal Notice:** {LEGAL_NOTICE}")
        L.append("")
        L.append(f"- **Date:** {r.timestamp:%Y-%m-%d %H:%M}")
        L.append(f"- **Duration:** {r.duration:.1f}s")
        L.append(f"- **Modules:** {', '.join(r.modules_run)}")
        L.append(
            f"- **Pages:** {len(r.pages)} | "
            f"**Forms:** {len(r.forms)} | "
            f"**JS:** {len(r.scripts)}"
        )
        L.append("")

        L.append("## Summary")
        L.append("")
        L.append("| Severity | Count |")
        L.append("|---|---|")
        for s, n in r.counts().items():
            L.append(f"| {s.name} | {n} |")
        L.append("")

        L.append("## Tech Stack")
        if r.tech:
            L.extend([f"- {t}" for t in sorted(r.tech)])
        else:
            L.append("- Not detected")
        L.append("")

        L.append("## Findings")
        L.append("")
        if not r.findings:
            L.append("_No findings._")
        for i, f in enumerate(sorted(r.findings, key=lambda x: x.severity), 1):
            L.append(f"### {i}. [{f.severity.name}] {f.title}")
            L.append("")
            L.append(f"- **Module:** `{f.module}`")
            if f.url:
                L.append(f"- **URL:** `{f.url}`")
            L.append(f"- **Detail:** {f.detail}")
            if f.fix:
                L.append(f"- **Fix:** {f.fix}")
            if f.cwe or f.owasp:
                refs = " ".join(x for x in (f.cwe, f.owasp) if x)
                L.append(f"- **Refs:** {refs}")
            if f.evidence:
                L.append("")
                L.append("```")
                L.append(f.evidence[:500])
                L.append("```")
            L.append("")

        if r.js_endpoints:
            L.append("## JS Endpoints Discovered")
            L.append("")
            L.extend(f"- `{e}`" for e in sorted(r.js_endpoints))
            L.append("")

        L.append("## Pages Crawled")
        L.append("")
        L.append("| Status | Type | URL |")
        L.append("|---|---|---|")
        for u, (s, t) in sorted(r.pages.items()):
            L.append(f"| {s} | {t} | {u} |")
        L.append("")
        L.append("---")
        L.append(f"*Disclaimer: {REPORT_DISCLAIMER}*")
        L.append("")
        return "\n".join(L)