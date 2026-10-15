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

        from veylance.modules import ADVANCED_MODULES, ADVANCED_MODULE_EXPLAINERS

        comb_findings = [f for f in r.findings if f.module == "combined_risk_scenarios"]
        adv_findings = [f for f in r.findings if f.module in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]
        std_findings = [f for f in r.findings if f.module not in ADVANCED_MODULES and f.module != "combined_risk_scenarios"]

        def _render_finding_block(i: int, f) -> list[str]:
            block: list[str] = []
            block.append(f"### {i}. [{f.severity.name}] {f.title}")
            block.append("")
            block.append(f"- **Module:** `{f.module}`")
            if f.url:
                block.append(f"- **URL:** `{f.url}`")
            block.append(f"- **Detail:** {f.detail}")
            if f.fix:
                block.append(f"- **Fix:** {f.fix}")
            if f.cwe or f.owasp:
                refs = " ".join(x for x in (f.cwe, f.owasp) if x)
                block.append(f"- **Refs:** {refs}")
            if f.evidence:
                block.append("")
                block.append("```")
                block.append(f.evidence[:500])
                block.append("```")
            block.append("")
            return block

        # 1. Combined Risk Scenarios (Highest value signal — rendered ABOVE Standard Findings)
        if comb_findings:
            L.append("## Combined Risk Scenarios")
            L.append("")
            L.append("> Multi-stage attack vectors and compounded risk scenarios formed by dangerous combinations of findings:")
            L.append("")
            for i, f in enumerate(sorted(comb_findings, key=lambda x: x.severity), 1):
                L.extend(_render_finding_block(i, f))

        # 2. Standard Security Findings
        L.append("## Standard Security Findings")
        L.append("")
        if not std_findings:
            L.append("_No standard findings._")
            L.append("")
        else:
            for i, f in enumerate(sorted(std_findings, key=lambda x: x.severity), 1):
                L.extend(_render_finding_block(i, f))

        # 3. Advanced / Hidden Exposure
        L.append("## Advanced / Hidden Exposure")
        L.append("")
        if not adv_findings:
            L.append("_No advanced or hidden exposures detected._")
            L.append("")
        else:
            L.append("> **Incident Prevention & Detection Focus:**")
            active_adv_mods = sorted(set(f.module for f in adv_findings))
            for mod in active_adv_mods:
                if mod in ADVANCED_MODULE_EXPLAINERS:
                    L.append(f"> - **`{mod}`**: {ADVANCED_MODULE_EXPLAINERS[mod]}")
            L.append("")
            for i, f in enumerate(sorted(adv_findings, key=lambda x: x.severity), 1):
                L.extend(_render_finding_block(i, f))

        # 4. Changes Since Last Scan (Temporal Drift)
        drift = r.info.get("scan_drift")
        if drift and (isinstance(drift, dict) or hasattr(drift, "new_findings")):
            prior_time = drift.get("prior_timestamp") if isinstance(drift, dict) else drift.prior_timestamp
            new_f = drift.get("new_findings") if isinstance(drift, dict) else drift.new_findings
            res_f = drift.get("resolved_findings") if isinstance(drift, dict) else drift.resolved_findings
            new_eps = drift.get("new_js_endpoints") if isinstance(drift, dict) else drift.new_js_endpoints
            new_subs = drift.get("new_subdomains") if isinstance(drift, dict) else drift.new_subdomains

            L.append(f"## Changes Since Last Scan ({prior_time[:16]})")
            L.append("")
            if new_f:
                L.append(f"### New Findings ({len(new_f)})")
                for nf in new_f:
                    t = nf.get("title", "") if isinstance(nf, dict) else getattr(nf, "title", str(nf))
                    s = nf.get("severity", "") if isinstance(nf, dict) else getattr(nf, "severity", "")
                    L.append(f"- **[{s}]** {t}")
                L.append("")
            if res_f:
                L.append(f"### Resolved Findings ({len(res_f)})")
                for rf in res_f:
                    t = rf.get("title", "") if isinstance(rf, dict) else getattr(rf, "title", str(rf))
                    s = rf.get("severity", "") if isinstance(rf, dict) else getattr(rf, "severity", "")
                    L.append(f"- ~[{s}] {t}~ *(Remediated)*")
                L.append("")
            if new_eps:
                L.append("### New JS Endpoints Discovered")
                for ep in new_eps:
                    L.append(f"- `{ep}`")
                L.append("")
            if new_subs:
                L.append("### New Subdomains Discovered")
                for sb in new_subs:
                    L.append(f"- `{sb}`")
                L.append("")

        suppressed = sorted(set(r.info.get("spa_catchall_suppressed", [])))
        if suppressed:
            L.append("## SPA Catch-All Suppressed")
            L.append("")
            L.append("<details>")
            L.append(f"<summary><b>View {len(suppressed)} paths suppressed by baseline diffing</b></summary>")
            L.append("")
            L.append("> These paths returned the SPA catch-all response identical to the baseline route and were not flagged as real exposures:")
            L.append("")
            for p in suppressed:
                L.append(f"- `{p}`")
            L.append("")
            L.append("</details>")
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