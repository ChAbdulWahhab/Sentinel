"""Temporal drift detection module comparing scan results with prior audit history."""
from __future__ import annotations

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.drift import compute_scan_drift


class ScanDriftModule(BaseModule):
    name = "scan_drift"
    description = "Temporal drift detection comparing findings and attack surface with prior scan"

    async def run(self):
        # Uses already collected findings and attack surface metadata
        existing_findings = list(self.ctx.get("findings", []))
        js_endpoints = set(self.ctx.get("js_endpoints", []))
        discovered_subs = set(self.ctx.get("discovered_subdomains", []))

        # Check for --no-history override in ctx
        if self.ctx.get("no_history", False):
            return self.findings

        history_dir = self.ctx.get("history_dir")
        drift = compute_scan_drift(
            target_url=self.target.base,
            current_findings=existing_findings,
            current_js_endpoints=js_endpoints,
            current_subdomains=discovered_subs,
            history_dir=history_dir,
        )

        if drift is None:
            # First-ever scan of this target — skip section as requested
            self.ctx["scan_drift"] = None
            return self.findings

        # Store drift in shared context for reporting
        self.ctx["scan_drift"] = drift
        self.ctx.setdefault("info", {})["scan_drift"] = {
            "prior_timestamp": drift.prior_timestamp,
            "new_findings_count": len(drift.new_findings),
            "resolved_findings_count": len(drift.resolved_findings),
            "new_js_endpoints_count": len(drift.new_js_endpoints),
            "new_subdomains_count": len(drift.new_subdomains),
            "new_findings": drift.new_findings,
            "resolved_findings": drift.resolved_findings,
            "new_js_endpoints": drift.new_js_endpoints,
            "new_subdomains": drift.new_subdomains,
        }

        # If new HIGH or CRITICAL findings were introduced, highlight as drift finding
        high_or_crit_new = [f for f in drift.new_findings if f["severity"] in ("CRITICAL", "HIGH")]
        if high_or_crit_new:
            titles = ", ".join(f["title"] for f in high_or_crit_new[:3])
            self.add(
                severity=Severity.HIGH,
                title=f"Security Regression: {len(high_or_crit_new)} new Critical/High findings since prior scan",
                detail=(
                    f"Scan comparison with prior audit ({drift.prior_timestamp}) detected {len(drift.new_findings)} "
                    f"total new findings ({len(high_or_crit_new)} Critical/High).\n"
                    f"Regressions: {titles}"
                ),
                fix="Investigate recent code deployments and configuration changes to remediate newly introduced exposures.",
                url=self.target.base,
                evidence=f"New High/Crit findings: {titles}",
            )

        # If findings were resolved since the last scan, record positive feedback
        if drift.resolved_findings:
            resolved_titles = ", ".join(f["title"] for f in drift.resolved_findings[:3])
            self.add(
                severity=Severity.INFO,
                title=f"Security Progress: {len(drift.resolved_findings)} findings resolved since prior scan",
                detail=(
                    f"{len(drift.resolved_findings)} findings from the previous audit ({drift.prior_timestamp}) "
                    "are no longer present.\n"
                    f"Resolved: {resolved_titles}"
                ),
                fix="Verified remediation. Ensure automated security regression tests prevent reintroduction.",
                url=self.target.base,
                evidence=f"Resolved: {resolved_titles}",
            )

        return self.findings
