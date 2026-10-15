import json
from dataclasses import asdict
from veylance.config import LEGAL_NOTICE, REPORT_DISCLAIMER
from veylance.core.findings import ScanResult
from veylance.report.base import BaseReporter


class JsonReporter(BaseReporter):
    extension = "json"

    def render(self, r: ScanResult) -> str:
        from veylance.modules import ADVANCED_MODULES, ADVANCED_MODULE_EXPLAINERS

        data = {
            "legal_banner": LEGAL_NOTICE,
            "legal_disclaimer": REPORT_DISCLAIMER,
            "target": r.target,
            "timestamp": r.timestamp.isoformat(),
            "duration_seconds": round(r.duration, 2),
            "modules": r.modules_run,
            "advanced_modules": sorted(ADVANCED_MODULES),
            "advanced_module_explainers": ADVANCED_MODULE_EXPLAINERS,
            "tech": sorted(r.tech),
            "info": r.info,
            "spa_catchall_suppressed": sorted(set(r.info.get("spa_catchall_suppressed", []))),
            "findings": [
                {
                    **asdict(f),
                    "severity": f.severity.name,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in r.findings
            ],
            "findings_combined": [
                {
                    **asdict(f),
                    "severity": f.severity.name,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in r.findings if f.module == "combined_risk_scenarios"
            ],
            "findings_standard": [
                {
                    **asdict(f),
                    "severity": f.severity.name,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in r.findings if f.module not in ADVANCED_MODULES and f.module != "combined_risk_scenarios"
            ],
            "findings_advanced": [
                {
                    **asdict(f),
                    "severity": f.severity.name,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in r.findings if f.module in ADVANCED_MODULES and f.module != "combined_risk_scenarios"
            ],
            "scan_drift": r.info.get("scan_drift"),
            "pages": {u: {"status": s, "type": t} for u, (s, t) in r.pages.items()},
            "js_endpoints": sorted(r.js_endpoints),
            "forms": [{"page": p, "form": f} for p, f in r.forms],
        }
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)