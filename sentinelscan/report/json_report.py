import json
from dataclasses import asdict
from sentinelscan.core.findings import ScanResult
from sentinelscan.report.base import BaseReporter


class JsonReporter(BaseReporter):
    extension = "json"

    def render(self, r: ScanResult) -> str:
        data = {
            "target": r.target,
            "timestamp": r.timestamp.isoformat(),
            "duration_seconds": round(r.duration, 2),
            "modules": r.modules_run,
            "tech": sorted(r.tech),
            "info": r.info,
            "findings": [
                {
                    **asdict(f),
                    "severity": f.severity.name,
                    "timestamp": f.timestamp.isoformat(),
                }
                for f in r.findings
            ],
            "pages": {u: {"status": s, "type": t} for u, (s, t) in r.pages.items()},
            "js_endpoints": sorted(r.js_endpoints),
            "forms": [{"page": p, "form": f} for p, f in r.forms],
        }
        return json.dumps(data, indent=2, default=str, ensure_ascii=False)