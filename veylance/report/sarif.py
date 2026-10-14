"""SARIF 2.1.0 reporter for GitHub code scanning."""
from __future__ import annotations
import json
from veylance.config import LEGAL_NOTICE, REPORT_DISCLAIMER
from veylance.core.findings import ScanResult, Severity
from veylance.report.base import BaseReporter


LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


class SarifReporter(BaseReporter):
    extension = "sarif"

    def render(self, r: ScanResult) -> str:
        rules = {}
        results = []
        for f in r.findings:
            rule_id = f"{f.module}.{f.title[:40].replace(' ', '_')}"
            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": f.title,
                    "shortDescription": {"text": f.title},
                    "fullDescription": {"text": f.detail},
                    "help": {"text": f.fix or ""},
                    "properties": {
                        "security-severity": str(10 - int(f.severity)),
                        "tags": [t for t in (f.cwe, f.owasp) if t],
                    },
                }
            results.append({
                "ruleId": rule_id,
                "level": LEVEL[f.severity],
                "message": {"text": f.detail},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.url or r.target},
                    }
                }],
                "properties": {
                    "severity": f.severity.name,
                    "module": f.module,
                    "cwe": f.cwe,
                    "owasp": f.owasp,
                },
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Veylance",
                        "informationUri": "https://github.com/ChAbdulWahhab/veylance",
                        "rules": list(rules.values()),
                        "properties": {
                            "legalNotice": LEGAL_NOTICE,
                            "disclaimer": REPORT_DISCLAIMER,
                        },
                    }
                },
                "properties": {
                    "legalNotice": LEGAL_NOTICE,
                    "disclaimer": REPORT_DISCLAIMER,
                },
                "results": results,
            }],
        }
        return json.dumps(sarif, indent=2)