"""SQLi error-based heuristic (safe)."""
from __future__ import annotations

import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

SQL_ERRORS = [
    r"SQL syntax.*MySQL", r"Warning.*mysql_", r"MySQLSyntaxErrorException",
    r"valid MySQL result", r"PostgreSQL.*ERROR", r"pg_query\(\)",
    r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite",
    r"Microsoft OLE DB Provider for SQL Server", r"ODBC SQL Server Driver",
    r"Oracle error", r"ORA-\d{5}", r"quoted string not properly terminated",
    r"Unclosed quotation mark after the character string",
    r"SQL command not properly ended",
    r"unterminated quoted string",
]

PAYLOADS = ["'", "\"", "')", "';--", "' OR '1'='1"]


class SqliHeuristicModule(BaseModule):
    name = "sqli_heuristic"
    description = "SQL injection error-based heuristic"
    requires_crawl = True

    async def run(self):
        pages = [self.target.root] + list(self.ctx.get("pages", {}).keys())[:10]
        for page in pages:
            u = urlparse(page)
            q = parse_qs(u.query)
            if not q:
                continue
            for param in list(q.keys())[:5]:
                for pl in PAYLOADS:
                    test = dict(q)
                    test[param] = [pl]
                    new_url = urlunparse(u._replace(query=urlencode(test, doseq=True)))
                    r = await self.session.get(new_url)
                    if r is None:
                        continue
                    for pat in SQL_ERRORS:
                        m = re.search(pat, r.text, re.I)
                        if m:
                            self.add(
                                severity=Severity.HIGH,
                                title=f"Possible SQLi: `{param}` param",
                                detail=f"Payload `{pl}` triggered a database error: `{m.group(0)[:80]}`",
                                fix="Use parameterized queries or prepared statements. Verify manually.",
                                url=page, cwe="CWE-89", owasp="A03:2021",
                                evidence=r.text[max(0,m.start()-50):m.end()+150],
                            )
                            return self.findings
        return self.findings