"""End-to-end integration tests for advanced detection modules against a live HTTP server.

WHY E2E COVERAGE MATTERS HERE:
Unit tests with MockResponse are valuable for isolating regexes, but they cannot catch
critical end-to-end integration failure modes:
1. HTTP header handling, content-length negotiation, and chunked transfer decoding
2. Crawler link and script discovery navigating actual HTML DOM structures
3. Baseline diffing interaction with real HTTP responses across consecutive requests
4. Secret masking verification across all three output report formats (Markdown, HTML, JSON)
5. Module execution scheduling, timeout management, and semaphore concurrency under live I/O
"""
from __future__ import annotations

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import threading
from typing import Generator
import pytest

from veylance.core.engine import ScanEngine
from veylance.core.findings import Severity
from veylance.core.target import Target
from veylance.report.html_report import HtmlReporter
from veylance.report.json_report import JsonReporter
from veylance.report.markdown import MarkdownReporter
from veylance.ui.progress import ScanProgress

RAW_FAKE_AWS_KEY = "AKIA2V3X7Y8Z9A0B1C2D"


class VulnerableTestServerHandler(BaseHTTPRequestHandler):
    """Custom HTTP handler serving deliberately exposed and vulnerable resources."""

    def log_message(self, format, *args):
        # Silence console logging during test runs
        pass

    def do_GET(self):
        # 1. Cache poisoning header reflection
        xf_host = self.headers.get("X-Forwarded-Host")
        if xf_host:
            body = f"<html><head><script src='//{xf_host}/runtime.js'></script></head><body>Reflected host</body></html>".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "public, max-age=3600")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 2. Git HEAD exposure
        if self.path == "/.git/HEAD":
            body = b"ref: refs/heads/main\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 3. Source map file
        if self.path == "/bundle.js.map":
            body = b'{"version": 3, "file": "bundle.js", "sources": ["src/auth.ts"], "mappings": "AAAA"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 4. JS Bundle with hardcoded secrets and sourcemap pointer
        if self.path == "/bundle.js":
            content = f"const AWS_KEY = '{RAW_FAKE_AWS_KEY}';\n//# sourceMappingURL=bundle.js.map"
            body = content.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 5. Dependency manifest
        if self.path == "/package.json":
            body = b'{"name": "vulnerable-app", "dependencies": {"express": "4.18.2", "jsonwebtoken": "9.0.0"}}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 6. CI/CD & Env file exposure
        if self.path == "/.env":
            body = b"DB_PASSWORD=SuperSecretPass123!\nAWS_SECRET=live_secret_sample\nNODE_ENV=production\n"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 7. Homepage with SRI deficiency and developer comment leak
        if self.path == "/":
            html = """<!doctype html>
            <html>
            <head>
                <title>Vulnerable App</title>
                <!-- Third party script without SRI -->
                <script src="https://cdnjs.cloudflare.com/ajax/libs/react/18.2.0/react.production.min.js"></script>
                <script src="/bundle.js"></script>
            </head>
            <body>
                <h1>Vulnerable Test App</h1>
                <!-- TODO: remove auth bypass before prod release -->
                <!-- temp admin pass: InsecureDevPass123 -->
            </body>
            </html>"""
            body = html.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # Default 404 for nonexistent probe paths
        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.end_headers()


@pytest.fixture(scope="module")
def vulnerable_server() -> Generator[str, None, None]:
    """Start local ThreadingHTTPServer serving vulnerable endpoints."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), VulnerableTestServerHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_advanced_modules_e2e_pipeline(vulnerable_server: str):
    """Run full ScanEngine scan against live test server and verify true-positive pipeline."""
    target = Target(vulnerable_server)
    modules = [
        "git_exposure",
        "secrets_in_js",
        "source_map_exposure",
        "dependency_exposure",
        "ci_cd_exposure",
        "sri_check",
        "comment_leak",
        "cache_poisoning_headers",
    ]

    engine = ScanEngine(
        target=target,
        modules=modules,
        max_pages=5,
        concurrency=4,
        rate_requests=10,
        timeout=3,
        verify_tls=False,
    )

    result = asyncio.run(engine.run(progress=ScanProgress(quiet=True)))
    assert result.errors == [], f"Engine encountered unexpected module errors: {result.errors}"

    findings = result.findings
    finding_modules = {f.module for f in findings}

    # 1. git_exposure verification
    assert "git_exposure" in finding_modules
    git_f = next(f for f in findings if f.module == "git_exposure")
    assert git_f.severity == Severity.CRITICAL
    assert "BLAST RADIUS" in git_f.detail
    assert "refs/heads/main" in git_f.evidence

    # 2. secrets_in_js verification & secret masking in pipeline
    assert "secrets_in_js" in finding_modules
    secret_f = next(f for f in findings if f.module == "secrets_in_js")
    assert secret_f.severity == Severity.CRITICAL
    assert RAW_FAKE_AWS_KEY not in secret_f.evidence
    assert RAW_FAKE_AWS_KEY not in secret_f.detail
    assert "****" in secret_f.evidence
    assert secret_f.evidence.startswith("Matched: AWS Access Key -> AKIA")

    # 3. source_map_exposure verification
    assert "source_map_exposure" in finding_modules
    smap_f = next(f for f in findings if f.module == "source_map_exposure")
    assert smap_f.severity == Severity.HIGH
    assert "bundle.js.map" in smap_f.url

    # 4. dependency_exposure verification
    assert "dependency_exposure" in finding_modules
    dep_f = next(f for f in findings if f.module == "dependency_exposure")
    assert dep_f.severity == Severity.HIGH
    assert "package.json" in dep_f.url

    # 5. ci_cd_exposure verification
    assert "ci_cd_exposure" in finding_modules
    cicd_f = next(f for f in findings if f.module == "ci_cd_exposure")
    assert cicd_f.severity == Severity.CRITICAL
    assert "/.env" in cicd_f.url
    assert "SuperSecretPass123!" not in cicd_f.evidence

    # 6. sri_check verification
    assert "sri_check" in finding_modules
    sri_f = next(f for f in findings if f.module == "sri_check")
    assert sri_f.severity == Severity.MEDIUM
    assert "cdnjs.cloudflare.com" in sri_f.url

    # 7. comment_leak verification
    assert "comment_leak" in finding_modules
    comment_f = next(f for f in findings if f.module == "comment_leak")
    assert "InsecureDevPass123" not in comment_f.evidence

    # 8. cache_poisoning_headers verification
    assert "cache_poisoning_headers" in finding_modules
    cache_f = next(f for f in findings if f.module == "cache_poisoning_headers")
    assert "veylance-cache-canary.internal" in cache_f.evidence

    # 9. Verify secret masking across Markdown, HTML, and JSON reports
    md_output = MarkdownReporter().render(result)
    html_output = HtmlReporter().render(result)
    json_output = JsonReporter().render(result)

    for report_text in (md_output, html_output, json_output):
        assert RAW_FAKE_AWS_KEY not in report_text, "CRITICAL: Raw AWS key leaked unmasked into report!"
        assert "SuperSecretPass123!" not in report_text, "CRITICAL: Raw DB password leaked unmasked into report!"
        assert "InsecureDevPass123" not in report_text, "CRITICAL: Dev password comment leaked unmasked into report!"

    assert "Advanced / Hidden Exposure" in md_output
    assert "Advanced / Hidden Exposure" in html_output
    assert "findings_advanced" in json_output
    assert "advanced_modules" in json_output
