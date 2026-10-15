import asyncio
import http.server
import threading
from typing import ClassVar

import pytest

from veylance.core.engine import ScanEngine
from veylance.core.target import Target
from veylance.modules import ALL_MODULES
from veylance.ui.progress import ScanProgress


class MockWebServer(http.server.SimpleHTTPRequestHandler):
    """Local mock web server providing standard endpoints for scan modules."""

    def do_GET(self):
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Set-Cookie", "session=mock_session_id; Path=/; HttpOnly")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            html = (
                "<!doctype html>"
                "<html>"
                "<head><script src=\"/bundle.js\"></script></head>"
                "<body>"
                "<h1>Veylance Smoke Test</h1>"
                "<a href=\"/docs\">Documentation</a>"
                "<form action=\"/login\" method=\"post\">"
                "<input type=\"text\" name=\"user\">"
                "<input type=\"password\" name=\"password\">"
                "<input type=\"submit\" value=\"Login\">"
                "</form>"
                "</body>"
                "</html>"
            )
            self.wfile.write(html.encode("utf-8"))
        elif self.path == "/docs":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(b"<html><body>Documentation page</body></html>")
        elif self.path == "/bundle.js":
            self.send_response(200)
            self.send_header("Content-Type", "application/javascript")
            self.end_headers()
            self.wfile.write(b"console.log('init'); const endpoint = '/api/v1/status';")
        elif self.path == "/robots.txt":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"User-agent: *\nDisallow: /admin\nSitemap: /sitemap.xml\n")
        elif self.path == "/sitemap.xml":
            self.send_response(200)
            self.send_header("Content-Type", "application/xml")
            self.end_headers()
            self.wfile.write(b"<urlset><url><loc>http://localhost/docs</loc></url></urlset>")
        elif self.path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html><body>Login Response</body></html>")
        else:
            self.send_response(404)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Not Found")

    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{\"status\": \"ok\"}")

    def do_HEAD(self):
        self.send_response(200)
        self.end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Allow", "GET, POST, OPTIONS, HEAD")
        self.end_headers()

    def do_PUT(self):
        self.send_response(405)
        self.end_headers()

    def do_DELETE(self):
        self.send_response(405)
        self.end_headers()

    def log_message(self, format, *args):
        # Suppress request logging to keep test output clean
        pass


@pytest.fixture(scope="module")
def mock_server():
    server = http.server.HTTPServer(("127.0.0.1", 0), MockWebServer)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    server.server_close()


def test_smoke_all_modules(mock_server: str):
    """Run all modules via ScanEngine against a local mock target and verify no errors."""
    assert len(ALL_MODULES) == 35

    target = Target(mock_server)
    engine = ScanEngine(
        target=target,
        modules=list(ALL_MODULES.keys()),
        max_pages=5,
        concurrency=5,
        rate_requests=5,
        timeout=3,
        verify_tls=False,
    )

    result = asyncio.run(engine.run(progress=ScanProgress(quiet=True)))

    # Verify that all 35 modules were executed
    assert len(result.modules_run) == 35
    assert set(result.modules_run) == set(ALL_MODULES.keys())

    # Verify that zero unhandled exceptions or runtime crashes occurred
    assert result.errors == [], f"Modules failed with errors: {result.errors}"

    # Verify that result contains findings without crashing
    assert isinstance(result.findings, list)
    assert len(result.findings) >= 0


@pytest.mark.parametrize("module_name", list(ALL_MODULES.keys()))
def test_individual_module_smoke(mock_server: str, module_name: str):
    """Run each module individually and ensure zero unhandled exceptions."""
    target = Target(mock_server)
    engine = ScanEngine(
        target=target,
        modules=[module_name],
        max_pages=2,
        concurrency=2,
        rate_requests=2,
        timeout=3,
        verify_tls=False,
    )

    result = asyncio.run(engine.run(progress=ScanProgress(quiet=True)))
    assert result.errors == [], f"Module {module_name} raised error: {result.errors}"
    assert len(result.modules_run) == 1
    assert result.modules_run[0] == module_name
