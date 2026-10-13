"""TLS/HTTPS/redirect checks."""
from __future__ import annotations

import asyncio
import datetime
import shutil
import socket
import ssl
import subprocess

from sentinelscan.core.findings import Severity
from sentinelscan.modules.base import BaseModule


class TlsHttpsModule(BaseModule):
    name = "tls_https"
    description = "HTTPS enforcement, TLS version, certificate expiry"

    async def run(self):
        if self.target.scheme == "http":
            self.add(
                severity=Severity.HIGH,
                title="Site does not use HTTPS",
                detail="Base URL is http://.",
                fix="Install TLS (Let's Encrypt) and configure a 301 redirect to HTTPS.",
                url=self.target.base,
                cwe="CWE-319", owasp="A02:2021",
            )
            return self.findings

        # HTTP -> HTTPS redirect check
        http_url = "http://" + self.target.host + "/"
        r = await self.session.get(http_url, follow_redirects=False)
        if r is not None:
            loc = r.headers.get("location", "")
            if not (300 <= r.status_code < 400 and loc.startswith("https://")):
                self.add(
                    severity=Severity.MEDIUM,
                    title="HTTP does not redirect to HTTPS",
                    detail=f"http:// request -> {r.status_code}",
                    fix="Enable a 301 redirect to HTTPS on the server.",
                    url=http_url,
                )

        # Deep TLS inspection (blocking — run in thread)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._inspect_tls)
        return self.findings

    def _inspect_tls(self):
        host = self.target.hostname
        port = self.target.port or 443

        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    version = ss.version()
                    self.ctx.setdefault("info", {})["TLS version"] = version

                    exp = datetime.datetime.strptime(
                        cert["notAfter"], "%b %d %H:%M:%S %Y %Z"
                    )
                    days = (exp - datetime.datetime.utcnow()).days
                    self.ctx["info"]["Certificate expiry"] = f"{exp:%Y-%m-%d} ({days}d remaining)"

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    self.ctx["info"]["Certificate subject"] = subject.get("commonName", "")
                    self.ctx["info"]["Certificate issuer"] = issuer.get("organizationName", "")

                    if days < 0:
                        self.add(severity=Severity.HIGH,
                                 title="TLS certificate has expired",
                                 detail=f"Expiry: {exp:%Y-%m-%d}",
                                 fix="Renew the certificate.",
                                 url=self.target.base)
                    elif days < 15:
                        self.add(severity=Severity.MEDIUM,
                                 title="TLS certificate expires soon",
                                 detail=f"{days} days remaining",
                                 fix="Set up auto-renewal.",
                                 url=self.target.base)

                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.add(severity=Severity.HIGH,
                                 title="Outdated TLS version",
                                 detail=version,
                                 fix="Allow only TLS 1.2 or higher.",
                                 url=self.target.base, cwe="CWE-326")

                    cipher = ss.cipher()
                    if cipher and any(
                        x in cipher[0] for x in ("RC4", "3DES", "MD5", "NULL")
                    ):
                        self.add(severity=Severity.MEDIUM,
                                 title="Weak cipher",
                                 detail=cipher[0],
                                 fix="AEAD ciphers only (AES-GCM, ChaCha20).",
                                 url=self.target.base)

        except ssl.SSLCertVerificationError as e:
            # 🔥 False positive guard: Python's local trust store may be stale
            # (especially on macOS). Verify with OpenSSL.
            if self._openssl_verifies_ok(host, port):
                # False positive — Python bundle was stale, but certificate is valid
                self.ctx.setdefault("info", {})["TLS note"] = (
                    "Python default TLS verification failed but OpenSSL passed — "
                    "upgrade certifi: pip install --upgrade certifi"
                )
                # Downgrade to LOW severity instead of HIGH
                self.add(
                    severity=Severity.LOW,
                    title="TLS verification failed in Python (certificate is valid)",
                    detail=(
                        f"Python trust bundle appears stale.\n"
                        f"Error: {e}\n"
                        f"openssl verify: OK"
                    ),
                    fix="Run `pip install --upgrade certifi`. The certificate itself is valid.",
                    url=self.target.base,
                )
            else:
                self.add(
                    severity=Severity.HIGH,
                    title="TLS certificate invalid",
                    detail=str(e),
                    fix="Install a valid CA-signed certificate.",
                    url=self.target.base,
                    cwe="CWE-295", owasp="A02:2021",
                )
        except Exception:
            pass

    def _openssl_verifies_ok(self, host: str, port: int) -> bool:
        """Independent verification using openssl s_client.

        If the openssl CLI is unavailable, return False
        (conservative — so a HIGH finding is not suppressed).
        """
        if not shutil.which("openssl"):
            return False
        try:
            proc = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-servername", host,
                ],
                input=b"",
                capture_output=True,
                timeout=10,
            )
            out = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore")
            # "Verify return code: 0 (ok)" or "Verify return code: 0"
            return "Verify return code: 0" in out
        except Exception:
            return False