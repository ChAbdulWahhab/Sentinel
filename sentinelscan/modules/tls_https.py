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
                title="Site HTTPS par nahi hai",
                detail="Base URL http:// hai.",
                fix="TLS lagayein (Let's Encrypt) aur 301 redirect to HTTPS.",
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
                    title="HTTP se HTTPS redirect nahi",
                    detail=f"http:// request -> {r.status_code}",
                    fix="Server par 301 redirect to HTTPS enable karein.",
                    url=http_url,
                )

        # Deep TLS inspection (blocking — thread me chalao)
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
                    self.ctx["info"]["Certificate expiry"] = f"{exp:%Y-%m-%d} ({days}d baqi)"

                    subject = dict(x[0] for x in cert.get("subject", []))
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    self.ctx["info"]["Certificate subject"] = subject.get("commonName", "")
                    self.ctx["info"]["Certificate issuer"] = issuer.get("organizationName", "")

                    if days < 0:
                        self.add(severity=Severity.HIGH,
                                 title="TLS certificate expire ho chuka",
                                 detail=f"Expiry: {exp:%Y-%m-%d}",
                                 fix="Renew karein.",
                                 url=self.target.base)
                    elif days < 15:
                        self.add(severity=Severity.MEDIUM,
                                 title="TLS certificate jaldi expire",
                                 detail=f"{days} din baqi",
                                 fix="Auto-renewal setup karein.",
                                 url=self.target.base)

                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.add(severity=Severity.HIGH,
                                 title="Purana TLS version",
                                 detail=version,
                                 fix="Sirf TLS 1.2+ allow karein.",
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
            # 🔥 False positive guard: Python ka local trust store stale
            # ho sakta hai (khaas kar macOS pe). openssl se verify karo.
            if self._openssl_verifies_ok(host, port):
                # False positive — Python bundle stale tha, but cert valid hai
                self.ctx.setdefault("info", {})["TLS note"] = (
                    "Python default TLS verify fail hua lekin openssl pass — "
                    "certifi upgrade karein: pip install --upgrade certifi"
                )
                # LOW severity me downgrade karo, HIGH me na
                self.add(
                    severity=Severity.LOW,
                    title="TLS verification Python me fail (par cert valid hai)",
                    detail=(
                        f"Python ka trust bundle stale lagta hai.\n"
                        f"Error: {e}\n"
                        f"openssl verify: OK"
                    ),
                    fix="`pip install --upgrade certifi` chalao. Actual cert valid hai.",
                    url=self.target.base,
                )
            else:
                self.add(
                    severity=Severity.HIGH,
                    title="TLS certificate invalid",
                    detail=str(e),
                    fix="Valid CA-signed certificate lagayein.",
                    url=self.target.base,
                    cwe="CWE-295", owasp="A02:2021",
                )
        except Exception:
            pass

    def _openssl_verifies_ok(self, host: str, port: int) -> bool:
        """openssl s_client se independent verification.

        Agar openssl CLI available nahi hai to False return karo
        (conservative — HIGH finding suppress na ho).
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
            # "Verify return code: 0 (ok)" ya "Verify return code: 0"
            return "Verify return code: 0" in out
        except Exception:
            return False