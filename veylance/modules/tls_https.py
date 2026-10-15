"""TLS/HTTPS/redirect checks with deep cipher, protocol, and certificate inspection."""
from __future__ import annotations

import asyncio
import datetime
import shutil
import socket
import ssl
import subprocess

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

WEAK_CIPHER_SUBSTRINGS = ("RC4", "3DES", "DES", "MD5", "NULL", "EXPORT", "_CBC_")


class TlsHttpsModule(BaseModule):
    name = "tls_https"
    description = "HTTPS enforcement, cipher strength, TLS downgrade, HSTS preload, OCSP"

    async def run(self):
        if self.target.scheme == "http":
            self.add(
                severity=Severity.HIGH,
                title="Site does not use HTTPS",
                detail="Base URL is unencrypted http://.",
                fix="Install a valid TLS certificate and configure a permanent 301 redirect to HTTPS.",
                url=self.target.base,
                evidence="Protocol: http:// (unencrypted plaintext)",
                cwe="CWE-319",
                owasp="A02:2021",
            )
            return self.findings

        # 1. HTTP -> HTTPS redirect check
        http_url = "http://" + self.target.host + "/"
        r = await self.session.get(http_url, follow_redirects=False)
        if r is not None:
            loc = r.headers.get("location", "")
            if not (300 <= r.status_code < 400 and loc.startswith("https://")):
                self.add(
                    severity=Severity.MEDIUM,
                    title="HTTP does not redirect to HTTPS",
                    detail=f"Plain HTTP request returned status {r.status_code} without HTTPS redirect location.",
                    fix="Configure web server (Nginx/Apache/Caddy) to return a 301 redirect to https://$host$request_uri.",
                    url=http_url,
                    evidence=f"Status: {r.status_code}, Location: '{loc}'",
                )

        # 2. HSTS Preload Eligibility Check
        r_https = await self.session.get(self.target.base + "/", follow_redirects=False)
        if r_https is not None:
            hsts = r_https.headers.get("strict-transport-security", "")
            self._check_hsts_preload(hsts)

        # 3. Deep TLS inspection in executor (non-blocking for asyncio loop)
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self._inspect_tls)
        return self.findings

    def _check_hsts_preload(self, hsts_header: str) -> None:
        """Check HSTS preload eligibility according to hstspreload.org requirements."""
        if not hsts_header:
            return  # Handled in headers module as missing HSTS

        low = hsts_header.lower()
        parts = [p.strip() for p in low.split(";")]
        max_age = 0
        has_subdomains = "includesubdomains" in parts
        has_preload = "preload" in parts

        for p in parts:
            if p.startswith("max-age="):
                try:
                    max_age = int(p.split("=", 1)[1].strip())
                except ValueError:
                    pass

        # Preload requires max-age >= 31536000 (1 year), includeSubDomains, and preload
        deficiencies = []
        if max_age < 31536000:
            deficiencies.append(f"max-age={max_age} is less than recommended 31536000 (1 year)")
        if not has_subdomains:
            deficiencies.append("missing 'includeSubDomains'")
        if not has_preload:
            deficiencies.append("missing 'preload'")

        if deficiencies:
            self.add(
                severity=Severity.LOW,
                title="HSTS header not eligible for browser preload list",
                detail="To submit domain to browser HSTS preload list (hstspreload.org), all requirements must be met: "
                       + "; ".join(deficiencies),
                fix="Update header to: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                url=self.target.base,
                evidence=f"Strict-Transport-Security: {hsts_header}",
                references=["https://hstspreload.org/"],
            )

    def _inspect_tls(self):
        host = self.target.hostname
        port = self.target.port or 443

        # A. Primary TLS Handshake & Cert Inspection
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    cert = ss.getpeercert()
                    version = ss.version()
                    cipher = ss.cipher()
                    self.ctx.setdefault("info", {})["TLS version"] = version

                    # Cipher strength inspection
                    if cipher:
                        c_name, proto, bits = cipher[0], cipher[1], cipher[2]
                        self.ctx["info"]["TLS cipher"] = f"{c_name} ({bits} bits)"

                        if any(sub in c_name for sub in WEAK_CIPHER_SUBSTRINGS):
                            self.add(
                                severity=Severity.MEDIUM,
                                title=f"Weak cipher suite in use: {c_name}",
                                detail=f"Cipher {c_name} utilizes legacy or vulnerable algorithms (CBC/3DES/RC4/MD5).",
                                fix="Configure modern AEAD ciphers only (e.g. ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES256-GCM-SHA384, ChaCha20-Poly1305).",
                                url=self.target.base,
                                evidence=f"Cipher: {c_name}, Protocol: {proto}, Bits: {bits}",
                                cwe="CWE-326",
                            )
                        elif c_name.startswith("RSA_") or "TLS_RSA_" in c_name:
                            self.add(
                                severity=Severity.LOW,
                                title=f"Cipher lacks Forward Secrecy: {c_name}",
                                detail="Static RSA key exchange does not provide Perfect Forward Secrecy (PFS).",
                                fix="Prefer Ephemeral Diffie-Hellman (ECDHE/DHE) key exchange ciphers.",
                                url=self.target.base,
                                evidence=f"Cipher: {c_name}",
                                cwe="CWE-326",
                            )

                    # Certificate expiration and validity period
                    if cert and "notAfter" in cert:
                        exp = datetime.datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        days = (exp - datetime.datetime.now()).days
                        self.ctx["info"]["Certificate expiry"] = f"{exp:%Y-%m-%d} ({days}d remaining)"

                        if "notBefore" in cert:
                            start_date = datetime.datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z")
                            validity_days = (exp - start_date).days
                            if validity_days > 398 and start_date >= datetime.datetime(2020, 9, 1):
                                self.add(
                                    severity=Severity.LOW,
                                    title="Certificate validity exceeds 398-day CA/Browser limit",
                                    detail=f"Certificate validity period is {validity_days} days. Modern browsers reject certs with lifetime > 398 days.",
                                    fix="Issue certificates with a validity period of 398 days or 90 days (Let's Encrypt).",
                                    url=self.target.base,
                                    evidence=f"Validity: {start_date:%Y-%m-%d} to {exp:%Y-%m-%d} ({validity_days} days)",
                                )

                        subject = dict(x[0] for x in cert.get("subject", []))
                        issuer = dict(x[0] for x in cert.get("issuer", []))
                        self.ctx["info"]["Certificate subject"] = subject.get("commonName", "")
                        self.ctx["info"]["Certificate issuer"] = issuer.get("organizationName", "")

                        if days < 0:
                            self.add(
                                severity=Severity.HIGH,
                                title="TLS certificate has expired",
                                detail=f"Certificate expired on {exp:%Y-%m-%d}.",
                                fix="Renew the certificate immediately.",
                                url=self.target.base,
                                evidence=f"Expired: {exp:%Y-%m-%d} ({abs(days)} days ago)",
                                cwe="CWE-298",
                            )
                        elif days < 15:
                            self.add(
                                severity=Severity.MEDIUM,
                                title="TLS certificate expires soon",
                                detail=f"Certificate expires in {days} days ({exp:%Y-%m-%d}).",
                                fix="Automate renewal using certbot or your hosting provider.",
                                url=self.target.base,
                                evidence=f"Days remaining: {days}",
                            )

                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        self.add(
                            severity=Severity.HIGH,
                            title="Outdated TLS protocol active",
                            detail=f"Negotiated deprecated protocol {version}.",
                            fix="Disable TLS 1.0, TLS 1.1, and SSLv3. Require TLS 1.2 or TLS 1.3.",
                            url=self.target.base,
                            evidence=f"Active version: {version}",
                            cwe="CWE-326",
                        )

        except ssl.SSLCertVerificationError as e:
            if self._openssl_verifies_ok(host, port):
                self.ctx.setdefault("info", {})["TLS note"] = (
                    "Python trust store verification failed but OpenSSL passed — cert is valid."
                )
                self.add(
                    severity=Severity.LOW,
                    title="TLS verification failed in Python (certificate is valid)",
                    detail=f"Local Python trust store was unable to verify certificate chain:\n{e}",
                    fix="Run `pip install --upgrade certifi`.",
                    url=self.target.base,
                    evidence=str(e),
                )
            else:
                self.add(
                    severity=Severity.HIGH,
                    title="TLS certificate chain invalid",
                    detail=f"Certificate verification failed: {e}",
                    fix="Install a valid CA-signed certificate with complete intermediate trust chain.",
                    url=self.target.base,
                    evidence=str(e),
                    cwe="CWE-295",
                    owasp="A02:2021",
                )
        except Exception:
            pass

        # B. Protocol Downgrade Checks (TLS 1.0 and TLS 1.1)
        self._check_legacy_protocol(host, port, "TLSv1.0", getattr(ssl.TLSVersion, "TLSv1", None))
        self._check_legacy_protocol(host, port, "TLSv1.1", getattr(ssl.TLSVersion, "TLSv1_1", None))

        # C. OCSP Stapling Check
        self._check_ocsp_stapling(host, port)

    def _check_legacy_protocol(self, host: str, port: int, proto_name: str, tls_version_enum) -> None:
        """Test if server accepts connection using deprecated TLS 1.0 or 1.1."""
        if not tls_version_enum:
            return
        try:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ctx.minimum_version = tls_version_enum
            ctx.maximum_version = tls_version_enum

            with socket.create_connection((host, port), timeout=4) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ss:
                    if ss.version() in ("TLSv1", "TLSv1.1"):
                        self.add(
                            severity=Severity.HIGH,
                            title=f"Deprecated protocol supported: {proto_name}",
                            detail=f"Server negotiated connection using deprecated {proto_name} (RFC 8996).",
                            fix="Disable TLS 1.0 and TLS 1.1 in web server configuration. Enable only TLS 1.2 and TLS 1.3.",
                            url=self.target.base,
                            evidence=f"Connected with {proto_name}",
                            cwe="CWE-326",
                            owasp="A02:2021",
                        )
        except Exception:
            # Server properly rejected legacy protocol handshake
            pass

    def _check_ocsp_stapling(self, host: str, port: int) -> None:
        """Inspect if OCSP stapling is configured on the server."""
        if not shutil.which("openssl"):
            return
        try:
            proc = subprocess.run(
                [
                    "openssl", "s_client",
                    "-connect", f"{host}:{port}",
                    "-servername", host,
                    "-status",
                ],
                input=b"",
                capture_output=True,
                timeout=5,
            )
            out = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore").lower()
            if "ocsp response: no response sent" in out:
                self.add(
                    severity=Severity.INFO,
                    title="OCSP stapling not enabled",
                    detail="Server did not send an OCSP staple response during the TLS handshake.",
                    fix="Enable OCSP stapling in web server configuration (e.g. `ssl_stapling on;` in Nginx).",
                    url=self.target.base,
                    evidence="OpenSSL status: 'OCSP Response: no response sent'",
                )
        except Exception:
            pass

    def _openssl_verifies_ok(self, host: str, port: int) -> bool:
        """Independent verification using openssl s_client."""
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
                timeout=8,
            )
            out = (proc.stdout + proc.stderr).decode("utf-8", errors="ignore")
            return "Verify return code: 0" in out
        except Exception:
            return False