"""JWT token detection, 'alg: none', weak HMAC secrets wordlist check, and claim validation."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule

JWT_RX = re.compile(r"eyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*")

# Curated list of known publicly available weak HMAC secrets (defensive validation only — no brute force)
KNOWN_WEAK_SECRETS = [
    "secret", "password", "123456", "12345678", "jwt_secret",
    "admin", "test", "key", "app", "development", "qwerty",
    "auth", "token", "supersecret", "secret123", "default",
    "changeme", "12345", "root", "mysecret", "private",
]


def _b64_url_decode(segment: str) -> bytes:
    """Decode base64url without padding."""
    rem = len(segment) % 4
    if rem > 0:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment)


def _b64_url_encode(data: bytes) -> str:
    """Encode base64url without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


class JwtProbeModule(BaseModule):
    name = "jwt_probe"
    description = "JWT token inspection: alg:none, weak HMAC secret matching, missing exp/iat claims"
    requires_crawl = True

    async def run(self):
        scripts = self.ctx.get("scripts") or set()
        if not isinstance(scripts, (set, list, tuple)):
            scripts = set()
        scripts = list(scripts)[:20]

        pages = self.ctx.get("pages") or {}
        if not isinstance(pages, dict):
            pages = {}

        discovered_tokens: set[tuple[str, str]] = set()

        # 1. Search in crawled JS files
        for js in scripts:
            if not isinstance(js, str) or not js:
                continue
            r = await self.session.get(js)
            if r is None or r.status_code != 200:
                continue
            body = r.text or ""
            for tok in set(JWT_RX.findall(body)):
                discovered_tokens.add((tok, js))

        # 2. Search in crawled response bodies
        for url in list(pages.keys())[:20]:
            if not isinstance(url, str) or not url:
                continue
            r = await self.session.get(url)
            if r is None:
                continue
            body = r.text or ""
            for tok in set(JWT_RX.findall(body)):
                discovered_tokens.add((tok, url))

        # 3. Analyze each discovered token
        for tok, source in list(discovered_tokens)[:15]:
            self._analyze(tok, source)

        return self.findings

    def _analyze(self, tok: str, source: str) -> None:
        parts = tok.split(".")
        if len(parts) < 2:
            return

        try:
            header_bytes = _b64_url_decode(parts[0])
            header = json.loads(header_bytes)
        except Exception:
            return

        payload = {}
        try:
            payload_bytes = _b64_url_decode(parts[1])
            payload = json.loads(payload_bytes)
        except Exception:
            pass

        if not isinstance(header, dict):
            return

        alg = str(header.get("alg", "")).lower()

        # A. alg: none check
        if alg == "none" or alg == "":
            self.add(
                severity=Severity.CRITICAL,
                title="JWT token using insecure 'alg: none'",
                detail="A JWT token configured with 'alg: none' was found. Tokens signed with 'none' bypass cryptographic signature verification.",
                fix="Strictly reject 'none' algorithm tokens on the server and enforce an allowlist of strong algorithms (RS256, ES256, EdDSA, or HS256).",
                url=source,
                evidence=f"Header: {header}, Token prefix: {tok[:30]}...",
                cwe="CWE-347",
                owasp="A02:2021",
            )

        # B. Weak HMAC secret verification against known weak wordlist
        if alg in ("hs256", "hs384", "hs512") and len(parts) == 3 and parts[2]:
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
            hash_func = {
                "hs256": hashlib.sha256,
                "hs384": hashlib.sha384,
                "hs512": hashlib.sha512,
            }.get(alg, hashlib.sha256)

            for weak_secret in KNOWN_WEAK_SECRETS:
                computed_sig = hmac.new(weak_secret.encode("utf-8"), signing_input, hash_func).digest()
                computed_b64 = _b64_url_encode(computed_sig)
                if computed_b64 == parts[2]:
                    self.add(
                        severity=Severity.HIGH,
                        title=f"JWT signed with known weak HMAC secret: '{weak_secret}'",
                        detail=f"The token signature matched a known public weak secret ('{weak_secret}'). "
                               "Attackers can forge arbitrary claims and tamper with tokens.",
                        fix="Generate a cryptographically secure, high-entropy HMAC secret (at least 256 bits of random entropy) or migrate to asymmetric keys (RS256/ES256).",
                        url=source,
                        evidence=f"Secret match: '{weak_secret}', Alg: {alg.upper()}, Signature: {parts[2]}",
                        cwe="CWE-326",
                        owasp="A02:2021",
                    )
                    break
        elif alg == "hs256":
            self.add(
                severity=Severity.INFO,
                title="Symmetric HMAC (HS256) JWT detected",
                detail="Symmetric HMAC relies on a shared secret between all signers and verifiers.",
                fix="Ensure HMAC secrets are at least 256-bit high-entropy strings, or migrate to asymmetric key pairs (RS256/ES256).",
                url=source,
                evidence=f"Header: {header}",
            )

        # C. Missing claims check (exp, iat)
        if isinstance(payload, dict):
            if "exp" not in payload:
                self.add(
                    severity=Severity.MEDIUM,
                    title="JWT payload missing 'exp' (expiration) claim",
                    detail="The token does not specify an expiration timestamp, meaning it remains valid indefinitely if intercepted.",
                    fix="Add an 'exp' claim with a short lifespan (e.g., 15-60 minutes) and use refresh tokens for prolonged sessions.",
                    url=source,
                    evidence=f"Payload keys: {list(payload.keys())}",
                    cwe="CWE-613",
                    owasp="A07:2021",
                )
            if "iat" not in payload:
                self.add(
                    severity=Severity.LOW,
                    title="JWT payload missing 'iat' (issued at) claim",
                    detail="Missing 'iat' claim prevents verifying when the token was created and evaluating token age.",
                    fix="Include the 'iat' timestamp claim in all generated JWT payloads.",
                    url=source,
                    evidence=f"Payload keys: {list(payload.keys())}",
                )