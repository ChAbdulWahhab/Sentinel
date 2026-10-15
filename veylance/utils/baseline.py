"""Baseline response probing for SPA catch-all and soft-404 detection."""
from __future__ import annotations

import hashlib
import re
import uuid
from dataclasses import dataclass
from typing import Any

CONTENT_SIGNATURES = {
    "pem_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.I),
    "sql_dump": re.compile(r"(?:INSERT\s+INTO\s+`?\w+`?|CREATE\s+TABLE\s+`?\w+`?|/\*!40101\s+SET\s+|DROP\s+TABLE\s+IF\s+EXISTS)", re.I),
    "json_creds": re.compile(r'["\'](?:private_key|client_secret|aws_secret_access_key|aws_access_key_id|api_key|app_secret|access_token|refresh_token)["\']\s*:', re.I),
    "phpinfo": re.compile(r"<title>phpinfo\(\)</title>|Configuration File \(php\.ini\) Path|PHP Version\s+[\d\.]+", re.I),
    "mod_status": re.compile(r"Apache Server Status for|Server uptime:|Restart Time:\s+<dt>|Current Time:\s+<dt>", re.I),
    "env_file": re.compile(r"^(?:DB_PASSWORD|APP_KEY|AWS_SECRET|SECRET_KEY|DATABASE_URL|API_SECRET|NODE_ENV|JWT_SECRET)\s*=", re.I | re.M),
    "git_head": re.compile(r"^ref:\s+refs/heads/|[core]\s+repositoryformatversion", re.I | re.M),
    "swagger_doc": re.compile(r'["\'](?:openapi|swagger)["\']\s*:\s*["\']\d|id=["\']swagger-ui["\']|<redoc\b', re.I),
}

ARCHIVE_SIGNATURES = [
    b"PK\x03\x04",        # ZIP
    b"\x1f\x8b\x08",      # GZIP
    b"Rar!\x1a\x07",      # RAR
    b"7z\xbc\xaf\x27\x1c", # 7Z
    b"BZh",               # BZIP2
]



@dataclass
class BaselineProbeResult:
    probe_url: str
    status_code: int
    content_length: int
    body_hash: str
    is_catch_all: bool  # True when server returns 200 OK on guaranteed random nonexistent path

    def matches(self, status: int, length: int, body_hash: str, length_tolerance: int = 64) -> bool:
        """Return True if a probed response is effectively identical to the catch-all baseline."""
        if status != self.status_code:
            return False
        # Exact body match
        if body_hash == self.body_hash:
            return True
        # If server returns 200 for missing pages (SPA), check length proximity
        if self.is_catch_all and abs(length - self.content_length) <= length_tolerance:
            return True
        return False


async def get_or_create_baseline(session: Any, base_url: str, ctx: dict[str, Any]) -> BaselineProbeResult:
    """Send one request to a random nonexistent path to establish baseline behavior."""
    if "baseline_probe" in ctx:
        return ctx["baseline_probe"]

    probe_path = f"/__veylance_probe_{uuid.uuid4().hex}__"
    probe_url = base_url.rstrip("/") + probe_path

    try:
        r = await session.get(probe_url, follow_redirects=False)
        if r is not None:
            content = getattr(r, "content", None)
            if content is None:
                content = r.text.encode("utf-8") if getattr(r, "text", None) else b""
            status = r.status_code
            length = len(content)
            b_hash = hashlib.sha256(content).hexdigest()
            # If server returns 200 for a random GUID, it has a catch-all / SPA router
            is_catch_all = (status == 200)
            baseline = BaselineProbeResult(
                probe_url=probe_url,
                status_code=status,
                content_length=length,
                body_hash=b_hash,
                is_catch_all=is_catch_all,
            )
        else:
            baseline = BaselineProbeResult(
                probe_url=probe_url,
                status_code=404,
                content_length=0,
                body_hash="",
                is_catch_all=False,
            )
    except Exception:
        baseline = BaselineProbeResult(
            probe_url=probe_url,
            status_code=404,
            content_length=0,
            body_hash="",
            is_catch_all=False,
        )

    ctx["baseline_probe"] = baseline
    if baseline.is_catch_all:
        ctx.setdefault("info", {})["Catch-all routing"] = "SPA catch-all detected (returns 200 for unmatched paths)"
    return baseline


def has_content_signature(body: str, sig_type: str | None = None) -> bool:
    """Verify if the body contains authentic content signatures rather than SPA fallback HTML."""
    if not body:
        return False

    # Disqualify if it's clearly a generic HTML page unless checking phpinfo/swagger/mod_status
    is_html = bool(re.search(r"<!doctype\s+html|<html|<body", body[:500], re.I))

    if sig_type and sig_type in CONTENT_SIGNATURES:
        return bool(CONTENT_SIGNATURES[sig_type].search(body))

    # General signature search
    for name, pattern in CONTENT_SIGNATURES.items():
        if pattern.search(body):
            if is_html and name not in ("phpinfo", "mod_status", "swagger_doc"):
                continue
            return True

    return False


def is_valid_archive(content: bytes) -> bool:
    """Check if binary content starts with recognized archive magic bytes."""
    if not content or len(content) < 10:
        return False
    return any(content.startswith(sig) for sig in ARCHIVE_SIGNATURES)
