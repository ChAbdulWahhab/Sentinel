"""Detection of publicly accessible .git directory and commit history."""
from __future__ import annotations

import asyncio
import hashlib
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import get_or_create_baseline

GIT_PROBES = [
    ("/.git/HEAD", re.compile(r"^(?:ref:\s+refs/heads/|[0-9a-f]{40})", re.M)),
    ("/.git/config", re.compile(r"\[core\]|repositoryformatversion\s*=|\[remote\s+[\"']", re.I)),
    ("/.git/logs/HEAD", re.compile(r"[0-9a-f]{40}\s+[0-9a-f]{40}\s+.*?>\s+\d+\s+[-+]\d{4}", re.I)),
]


class GitExposureModule(BaseModule):
    name = "git_exposure"
    description = "Public .git repository metadata and commit history exposure"

    async def run(self):
        baseline = await get_or_create_baseline(self.session, self.target.base, self.ctx)
        sem = asyncio.Semaphore(4)

        async def check_probe(path: str, signature_rx: re.Pattern):
            async with sem:
                url = self.target.base.rstrip("/") + path
                r = await self.session.get(url, follow_redirects=False)
                if r is None or r.status_code != 200:
                    return

                content = getattr(r, "content", None)
                if content is None:
                    content = r.text.encode("utf-8") if getattr(r, "text", None) else b""
                b_hash = hashlib.sha256(content).hexdigest()
                text = r.text or ""

                # 1. Baseline diff check
                if baseline.matches(r.status_code, len(content), b_hash):
                    # Only escalate if genuine signature matched
                    if not signature_rx.search(text):
                        return

                # 2. Authentic signature check
                if signature_rx.search(text):
                    snippet = text.strip().splitlines()[0] if text.strip() else ""
                    self.add(
                        code="GIT_EXPOSURE",
                        severity=Severity.CRITICAL,
                        title=f"Git repository exposure: {path}",
                        detail=(
                            f"The internal Git repository metadata file '{path}' is publicly accessible.\n"
                            "BLAST RADIUS: This allows an attacker to download the entire Git object tree, "
                            "reconstruct full source code history, access commit logs, author credentials, "
                            "and extract secrets deleted from current branches."
                        ),
                        fix=(
                            "Deny public access to hidden directories (.git) at the web server/proxy layer immediately. "
                            "For Nginx: 'location ~ /\\.git { deny all; return 404; }'. "
                            "For Apache: '<DirectoryMatch \"/\\.git\"> Require all denied </DirectoryMatch>'."
                        ),
                        url=url,
                        evidence=f"HTTP 200 — Verified Signature: {snippet[:120]}",
                        cwe="CWE-538",
                        owasp="A05:2021",
                    )

        await asyncio.gather(*(check_probe(p, rx) for p, rx in GIT_PROBES))
        return self.findings
