"""Detection of publicly accessible dependency and package manifest files."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import get_or_create_baseline

MANIFEST_PROBES = [
    ("/package.json", "json", ("dependencies", "devDependencies", "peerDependencies", "scripts")),
    ("/package-lock.json", "json", ("lockfileVersion", "packages")),
    ("/composer.json", "json", ("require", "require-dev", "autoload")),
    ("/composer.lock", "json", ("packages", "packages-dev", "platform")),
    ("/Pipfile.lock", "json", ("_meta", "default", "develop")),
    ("/yarn.lock", "text", re.compile(r"#\s*yarn\s+lockfile\s+v\d+|__metadata:", re.I)),
    ("/requirements.txt", "text", re.compile(r"^[a-zA-Z0-9_\-\.]+\s*(?:==|>=|<=|~=)\s*[\d\.]+", re.M)),
    ("/Gemfile.lock", "text", re.compile(r"^GEM\b|^\s+specs:\b", re.M)),
    ("/.npmrc", "text", re.compile(r"(?:registry\s*=|//registry\.npmjs\.org/|package-lock\s*=|@[\w\-]+:registry)", re.I)),
]


def _mask_npmrc(text: str) -> str:
    """Mask any authToken in .npmrc to avoid secret leak."""
    return re.sub(r"(_authToken\s*=\s*)([^\s]+)", r"\1****MASKED****", text)


class DependencyExposureModule(BaseModule):
    name = "dependency_exposure"
    description = "Publicly accessible dependency manifests (package.json, composer.json, requirements.txt, .npmrc)"

    async def run(self):
        baseline = await get_or_create_baseline(self.session, self.target.base, self.ctx)
        sem = asyncio.Semaphore(6)

        async def probe(path: str, kind: str, validator: Any):
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

                # Baseline diff check
                if baseline.matches(r.status_code, len(content), b_hash):
                    return

                is_valid = False
                snippet = ""

                if kind == "json":
                    try:
                        data = json.loads(text)
                        if isinstance(data, dict):
                            keys = [k for k in validator if k in data]
                            if keys:
                                is_valid = True
                                snippet = f"Matched keys: {', '.join(keys)}"
                    except Exception:
                        pass
                elif kind == "text":
                    if isinstance(validator, re.Pattern) and validator.search(text):
                        is_valid = True
                        if path == "/.npmrc":
                            text = _mask_npmrc(text)
                        snippet = text.strip()[:100]

                if is_valid:
                    sev = Severity.CRITICAL if path == "/.npmrc" else Severity.HIGH
                    self.add(
                        severity=sev,
                        title=f"Exposed dependency manifest: {path}",
                        detail=(
                            f"The project dependency manifest '{path}' is publicly accessible at {url}.\n"
                            "This exposes exact library versions and internal package naming to attackers, "
                            "facilitating targeted CVE matching and supply chain dependency-confusion attacks."
                        ),
                        fix=(
                            f"Remove '{path}' from the published web root or configure your server / reverse proxy "
                            "to deny access to build manifests and dotfiles."
                        ),
                        url=url,
                        evidence=f"HTTP 200 ({len(content)} bytes) | {snippet}",
                        cwe="CWE-200",
                        owasp="A05:2021",
                    )

        await asyncio.gather(*(probe(p, k, v) for p, k, v in MANIFEST_PROBES))
        return self.findings
