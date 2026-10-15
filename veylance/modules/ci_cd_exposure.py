"""Detection of exposed CI/CD pipelines and infrastructure configuration files."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re

from veylance.core.findings import Severity
from veylance.modules.base import BaseModule
from veylance.utils.baseline import get_or_create_baseline

CI_CD_PROBES = [
    ("/.env", "env", re.compile(r"^(?:DB_|APP_|AWS_|SECRET_|API_|JWT_|DATABASE_|NODE_ENV)[A-Z0-9_]*\s*=", re.I | re.M)),
    ("/.env.local", "env", re.compile(r"^(?:DB_|APP_|AWS_|SECRET_|API_|JWT_|DATABASE_|NODE_ENV)[A-Z0-9_]*\s*=", re.I | re.M)),
    ("/.env.production", "env", re.compile(r"^(?:DB_|APP_|AWS_|SECRET_|API_|JWT_|DATABASE_|NODE_ENV)[A-Z0-9_]*\s*=", re.I | re.M)),
    ("/.env.staging", "env", re.compile(r"^(?:DB_|APP_|AWS_|SECRET_|API_|JWT_|DATABASE_|NODE_ENV)[A-Z0-9_]*\s*=", re.I | re.M)),
    ("/.github/workflows/main.yml", "yaml", re.compile(r"^(?:name:\s*|on:\s*|jobs:\s*)", re.M)),
    ("/.github/workflows/ci.yml", "yaml", re.compile(r"^(?:name:\s*|on:\s*|jobs:\s*)", re.M)),
    ("/.github/workflows/deploy.yml", "yaml", re.compile(r"^(?:name:\s*|on:\s*|jobs:\s*)", re.M)),
    ("/.gitlab-ci.yml", "yaml", re.compile(r"^(?:stages:|image:\s*|\w+:\s*\n\s+stage:)", re.M)),
    ("/docker-compose.yml", "yaml", re.compile(r"^(?:version:\s*['\"]?\d|services:)", re.M)),
    ("/Dockerfile", "docker", re.compile(r"^FROM\s+[a-zA-Z0-9_\-\./:]+", re.I | re.M)),
    ("/wrangler.toml", "toml", re.compile(r"(?:name\s*=\s*['\"]|compatibility_date\s*=)", re.I)),
    ("/netlify.toml", "toml", re.compile(r"(?:\[build\]|publish\s*=|command\s*=)", re.I)),
    ("/vercel.json", "json", ("buildCommand", "outputDirectory", "routes", "rewrites", "headers", "version")),
]


def _mask_env_content(raw: str) -> str:
    """Mask assignment values in env files for safe reporting."""
    lines = []
    for line in raw.splitlines()[:6]:
        if "=" in line and not line.strip().startswith("#"):
            k, v = line.split("=", 1)
            v_clean = v.strip()
            if len(v_clean) > 8:
                masked_v = v_clean[:2] + "****" + v_clean[-2:]
            elif v_clean:
                masked_v = "****"
            else:
                masked_v = ""
            lines.append(f"{k.strip()}={masked_v}")
        else:
            lines.append(line)
    return "\n".join(lines)


class CiCdExposureModule(BaseModule):
    name = "ci_cd_exposure"
    description = "Exposed CI/CD workflows and infrastructure config files (.env, Dockerfile, workflows, wrangler.toml)"

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
                                snippet = f"JSON config with keys: {', '.join(keys)}"
                    except Exception:
                        pass
                elif kind == "env":
                    if validator.search(text):
                        is_valid = True
                        snippet = _mask_env_content(text)
                else:
                    if isinstance(validator, re.Pattern) and validator.search(text):
                        is_valid = True
                        snippet = text.strip()[:100]

                if is_valid:
                    sev = Severity.CRITICAL if kind == "env" or "workflows" in path else Severity.HIGH
                    self.add(
                        severity=sev,
                        title=f"Exposed infrastructure / CI-CD file: {path}",
                        detail=(
                            f"The configuration or CI/CD definition '{path}' is publicly served at {url}.\n"
                            "This exposes build pipelines, deployment triggers, environment variables, "
                            "and server container definitions that should never be publicly reachable."
                        ),
                        fix=(
                            f"Exclude '{path}' from deployment artifacts or configure server / CDN rules to block "
                            "access to .env files, Docker definitions, and .github directories."
                        ),
                        url=url,
                        evidence=f"HTTP 200 ({len(content)} bytes) | {snippet[:150]}",
                        cwe="CWE-538",
                        owasp="A05:2021",
                    )

        await asyncio.gather(*(probe(p, k, v) for p, k, v in CI_CD_PROBES))
        return self.findings
