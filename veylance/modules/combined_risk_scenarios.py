"""Rule-based correlation engine for combined risk scenarios.

Evaluates the full finding set collected across all scan modules to identify
compound vulnerability chains and multi-stage attack paths that individually
appear low/medium severity but together form a critical breach vector.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable
import re

from veylance.core.findings import Finding, Severity
from veylance.core.target import Target
from veylance.modules.base import BaseModule


@dataclass
class CorrelationRule:
    """Extensible rule definition for combined risk scenarios."""
    id: str
    name: str
    combined_severity: Severity
    explanation: str
    remediation: str
    cwe: str
    owasp: str
    evaluator: Callable[[list[Finding], dict[str, Any], Target], tuple[bool, str, str]]


def _eval_cors_admin_no_rate_limit(findings: list[Finding], ctx: dict[str, Any], target: Target) -> tuple[bool, str, str]:
    """CORS wildcard on admin endpoint + no rate limit + unauthenticated response."""
    cors_admin = False
    cors_evidence = ""
    for f in findings:
        code = f.code or f.finding_code or ""
        is_cors = code.startswith("CORS_") or f.module == "cors"
        if is_cors and (
            code in ("CORS_WILDCARD", "CORS_REFLECTED_ORIGIN", "CORS_REFLECTED_CREDENTIALS", "CORS_WILDCARD_CREDENTIALS")
            or "admin" in (f.url or "").lower()
            or "admin" in f.title.lower()
            or "wildcard" in f.title.lower()
        ):
            cors_admin = True
            cors_evidence = f.evidence or f.title
            break

    # Also check if pages contain /api/admin or /admin returning 200
    pages = ctx.get("pages", {})
    admin_page_unauth = False
    admin_url = ""
    for url, (status, _) in pages.items():
        if re.search(r"/api/(?:[\w\-]+/)?admin\b|/admin\b", url, re.I):
            if status == 200:
                admin_page_unauth = True
                admin_url = url
                break

    no_rate_limit = False
    for f in findings:
        code = f.code or f.finding_code or ""
        if code == "RATE_LIMIT_NOT_DETECTED" or (
            f.module == "rate_limit" and any(k in f.title.lower() for k in ("not detected", "no rate limit", "missing rate limit"))
        ):
            no_rate_limit = True
            break

    if (cors_admin or admin_page_unauth) and no_rate_limit:
        target_endpoint = admin_url or target.base + "/api/admin"
        evidence = f"CORS Finding: [{cors_evidence}] | Unauthenticated admin endpoint: {target_endpoint} | No rate limiting detected."
        return True, "Unauthenticated cross-origin access to admin endpoint with no rate limiting", evidence

    return False, "", ""


def _eval_xss_no_csp_no_csrf(findings: list[Finding], ctx: dict[str, Any], target: Target) -> tuple[bool, str, str]:
    """Missing defense-in-depth: XSS + Missing CSP + No CSRF on forms."""
    has_xss = any(
        (f.code or f.finding_code) == "XSS_REFLECTION"
        or (f.module == "xss_reflection" and f.severity <= Severity.MEDIUM)
        for f in findings
    )
    has_no_csp = any(
        (f.code or f.finding_code) in ("CSP_MISSING", "CSP_WEAK")
        or (f.module in ("headers", "csp_analyzer") and "csp" in f.title.lower() and ("missing" in f.title.lower() or "unsafe" in f.title.lower()))
        for f in findings
    )
    has_no_csrf = any(
        (f.code or f.finding_code) == "CSRF_TOKEN_MISSING"
        or (f.module == "forms_csrf" and "csrf" in f.title.lower())
        for f in findings
    ) or (len(ctx.get("forms", [])) > 0 and not any(f.module == "forms_csrf" and "protected" in f.title.lower() for f in findings))

    if has_xss and has_no_csp and has_no_csrf:
        evidence = "XSS reflection confirmed on target + Content-Security-Policy missing/weak + Form endpoints lack CSRF token protection."
        return True, "Missing defense-in-depth: XSS finding combined with no CSP and absent CSRF protection", evidence

    return False, "", ""


def _eval_dangling_subdomain_mail(findings: list[Finding], ctx: dict[str, Any], target: Target) -> tuple[bool, str, str]:
    """Subdomain takeover candidate + subdomain in SPF/DMARC mail configuration."""
    takeover_findings = [
        f for f in findings
        if (f.code or f.finding_code) == "SUBDOMAIN_TAKEOVER_CANDIDATE" or f.module == "subdomain_takeover"
    ]
    if not takeover_findings:
        return False, "", ""

    # Check for POSITIVE presence of mail setup (SPF/DMARC/MX configured, NOT missing)
    has_mail_setup = False
    for f in findings:
        code = f.code or f.finding_code or ""
        if code in ("SPF_RECORD_PRESENT", "DMARC_RECORD_PRESENT", "DMARC_POLICY_WEAK", "MX_RECORDS_PRESENT"):
            has_mail_setup = True
            break
        # Check title only for positive presence, NEVER if title mentions missing
        if f.module == "dns_recon" and any(k in f.title.lower() for k in ("configured", "present", "active", "enforced")) and "missing" not in f.title.lower():
            has_mail_setup = True
            break

    # Context info check for confirmed positive records
    info = ctx.get("info", {})
    if info.get("spf_record") or info.get("dmarc_record") or info.get("MX records") or info.get("mail_configured"):
        has_mail_setup = True

    if has_mail_setup:
        sub = takeover_findings[0].url or "subdomain"
        evidence = f"Dangling CNAME on {sub} | Domain has active organizational mail policy (phishing sender forgery risk)."
        return True, "Dangling subdomain takeover risk combined with active organizational mail policy", evidence

    return False, "", ""


def _eval_git_exposure_with_secrets(findings: list[Finding], ctx: dict[str, Any], target: Target) -> tuple[bool, str, str]:
    """Exposed .git repository + secrets found in JS bundles."""
    has_git = any(
        (f.code or f.finding_code) == "GIT_EXPOSURE"
        or (f.module == "git_exposure" and f.severity == Severity.CRITICAL)
        for f in findings
    )
    has_secrets = any(
        (f.code or f.finding_code) == "SECRET_IN_JS"
        or f.module == "secrets_in_js"
        for f in findings
    )

    if has_git and has_secrets:
        evidence = "Publicly accessible .git object history verified + Hardcoded API keys/secrets identified in client bundles."
        return True, "Full source history exposure combined with client credential leak", evidence

    return False, "", ""


def _eval_sourcemap_with_sensitive_comments(findings: list[Finding], ctx: dict[str, Any], target: Target) -> tuple[bool, str, str]:
    """Exposed sourcemap + developer comments or internal endpoints leak."""
    has_map = any(
        (f.code or f.finding_code) == "SOURCE_MAP_EXPOSURE"
        or f.module == "source_map_exposure"
        for f in findings
    )
    has_comment = any(
        (f.code or f.finding_code) == "COMMENT_LEAK"
        or f.module == "comment_leak"
        for f in findings
    )
    has_secret = any(
        (f.code or f.finding_code) == "SECRET_IN_JS"
        or f.module == "secrets_in_js"
        for f in findings
    )

    if has_map and (has_comment or has_secret):
        evidence = "Unminified JavaScript source maps publicly accessible + Internal endpoints/credentials exposed in client code."
        return True, "Exposed source maps provide complete structural roadmap for leaked credentials/internal endpoints", evidence

    return False, "", ""


# Extensible rule registry table
CORRELATION_RULES: list[CorrelationRule] = [
    CorrelationRule(
        id="RULE_01_CORS_ADMIN_NO_RATE_LIMIT",
        name="Unauthenticated CORS Wildcard on Admin Endpoint without Rate Limiting",
        combined_severity=Severity.CRITICAL,
        explanation="Unauthenticated cross-origin access to admin endpoint with no rate limiting — remote attackers can enumerate/abuse this endpoint from any origin without throttling.",
        remediation="Restrict CORS origins on admin endpoints to trusted internal origins, enforce authentication, and implement IP/token rate limits.",
        cwe="CWE-346",
        owasp="A01:2021",
        evaluator=_eval_cors_admin_no_rate_limit,
    ),
    CorrelationRule(
        id="RULE_02_XSS_NO_CSP_NO_CSRF",
        name="Compounded Client-Side Exploitation (XSS + Missing CSP + Absent CSRF)",
        combined_severity=Severity.HIGH,
        explanation="Missing defense-in-depth: an XSS finding combined with no CSP and no CSRF protection significantly raises exploitation impact.",
        remediation="Deploy strict Content-Security-Policy (CSP) headers without unsafe-inline, sanitize reflection inputs, and enforce anti-CSRF tokens.",
        cwe="CWE-79",
        owasp="A03:2021",
        evaluator=_eval_xss_no_csp_no_csrf,
    ),
    CorrelationRule(
        id="RULE_03_DANGLING_SUBDOMAIN_PHISHING",
        name="Dangling Subdomain Takeover with Mail Trust Forgery",
        combined_severity=Severity.CRITICAL,
        explanation="Dangling subdomain could be used for phishing with a trusted-looking sender domain.",
        remediation="Remove dangling CNAME DNS pointers immediately and ensure strict DMARC policy (p=reject).",
        cwe="CWE-284",
        owasp="A01:2021",
        evaluator=_eval_dangling_subdomain_mail,
    ),
    CorrelationRule(
        id="RULE_04_GIT_HISTORY_WITH_SECRETS",
        name="Full Source History Exposure Combined with Detected Secret",
        combined_severity=Severity.CRITICAL,
        explanation="Full source history exposure combined with a detected secret suggests the secret may be recoverable from git history even if rotated in the current build.",
        remediation="Deny public access to .git directories, immediately revoke and rotate all leaked credentials across all historical commits, and scrub git history.",
        cwe="CWE-538",
        owasp="A05:2021",
        evaluator=_eval_git_exposure_with_secrets,
    ),
    CorrelationRule(
        id="RULE_05_SOURCEMAP_LEAK_AMPLIFICATION",
        name="Source Map Exposure Amplifies Leaked Internal Secrets",
        combined_severity=Severity.HIGH,
        explanation="Source maps expose original unminified source code, file structures, and internal comments, enabling adversaries to understand how exposed credentials and internal APIs interact.",
        remediation="Disable production source map generation and block public access to *.map files in web server rules.",
        cwe="CWE-540",
        owasp="A05:2021",
        evaluator=_eval_sourcemap_with_sensitive_comments,
    ),
]


class CombinedRiskScenariosModule(BaseModule):
    name = "combined_risk_scenarios"
    description = "Correlates findings into multi-stage attack scenarios and compounded risk paths"

    async def run(self) -> list[Finding]:
        # Evaluates already-collected findings stored in self.ctx["findings"]
        existing_findings: list[Finding] = list(self.ctx.get("findings", []))

        for rule in CORRELATION_RULES:
            matched, title, evidence = rule.evaluator(existing_findings, self.ctx, self.target)
            if matched:
                self.add(
                    severity=rule.combined_severity,
                    title=f"[Compound Risk] {rule.name}",
                    detail=rule.explanation,
                    fix=rule.remediation,
                    url=self.target.base,
                    evidence=f"[{rule.id}] {evidence}",
                    cwe=rule.cwe,
                    owasp=rule.owasp,
                )

        return self.findings
