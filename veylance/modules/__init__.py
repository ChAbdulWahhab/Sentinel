"""Module registry — register new modules here."""
from veylance.modules.base import BaseModule
from veylance.modules.headers import HeadersModule
from veylance.modules.tls_https import TlsHttpsModule
from veylance.modules.cookies import CookiesModule
from veylance.modules.cors import CorsModule
from veylance.modules.http_methods import HttpMethodsModule
from veylance.modules.sensitive_paths import SensitivePathsModule
from veylance.modules.error_leak import ErrorLeakModule
from veylance.modules.forms_csrf import FormsCsrfModule
from veylance.modules.js_analysis import JsAnalysisModule
from veylance.modules.tech_fingerprint import TechFingerprintModule
from veylance.modules.rate_limit import RateLimitModule
from veylance.modules.robots_sitemap import RobotsSitemapModule
from veylance.modules.dns_recon import DnsReconModule
from veylance.modules.subdomain import SubdomainModule
from veylance.modules.open_redirect import OpenRedirectModule
from veylance.modules.xss_reflection import XssReflectionModule
from veylance.modules.sqli_heuristic import SqliHeuristicModule
from veylance.modules.directory_list import DirectoryListModule
from veylance.modules.exposed_files import ExposedFilesModule
from veylance.modules.waf_detect import WafDetectModule
from veylance.modules.csp_analyzer import CspAnalyzerModule
from veylance.modules.graphql_probe import GraphqlProbeModule
from veylance.modules.jwt_probe import JwtProbeModule

# Part 2 Advanced / Hidden Exposure Modules
from veylance.modules.secrets_in_js import SecretsInJsModule
from veylance.modules.source_map_exposure import SourceMapExposureModule
from veylance.modules.git_exposure import GitExposureModule
from veylance.modules.subdomain_takeover import SubdomainTakeoverModule
from veylance.modules.dependency_exposure import DependencyExposureModule
from veylance.modules.ci_cd_exposure import CiCdExposureModule
from veylance.modules.sri_check import SriCheckModule
from veylance.modules.comment_leak import CommentLeakModule
from veylance.modules.cert_transparency_recon import CertTransparencyReconModule
from veylance.modules.cache_poisoning_headers import CachePoisoningHeadersModule

# Part 3 Correlation & Differentiation Modules
from veylance.modules.combined_risk_scenarios import CombinedRiskScenariosModule
from veylance.modules.scan_drift import ScanDriftModule

ADVANCED_MODULE_EXPLAINERS: dict[str, str] = {
    "secrets_in_js": "catches leaked API keys, tokens, and private credentials in client-side bundles before malicious actors scrape them.",
    "source_map_exposure": "catches exposed unminified source code, file structures, and internal comments left behind by build tools.",
    "git_exposure": "prevents full source code and history leaks — this is how many real breaches start.",
    "subdomain_takeover": "detects dangling DNS pointers to decommissioned SaaS apps that let attackers hijack company subdomains.",
    "dependency_exposure": "discovers publicly accessible package/manifest files revealing precise library versions and supply-chain vulnerabilities.",
    "ci_cd_exposure": "prevents exposure of CI/CD pipeline definitions, environment files, and infrastructure configs that reveal deployment architecture.",
    "sri_check": "detects external CDN scripts lacking subresource integrity attributes, protecting against supply chain CDN compromises.",
    "comment_leak": "catches developer comments revealing passwords, auth bypasses, internal IP addresses, and staging endpoints.",
    "cert_transparency_recon": "queries public certificate transparency logs to surface unlisted staging, dev, and internal subdomains.",
    "cache_poisoning_headers": "detects unkeyed headers reflected into cached responses that enable web cache poisoning.",
    "combined_risk_scenarios": "correlates independent findings into multi-stage attack scenarios that form actionable breach paths.",
    "scan_drift": "tracks temporal security drift and attack surface changes compared to historical audits.",
}

ADVANCED_MODULES: set[str] = set(ADVANCED_MODULE_EXPLAINERS.keys())
CORRELATION_MODULES: set[str] = {"combined_risk_scenarios", "scan_drift"}

ALL_MODULES: dict[str, type[BaseModule]] = {
    m.name: m for m in [
        HeadersModule, TlsHttpsModule, CookiesModule, CorsModule,
        HttpMethodsModule, SensitivePathsModule, ErrorLeakModule,
        FormsCsrfModule, JsAnalysisModule, TechFingerprintModule,
        RateLimitModule, RobotsSitemapModule, DnsReconModule,
        SubdomainModule, OpenRedirectModule, XssReflectionModule,
        SqliHeuristicModule, DirectoryListModule, ExposedFilesModule,
        WafDetectModule, CspAnalyzerModule, GraphqlProbeModule,
        JwtProbeModule,
        # Advanced modules
        SecretsInJsModule, SourceMapExposureModule, GitExposureModule,
        SubdomainTakeoverModule, DependencyExposureModule, CiCdExposureModule,
        SriCheckModule, CommentLeakModule, CertTransparencyReconModule,
        CachePoisoningHeadersModule,
        # Correlation modules
        CombinedRiskScenariosModule, ScanDriftModule,
    ]
}