"""Module registry — register new modules here."""
from sentinelscan.modules.base import BaseModule
from sentinelscan.modules.headers import HeadersModule
from sentinelscan.modules.tls_https import TlsHttpsModule
from sentinelscan.modules.cookies import CookiesModule
from sentinelscan.modules.cors import CorsModule
from sentinelscan.modules.http_methods import HttpMethodsModule
from sentinelscan.modules.sensitive_paths import SensitivePathsModule
from sentinelscan.modules.error_leak import ErrorLeakModule
from sentinelscan.modules.forms_csrf import FormsCsrfModule
from sentinelscan.modules.js_analysis import JsAnalysisModule
from sentinelscan.modules.tech_fingerprint import TechFingerprintModule
from sentinelscan.modules.rate_limit import RateLimitModule
from sentinelscan.modules.robots_sitemap import RobotsSitemapModule
from sentinelscan.modules.dns_recon import DnsReconModule
from sentinelscan.modules.subdomain import SubdomainModule
from sentinelscan.modules.open_redirect import OpenRedirectModule
from sentinelscan.modules.xss_reflection import XssReflectionModule
from sentinelscan.modules.sqli_heuristic import SqliHeuristicModule
from sentinelscan.modules.directory_list import DirectoryListModule
from sentinelscan.modules.exposed_files import ExposedFilesModule
from sentinelscan.modules.waf_detect import WafDetectModule
from sentinelscan.modules.csp_analyzer import CspAnalyzerModule
from sentinelscan.modules.graphql_probe import GraphqlProbeModule
from sentinelscan.modules.jwt_probe import JwtProbeModule

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
    ]
}