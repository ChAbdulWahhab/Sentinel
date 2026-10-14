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