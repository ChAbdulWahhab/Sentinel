# 🛡️ SentinelScan

Interactive CLI security self-audit tool.

## Install

```bash
pip install -e ".[dev,pdf]"
```

## Usage

```bash
sentinelscan scan https://example.com
sscan scan example.com -f markdown,json,html,sarif -o ./reports
sscan modules-list
sscan version
```

## Modules (23)

- headers, tls_https, cookies, cors, http_methods, sensitive_paths,
  error_leak, forms_csrf, js_analysis, tech_fingerprint, rate_limit,
  robots_sitemap, dns_recon, subdomain, open_redirect, xss_reflection,
  sqli_heuristic, directory_list, exposed_files, waf_detect,
  csp_analyzer, graphql_probe, jwt_probe

## Report Formats

markdown, json, html, sarif, csv, pdf

## Legal

Sirf apni ya authorized websites par. Authorized hone ki zimmedari user ki.