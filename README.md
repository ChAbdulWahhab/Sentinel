# 🛡️ SentinelScan (`sscan`)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://python.org)
[![Tests](https://img.shields.io/badge/Tests-Passing-brightgreen.svg)](tests/)

**SentinelScan** is a fast, developer-friendly, interactive command-line security self-audit tool designed to help website owners, administrators, and security practitioners identify misconfigurations and common vulnerabilities before attackers do.

---

## ⚡ Features

- **Interactive Terminal UI:** Launch `sscan` without arguments in an interactive terminal to access the rich TUI menu with live progress bars and summaries.
- **23 Security Modules:** Automated checks covering SSL/TLS, CORS, CSRF, security headers, JWT flaws, SQLi heuristics, open redirects, sensitive paths, GraphQL introspection, and more.
- **6 Report Formats:** Export findings in `markdown`, `json`, `html`, `sarif` (GitHub Code Scanning compatible), `csv` (Excel-friendly with UTF-8 BOM), and `pdf`.
- **Legal Safeguards:** Built-in consent tracking (`~/.sentinelscan/consent.json`), domain ownership verification (`--i-own-this`), and local audit logging (`~/.sentinelscan/audit.log`).
- **Zero External Runtime Dependencies (Binaries):** Standalone executables for macOS, Linux, and Windows.

---

## 📦 Installation

### Option 1: Quick Install via Script (Linux & macOS)

```bash
curl -sSL https://raw.githubusercontent.com/ChAbdulWahhab/sentinelscan/main/install.sh | bash
```

### Option 2: Python / pip

Install the package directly into your virtual environment:

```bash
# Clone the repository
git clone https://github.com/ChAbdulWahhab/sentinelscan.git
cd sentinelscan

# Install in editable mode with development & PDF dependencies
pip install -e ".[dev,pdf]"
```

### Option 3: Pre-built Binaries

Download standalone executables and SHA256 checksums directly from the [GitHub Releases](https://github.com/ChAbdulWahhab/sentinelscan/releases) page for:
- **macOS:** Apple Silicon (`arm64`) and Intel (`x86_64`)
- **Linux:** `x86_64` and `arm64`
- **Windows:** `x86_64` executable (`sscan.exe`)

### Option 4: Package Managers

- **Homebrew (macOS & Linux):**
  ```bash
  brew tap ChAbdulWahhab/sentinelscan
  brew install sentinelscan
  ```
- **WinGet (Windows):**
  ```powershell
  winget install ChAbdulWahhab.SentinelScan
  ```

---

## 🚀 Quick Start & Usage

### 1. Interactive Menu
Running `sscan` in any interactive terminal (TTY) launches the interactive menu:

```bash
sscan
```

### 2. Direct CLI Scans

```bash
# Full audit of a target domain
sscan scan https://example.com

# Audit with specific modules and export reports
sscan scan https://example.com -m headers,tls_https,cors -f markdown,html,json -o ./reports

# Declare ownership to skip interactive consent prompt
sscan scan https://example.com --i-own-this example.com

# Non-interactive / CI automation (skips prompt)
sscan scan https://example.com --yes
```

### 3. List Available Modules

```bash
sscan modules-list
```

### 4. Show Version

```bash
sscan version
# or
sscan --version
```

---

## 🔍 Modules (23)

| Category | Modules |
| :--- | :--- |
| **Transport & Infrastructure** | `tls_https`, `dns_recon`, `subdomain`, `waf_detect`, `rate_limit` |
| **HTTP Configuration** | `headers`, `cookies`, `cors`, `csp_analyzer`, `http_methods` |
| **Information Disclosure** | `sensitive_paths`, `exposed_files`, `directory_list`, `error_leak`, `robots_sitemap`, `tech_fingerprint` |
| **Application & API Logic** | `forms_csrf`, `graphql_probe`, `jwt_probe`, `js_analysis` |
| **Injection & Redirection** | `xss_reflection`, `sqli_heuristic`, `open_redirect` |

---

## 📊 Report Formats

- **Markdown (`.md`):** Clean tables and findings formatted for GitHub/GitLab pull request comments and issue trackers.
- **JSON (`.json`):** Machine-readable structured output for CI/CD pipelines and SIEM ingestion.
- **HTML (`.html`):** Dark-mode responsive dashboard for browser viewing and executive presentation.
- **SARIF (`.sarif`):** OASIS standard format for GitHub Code Scanning and IDE integrations.
- **CSV (`.csv`):** Spreadsheet format with UTF-8 BOM encoding for Excel compatibility.
- **PDF (`.pdf`):** Formal audit document (requires `reportlab`).

---

## ⚠️ Legal Warning & Authorized Testing Policy

> **IMPORTANT:** SentinelScan is created exclusively for educational, defensive, and authorized self-assessment purposes.

- You may run SentinelScan **only** against websites, systems, and networks that you own or for which you have received express, prior written authorization from the owner.
- Unauthorized scanning against third-party systems is illegal under applicable cybercrime laws (including the **U.S. CFAA 18 U.S.C. Section 1030**, **UK Computer Misuse Act 1990**, and **India IT Act 2000**).
- The creators and maintainers of SentinelScan accept **zero liability** for any misuse, damage, or legal consequences arising from using this tool.
- Review [DISCLAIMER.md](DISCLAIMER.md) and [TERMS.md](TERMS.md) before conducting any scan.

---

## 🛡️ Antivirus False-Positive Advisory

Pre-compiled standalone executables for Windows and macOS are packaged using [PyInstaller](https://pyinstaller.org/). Because PyInstaller bundles Python runtime files, dependencies, and scripts into a single compressed binary that unpacks into temporary memory at runtime, generic heuristic engines (e.g. Windows Defender, VirusTotal, or CrowdStrike) may occasionally report a **false positive** (often labeled as `Generic.Trojan` or `Heur.Boring.Packed`).

If your security software flags the standalone binary:
1. Verify the binary's cryptographic signature against the official `SHA256SUMS.txt` provided in the release.
2. If you prefer not to whitelist the packaged executable, you can run SentinelScan directly from source via `pip install -e .` without triggering binary unpacker heuristics.

---

## 🤝 Security Disclosure & Contributing

Please see [SECURITY.md](SECURITY.md) for vulnerability disclosure guidelines and contact procedures. Contributions and pull requests are welcome under the [MIT License](LICENSE).