# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for building standalone SentinelScan (sscan) binary."""
import os
import sys
from pathlib import Path

block_cipher = None

repo_root = Path(SPECPATH).resolve()

# Bundled data files (sensitive paths, subdomains, user agents, etc.)
datas = [
    (str(repo_root / "sentinelscan" / "data"), "sentinelscan/data"),
]

# Hidden imports for dynamically registered modules and CLI dependencies
hiddenimports = [
    # Core CLI & UI
    "sentinelscan.cli",
    "sentinelscan.config",
    "sentinelscan.ui.banner",
    "sentinelscan.ui.consent",
    "sentinelscan.ui.menu",
    "sentinelscan.ui.progress",
    "sentinelscan.ui.tables",
    "sentinelscan.utils.audit",
    "sentinelscan.utils.logger",
    "sentinelscan.utils.wordlists",
    # All 23 security modules
    "sentinelscan.modules",
    "sentinelscan.modules.base",
    "sentinelscan.modules.headers",
    "sentinelscan.modules.tls_https",
    "sentinelscan.modules.cookies",
    "sentinelscan.modules.cors",
    "sentinelscan.modules.http_methods",
    "sentinelscan.modules.sensitive_paths",
    "sentinelscan.modules.error_leak",
    "sentinelscan.modules.forms_csrf",
    "sentinelscan.modules.js_analysis",
    "sentinelscan.modules.tech_fingerprint",
    "sentinelscan.modules.rate_limit",
    "sentinelscan.modules.robots_sitemap",
    "sentinelscan.modules.dns_recon",
    "sentinelscan.modules.subdomain",
    "sentinelscan.modules.open_redirect",
    "sentinelscan.modules.xss_reflection",
    "sentinelscan.modules.sqli_heuristic",
    "sentinelscan.modules.directory_list",
    "sentinelscan.modules.exposed_files",
    "sentinelscan.modules.waf_detect",
    "sentinelscan.modules.csp_analyzer",
    "sentinelscan.modules.graphql_probe",
    "sentinelscan.modules.jwt_probe",
    # All report generators
    "sentinelscan.report",
    "sentinelscan.report.base",
    "sentinelscan.report.markdown",
    "sentinelscan.report.json_report",
    "sentinelscan.report.html_report",
    "sentinelscan.report.sarif",
    "sentinelscan.report.csv_report",
    "sentinelscan.report.pdf_report",
    # External libraries
    "dns.resolver",
    "dns.exception",
    "bs4",
    "yaml",
    "httpx",
    "rich",
    "rich.console",
    "rich.table",
    "rich.panel",
    "rich.prompt",
    "rich.progress",
    "typer",
]

a = Analysis(
    [str(repo_root / "sentinelscan" / "__main__.py")],
    pathex=[str(repo_root)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "scipy", "pandas"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="sscan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
