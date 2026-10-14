# Veylance (veyl) Windows Installation Script
# Supports Windows x64 (amd64) architecture.

$ErrorActionPreference = "Stop"

$repo = "ChAbdulWahhab/veylance"
$installDir = if ($env:VEYLANCE_INSTALL_DIR) {
    $env:VEYLANCE_INSTALL_DIR
} else {
    Join-Path $env:USERPROFILE ".veylance\bin"
}

# 1. Detect Architecture
$arch = [System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLower()
if ($arch -notin @("x64", "amd64")) {
    if ($env:PROCESSOR_ARCHITECTURE -notin @("AMD64", "x64")) {
        Write-Error "[-] Unsupported architecture: $arch. Veylance currently supports Windows x64."
        exit 1
    }
}
Write-Host "[*] Detected platform: Windows (amd64)" -ForegroundColor Cyan

# 2. Determine Version
$version = $null
$defaultVersion = "v0.1.0"
$directFallbackUrl = "https://github.com/$repo/releases/download/$defaultVersion/veyl-windows-amd64.zip"

if ($env:VERSION) {
    $version = $env:VERSION.Trim()
} else {
    Write-Host "[*] Resolving latest release version..." -ForegroundColor Cyan
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -UseBasicParsing -Headers @{ "User-Agent" = "Veylance-Installer" } -ErrorAction Stop
        if ($release -and $release.tag_name) {
            $version = [string]$release.tag_name
        }
    } catch {
        # API query failed or repository has no releases yet
    }
}

if ([string]::IsNullOrWhiteSpace($version)) {
    $version = $defaultVersion
    Write-Warning "[!] No release found via GitHub API. Falling back to direct static release URL: $directFallbackUrl"
}

if (-not $version.StartsWith("v", [System.StringComparison]::OrdinalIgnoreCase)) {
    $version = "v$version"
}

$assetName = "veyl-windows-amd64.zip"
$downloadUrl = "https://github.com/$repo/releases/download/$version/$assetName"
$checksumUrl = "https://github.com/$repo/releases/download/$version/SHA256SUMS.txt"

$tmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("veylance-install-" + [System.Guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $tmpDir -Force | Out-Null

try {
    $zipPath = Join-Path $tmpDir $assetName
    $sumsPath = Join-Path $tmpDir "SHA256SUMS.txt"

    # 3. Download Archive & Checksums
    Write-Host "[*] Downloading Veylance $version ($assetName)..." -ForegroundColor Cyan
    try {
        Invoke-WebRequest -Uri $downloadUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
    } catch {
        if ($downloadUrl -ne $directFallbackUrl) {
            Write-Warning "[!] Primary download URL failed. Falling back to direct static URL: $directFallbackUrl"
            Invoke-WebRequest -Uri $directFallbackUrl -OutFile $zipPath -UseBasicParsing -ErrorAction Stop
        } else {
            throw $_
        }
    }

    try {
        Invoke-WebRequest -Uri $checksumUrl -OutFile $sumsPath -UseBasicParsing -ErrorAction SilentlyContinue
    } catch {
        # Optional checksum verification file
    }

    # 4. Verify SHA256 Checksum
    if (Test-Path $sumsPath) {
        Write-Host "[*] Verifying SHA256 checksum..." -ForegroundColor Cyan
        $actualHash = (Get-FileHash -Path $zipPath -Algorithm SHA256).Hash.ToLower()
        $sumsContent = Get-Content $sumsPath
        $expectedLine = $sumsContent | Where-Object { $_ -match $assetName }
        if ($expectedLine) {
            $expectedHash = ($expectedLine -split "\s+")[0].Trim().ToLower()
            if ($actualHash -ne $expectedHash) {
                Write-Error "[-] Checksum verification failed!`n    Expected: $expectedHash`n    Actual:   $actualHash"
                exit 1
            }
            Write-Host "[+] Checksum verified." -ForegroundColor Green
        }
    }

    # 5. Extract Binary
    New-Item -ItemType Directory -Path $installDir -Force | Out-Null
    Write-Host "[*] Extracting $assetName to $installDir..." -ForegroundColor Cyan
    Expand-Archive -Path $zipPath -DestinationPath $tmpDir -Force

    $extractedExe = Get-ChildItem -Path $tmpDir -Filter "veyl.exe" -Recurse | Select-Object -First 1
    if (-not $extractedExe) {
        Write-Error "[-] veyl.exe was not found in the downloaded archive."
        exit 1
    }

    $targetExe = Join-Path $installDir "veyl.exe"
    Move-Item -Path $extractedExe.FullName -Destination $targetExe -Force

    # 6. Update User PATH Environment Variable
    $userPath = [Environment]::GetEnvironmentVariable("PATH", "User")
    $paths = ($userPath -split ';') | Where-Object { $_ -and $_.Trim() }
    if ($paths -notcontains $installDir) {
        Write-Host "[*] Adding $installDir to User PATH environment variable..." -ForegroundColor Cyan
        $newUserPath = (($paths + $installDir) | Select-Object -Unique) -join ';'
        [Environment]::SetEnvironmentVariable("PATH", $newUserPath, "User")
    }

    if (($env:PATH -split ';') -notcontains $installDir) {
        $env:PATH = "$env:PATH;$installDir"
    }

    Write-Host "[+] Successfully installed veyl to $targetExe" -ForegroundColor Green
    Write-Host "[+] Added $installDir to user PATH." -ForegroundColor Green
    Write-Host ""
    Write-Host "Please restart your terminal (or refresh your environment) and run 'veyl' to begin." -ForegroundColor Cyan
} finally {
    if (Test-Path $tmpDir) {
        Remove-Item -Path $tmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}
