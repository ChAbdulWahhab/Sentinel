#!/usr/bin/env bash
# SentinelScan (sscan) Unix Installation Script
# Supports Linux and macOS on x86_64 and arm64 architectures.

set -euo pipefail

REPO="ChAbdulWahhab/sentinelscan"
INSTALL_DIR="${SENTINELSCAN_INSTALL_DIR:-/usr/local/bin}"

# 1. Detect Operating System
OS="$(uname -s)"
case "${OS}" in
    Linux*)     PLATFORM="linux" ;;
    Darwin*)    PLATFORM="darwin" ;;
    *)
        echo "[-] Unsupported operating system: ${OS}"
        exit 1
        ;;
esac

# 2. Detect Architecture
ARCH="$(uname -m)"
case "${ARCH}" in
    x86_64|amd64)   ARCH="amd64" ;;
    arm64|aarch64)  ARCH="arm64" ;;
    *)
        echo "[-] Unsupported architecture: ${ARCH}"
        exit 1
        ;;
esac

TARGET="sscan-${PLATFORM}-${ARCH}"
echo "[*] Detected platform: ${PLATFORM} (${ARCH})"

# 3. Determine Version & Download URL
if [ -z "${VERSION:-}" ]; then
    echo "[*] Resolving latest release version..."
    VERSION="$(curl -sSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "")"
    if [ -z "${VERSION}" ]; then
        VERSION="v0.1.0"
        echo "[!] Warning: Failed to query GitHub API. Falling back to default version ${VERSION}"
    fi
fi

DOWNLOAD_URL="https://github.com/repos/${REPO}/releases/download/${VERSION}/${TARGET}"
CHECKSUMS_URL="https://github.com/repos/${REPO}/releases/download/${VERSION}/SHA256SUMS.txt"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

echo "[*] Downloading SentinelScan ${VERSION} (${TARGET})..."
if command -v curl >/dev/null 2>&1; then
    curl -fSL "${DOWNLOAD_URL}" -o "${TMP_DIR}/sscan"
    curl -fSL "${CHECKSUMS_URL}" -o "${TMP_DIR}/SHA256SUMS.txt" || true
elif command -v wget >/dev/null 2>&1; then
    wget -q "${DOWNLOAD_URL}" -O "${TMP_DIR}/sscan"
    wget -q "${CHECKSUMS_URL}" -O "${TMP_DIR}/SHA256SUMS.txt" || true
else
    echo "[-] Error: curl or wget is required to download SentinelScan."
    exit 1
fi

# 4. Optional Checksum Verification
if [ -f "${TMP_DIR}/SHA256SUMS.txt" ] && grep -q "${TARGET}" "${TMP_DIR}/SHA256SUMS.txt"; then
    echo "[*] Verifying SHA256 checksum..."
    EXPECTED_HASH="$(grep "${TARGET}" "${TMP_DIR}/SHA256SUMS.txt" | awk '{print $1}')"
    if command -v sha256sum >/dev/null 2>&1; then
        ACTUAL_HASH="$(sha256sum "${TMP_DIR}/sscan" | awk '{print $1}')"
    elif command -v shasum >/dev/null 2>&1; then
        ACTUAL_HASH="$(shasum -a 256 "${TMP_DIR}/sscan" | awk '{print $1}')"
    else
        ACTUAL_HASH=""
    fi

    if [ -n "${ACTUAL_HASH}" ] && [ "${EXPECTED_HASH}" != "${ACTUAL_HASH}" ]; then
        echo "[-] Checksum verification failed!"
        echo "    Expected: ${EXPECTED_HASH}"
        echo "    Actual:   ${ACTUAL_HASH}"
        exit 1
    fi
    echo "[+] Checksum verified."
fi

chmod +x "${TMP_DIR}/sscan"

# 5. Install Binary
if [ ! -d "${INSTALL_DIR}" ]; then
    INSTALL_DIR="${HOME}/.local/bin"
    mkdir -p "${INSTALL_DIR}"
fi

if [ -w "${INSTALL_DIR}" ]; then
    mv "${TMP_DIR}/sscan" "${INSTALL_DIR}/sscan"
else
    echo "[*] Root permissions required to install to ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/sscan" "${INSTALL_DIR}/sscan"
fi

echo "[+] Successfully installed sscan to ${INSTALL_DIR}/sscan"

# Verify command path
if ! command -v sscan >/dev/null 2>&1; then
    echo "[!] Notice: ${INSTALL_DIR} is not in your current PATH."
    echo "    Add it by running:"
    echo "    export PATH=\"${INSTALL_DIR}:\$PATH\""
else
    echo "[+] Verification:"
    sscan --version || true
fi

echo "[+] Done. Run 'sscan' to launch the interactive terminal audit menu."
