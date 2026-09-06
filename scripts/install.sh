#!/bin/sh
# Shinkiro installer — downloads assets produced by .github/workflows/release.yml
# Usage:
#   curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh
#   SHINKIRO_VERSION=v1.0.0 sh install.sh
set -eu

REPO="Haiagari/shinkiro"
BINARY="shinkiro"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
BASE_URL="https://github.com/${REPO}/releases/download"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *)
    echo "Unsupported architecture: $ARCH" >&2
    exit 1
    ;;
esac

case "$OS" in
  linux) ;;
  darwin)
    echo "Pre-built Darwin (macOS) binaries are not published by the current release workflow." >&2
    echo "Build from source: git clone https://github.com/${REPO}.git && cd shinkiro && make build" >&2
    exit 1
    ;;
  *)
    echo "Unsupported OS: $OS (pre-built releases are linux-amd64 / linux-arm64 only)" >&2
    exit 1
    ;;
esac

resolve_tag() {
  if [ -n "${SHINKIRO_VERSION:-}" ]; then
    echo "$SHINKIRO_VERSION"
    return
  fi
  if [ -n "${VERSION:-}" ]; then
    echo "$VERSION"
    return
  fi
  tag="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)"
  if [ -z "$tag" ]; then
    echo "Could not resolve latest release tag from GitHub API." >&2
    echo "Set SHINKIRO_VERSION explicitly (e.g. SHINKIRO_VERSION=v1.0.0)." >&2
    exit 1
  fi
  echo "$tag"
}

TAG="$(resolve_tag)"
# Accept v1.0.0 or 1.0.0
case "$TAG" in
  v*) ;;
  *) TAG="v${TAG}" ;;
esac

ASSET="${BINARY}-${OS}-${ARCH}"
DOWNLOAD_URL="${BASE_URL}/${TAG}/${ASSET}"
CHECKSUMS_URL="${BASE_URL}/${TAG}/checksums.txt"

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

echo "Fetching Shinkiro ${TAG} for ${OS}/${ARCH}..."
echo "Asset: ${ASSET}"

if ! curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/${ASSET}"; then
  echo "Failed to download ${DOWNLOAD_URL}" >&2
  echo "Build from source: git clone https://github.com/${REPO}.git && cd shinkiro && make build" >&2
  exit 1
fi

if curl -fsSL "$CHECKSUMS_URL" -o "${TMP_DIR}/checksums.txt"; then
  echo "Verifying SHA-256 against checksums.txt..."
  (
    cd "$TMP_DIR"
    # sha256sum -c expects "HASH  filename" lines; filter to our asset only
    if command -v sha256sum >/dev/null 2>&1; then
      awk -v f="$ASSET" '$2 == f {print}' checksums.txt | sha256sum -c -
    elif command -v shasum >/dev/null 2>&1; then
      expected="$(awk -v f="$ASSET" '$2 == f {print $1}' checksums.txt)"
      actual="$(shasum -a 256 "$ASSET" | awk '{print $1}')"
      if [ "$expected" != "$actual" ]; then
        echo "Checksum mismatch for ${ASSET}" >&2
        echo "expected: ${expected}" >&2
        echo "actual:   ${actual}" >&2
        exit 1
      fi
      echo "${ASSET}: OK"
    else
      echo "Warning: neither sha256sum nor shasum found; skipping checksum verification" >&2
    fi
  )
else
  echo "Warning: checksums.txt not found for ${TAG}; installing without verification" >&2
fi

chmod +x "${TMP_DIR}/${ASSET}"

if [ -w "$INSTALL_DIR" ] || [ "$(id -u)" -eq 0 ]; then
  mv "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/${BINARY}"
else
  echo "Installing to ${INSTALL_DIR} (requires sudo)..."
  sudo mv "${TMP_DIR}/${ASSET}" "${INSTALL_DIR}/${BINARY}"
fi

echo "Shinkiro installed to ${INSTALL_DIR}/${BINARY}"
echo "Run 'shinkiro version' or 'shinkiro tui' to get started."
