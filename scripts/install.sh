#!/bin/sh
set -e

# Shinkiro Instant Installer
# Usage: curl -sSL https://raw.githubusercontent.com/Haiagari/shinkiro/main/scripts/install.sh | sh

REPO="Haiagari/shinkiro"
BINARY="shinkiro"
INSTALL_DIR="/usr/local/bin"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64) ARCH="amd64" ;;
  aarch64|arm64) ARCH="arm64" ;;
  *) echo "❌ Unsupported architecture: $ARCH" && exit 1 ;;
esac

echo "⚡ Fetching latest release of Shinkiro for $OS/$ARCH..."

LATEST_TAG=$(curl -sSL "https://api.github.com/repos/$REPO/releases/latest" 2>/dev/null | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/' || echo "v0.2.0")
if [ -z "$LATEST_TAG" ]; then
  LATEST_TAG="v0.2.0"
fi

DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/${BINARY}_${LATEST_TAG#v}_${OS}_${ARCH}.tar.gz"
TMP_DIR=$(mktemp -d)

echo "📦 Downloading $DOWNLOAD_URL..."
if curl -sSL "$DOWNLOAD_URL" -o "$TMP_DIR/shinkiro.tar.gz" 2>/dev/null; then
  tar -xzf "$TMP_DIR/shinkiro.tar.gz" -C "$TMP_DIR"
  if [ -w "$INSTALL_DIR" ]; then
    mv "$TMP_DIR/shinkiro" "$INSTALL_DIR/shinkiro"
  else
    sudo mv "$TMP_DIR/shinkiro" "$INSTALL_DIR/shinkiro"
  fi
  chmod +x "$INSTALL_DIR/shinkiro"
  rm -rf "$TMP_DIR"
  echo "✅ Shinkiro installed successfully to $INSTALL_DIR/shinkiro"
  echo "🚀 Run 'shinkiro tui' to start the interactive deception dashboard!"
else
  echo "⚠️ Pre-built release not found. Please compile from source: 'git clone https://github.com/Haiagari/shinkiro && make build'"
  rm -rf "$TMP_DIR"
  exit 0
fi
