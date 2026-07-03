#!/bin/sh
# Confide installer.
#
#   curl -fsSL https://raw.githubusercontent.com/NielsenMax/confide/main/install.sh | sh
#
# Detects your OS/arch, downloads the matching prebuilt binary from the latest
# GitHub release, and installs it onto your PATH via `confide install --add-path`.
#
# Env overrides:
#   CONFIDE_VERSION=v0.1.0   install a specific tag instead of the latest
#   CONFIDE_INSTALL_DIR=...  passed through to `confide install --dir`
set -eu

REPO="NielsenMax/confide"

err() { printf 'install: %s\n' "$1" >&2; exit 1; }

command -v curl >/dev/null 2>&1 || err "curl is required but not found"

os=$(uname -s)
arch=$(uname -m)

case "$os" in
  Linux)  goos=linux ;;
  Darwin) goos=darwin ;;
  *) err "unsupported OS '$os' — download a binary manually from https://github.com/$REPO/releases" ;;
esac

case "$arch" in
  x86_64|amd64)  goarch=amd64 ;;
  arm64|aarch64) goarch=arm64 ;;
  *) err "unsupported architecture '$arch' — download a binary manually from https://github.com/$REPO/releases" ;;
esac

asset="confide_${goos}_${goarch}"

# Resolve the download URL. Default to the "latest" redirect; honor a pinned tag.
version="${CONFIDE_VERSION:-}"
if [ -n "$version" ]; then
  url="https://github.com/$REPO/releases/download/${version}/${asset}"
else
  url="https://github.com/$REPO/releases/latest/download/${asset}"
fi

tmp=$(mktemp -d 2>/dev/null || mktemp -d -t confide)
trap 'rm -rf "$tmp"' EXIT
bin="$tmp/confide"

printf 'Downloading %s ...\n' "$asset"
curl -fSL --proto '=https' --tlsv1.2 -o "$bin" "$url" \
  || err "download failed from $url"
chmod +x "$bin"

# Reuse the binary's own install logic: copy onto PATH (+ update shell rc).
set -- install --add-path
[ -n "${CONFIDE_INSTALL_DIR:-}" ] && set -- "$@" --dir "$CONFIDE_INSTALL_DIR"
"$bin" "$@"

printf '\nInstalled %s. Next: run `confide login` to authorize your Google account.\n' \
  "$("$bin" version 2>/dev/null || echo confide)"
