#!/bin/bash
# install.sh — Symlink bwrap sandbox wrappers into ~/.local/bin
set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
BIN_DIR="$HOME/.local/bin"

# Colors & symbols
BOLD='\033[1m'
DIM='\033[2m'
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
RESET='\033[0m'

step=0
total=5

header() {
  echo ""
  echo -e "${BOLD}${CYAN}  bw-AICode installer${RESET}"
  echo -e "${DIM}  Sandboxed AI coding tools${RESET}"
  echo ""
}

step() {
  step=$((step + 1))
  echo -e "  ${DIM}[${step}/${total}]${RESET} ${BOLD}$1${RESET}"
}

ok()   { echo -e "       ${GREEN}+${RESET} $1"; }
warn() { echo -e "       ${YELLOW}!${RESET} ${YELLOW}$1${RESET}"; }
err()  { echo -e "       ${RED}x${RESET} ${RED}$1${RESET}"; }

header

# --- Step 1: Create bin directory ---
step "Preparing install directory"
mkdir -p "$BIN_DIR"
ok "$BIN_DIR"

# --- Step 2: Symlink wrappers ---
step "Installing wrappers"
for script in claude-bw.sh opencode-bw.sh; do
  name="${script%.sh}"
  target="$SCRIPT_DIR/$script"
  link="$BIN_DIR/$name"

  if [[ -L "$link" ]]; then
    ln -sf "$target" "$link"
    ok "${name} ${DIM}updated${RESET}"
  elif [[ -e "$link" ]]; then
    rm "$link"
    ln -s "$target" "$link"
    ok "${name} ${DIM}replaced regular file with symlink${RESET}"
  else
    ln -s "$target" "$link"
    ok "${name} ${DIM}created${RESET}"
  fi
done

# Remove old bw-docker-proxy symlink if present
if [[ -L "$BIN_DIR/bw-docker-proxy" ]]; then
  rm "$BIN_DIR/bw-docker-proxy"
  ok "bw-docker-proxy ${DIM}removed (replaced by bw-docker-guard)${RESET}"
fi

# --- Step 3: Build bw-docker-guard ---
step "Building bw-docker-guard"
if command -v go &>/dev/null; then
  if (cd "$SCRIPT_DIR" && go build -o "$BIN_DIR/bw-docker-guard" ./cmd/bw-docker-guard 2>&1); then
    ok "bw-docker-guard ${DIM}built and installed${RESET}"
  else
    err "bw-docker-guard build failed"
  fi
else
  err "go not found — needed to build bw-docker-guard (install Go 1.22+)"
fi

# --- Step 4: Verify PATH ---
step "Checking PATH"
if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
  ok "$BIN_DIR is in PATH"
else
  warn "$BIN_DIR is not in PATH — add it to your shell profile"
fi

# --- Step 5: Checking dependencies ---
step "Checking dependencies"

if command -v bwrap &>/dev/null; then
  ok "bwrap $(bwrap --version 2>/dev/null | head -1 || echo '')"
else
  err "bwrap not found — install bubblewrap first"
fi

if command -v claude &>/dev/null; then
  ok "claude found at $(command -v claude)"
else
  warn "claude not found — install Claude Code before using claude-bw"
fi

if command -v opencode &>/dev/null; then
  ok "opencode found at $(command -v opencode)"
else
  warn "opencode not found — install OpenCode before using opencode-bw"
fi

if command -v docker &>/dev/null; then
  ok "docker found at $(command -v docker)"
else
  warn "docker not found — needed for Docker-based MCP servers and compose workflows"
fi

if command -v jq &>/dev/null; then
  ok "jq found at $(command -v jq)"
else
  warn "jq not found — needed for Docker allowlist derivation"
fi

if command -v go &>/dev/null; then
  ok "go $(go version 2>/dev/null | awk '{print $3}' || echo '')"
else
  warn "go not found — needed to build bw-docker-guard"
fi

echo ""
echo -e "  ${GREEN}${BOLD}Done.${RESET} Run ${CYAN}claude-bw${RESET} or ${CYAN}opencode-bw${RESET} from your project directory"
echo ""
