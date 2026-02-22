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
total=4

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
for script in claude-bw.sh opencode-bw.sh bw-docker-proxy.sh; do
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

# --- Step 3: Verify PATH ---
step "Checking PATH"
if [[ ":$PATH:" == *":$BIN_DIR:"* ]]; then
  ok "$BIN_DIR is in PATH"
else
  warn "$BIN_DIR is not in PATH — add it to your shell profile"
fi

# --- Step 4: Checking dependencies ---
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
  warn "docker not found — needed for bw-docker-proxy"
fi

echo ""
echo -e "  ${GREEN}${BOLD}Done.${RESET} Run ${CYAN}bw-docker-proxy up -d${RESET} then ${CYAN}claude-bw${RESET} or ${CYAN}opencode-bw${RESET} from inside ${BOLD}~/local_dev${RESET}"
echo ""
