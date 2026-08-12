#!/bin/bash
# pi-bw — Run the pi coding agent sandboxed via bubblewrap
# Writable: current directory only. Everything else is read-only or invisible.
# pi has no permission-prompt system — bwrap is the enforcement layer, plus the
# bw-deny-files.ts extension (installed to ~/.pi/agent/extensions/ by install.sh).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"

# Locate pi on the host (lives under ~/.nvm, which isn't in the default sandbox
# PATH). Checked before parse_bw_flags so we fail before the docker guard starts.
if ! PI_BIN="$(command -v pi)"; then
  echo "Error: pi not found in PATH — install with: npm install -g @earendil-works/pi-coding-agent" >&2
  exit 1
fi
PI_BIN_DIR="$(dirname "$PI_BIN")"

parse_bw_flags "$@"

# Load sensitive file deny patterns (unless --no-deny-files)
if [[ "$BW_NO_DENY_FILES" != true ]]; then
  load_deny_patterns
fi

# Load MCP env vars from .env if needed
load_mcp_env_vars

# Tool-specific binds (added to common)
BINDS=(
  "${COMMON_BINDS[@]}"

  # pi + its node runtime (installed via nvm)
  "ro $HOME/.nvm"

  # pi config/state — rw! creates if missing
  "rw! $HOME/.pi"
)

# Symlinks directly under ~/.pi/agent/ can point outside bound paths
# (e.g. models.json -> a host-managed config repo). Bind resolved targets
# read-only so they don't dangle inside the sandbox.
for link in "$HOME/.pi/agent"/*; do
  [[ -L "$link" ]] || continue
  target="$(readlink -f "$link" || true)"
  if [[ -z "$target" || ! -e "$target" ]]; then
    echo "[bw] ⚠ skipping dangling symlink: $link" >&2
    continue
  fi
  case "$target" in
    "$HOME/.pi"|"$HOME/.pi"/*|"$STARTDIR"|"$STARTDIR"/*) continue ;;
  esac
  BINDS+=("ro $target")
done

# Overlay binds — placed after --tmpfs /tmp and --tmpfs /run
OVERLAY_BINDS=(
  "${COMMON_OVERLAY_BINDS[@]}"
)

add_docker_overlay_bind OVERLAY_BINDS

# Bind-mount deny patterns file into sandbox (read-only, under /tmp so it's an overlay)
if [[ -n "${BW_DENY_PATTERNS_FILE:-}" ]]; then
  OVERLAY_BINDS+=("ro $BW_DENY_PATTERNS_FILE")
fi

build_bwrap_args BINDS BWRAP_ARGS
build_bwrap_args OVERLAY_BINDS BWRAP_OVERLAY_ARGS

BWRAP_CMD=(
  bwrap
  "${BWRAP_ARGS[@]}"
  --proc /proc
  --dev /dev
  --tmpfs /dev/shm
  --tmpfs /tmp
  --tmpfs /run
  "${BWRAP_OVERLAY_ARGS[@]}"
  --symlink /run /var/run
  --setenv HOME "$HOME"
  --setenv PATH "${BW_VENV_PATH:+$BW_VENV_PATH/bin:}$PI_BIN_DIR:$HOME/.local/bin:$HOME/.npm-global/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin"
  --setenv SHELL /bin/bash
  ${SSH_AUTH_SOCK:+--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK"}
  ${SSH_AUTH_SOCK:+--setenv SSH_AUTH_SOCK "$SSH_AUTH_SOCK"}
  ${BW_VENV_PATH:+--setenv VIRTUAL_ENV "$BW_VENV_PATH"}
  ${BW_DENY_PATTERNS_FILE:+--setenv BW_DENY_PATTERNS_FILE "$BW_DENY_PATTERNS_FILE"}
  "${BW_MCP_ENV_ARGS[@]}"
  --setenv DOCKER_HOST "$BW_DOCKER_HOST"
  --chdir "$STARTDIR"
  --unshare-ipc
  --unshare-pid
  --die-with-parent
  pi "${BW_TOOL_ARGS[@]}"
)

if [[ -n "${BW_GUARD_PID:-}" || -n "${BW_DENY_PATTERNS_FILE:-}" ]]; then
  # Resources to clean up — use foreground bwrap so cleanup trap fires on exit
  trap cleanup_bw EXIT
  "${BWRAP_CMD[@]}"
else
  # Nothing to clean up — exec replaces this process
  exec "${BWRAP_CMD[@]}"
fi
