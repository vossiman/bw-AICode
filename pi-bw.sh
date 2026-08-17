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

# Symlinks under ~/.pi/agent/ (up to 3 levels deep: agent/<dir>/<subdir>/<file>)
# can point outside bound paths — e.g. models.json, agents/*.md,
# extensions/**/*.ts symlinked from a host-managed config repo. Bind resolved
# targets read-only so they don't dangle inside the sandbox. Only regular-file
# targets are followed; /, $HOME, and $HOME's ancestors are rejected, and
# duplicate targets are bound once (see resolve_symlink_binds in bw-common.sh).
# Residual risk: ~/.pi is bound read-write, so a prior sandboxed session
# could plant a symlink here pointing at any other same-user-readable
# regular file (e.g. ~/.aws/credentials); on a later launch that file
# would be mounted read-only into the sandbox. Recursing WIDENS that
# surface: a planted link no longer has to sit at the top level of
# ~/.pi/agent/ where it would be conspicuous — it can hide three levels
# deep in an extensions/ subdirectory. The deny-files extension only
# pattern-matches common secret basenames on pi's tool calls (best-effort,
# bypassable, and blind to files with unremarkable names), so it does NOT
# close this hole. bwrap remains the primary boundary; this bind pass is
# a convenience for host-managed config, not a hard guarantee — audit
# ~/.pi/agent/ symlinks if the sandbox may have run untrusted output.
PI_SYMLINK_TARGETS=()
resolve_symlink_binds PI_SYMLINK_TARGETS "$HOME/.pi/agent" "$HOME/.pi"

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

# Symlink targets are appended as explicit --ro-bind args (not BINDS entries):
# the "mode source [dest]" string format splits on whitespace, so paths with
# spaces would be mangled by build_bwrap_args.
for target in "${PI_SYMLINK_TARGETS[@]}"; do
  BWRAP_ARGS+=(--ro-bind "$target" "$target")
done

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
