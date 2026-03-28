#!/bin/bash
# claude-bw — Run Claude Code sandboxed via bubblewrap
# Writable: current directory only. Everything else is read-only or invisible.
# Runs with --dangerously-skip-permissions (safe because we're sandboxed).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"
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

  # Claude CLI installation (binary + versions)
  "ro $HOME/.local/share/claude"

  # Claude Code config
  "rw $HOME/.claude"
  "rw $HOME/.claude.json"
  "rw $HOME/.planning"

  # Claude desktop config
  "ro $HOME/.config/Claude"
)

# Overlay binds — placed after --tmpfs /tmp and --tmpfs /run
OVERLAY_BINDS=(
  "${COMMON_OVERLAY_BINDS[@]}"

  # tmux socket dir — isolated from host sessions via TMUX_TMPDIR
  "rw!700 /tmp/tmux-claude-$(id -u)"
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
  --setenv PATH "${BW_VENV_PATH:+$BW_VENV_PATH/bin:}$HOME/.local/bin:$HOME/.npm-global/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin"
  --setenv SHELL /bin/bash
  ${SSH_AUTH_SOCK:+--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK"}
  ${SSH_AUTH_SOCK:+--setenv SSH_AUTH_SOCK "$SSH_AUTH_SOCK"}
  ${BW_VENV_PATH:+--setenv VIRTUAL_ENV "$BW_VENV_PATH"}
  --setenv CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS 1
  --setenv CLAUDE_CODE_DISABLE_AUTO_MEMORY 0
  --setenv TMUX_TMPDIR "/tmp/tmux-claude-$(id -u)"
  --setenv CLAUDE_CODE_SPAWN_BACKEND "tmux"
  ${BW_DENY_PATTERNS_FILE:+--setenv BW_DENY_PATTERNS_FILE "$BW_DENY_PATTERNS_FILE"}
  "${BW_MCP_ENV_ARGS[@]}"
  --setenv PLAYWRIGHT_MCP_BROWSER chromium
  --setenv PLAYWRIGHT_MCP_SANDBOX false
  --setenv DOCKER_HOST "$BW_DOCKER_HOST"
  --chdir "$STARTDIR"
  --unshare-ipc
  --unshare-pid
  --die-with-parent
  claude --dangerously-skip-permissions "${BW_TOOL_ARGS[@]}"
)

if [[ -n "${BW_GUARD_PID:-}" || -n "${BW_DENY_PATTERNS_FILE:-}" ]]; then
  # Resources to clean up — use foreground bwrap so cleanup trap fires on exit
  trap cleanup_bw EXIT
  "${BWRAP_CMD[@]}"
else
  # Nothing to clean up — exec replaces this process
  exec "${BWRAP_CMD[@]}"
fi
