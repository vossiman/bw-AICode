#!/bin/bash
# claude-bw — Run Claude Code sandboxed via bubblewrap
# Must be run from within ~/local_dev or a subdirectory.
# Writable: ~/local_dev only. Everything else is read-only or invisible.
# Runs with --dangerously-skip-permissions (safe because we're sandboxed).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"

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

build_bwrap_args BINDS BWRAP_ARGS
build_bwrap_args OVERLAY_BINDS BWRAP_OVERLAY_ARGS

exec bwrap \
  "${BWRAP_ARGS[@]}" \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --tmpfs /run \
  "${BWRAP_OVERLAY_ARGS[@]}" \
  --symlink /run /var/run \
  --setenv HOME "$HOME" \
  --setenv PATH "$HOME/.local/bin:$HOME/.npm-global/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin" \
  --setenv SHELL /bin/bash \
  ${SSH_AUTH_SOCK:+--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK"} \
  ${SSH_AUTH_SOCK:+--setenv SSH_AUTH_SOCK "$SSH_AUTH_SOCK"} \
  --setenv CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS 1 \
  --setenv CLAUDE_CODE_DISABLE_AUTO_MEMORY 0 \
  --setenv TMUX_TMPDIR "/tmp/tmux-claude-$(id -u)" \
  --setenv CLAUDE_CODE_SPAWN_BACKEND "tmux" \
  --chdir "$STARTDIR" \
  --unshare-ipc \
  --unshare-pid \
  --die-with-parent \
  claude --dangerously-skip-permissions "$@"
