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

  # Claude Code config
  "rw $HOME/.claude"
  "rw $HOME/.claude.json"
  "rw $HOME/.planning"

  # Claude desktop config
  "ro $HOME/.config/Claude"
)

build_bwrap_args

TMUX_DIR="/tmp/tmux-$(id -u)"
mkdir -p "$TMUX_DIR"

exec bwrap \
  "${BWRAP_ARGS[@]}" \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --tmpfs /run \
  --bind /run/docker.sock /run/docker.sock \
  --ro-bind /run/systemd /run/systemd \
  --symlink /run /var/run \
  --bind "$TMUX_DIR" "$TMUX_DIR" \
  --setenv HOME "$HOME" \
  --setenv PATH "/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin" \
  --setenv SHELL /bin/bash \
  --setenv CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS 1 \
  --setenv CLAUDE_CODE_DISABLE_AUTO_MEMORY 0 \
  --chdir "$STARTDIR" \
  --unshare-ipc \
  --unshare-pid \
  --die-with-parent \
  claude --dangerously-skip-permissions "$@"
