#!/bin/bash
# claude-bw — Run Claude Code sandboxed via bubblewrap
# Must be run from within ~/local_dev or a subdirectory.
# Writable: ~/local_dev only. Everything else is read-only or invisible.
# Runs with --dangerously-skip-permissions (safe because we're sandboxed).

set -euo pipefail

WORKSPACE="$HOME/local_dev"
STARTDIR="$(pwd)"

# Verify we're inside ~/local_dev
case "$STARTDIR" in
  "$WORKSPACE"|"$WORKSPACE"/*)
    ;;
  *)
    echo "Error: Must be run from within $WORKSPACE"
    echo "Current directory: $STARTDIR"
    exit 1
    ;;
esac

mkdir -p /tmp/tmux-$(id -u)

exec bwrap \
  --ro-bind /usr /usr \
  --ro-bind /lib /lib \
  --ro-bind /lib64 /lib64 \
  --ro-bind /bin /bin \
  --ro-bind /sbin /sbin \
  --ro-bind /etc /etc \
  --proc /proc \
  --dev /dev \
  --tmpfs /tmp \
  --tmpfs /run \
  \
  `# Docker: bind socket + fix /var/run symlink so docker CLI finds it` \
  --bind /run/docker.sock /run/docker.sock \
  --ro-bind /run/systemd /run/systemd \
  --symlink /run /var/run \
  \
  `# Linuxbrew (claude, rg live here)` \
  --ro-bind /home/linuxbrew /home/linuxbrew \
  \
  `# Workspace — the ONLY writable project area` \
  --bind "$WORKSPACE" "$WORKSPACE" \
  \
  `# Claude Code config — needs read-write for sessions/state` \
  --bind "$HOME/.claude" "$HOME/.claude" \
  --bind "$HOME/.claude.json" "$HOME/.claude.json" \
  \
  `# Planning folder — read-write` \
  --bind "$HOME/.planning" "$HOME/.planning" \
  \
  `# tmux` \
  --bind /tmp/tmux-$(id -u) /tmp/tmux-$(id -u) \
  \
  `# Git config — read-only` \
  --ro-bind "$HOME/.gitconfig" "$HOME/.gitconfig" \
  --ro-bind "$HOME/.config/git" "$HOME/.config/git" \
  --ro-bind "$HOME/python3.14" "$HOME/python3.14" \
  --ro-bind "$HOME/.config/Claude" "$HOME/.config/Claude" \
  --ro-bind "$HOME/.local/share/uv" "$HOME/.local/share/uv" \
  \
  --setenv HOME "$HOME" \
  --setenv PATH "/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin" \
  --setenv SHELL /bin/bash \
  --setenv CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS 1 \
  --setenv CLAUDE_CODE_DISABLE_AUTO_MEMORY 0 \
  --chdir "$STARTDIR" \
  \
  `# Isolate IPC/PID/UTS/cgroup but NOT user namespace (preserves docker group)` \
  --unshare-ipc \
  --unshare-pid \
  --die-with-parent \
  \
  claude --dangerously-skip-permissions "$@"
