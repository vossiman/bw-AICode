#!/bin/bash
# opencode-bw — Run OpenCode sandboxed via bubblewrap
# Must be run from within ~/local_dev or a subdirectory.
# Writable: ~/local_dev only. Everything else is read-only or invisible.
# OpenCode allows all operations by default — no skip-permissions flag needed.

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

# Ensure OpenCode dirs exist (bwrap fails on missing bind sources)
mkdir -p "$HOME/.config/opencode"
mkdir -p "$HOME/.local/share/opencode"
mkdir -p "$HOME/.cache/opencode"

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
  `# Linuxbrew (opencode, rg live here)` \
  --ro-bind /home/linuxbrew /home/linuxbrew \
  \
  `# Workspace — the ONLY writable project area` \
  --bind "$WORKSPACE" "$WORKSPACE" \
  \
  `# OpenCode config — needs read-write` \
  --bind "$HOME/.config/opencode" "$HOME/.config/opencode" \
  \
  `# OpenCode data — sessions, auth, snapshots — needs read-write` \
  --bind "$HOME/.local/share/opencode" "$HOME/.local/share/opencode" \
  \
  `# OpenCode cache — models, bun cache — needs read-write` \
  --bind "$HOME/.cache/opencode" "$HOME/.cache/opencode" \
  \
  `# Git config — read-only` \
  --ro-bind "$HOME/.gitconfig" "$HOME/.gitconfig" \
  --ro-bind "$HOME/.config/git" "$HOME/.config/git" \
  --ro-bind "$HOME/python3.14" "$HOME/python3.14" \
  \
  --setenv HOME "$HOME" \
  --setenv PATH "/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin" \
  --setenv SHELL /bin/bash \
  --chdir "$STARTDIR" \
  \
  `# Isolate IPC/PID/UTS/cgroup but NOT user namespace (preserves docker group)` \
  --unshare-ipc \
  --unshare-pid \
  --die-with-parent \
  \
  opencode "$@"
