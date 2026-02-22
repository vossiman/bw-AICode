#!/bin/bash
# opencode-bw — Run OpenCode sandboxed via bubblewrap
# Must be run from within ~/local_dev or a subdirectory.
# Writable: ~/local_dev only. Everything else is read-only or invisible.
# OpenCode allows all operations by default — no skip-permissions flag needed.

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"

# Tool-specific binds (added to common)
BINDS=(
  "${COMMON_BINDS[@]}"

  # OpenCode config/data/cache — rw! creates if missing
  "rw! $HOME/.config/opencode"
  "rw! $HOME/.local/share/opencode"
  "rw! $HOME/.cache/opencode"
)

# Overlay binds — placed after --tmpfs /tmp and --tmpfs /run
OVERLAY_BINDS=(
  "${COMMON_OVERLAY_BINDS[@]}"
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
  --chdir "$STARTDIR" \
  --unshare-ipc \
  --unshare-pid \
  --die-with-parent \
  opencode "$@"
