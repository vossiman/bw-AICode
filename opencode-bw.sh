#!/bin/bash
# opencode-bw — Run OpenCode sandboxed via bubblewrap
# Must be run from within ~/local_dev or a subdirectory.
# Writable: ~/local_dev only. Everything else is read-only or invisible.
# Runs with OPENCODE_PERMISSION=allow (safe because bwrap enforces the sandbox).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"
parse_bw_flags "$@"

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

if [[ "$BW_FULL_DOCKER" == true ]]; then
  OVERLAY_BINDS+=("rw /run/docker.sock")
fi

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
  --setenv PATH "${BW_VENV_PATH:+$BW_VENV_PATH/bin:}$HOME/.local/bin:$HOME/.npm-global/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin" \
  --setenv SHELL /bin/bash \
  ${SSH_AUTH_SOCK:+--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK"} \
  ${SSH_AUTH_SOCK:+--setenv SSH_AUTH_SOCK "$SSH_AUTH_SOCK"} \
  ${BW_VENV_PATH:+--setenv VIRTUAL_ENV "$BW_VENV_PATH"} \
  --setenv OPENCODE_PERMISSION '{"*":"allow"}' \
  --setenv DOCKER_HOST "$BW_DOCKER_HOST" \
  --chdir "$STARTDIR" \
  --unshare-ipc \
  --unshare-pid \
  --die-with-parent \
  opencode "${BW_TOOL_ARGS[@]}"
