#!/bin/bash
# opencode-bw — Run OpenCode sandboxed via bubblewrap
# Writable: current directory only. Everything else is read-only or invisible.
# Runs with OPENCODE_PERMISSION=allow (safe because bwrap enforces the sandbox).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"
parse_bw_flags "$@"

# Load sensitive file deny patterns (unless --no-deny-files)
if [[ "$BW_NO_DENY_FILES" != true ]]; then
  load_deny_patterns
fi

# Build OPENCODE_PERMISSION JSON with deny rules for sensitive files
build_opencode_permission() {
  if [[ -z "${BW_DENY_PATTERNS_FILE:-}" || ! -f "$BW_DENY_PATTERNS_FILE" ]]; then
    echo '{"*":"allow"}'
    return
  fi

  local deny_rules=""
  while IFS= read -r pattern; do
    [[ -z "$pattern" ]] && continue
    # OpenCode uses glob patterns — prefix with **/ for recursive matching
    local escaped
    escaped="$(echo "$pattern" | sed 's/"/\\"/g')"
    deny_rules+="\"**/${escaped}\": \"deny\", "
  done < "$BW_DENY_PATTERNS_FILE"

  if [[ -z "$deny_rules" ]]; then
    echo '{"*":"allow"}'
    return
  fi

  # Build JSON with read+edit denials and a catch-all allow
  cat <<EOF
{"read": {${deny_rules}"*": "allow"}, "edit": {${deny_rules}"*": "allow"}, "*": "allow"}
EOF
}

OPENCODE_PERMISSION_JSON="$(build_opencode_permission)"

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

add_docker_overlay_bind OVERLAY_BINDS

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
  --setenv OPENCODE_PERMISSION "$OPENCODE_PERMISSION_JSON"
  --setenv DOCKER_HOST "$BW_DOCKER_HOST"
  --chdir "$STARTDIR"
  --unshare-ipc
  --unshare-pid
  --die-with-parent
  opencode "${BW_TOOL_ARGS[@]}"
)

if [[ -n "${BW_GUARD_PID:-}" || -n "${BW_DENY_PATTERNS_FILE:-}" ]]; then
  # Resources to clean up — use foreground bwrap so cleanup trap fires on exit
  trap cleanup_bw EXIT
  "${BWRAP_CMD[@]}"
else
  # Nothing to clean up — exec replaces this process
  exec "${BWRAP_CMD[@]}"
fi
