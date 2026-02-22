# bw-common.sh — Shared bind definitions and builder for bwrap sandbox scripts
# Sourced by claude-bw.sh and opencode-bw.sh. Not executable.

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

# --- Shared bind definitions ---
# Format: "mode source [dest]"
#   ro      = read-only bind (--ro-bind), skip if source missing
#   rw      = read-write bind (--bind), skip if source missing
#   rw!     = mkdir -p source, then read-write bind
#   rw!PERM = mkdir -p source + chmod PERM, then read-write bind (e.g. rw!700)
# If dest is omitted, defaults to source.
COMMON_BINDS=(
  # System (read-only)
  "ro /usr"
  "ro /lib"
  "ro /lib64"
  "ro /bin"
  "ro /sbin"
  "ro /etc"

  # WSL2: /etc/resolv.conf -> /mnt/wsl/resolv.conf — bind the target so DNS works
  "ro /mnt/wsl/resolv.conf"

  # Linuxbrew
  "ro /home/linuxbrew"

  # Workspace — the ONLY writable project area
  "rw $WORKSPACE"

  # Git config + SSH keys (read-only — push needs key access)
  "ro $HOME/.gitconfig"
  "ro $HOME/.config/git"
  "ro $HOME/.ssh"

  # User-local binaries (e.g. claude CLI)
  "ro $HOME/.local/bin"

  # Node / npm / pnpm
  "ro $HOME/.npm-global"
  "ro $HOME/.npmrc"
  "rw $HOME/.local/share/pnpm"

  # Python / uv
  "ro $HOME/python3.14"
  "ro $HOME/.local/share/uv"
)

# --- Overlay bind definitions ---
# These target paths under /tmp or /run and must be placed AFTER --tmpfs /tmp
# and --tmpfs /run in the bwrap command, otherwise the tmpfs hides them.
COMMON_OVERLAY_BINDS=(
  # Docker socket — skip if docker not installed
  # SECURITY: RW docker socket is a sandbox escape (docker run -v /:/host).
  # Needed for container workflows. Restrict to ro if only inspecting.
  "rw /run/docker.sock"

  # systemd runtime — skip if not present
  "ro /run/systemd"
)

# --- Builder function ---
# Takes two arguments: name of input binds array, name of output args array.
# Reads from the input array, populates the output array with bwrap flags.
# Usage: build_bwrap_args BINDS BWRAP_ARGS
build_bwrap_args() {
  local -n _binds=$1
  local -n _args=$2
  _args=()
  for entry in "${_binds[@]}"; do
    read -r mode src dest <<< "$entry"
    [[ -z "$dest" ]] && dest="$src"
    case "$mode" in
      rw!*)
        local perm="${mode#rw!}"
        mkdir -p "$src"
        [[ -n "$perm" ]] && chmod "$perm" "$src"
        ;;
      ro|rw) [[ -e "$src" ]] || continue ;;
    esac
    case "$mode" in
      ro)    _args+=(--ro-bind "$src" "$dest") ;;
      rw|rw!*) _args+=(--bind "$src" "$dest") ;;
    esac
  done
}
