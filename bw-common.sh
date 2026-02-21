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
#   ro  = read-only bind (--ro-bind), skip if source missing
#   rw  = read-write bind (--bind), skip if source missing
#   rw! = mkdir -p source, then read-write bind
# If dest is omitted, defaults to source.
COMMON_BINDS=(
  # System (read-only)
  "ro /usr"
  "ro /lib"
  "ro /lib64"
  "ro /bin"
  "ro /sbin"
  "ro /etc"

  # Linuxbrew
  "ro /home/linuxbrew"

  # Workspace — the ONLY writable project area
  "rw $WORKSPACE"

  # Git config + SSH keys (read-only — push needs key access)
  "ro $HOME/.gitconfig"
  "ro $HOME/.config/git"
  "ro $HOME/.ssh"

  # Node / npm / pnpm
  "ro $HOME/.npm-global"
  "ro $HOME/.npmrc"
  "rw $HOME/.local/share/pnpm"

  # Python / uv
  "ro $HOME/python3.14"
  "ro $HOME/.local/share/uv"
)

# --- Builder function ---
# Reads from BINDS array, populates BWRAP_ARGS array
build_bwrap_args() {
  BWRAP_ARGS=()
  for entry in "${BINDS[@]}"; do
    read -r mode src dest <<< "$entry"
    [[ -z "$dest" ]] && dest="$src"
    case "$mode" in
      rw!) mkdir -p "$src" ;;
      ro|rw) [[ -e "$src" ]] || continue ;;
    esac
    case "$mode" in
      ro)     BWRAP_ARGS+=(--ro-bind "$src" "$dest") ;;
      rw|rw!) BWRAP_ARGS+=(--bind "$src" "$dest") ;;
    esac
  done
}
