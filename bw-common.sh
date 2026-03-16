# bw-common.sh — Shared bind definitions and builder for bwrap sandbox scripts
# Sourced by claude-bw.sh and opencode-bw.sh. Not executable.

WORKSPACE="$HOME/local_dev"
STARTDIR="$(pwd)"

# Auto-detect local virtualenv (.venv) in the current directory
BW_VENV_PATH=""
if [[ -x "$STARTDIR/.venv/bin/python" ]]; then
  BW_VENV_PATH="$STARTDIR/.venv"
fi

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
  # Docker API: accessed via bw-docker-guard proxy (Unix socket) or raw socket
  # (--full-docker). The guard socket is added dynamically by start_docker_guard().

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

# --- Docker allowlist derivation ---
# Scans the project directory for Docker Compose files and Docker-based MCP
# server configs. Produces a JSON allowlist for bw-docker-guard.
# Sets: BW_DOCKER_MODE ("guarded"|"readonly"), BW_DOCKER_GUARD_CONFIG (path)
derive_docker_allowlist() {
  local images=() networks=() compose_project=""

  # --- Source 1: Docker Compose files ---
  local compose_file=""
  for f in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
    if [[ -f "$STARTDIR/$f" ]]; then
      compose_file="$STARTDIR/$f"
      break
    fi
  done

  if [[ -n "$compose_file" ]]; then
    compose_project="$(basename "$STARTDIR")"

    # Use docker compose config to resolve interpolation, extends, etc.
    local resolved
    if resolved="$(docker compose -f "$compose_file" config --format json 2>/dev/null)"; then
      # Extract service images
      local compose_images
      compose_images="$(echo "$resolved" | jq -r '.services // {} | to_entries[] | .value.image // empty' 2>/dev/null)"
      while IFS= read -r img; do
        [[ -n "$img" ]] && images+=("$img")
      done <<< "$compose_images"

      # Extract network names
      local compose_networks
      compose_networks="$(echo "$resolved" | jq -r '.networks // {} | keys[]' 2>/dev/null)"
      while IFS= read -r net; do
        [[ -n "$net" ]] && networks+=("${compose_project}_${net}")
      done <<< "$compose_networks"
    fi
  fi

  # --- Source 2: MCP server configs (Docker-based entries) ---
  # Extracts image names from MCP entries with "command": "docker"
  _extract_mcp_docker_images() {
    local file="$1"
    [[ -f "$file" ]] || return
    # Find entries where command is "docker", extract the image from args.
    # The image is the first arg that isn't a flag (doesn't start with -)
    # and isn't a flag value (not preceded by a flag that takes a value).
    local mcp_images
    mcp_images="$(jq -r '
      (.mcpServers // {}) | to_entries[] |
      select(.value.command == "docker") |
      .value.args // [] |
      # Walk args: skip "run" and flags, find the image
      reduce .[] as $arg (
        {state: "scanning", image: null};
        if .image != null then .
        elif .state == "skip_next" then .state = "scanning"
        elif $arg == "run" then .state = "scanning"
        elif ($arg | test("^--?[a-zA-Z]")) then
          # Flags that take a value: skip the next arg
          if ($arg | test("^--(network|name|env|volume|workdir|user|entrypoint|label|mount|publish|expose|hostname|domainname|memory|cpus|platform|pull|runtime|security-opt|ulimit|log-driver|log-opt|pid|uts|ipc|cgroupns|restart|stop-signal|stop-timeout)=")) then .
          elif ($arg | test("^-[evpw]$")) then {state: "skip_next", image: null}
          elif ($arg | test("^--(network|name|env|volume|workdir|user|entrypoint|label|mount|publish|expose|hostname)$")) then {state: "skip_next", image: null}
          else .
          end
        elif ($arg | test("^-")) then .
        else {state: "done", image: $arg}
        end
      ) | .image // empty
    ' "$file" 2>/dev/null)"
    while IFS= read -r img; do
      [[ -n "$img" ]] && images+=("$img")
    done <<< "$mcp_images"
  }

  # Check per-project MCP configs
  _extract_mcp_docker_images "$STARTDIR/.mcp.json"
  _extract_mcp_docker_images "$STARTDIR/.claude/settings.local.json"

  # Check global Claude desktop config
  _extract_mcp_docker_images "$HOME/.config/Claude/claude_desktop_config.json"

  # --- Deduplicate ---
  local unique_images=() unique_networks=()
  local -A seen_img seen_net
  for img in "${images[@]}"; do
    if [[ -z "${seen_img[$img]:-}" ]]; then
      unique_images+=("$img")
      seen_img[$img]=1
    fi
  done
  for net in "${networks[@]}"; do
    if [[ -z "${seen_net[$net]:-}" ]]; then
      unique_networks+=("$net")
      seen_net[$net]=1
    fi
  done

  # --- Determine mode ---
  if (( ${#unique_images[@]} > 0 )); then
    BW_DOCKER_MODE="guarded"
  else
    BW_DOCKER_MODE="readonly"
  fi

  # --- Write JSON config ---
  BW_DOCKER_GUARD_CONFIG="$(mktemp /tmp/bw-docker-guard-XXXXXX.json)"

  local images_json networks_json
  images_json="$(printf '%s\n' "${unique_images[@]}" | jq -R . | jq -s .)"
  if (( ${#unique_networks[@]} > 0 )); then
    networks_json="$(printf '%s\n' "${unique_networks[@]}" | jq -R . | jq -s .)"
  else
    networks_json="[]"
  fi

  jq -n \
    --arg project_dir "$STARTDIR" \
    --arg compose_project "$compose_project" \
    --argjson images "$images_json" \
    --argjson networks "$networks_json" \
    --arg volume_mount_root "$STARTDIR" \
    '{
      project_dir: $project_dir,
      compose_project: $compose_project,
      allowed_images: $images,
      allowed_networks: $networks,
      volume_mount_root: $volume_mount_root
    }' > "$BW_DOCKER_GUARD_CONFIG"
}

# --- Docker guard lifecycle ---
# Start bw-docker-guard proxy. Sets BW_GUARD_PID, BW_GUARD_SOCKET, BW_DOCKER_HOST.
start_docker_guard() {
  BW_GUARD_SOCKET="/tmp/bw-docker-guard-$$.sock"
  bw-docker-guard \
    --config "$BW_DOCKER_GUARD_CONFIG" \
    --socket "$BW_GUARD_SOCKET" &
  BW_GUARD_PID=$!

  # Wait for socket to appear (up to 1 second)
  local i
  for i in {1..20}; do
    [[ -S "$BW_GUARD_SOCKET" ]] && break
    sleep 0.05
  done

  if [[ ! -S "$BW_GUARD_SOCKET" ]]; then
    echo "Error: bw-docker-guard failed to start" >&2
    kill "$BW_GUARD_PID" 2>/dev/null
    exit 1
  fi

  # Inside the sandbox, the socket is bind-mounted to a fixed path
  BW_DOCKER_HOST="unix:///run/bw-docker-guard.sock"
}

cleanup_docker_guard() {
  [[ -n "${BW_GUARD_PID:-}" ]] && kill "$BW_GUARD_PID" 2>/dev/null
  [[ -n "${BW_GUARD_SOCKET:-}" ]] && rm -f "$BW_GUARD_SOCKET"
  [[ -n "${BW_DOCKER_GUARD_CONFIG:-}" ]] && rm -f "$BW_DOCKER_GUARD_CONFIG"
}

# Parse bw-AICode flags from arguments.
# Sets: BW_FULL_DOCKER (bool), BW_DOCKER_HOST (env value), BW_TOOL_ARGS (passthrough),
#       BW_DOCKER_MODE ("guarded"|"readonly"|"full"), BW_GUARD_PID, BW_GUARD_SOCKET
parse_bw_flags() {
  BW_FULL_DOCKER=false
  BW_TOOL_ARGS=()
  for arg in "$@"; do
    case "$arg" in
      --full-docker) BW_FULL_DOCKER=true ;;
      *) BW_TOOL_ARGS+=("$arg") ;;
    esac
  done

  if [[ "$BW_FULL_DOCKER" == true ]]; then
    BW_DOCKER_HOST="unix:///var/run/docker.sock"
    BW_DOCKER_MODE="full"

    # WSL2: Docker Desktop symlinks binaries and CLI plugins from /usr into
    # /mnt/wsl/docker-desktop/cli-tools/... which isn't mounted by default.
    # Bind-mount the entire cli-tools tree so docker, docker compose, buildx,
    # and all other plugins work inside the sandbox.
    local wsl_cli_tools="/mnt/wsl/docker-desktop/cli-tools"
    if [[ -d "$wsl_cli_tools" ]]; then
      COMMON_BINDS+=("ro $wsl_cli_tools")
    fi
  else
    # Derive allowlist from project config and start the guard proxy
    derive_docker_allowlist
    start_docker_guard
  fi
}
