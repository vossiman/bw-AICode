# bw-common.sh — Shared bind definitions and builder for bwrap sandbox scripts
# Sourced by claude-bw.sh and opencode-bw.sh. Not executable.

STARTDIR="$(pwd)"

# Auto-detect local virtualenv (.venv) in the current directory
BW_VENV_PATH=""
if [[ -x "$STARTDIR/.venv/bin/python" ]]; then
  BW_VENV_PATH="$STARTDIR/.venv"
fi

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

  # Project directory (pwd at launch) — the ONLY writable project area
  "rw $STARTDIR"

  # Git config + SSH keys (read-only — push needs key access)
  "ro $HOME/.gitconfig"
  "ro $HOME/.config/git"
  "ro $HOME/.ssh"

  # User-local binaries (e.g. claude CLI)
  "ro $HOME/.local/bin"

  # Node / npm / pnpm
  "ro $HOME/.npm-global"
  "ro $HOME/.npmrc"
  "ro $HOME/.npm"
  "rw $HOME/.npm/_cacache"
  "rw $HOME/.npm/_logs"
  "rw $HOME/.local/share/pnpm"

  # Playwright / Chrome
  "rw $HOME/.cache/ms-playwright"
  "ro /opt/google"

  # Python / uv
  "ro $HOME/python3.14"
  "rw $HOME/.local/share/uv"
  "rw $HOME/.cache/uv"
)

# --- Overlay bind definitions ---
# These target paths under /tmp or /run and must be placed AFTER --tmpfs /tmp
# and --tmpfs /run in the bwrap command, otherwise the tmpfs hides them.
COMMON_OVERLAY_BINDS=(
  # Docker API: accessed via bw-docker-guard proxy (Unix socket) or raw socket
  # (--full-docker). The guard socket is added dynamically by start_docker_guard().

  # X11 display socket — needed for GUI apps (e.g. Playwright/Chrome)
  "ro /tmp/.X11-unix"

  # D-Bus sockets — Chrome and other GUI apps need these
  "ro /run/dbus"
  "ro /run/user/$(id -u)/bus"

  # systemd runtime — skip if not present
  "ro /run/systemd"

  # Avahi mDNS socket — needed to resolve .local hostnames (e.g. SSH)
  "ro /run/avahi-daemon/socket"
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
  local images=() networks=() extra_volume_paths=() compose_project=""

  # --- Source 1: Docker Compose files ---
  local compose_file=""
  for f in docker-compose.yml docker-compose.yaml compose.yml compose.yaml; do
    if [[ -f "$STARTDIR/$f" ]]; then
      compose_file="$STARTDIR/$f"
      break
    fi
  done

  if [[ -n "$compose_file" ]]; then
    # Use docker compose config to resolve interpolation, extends, etc.
    local resolved
    if ! command -v docker &>/dev/null; then
      echo "Warning: docker not found; cannot resolve compose file" >&2
    elif ! docker compose version &>/dev/null; then
      echo "Warning: docker compose plugin not available; cannot resolve compose file" >&2
    elif resolved="$(docker compose -f "$compose_file" config --format json 2>/dev/null)"; then
      # Extract project name from resolved config (handles COMPOSE_PROJECT_NAME, name: directive, etc.)
      compose_project="$(echo "$resolved" | jq -r '.name // empty' 2>/dev/null)"
      [[ -z "$compose_project" ]] && compose_project="$(basename "$STARTDIR")"

      # Extract service images (explicit image or default name for build-only services)
      local compose_images
      compose_images="$(echo "$resolved" | jq -r --arg proj "$compose_project" '
        .services // {} | to_entries[] |
        if .value.image then .value.image
        elif .value.build then "\($proj)-\(.key)"
        else empty end
      ' 2>/dev/null)"
      while IFS= read -r img; do
        [[ -n "$img" ]] && images+=("$img")
      done <<< "$compose_images" || true

      # Extract resolved network names (uses .name field which includes project prefix)
      local compose_networks
      compose_networks="$(echo "$resolved" | jq -r '.networks // {} | to_entries[] | .value.name // .key' 2>/dev/null)"
      while IFS= read -r net; do
        [[ -n "$net" ]] && networks+=("$net")
      done <<< "$compose_networks" || true

      # Extract bind mount sources outside project dir (e.g. /var/run/docker.sock)
      local compose_binds
      compose_binds="$(echo "$resolved" | jq -r '
        [.services // {} | to_entries[] | .value.volumes // [] | .[] |
         select(type == "object" and .type == "bind") | .source] | unique[]
      ' 2>/dev/null)"
      while IFS= read -r bp; do
        [[ -n "$bp" ]] || continue
        case "$bp" in "$STARTDIR"|"$STARTDIR"/*) ;; *) extra_volume_paths+=("$bp") ;; esac
      done <<< "$compose_binds" || true
    else
      echo "Warning: docker compose config failed for $compose_file; allowlist may be incomplete" >&2
      compose_project="$(basename "$STARTDIR")"
    fi
  fi

  # --- Source 2: MCP server configs (Docker-based entries) ---
  # Extracts image names from MCP entries with "command": "docker"
  #
  # Best-effort: this parser handles common docker run flag patterns but cannot
  # cover every possible flag combination. Unknown flags with values may cause
  # the image to be missed; the user can add images to the allowlist manually.
  _extract_mcp_docker_images() {
    local file="$1"
    [[ -f "$file" ]] || return 0
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
          if ($arg | test("^--(network|name|env|volume|workdir|user|entrypoint|label|mount|publish|expose|hostname|domainname|memory|cpus|platform|pull|runtime|security-opt|ulimit|log-driver|log-opt|pid|uts|ipc|cgroupns|restart|stop-signal|stop-timeout|memory-swap|cpu-shares|shm-size|pids-limit|tmpfs|add-host|dns|mac-address|cap-add|cap-drop|device|cidfile)=")) then .
          elif ($arg | test("^-[evpwumlh]$")) then {state: "skip_next", image: null}
          elif ($arg | test("^--(network|name|env|volume|workdir|user|entrypoint|label|mount|publish|expose|hostname|domainname|memory|cpus|platform|pull|runtime|security-opt|ulimit|log-driver|log-opt|pid|uts|ipc|cgroupns|restart|stop-signal|stop-timeout|memory-swap|cpu-shares|shm-size|pids-limit|tmpfs|add-host|dns|mac-address|cap-add|cap-drop|device|cidfile)$")) then {state: "skip_next", image: null}
          else .
          end
        elif ($arg | test("^-")) then .
        else {state: "done", image: $arg}
        end
      ) | .image // empty
    ' "$file" 2>/dev/null)"
    while IFS= read -r img; do
      [[ -n "$img" ]] && images+=("$img")
    done <<< "$mcp_images" || true

    # Also extract images from shell-wrapped docker commands
    # (e.g. "command": "sh", "args": ["-c", "... docker run ... image ..."])
    local shell_mcp_images
    shell_mcp_images="$(jq -r '
      (.mcpServers // {}) | to_entries[] |
      select((.value.command // "") | test("^(sh|bash|/bin/sh|/bin/bash)$")) |
      .value.args // [] |
      (index("-c")) as $idx |
      if $idx then .[$idx + 1] // empty else empty end |
      capture("docker\\s+run\\s+(?<rest>.*)") | .rest |
      [split(" ")[] | select(. != "")] |
      reduce .[] as $arg (
        {state: "scanning", image: null};
        if .image != null then .
        elif .state == "skip_next" then .state = "scanning"
        elif ($arg | test("^--?[a-zA-Z]")) then
          if ($arg | test("^--(network|name|env|volume|workdir|user|entrypoint|label|mount|publish|expose|hostname|domainname|memory|cpus|platform|pull|runtime|security-opt|ulimit|log-driver|log-opt|pid|uts|ipc|cgroupns|restart|stop-signal|stop-timeout|memory-swap|cpu-shares|shm-size|pids-limit|tmpfs|add-host|dns|mac-address|cap-add|cap-drop|device|cidfile)=")) then .
          elif ($arg | test("^-[evpwumlh]$")) then {state: "skip_next", image: null}
          elif ($arg | test("^--(network|name|env|volume|workdir|user|entrypoint|label|mount|publish|expose|hostname|domainname|memory|cpus|platform|pull|runtime|security-opt|ulimit|log-driver|log-opt|pid|uts|ipc|cgroupns|restart|stop-signal|stop-timeout|memory-swap|cpu-shares|shm-size|pids-limit|tmpfs|add-host|dns|mac-address|cap-add|cap-drop|device|cidfile)$")) then {state: "skip_next", image: null}
          else .
          end
        elif ($arg | test("^-")) then .
        else {state: "done", image: $arg}
        end
      ) | .image // empty
    ' "$file" 2>/dev/null)"
    while IFS= read -r img; do
      [[ -n "$img" ]] && images+=("$img")
    done <<< "$shell_mcp_images" || true
  }

  # Check per-project MCP configs
  _extract_mcp_docker_images "$STARTDIR/.mcp.json"
  _extract_mcp_docker_images "$STARTDIR/.claude/settings.local.json"

  # Check global Claude Code config
  _extract_mcp_docker_images "$HOME/.claude.json"

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

  local images_json networks_json volume_paths_json
  images_json="$(printf '%s\n' "${unique_images[@]}" | jq -R . | jq -s .)"
  if (( ${#unique_networks[@]} > 0 )); then
    networks_json="$(printf '%s\n' "${unique_networks[@]}" | jq -R . | jq -s .)"
  else
    networks_json="[]"
  fi
  if (( ${#extra_volume_paths[@]} > 0 )); then
    volume_paths_json="$(printf '%s\n' "${extra_volume_paths[@]}" | jq -R . | jq -s .)"
  else
    volume_paths_json="[]"
  fi

  jq -n \
    --arg project_dir "$STARTDIR" \
    --arg compose_project "$compose_project" \
    --argjson images "$images_json" \
    --argjson networks "$networks_json" \
    --arg volume_mount_root "$STARTDIR" \
    --argjson volume_paths "$volume_paths_json" \
    '{
      project_dir: $project_dir,
      compose_project: $compose_project,
      allowed_images: $images,
      allowed_networks: $networks,
      volume_mount_root: $volume_mount_root,
      allowed_volume_paths: $volume_paths
    }' > "$BW_DOCKER_GUARD_CONFIG"
}

# --- Docker guard lifecycle ---
# Start bw-docker-guard proxy. Sets BW_GUARD_PID, BW_GUARD_SOCKET, BW_DOCKER_HOST.
start_docker_guard() {
  if ! command -v bw-docker-guard &>/dev/null; then
    echo "Error: bw-docker-guard not found in PATH" >&2
    echo "Run: cd $(dirname "$(readlink -f "${BASH_SOURCE[0]}")") && go build -o ~/.local/bin/bw-docker-guard ./cmd/bw-docker-guard" >&2
    exit 1
  fi

  BW_GUARD_SOCKET="/tmp/bw-docker-guard-$$.sock"
  BW_GUARD_LOG="/tmp/bw-docker-guard-$$.log"
  bw-docker-guard \
    --config "$BW_DOCKER_GUARD_CONFIG" \
    --socket "$BW_GUARD_SOCKET" \
    --log "$BW_GUARD_LOG" &
  BW_GUARD_PID=$!

  # Wait for socket to appear (up to 1 second)
  local i
  for i in {1..20}; do
    [[ -S "$BW_GUARD_SOCKET" ]] && break
    sleep 0.05
  done

  if [[ ! -S "$BW_GUARD_SOCKET" ]]; then
    echo "Error: bw-docker-guard failed to start" >&2
    [[ -s "$BW_GUARD_LOG" ]] && tail -5 "$BW_GUARD_LOG" >&2
    kill "$BW_GUARD_PID" 2>/dev/null
    exit 1
  fi

  # Verify the guard process is still alive after socket appeared
  if ! kill -0 "$BW_GUARD_PID" 2>/dev/null; then
    echo "Error: bw-docker-guard exited unexpectedly" >&2
    [[ -s "$BW_GUARD_LOG" ]] && tail -5 "$BW_GUARD_LOG" >&2
    rm -f "$BW_GUARD_SOCKET"
    exit 1
  fi

  # Inside the sandbox, the socket is bind-mounted to a fixed path
  BW_DOCKER_HOST="unix:///run/bw-docker-guard.sock"
}

cleanup_docker_guard() {
  [[ -n "${BW_GUARD_PID:-}" ]] && kill "$BW_GUARD_PID" 2>/dev/null
  [[ -n "${BW_GUARD_SOCKET:-}" ]] && rm -f "$BW_GUARD_SOCKET"
  [[ -n "${BW_GUARD_LOG:-}" ]] && rm -f "$BW_GUARD_LOG"
  [[ -n "${BW_DOCKER_GUARD_CONFIG:-}" ]] && rm -f "$BW_DOCKER_GUARD_CONFIG"
}

# --- Docker overlay bind helper ---
# Adds the appropriate Docker socket bind to the OVERLAY_BINDS array.
# Call after parse_bw_flags, passing the OVERLAY_BINDS array name.
add_docker_overlay_bind() {
  local -n _overlay=$1
  if [[ "$BW_FULL_DOCKER" == true ]]; then
    # --full-docker: mount raw Docker socket (unrestricted access)
    _overlay+=("rw /run/docker.sock")
  elif [[ -n "${BW_GUARD_SOCKET:-}" ]]; then
    # Guarded/read-only: bind-mount the guard proxy socket into the sandbox
    _overlay+=("ro $BW_GUARD_SOCKET /run/bw-docker-guard.sock")
  fi
}

# --- Sensitive file deny list ---
# Default basename patterns (glob syntax) to block AI tools from reading/writing.
# Per-project overrides via .bw-deny-files in the project root.
BW_DENY_FILE_DEFAULTS=(
  # Environment files
  ".env"
  ".env.local"
  ".env.*.local"
  ".env.production"
  ".env.development"
  ".env.staging"
  ".env.secret"
  ".envrc"

  # Private keys
  "id_rsa"
  "id_ed25519"
  "id_ecdsa"
  "id_dsa"
  "*.pem"
  "*.key"
  "*.p12"
  "*.pfx"

  # Credentials & secrets
  "credentials.json"
  "service-account*.json"
  ".secrets.json"
  "secrets.json"

  # Auth configs
  ".netrc"
  ".pypirc"
  ".htpasswd"
  ".pgpass"

  # Cloud / infra
  "terraform.tfvars"
  "*.tfvars"
)

# Load deny patterns: merge defaults with per-project .bw-deny-files overrides.
# Writes resolved patterns to a temp file and sets BW_DENY_PATTERNS_FILE.
load_deny_patterns() {
  local -A patterns=()

  # Start with defaults
  for p in "${BW_DENY_FILE_DEFAULTS[@]}"; do
    patterns["$p"]=1
  done

  # Apply per-project overrides
  local override_file="$STARTDIR/.bw-deny-files"
  if [[ -f "$override_file" ]]; then
    local first_line=true
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Strip inline comments and trailing whitespace
      line="${line%%#*}"
      line="${line%"${line##*[![:space:]]}"}"
      [[ -z "$line" ]] && continue

      # !reset clears defaults (must be first non-empty line)
      if [[ "$first_line" == true && "$line" == "!reset" ]]; then
        patterns=()
        first_line=false
        continue
      fi
      first_line=false

      case "$line" in
        -\ *|-[[:space:]]*)
          # Remove pattern
          local pat="${line#-}"
          pat="${pat#"${pat%%[![:space:]]*}"}"
          unset "patterns[$pat]"
          ;;
        +\ *|+[[:space:]]*)
          # Add pattern
          local pat="${line#+}"
          pat="${pat#"${pat%%[![:space:]]*}"}"
          patterns["$pat"]=1
          ;;
        *)
          # Bare line = add
          patterns["$line"]=1
          ;;
      esac
    done < "$override_file"
  fi

  # Write to temp file
  BW_DENY_PATTERNS_FILE="$(mktemp /tmp/bw-deny-patterns-XXXXXX.txt)"
  for p in "${!patterns[@]}"; do
    echo "$p"
  done > "$BW_DENY_PATTERNS_FILE"
}

# --- MCP env var loader ---
# Reads .mcp.json to find ${VAR} references, checks the environment, and
# loads missing vars from .env. Sets BW_MCP_ENV_ARGS with --setenv flags.
load_mcp_env_vars() {
  BW_MCP_ENV_ARGS=()

  local mcp_file="$STARTDIR/.mcp.json"
  [[ -f "$mcp_file" ]] || return 0

  # Extract all ${VAR_NAME} and ${VAR_NAME:-default} references from string values
  local needed_vars
  needed_vars="$(jq -r '.. | strings' "$mcp_file" 2>/dev/null \
    | grep -oP '\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-[^}]*)?\}' \
    | sed 's/\${//;s/:-.*//;s/}//' \
    | sort -u)" || true
  [[ -z "$needed_vars" ]] && return 0

  # Parse .env file into an associative array (only if it exists)
  local -A env_file_vars=()
  local env_file="$STARTDIR/.env"
  if [[ -f "$env_file" ]]; then
    while IFS= read -r line || [[ -n "$line" ]]; do
      # Skip blank lines and comments
      [[ -z "$line" || "$line" =~ ^[[:space:]]*# ]] && continue
      # Strip leading "export "
      line="${line#export }"
      # Split on first =
      local key="${line%%=*}"
      local val="${line#*=}"
      # Validate key
      [[ "$key" =~ ^[A-Za-z_][A-Za-z0-9_]*$ ]] || continue
      # Strip surrounding quotes from value
      if [[ "$val" =~ ^\"(.*)\"$ ]]; then
        val="${BASH_REMATCH[1]}"
      elif [[ "$val" =~ ^\'(.*)\'$ ]]; then
        val="${BASH_REMATCH[1]}"
      fi
      env_file_vars["$key"]="$val"
    done < "$env_file"
  fi

  # Resolve each needed var
  local var
  while IFS= read -r var; do
    [[ -z "$var" ]] && continue
    if [[ -n "${!var:-}" ]]; then
      # Already in environment — pass it through
      BW_MCP_ENV_ARGS+=(--setenv "$var" "${!var}")
    elif [[ -n "${env_file_vars[$var]+set}" ]]; then
      # Found in .env
      BW_MCP_ENV_ARGS+=(--setenv "$var" "${env_file_vars[$var]}")
      echo "[bw] MCP env: loaded $var from .env" >&2
    else
      echo "[bw] ⚠ MCP env: $var not found (not in environment or .env)" >&2
    fi
  done <<< "$needed_vars"
}

# Extended cleanup: docker guard + deny patterns temp file
cleanup_bw() {
  cleanup_docker_guard
  [[ -n "${BW_DENY_PATTERNS_FILE:-}" ]] && rm -f "$BW_DENY_PATTERNS_FILE"
}

# Parse bw-AICode flags from arguments.
# Sets: BW_FULL_DOCKER (bool), BW_DOCKER_HOST (env value), BW_TOOL_ARGS (passthrough),
#       BW_DOCKER_MODE ("guarded"|"readonly"|"full"), BW_GUARD_PID, BW_GUARD_SOCKET,
#       BW_NO_DENY_FILES (bool)
parse_bw_flags() {
  BW_FULL_DOCKER=false
  BW_NO_DENY_FILES=false
  BW_TOOL_ARGS=()
  for arg in "$@"; do
    case "$arg" in
      --full-docker) BW_FULL_DOCKER=true ;;
      --no-deny-files) BW_NO_DENY_FILES=true ;;
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

    echo "[bw] Docker: full (unrestricted socket access)" >&2
  else
    # Derive allowlist from project config and start the guard proxy
    derive_docker_allowlist
    start_docker_guard
    _print_guard_summary
  fi
}

# Print a startup summary of the Docker guard configuration.
_print_guard_summary() {
  local cfg="$BW_DOCKER_GUARD_CONFIG"
  local mode="$BW_DOCKER_MODE"
  local images networks

  if [[ "$mode" == "readonly" ]]; then
    echo "[bw] Docker: read-only (no images allowed)" >&2
    echo "[bw]   log: $BW_GUARD_LOG" >&2
    return
  fi

  images="$(jq -r '.allowed_images[]' "$cfg" 2>/dev/null)"
  networks="$(jq -r '.allowed_networks[]' "$cfg" 2>/dev/null)"

  echo "[bw] Docker: guarded" >&2
  echo "[bw]   log: $BW_GUARD_LOG" >&2
  if [[ -n "$images" ]]; then
    echo "[bw]   images:" >&2
    while IFS= read -r img; do
      echo "[bw]     + $img" >&2
    done <<< "$images"
  fi
  if [[ -n "$networks" ]]; then
    echo "[bw]   networks:" >&2
    while IFS= read -r net; do
      echo "[bw]     + $net" >&2
    done <<< "$networks"
  fi
}
