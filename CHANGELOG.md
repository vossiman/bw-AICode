# Changelog

## v1.0.0

First stable release of bw-AICode — bubblewrap sandbox wrappers with Docker API guard proxy.

### Sandbox features
- Read-only system mounts (`/usr`, `/lib`, `/bin`, `/etc`)
- Current directory as the only writable project area
- Isolated IPC/PID namespaces (user namespace preserved for docker group)
- Tmux socket isolation from host sessions
- Auto-detected local `.venv` activation
- WSL2 Docker Desktop CLI tools support

### Docker guard proxy (`bw-docker-guard`)
- Deny-by-default Docker API filtering via Unix socket proxy
- Three modes: **read-only** (no compose/MCPs found), **guarded** (allowlist derived), **full** (`--full-docker` flag)
- Automatic allowlist derivation from Docker Compose files and MCP server configs
- Container ownership tracking — only session-created containers can be managed
- Seed existing compose project containers (all states) on startup

### Guarded mode security policy
- Image allowlist enforced on container create and image pull
- Network allowlist enforced on network create (names resolved from compose config)
- Volume mounts restricted to project directory + explicitly allowed paths from compose bind mounts
- Docker/Podman socket mounts blocked unless explicitly allowed
- Symlink traversal detection on volume paths
- All builds allowed (security enforced at container-create time)
- Blocked: privileged mode, host namespaces (PID/network/user/IPC/cgroup/UTS), capabilities, devices, VolumesFrom, SecurityOpt
- Relative bind paths resolved against project directory
- Named volumes (Docker-managed) passed through

### Wrapper scripts
- `claude-bw` — Claude Code with `--dangerously-skip-permissions` (safe under bwrap)
- `opencode-bw` — OpenCode with `OPENCODE_PERMISSION=allow`
- `install.sh` — builds binary and symlinks wrappers to `~/.local/bin`
