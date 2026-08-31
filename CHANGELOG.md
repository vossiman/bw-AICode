# Changelog

## Unreleased

### Security: CAF-001 guard rewrite

An audit (CAF-001) found a three-step host escape built entirely from
caller-chosen names: an image name claiming to be infrastructure, a
compose-harvested bind path, and a `buildx_buildkit_`-prefixed container
name. The guard now grants privilege only from facts the host resolves,
never facts the caller supplies. Behaviour changes an operator will notice:

- **Untagged `docker build` is now denied**, and every `-t` tag on a build
  must be in the allowlist. Previously all builds were allowed
  unconditionally.
- **`docker load` / `POST /images/load` is now denied in every mode**
  (including guarded mode). A loaded tar's own repo-tags can't be checked
  without unpacking the stream, so it was an unconstrained way to mint an
  image name. Use `--full-docker` if you need it.
- Infrastructure images (buildkit, etc.) are now matched by content
  **digest**, resolved host-side at session start, not by name — and a
  digest match relaxes only `Privileged`, not the rest of `HostConfig`.
- Bind mount paths outside the project directory are no longer harvested
  from the project's own `docker-compose.yml`; they come only from the
  operator's `BW_EXTRA_VOLUME_PATHS` environment variable.
- Container ownership for pre-existing infrastructure containers is seeded
  from a host-side `docker ps` snapshot, not recognised by a
  `buildx_buildkit_` name prefix a caller could reproduce.
- Mount `Type` is now default-deny (only a validated `bind` and a harmless
  `tmpfs` pass); reads are now deny-by-default with ownership enforced on
  per-container reads (`logs`, `stats`, `archive`, `changes`, `top`,
  `export`), matching the write path.

See `docs/docker-security.md` for the full accounting, including the
residuals that remain open (named-volume binds, host-wide volume-name
visibility, `/events` verbosity, name-based image allowlisting, socket
denial not covering ancestor directories, and validate-time-vs-daemon-time
TOCTOU on symlinks).

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
