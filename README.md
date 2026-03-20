# bw-AICode

Bubblewrap (`bwrap`) sandbox wrappers for AI coding tools. Runs Claude Code and OpenCode with restricted filesystem access — only the current directory is writable, everything else is read-only or invisible.

## Sandbox security model

- System directories (`/usr`, `/lib`, `/bin`, `/etc`) mounted **read-only**
- Current directory (pwd) is the **only writable project area**
- Tool-specific config/state dirs mounted read-write as needed
- IPC/PID namespaces isolated (user namespace preserved for docker group)
- Docker API access via `bw-docker-guard` proxy (auto-detects allowed containers from project config)
- Tmux socket isolated from host sessions

## Scripts

| File | Description |
|---|---|
| `claude-bw.sh` | Sandbox wrapper for Claude Code. Runs with `--dangerously-skip-permissions` (safe because bwrap enforces the sandbox). |
| `opencode-bw.sh` | Sandbox wrapper for OpenCode. |
| `bw-common.sh` | Shared library — common bind definitions, Docker allowlist derivation, and builder function. Sourced by the wrapper scripts, not executable. |
| `cmd/bw-docker-guard/` | Go source for the Docker API guard proxy. Built by `install.sh`. |
| `install.sh` | Builds `bw-docker-guard` and symlinks the wrappers into `~/.local/bin`. |

## Install

```bash
git clone <repo-url> bw-AICode
cd bw-AICode
./install.sh
```

This builds `bw-docker-guard` and creates symlinks in `~/.local/bin/`:
- `claude-bw` -> `claude-bw.sh`
- `opencode-bw` -> `opencode-bw.sh`
- `bw-docker-guard` (built binary)

**Dependencies:** `bwrap` (bubblewrap), `go` (1.22+), `jq`, `docker` (optional).

Make sure `~/.local/bin` is in your `PATH`.

## Usage

```bash
cd my-project
claude-bw          # start Claude Code sandboxed
opencode-bw        # start OpenCode sandboxed
```

Run from the project directory you want to work in. Only that directory (and its subdirectories) will be writable inside the sandbox.

### Docker access modes

Docker access is auto-detected from project files. No flags needed for common cases.

| Project has | Docker mode | What works |
|---|---|---|
| No compose file or Docker MCPs | **Read-only** | `docker ps`, `docker inspect` (read-only). All writes blocked. |
| `docker-compose.yml` or Docker-based MCPs | **Guarded** | Full Docker access scoped to project containers and allowed images. Volume mounts restricted to project directory. Dangerous flags blocked. |
| `--full-docker` flag passed | **Unrestricted** | Full Docker access with no restrictions. |

The guarded mode derives its allowlist from:
- Docker Compose files (`docker-compose.yml`, `compose.yml`, etc.)
- MCP server configs (`.mcp.json`, `.claude/settings.local.json`)

See [docs/docker-security.md](docs/docker-security.md) for full details on the security model.

### Full Docker access (unrestricted)

Pass `--full-docker` to bypass the guard proxy entirely:

```bash
claude-bw --full-docker        # full Docker access inside the sandbox
opencode-bw --full-docker      # same for OpenCode
```

This mounts the raw Docker socket into the sandbox. **Warning:** this effectively gives the AI root access on the host via `docker run -v /:/host`. Only use this if you trust the AI tool completely or need Docker features that the guard proxy doesn't support.

## Adding bind mounts

Bind mounts are defined as data tables in `bw-common.sh` (shared) and each wrapper script (tool-specific).

Format: `"mode source [dest]"`

| Mode | Behavior |
|---|---|
| `ro` | Read-only bind. Skipped if source doesn't exist. |
| `rw` | Read-write bind. Skipped if source doesn't exist. |
| `rw!` | Read-write bind. Creates source directory if missing (`mkdir -p`). |
| `rw!PERM` | Read-write bind. Creates source directory + `chmod PERM` (e.g. `rw!700`). |

There are two bind arrays:

- **`BINDS`** / **`COMMON_BINDS`** — Regular binds, placed before `--tmpfs`. For paths outside `/tmp` and `/run`.
- **`OVERLAY_BINDS`** / **`COMMON_OVERLAY_BINDS`** — Overlay binds, placed *after* `--tmpfs /tmp` and `--tmpfs /run` in the bwrap command. Required for paths under `/tmp` or `/run`, since the tmpfs would otherwise hide them.

To add a shared bind, edit `COMMON_BINDS` or `COMMON_OVERLAY_BINDS` in `bw-common.sh`. To add a tool-specific bind, edit the `BINDS` or `OVERLAY_BINDS` array in the relevant wrapper script.
