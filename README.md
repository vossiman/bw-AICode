# bw-AICode

Bubblewrap (`bwrap`) sandbox wrappers for AI coding tools. Runs Claude Code and OpenCode with restricted filesystem access — only `~/local_dev` is writable, everything else is read-only or invisible.

## Sandbox security model

- System directories (`/usr`, `/lib`, `/bin`, `/etc`) mounted **read-only**
- `~/local_dev` is the **only writable project area**
- Tool-specific config/state dirs mounted read-write as needed
- IPC/PID namespaces isolated (user namespace preserved for docker group)
- Docker API access via read-only socket proxy (blocks container creation, only allows inspection)
- Tmux socket isolated from host sessions

## Scripts

| File | Description |
|---|---|
| `claude-bw.sh` | Sandbox wrapper for Claude Code. Runs with `--dangerously-skip-permissions` (safe because bwrap enforces the sandbox). |
| `opencode-bw.sh` | Sandbox wrapper for OpenCode. |
| `bw-common.sh` | Shared library — common bind definitions and builder function. Sourced by the wrapper scripts, not executable. |
| `bw-docker-proxy.sh` | Start/stop the Docker socket proxy. Passes arguments through to `docker compose`. |
| `install.sh` | Symlinks the wrappers into `~/.local/bin` as `claude-bw`, `opencode-bw`, and `bw-docker-proxy`. |

## Install

```bash
git clone <repo-url> ~/local_dev/bw-AICode
cd ~/local_dev/bw-AICode
./install.sh
```

This creates symlinks in `~/.local/bin/`:
- `claude-bw` -> `claude-bw.sh`
- `opencode-bw` -> `opencode-bw.sh`
- `bw-docker-proxy` -> `bw-docker-proxy.sh`

Make sure `~/.local/bin` is in your `PATH`.

## Usage

Start the Docker socket proxy (one-time, stays running):

```bash
bw-docker-proxy up -d
```

Then use the sandbox wrappers:

```bash
cd ~/local_dev/my-project
claude-bw          # start Claude Code sandboxed
opencode-bw        # start OpenCode sandboxed
```

Must be run from within `~/local_dev` or a subdirectory.

The socket proxy makes Docker read-only inside the sandbox — `docker ps` and `docker inspect` work, but `docker run` and `docker build` are blocked.

### Full Docker access

Pass `--full-docker` to mount the real Docker socket instead of using the read-only proxy:

```bash
claude-bw --full-docker        # full Docker access inside the sandbox
opencode-bw --full-docker      # same for OpenCode
```

This sets `DOCKER_HOST=unix:///var/run/docker.sock` and bind-mounts `/run/docker.sock` into the sandbox, enabling `docker run`, `docker build`, etc. The flag is consumed by the wrapper — all other arguments are passed through to the tool.

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
