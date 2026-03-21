# bw-AICode

Bubblewrap (`bwrap`) sandbox wrappers for AI coding tools. Runs Claude Code and OpenCode with restricted filesystem access — only `~/local_dev` is writable, everything else is read-only or invisible.

## Sandbox security model

- System directories (`/usr`, `/lib`, `/bin`, `/etc`) mounted **read-only**
- `~/local_dev` is the **only writable project area**
- Tool-specific config/state dirs mounted read-write as needed
- IPC/PID namespaces isolated (user namespace preserved for docker group)
- Docker API access via `bw-docker-guard` proxy (auto-detects allowed containers from project config)
- Sensitive file deny hooks block AI tools from reading/writing `.env`, private keys, credentials, etc.
- Tmux socket isolated from host sessions

## Scripts

| File | Description |
|---|---|
| `claude-bw.sh` | Sandbox wrapper for Claude Code. Runs with `--dangerously-skip-permissions` (safe because bwrap enforces the sandbox). |
| `opencode-bw.sh` | Sandbox wrapper for OpenCode. |
| `bw-common.sh` | Shared library — common bind definitions, Docker allowlist derivation, and builder function. Sourced by the wrapper scripts, not executable. |
| `cmd/bw-docker-guard/` | Go source for the Docker API guard proxy. Built by `install.sh`. |
| `hooks/bw-deny-files.sh` | Claude Code `PreToolUse` hook — blocks access to sensitive files inside the sandbox. |
| `install.sh` | Builds `bw-docker-guard`, installs hooks, and symlinks the wrappers into `~/.local/bin`. |

## Install

```bash
git clone <repo-url> ~/local_dev/bw-AICode
cd ~/local_dev/bw-AICode
./install.sh
```

This builds `bw-docker-guard`, installs the deny-files hook, and creates symlinks in `~/.local/bin/`:
- `claude-bw` -> `claude-bw.sh`
- `opencode-bw` -> `opencode-bw.sh`
- `bw-docker-guard` (built binary)
- `~/.claude/hooks/bw-deny-files.sh` (Claude Code hook)
- `PreToolUse` hook registered in `~/.claude/settings.json`

**Dependencies:** `bwrap` (bubblewrap), `go` (1.22+), `jq`, `docker` (optional).

Make sure `~/.local/bin` is in your `PATH`.

## Usage

```bash
cd ~/local_dev/my-project
claude-bw          # start Claude Code sandboxed
opencode-bw        # start OpenCode sandboxed
```

Must be run from within `~/local_dev` or a subdirectory.

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

## Sensitive file deny list

Even inside the writable `~/local_dev` area, the sandbox blocks AI tools from reading or writing sensitive files. This is a defense-in-depth layer on top of the filesystem sandbox.

**Default denied patterns:**

| Category | Patterns |
|---|---|
| Environment files | `.env`, `.env.local`, `.env.*.local`, `.env.production`, `.env.development`, `.env.staging`, `.env.secret`, `.envrc` |
| Private keys | `id_rsa`, `id_ed25519`, `id_ecdsa`, `id_dsa`, `*.pem`, `*.key`, `*.p12`, `*.pfx` |
| Credentials | `credentials.json`, `service-account*.json`, `.secrets.json`, `secrets.json` |
| Auth configs | `.netrc`, `.pypirc`, `.htpasswd`, `.pgpass` |
| Cloud / infra | `terraform.tfvars`, `*.tfvars` |

**How it works:**
- **Claude Code:** A `PreToolUse` hook intercepts Read, Edit, Write, Bash, and Grep tool calls. Matches file paths (and Bash command arguments) against the deny list.
- **OpenCode:** Permission rules are injected via `OPENCODE_PERMISSION` with per-pattern `read`/`edit` denials.

### Per-project overrides

Create a `.bw-deny-files` file in your project root to add or remove patterns:

```bash
# Add custom patterns
+ vault-token
+ *.credentials

# Remove a default (e.g., you need direnv)
- .envrc

# Use !reset as the first line to clear ALL defaults
# !reset
# + only-this-one
```

Lines starting with `+` add patterns, `-` removes patterns, bare lines add. Comments with `#`.

### Disabling the deny list

Pass `--no-deny-files` to bypass the deny list entirely:

```bash
claude-bw --no-deny-files
opencode-bw --no-deny-files
```

### Limitations

- **Bash bypass is partial** — common commands (`cat`, `head`, `tail`, `grep`, `sed`, etc.) and redirections (`< file`, `> file`) are caught, but exotic constructs (`python -c "open('.env').read()"`, `base64 .env`) are not. The bwrap sandbox is the primary security boundary; deny hooks are defense-in-depth.
- **Basename matching only** — a pattern like `.env` blocks all files named `.env` anywhere in the project tree. Path-specific rules are not supported.
- **Grep on directories** — grepping a directory that contains a denied file is not blocked (only direct grep on a denied file is caught).

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
