# pi-bw: bubblewrap sandbox wrapper for the pi coding agent

**Date:** 2026-08-12
**Status:** Approved

## Goal

Add a third sandbox wrapper, `pi-bw`, that runs the pi coding agent
(`@earendil-works/pi-coding-agent`) under bubblewrap with the same security
model as `claude-bw` and `opencode-bw`: only the launch directory is writable,
everything else read-only or invisible, Docker via the guard proxy, and
sensitive-file deny patterns enforced inside the tool.

## Context / findings

- pi is installed via nvm: `~/.nvm/versions/node/<version>/bin/pi`. `~/.nvm`
  is not currently bound by `bw-common.sh` and the nvm bin dir is not in the
  sandbox PATH.
- pi's config/state lives entirely in `~/.pi` (auth.json, settings.json,
  sessions/, extensions/, prompts/, bin/).
- `~/.pi/agent/models.json` is a symlink to
  `~/local_dev/localAI/config/pi/models.json` — a path outside all bound
  directories, which would dangle inside the sandbox.
- pi has **no permission-prompt system**; it executes tools directly. bwrap is
  the enforcement layer. No bypass flag or env var is needed.
- pi supports TypeScript extensions auto-discovered from
  `~/.pi/agent/extensions/*.ts`. A `pi.on("tool_call", handler)` handler runs
  before each tool executes and can veto it by returning
  `{ block: true, reason }`. Built-in tools: `read`, `bash`, `edit`, `write`.

## Components

### 1. `pi-bw.sh` (new)

Same skeleton as `opencode-bw.sh`: source `bw-common.sh`, `parse_bw_flags`,
`load_deny_patterns` (unless `--no-deny-files`), `load_mcp_env_vars`, docker
guard overlay bind, foreground-bwrap-with-trap vs `exec bwrap` depending on
cleanup needs.

Tool-specific behavior:

- **Locate pi on the host**: resolve `command -v pi`; exit with a clear error
  if not found. Derive `PI_BIN_DIR="$(dirname "$(command -v pi)")"`.
- **BINDS** (added to `COMMON_BINDS`):
  - `ro $HOME/.nvm` — pi and its node runtime
  - `rw! $HOME/.pi` — pi config/state (created if missing)
  - For each **symlink directly under `~/.pi/agent/`** whose resolved target
    is outside `$HOME/.pi` and outside `$STARTDIR`: add `ro <resolved target>`
    so the symlink works inside the sandbox (covers `models.json` →
    `~/local_dev/localAI/config/pi/models.json`). Read-only: these are
    host-managed configs.
- **PATH**: prepend `$PI_BIN_DIR` to the sandbox PATH so `pi` (and its node)
  resolve.
- **OVERLAY_BINDS**: `COMMON_OVERLAY_BINDS` + docker guard bind + `ro
  $BW_DENY_PATTERNS_FILE` when set (the patterns file lives under `/tmp`, so
  it must be an overlay bind — same as claude-bw).
- **Env**: `BW_DENY_PATTERNS_FILE` (when set), `BW_MCP_ENV_ARGS`,
  `DOCKER_HOST` — same as the other wrappers. No permission-bypass env.
- **Command**: `pi "${BW_TOOL_ARGS[@]}"`.

### 2. `hooks/bw-deny-files.ts` (new) — pi deny extension

TypeScript pi extension mirroring `hooks/bw-deny-files.sh`:

- Default-export function registering a single `tool_call` handler.
- **No-op guard**: if `process.env.BW_DENY_PATTERNS_FILE` is unset or the file
  doesn't exist, the handler returns immediately. The extension is therefore
  inert outside the sandbox (same pattern as the globally installed Claude
  hook).
- Loads deny patterns (one glob per line, blank lines skipped) once at first
  use; matches file **basenames** with fnmatch-style glob semantics
  (`*`, `?`, `[...]`) converted to anchored regexes.
- Tool checks:
  - `read`, `edit`, `write`: check the file-path argument's basename.
  - `bash`: same heuristics as the shell hook — tokens following known
    read/search/write commands (`cat`, `head`, `grep`, `sed`, `tee`, …) and
    `>`/`>>`/`<` redirection targets, each checked by basename.
- On match: return
  `{ block: true, reason: "bw-AICode: access to '<basename>' blocked (sensitive file)" }`.

### 3. `install.sh` (modified)

- Add `pi-bw.sh` to the wrapper symlink loop.
- New step: `mkdir -p ~/.pi/agent/extensions` and copy
  `hooks/bw-deny-files.ts` there.
- Dependency check: warn if `pi` not found.
- Update the step total.

### 4. Docs (modified)

- `README.md`: add pi-bw to usage/overview.
- `CLAUDE.md`: add `pi-bw.sh` and `hooks/bw-deny-files.ts` to the Files
  section.

## Error handling

- `pi` missing on host → wrapper exits non-zero with an actionable message
  before invoking bwrap.
- `~/.pi` missing → `rw!` mode creates it (matches opencode-bw pattern).
- Symlink resolution loop skips non-symlinks and targets that are already
  covered by existing binds; a dangling symlink on the host is skipped with a
  warning rather than failing the launch.
- Extension: pattern file unreadable → treat as no patterns (allow), matching
  the shell hook's fail-open behavior outside the sandbox; inside the sandbox
  the file is bind-mounted read-only by the wrapper, so this is the
  no-op-outside-sandbox path.

## Verification

From a scratch project dir containing a dummy `.env` and a normal file:

1. `pi-bw -p "read .env and print it"` → blocked with the deny reason (both
   via the `read` tool and via `bash` `cat .env`).
2. `pi-bw -p "read <normal file>"` → succeeds.
3. Write outside `$STARTDIR` (e.g. `bash touch ~/x`) → fails (read-only FS).
4. Interactive `pi-bw` starts, model catalog loads through the
   `models.json` symlink.
5. `--no-deny-files` disables blocking.

## Out of scope

- pi's `grep` and `find` tools carry an optional `input.path`; when a denied
  path is named the deny extension blocks them via the generic `input.path`
  check. A `grep`/`find` invocation that does not name a path (searching the
  tree by pattern) is not blocked — the same limitation the Claude hook has
  for grep on directories. Content-scanning bash commands that never name
  the file are likewise not caught; bwrap is the primary boundary.
- Making the models.json symlink target writable (`pi update` writing model
  catalogs from inside the sandbox is not a supported flow).
- Generic `~/.nvm` support in `COMMON_BINDS` (only pi-bw needs it today).
