# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repo contains three bubblewrap (`bwrap`) sandbox wrapper scripts that run AI coding tools (Claude Code, OpenCode, pi) with restricted filesystem access. The scripts enforce that only the current directory (where you launch the wrapper) is writable; everything else is read-only or invisible.

## Files

- **`claude-bw`** — Sandbox wrapper for Claude Code. Runs with `--dangerously-skip-permissions` (safe because bwrap enforces the sandbox). Enables `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`.
- **`opencode-bw`** — Sandbox wrapper for OpenCode. Pre-creates OpenCode directories before bwrap since bwrap fails on missing bind sources.
- **`pi-bw`** — Sandbox wrapper for the pi coding agent. Binds `~/.nvm` (pi's install location) read-only and resolves symlinks under `~/.pi/agent/` (recursively, up to 3 levels deep) to extra read-only binds via `resolve_symlink_binds` in `bw-common.sh` (regular-file targets only, deduplicated; `/`, `$HOME` and its ancestors excluded).
- **`bw-common.sh`** — Shared library: bind definitions, `build_bwrap_args()`, Docker allowlist derivation, guard proxy lifecycle, sensitive file deny patterns.
- **`hooks/bw-deny-files.sh`** — Claude Code `PreToolUse` hook that blocks access to sensitive files. Installed to `~/.claude/hooks/` by `install.sh`.
- **`hooks/bw-deny-files.ts`** — pi extension enforcing the same deny patterns via a `tool_call` handler. Installed to `~/.pi/agent/extensions/` by `install.sh`; unit tests run with `node --test hooks/bw-deny-files.test.ts`.
- **`cmd/bw-docker-guard/`** — Go source for the Docker API guard proxy. Inspects and filters Docker API requests against a derived allowlist.

## Sandbox Security Model

Both scripts share the same pattern:
1. Mount system dirs (`/usr`, `/lib`, `/bin`, `/etc`) **read-only**
2. Mount the current directory as the **only writable project area**
4. Mount tool-specific config/state dirs read-write (e.g., `~/.claude`, `~/.config/opencode`)
5. Isolate IPC/PID namespaces but **not** user namespace (preserves docker group membership)
6. Docker API via `bw-docker-guard` proxy — auto-derives allowlist from project config (compose files, MCP configs). Raw socket only mounted with `--full-docker`.
7. Sensitive file deny hooks block AI tools from reading/writing `.env`, private keys, credentials, etc. Per-project overrides via `.bw-deny-files`. Disabled with `--no-deny-files`.
8. Tmux socket isolated from host sessions via separate `TMUX_TMPDIR`

## Editing Guidelines

- These are `bash` scripts using `set -euo pipefail` — maintain strict error handling.
- When adding new bind mounts, decide read-only (`--ro-bind`) vs read-write (`--bind`) based on whether the tool needs to write there.
- If a bind source directory might not exist, use `rw!` mode so `build_bwrap_args` creates it. Use `rw!PERM` (e.g. `rw!700`) to also set permissions.
- Binds targeting paths under `/tmp` or `/run` must go in the `OVERLAY_BINDS` array (placed after `--tmpfs` in the bwrap command), not `BINDS`.
- When resources need cleanup (guard proxy or deny patterns temp file), scripts use foreground `bwrap` (not `exec`) so the `cleanup_bw` trap can fire. Otherwise `exec bwrap` is used.
- The Go proxy code is in `internal/` packages. Run `go test ./...` to verify changes.

## WSL2 Notes

- WSL2 appends the entire Windows PATH by default (`appendWindowsPath = true`), which puts `/mnt/c/Program Files/nodejs/` and other Windows binaries in the Linux PATH. This causes `npm install -g` to install packages on the Windows side, where they're invisible inside the bwrap sandbox (which doesn't mount `/mnt/c`). Fix: set `appendWindowsPath = false` in `/etc/wsl.conf` under `[interop]`, then `wsl --shutdown` from PowerShell. Ensure MCP server packages (`firecrawl-mcp`, `@brave/brave-search-mcp-server`, etc.) are installed via the Linux-side npm.

## Testing

- **OpenCode MCP connectivity**: `opencode-bw mcp list --print-logs --log-level DEBUG` — shows per-server connection status, stderr from MCP processes, and detailed error messages. This is the primary way to diagnose MCP failures inside the sandbox.
