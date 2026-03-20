# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repo contains two bubblewrap (`bwrap`) sandbox wrapper scripts that run AI coding tools (Claude Code, OpenCode) with restricted filesystem access. The scripts enforce that only the current directory (where you launch the wrapper) is writable; everything else is read-only or invisible.

## Files

- **`claude-bw`** — Sandbox wrapper for Claude Code. Runs with `--dangerously-skip-permissions` (safe because bwrap enforces the sandbox). Enables `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`.
- **`opencode-bw`** — Sandbox wrapper for OpenCode. Pre-creates OpenCode directories before bwrap since bwrap fails on missing bind sources.
- **`bw-common.sh`** — Shared library: bind definitions, `build_bwrap_args()`, Docker allowlist derivation, guard proxy lifecycle.
- **`cmd/bw-docker-guard/`** — Go source for the Docker API guard proxy. Inspects and filters Docker API requests against a derived allowlist.

## Sandbox Security Model

Both scripts share the same pattern:
1. Mount system dirs (`/usr`, `/lib`, `/bin`, `/etc`) **read-only**
2. Mount the current directory as the **only writable project area**
4. Mount tool-specific config/state dirs read-write (e.g., `~/.claude`, `~/.config/opencode`)
5. Isolate IPC/PID namespaces but **not** user namespace (preserves docker group membership)
6. Docker API via `bw-docker-guard` proxy — auto-derives allowlist from project config (compose files, MCP configs). Raw socket only mounted with `--full-docker`.
7. Tmux socket isolated from host sessions via separate `TMUX_TMPDIR`

## Editing Guidelines

- These are `bash` scripts using `set -euo pipefail` — maintain strict error handling.
- When adding new bind mounts, decide read-only (`--ro-bind`) vs read-write (`--bind`) based on whether the tool needs to write there.
- If a bind source directory might not exist, use `rw!` mode so `build_bwrap_args` creates it. Use `rw!PERM` (e.g. `rw!700`) to also set permissions.
- Binds targeting paths under `/tmp` or `/run` must go in the `OVERLAY_BINDS` array (placed after `--tmpfs` in the bwrap command), not `BINDS`.
- When the guard proxy is running, scripts use foreground `bwrap` (not `exec`) so the cleanup trap can fire. With `--full-docker`, `exec bwrap` is used as before.
- The Go proxy code is in `internal/` packages. Run `go test ./...` to verify changes.
