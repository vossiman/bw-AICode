# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This repo contains two bubblewrap (`bwrap`) sandbox wrapper scripts that run AI coding tools (Claude Code, OpenCode) with restricted filesystem access. The scripts enforce that only `~/local_dev` is writable; everything else is read-only or invisible.

## Files

- **`claude-bw`** — Sandbox wrapper for Claude Code. Runs with `--dangerously-skip-permissions` (safe because bwrap enforces the sandbox). Enables `CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1`.
- **`opencode-bw`** — Sandbox wrapper for OpenCode. Pre-creates OpenCode directories before bwrap since bwrap fails on missing bind sources.

## Sandbox Security Model

Both scripts share the same pattern:
1. Enforce `pwd` is within `~/local_dev`
2. Mount system dirs (`/usr`, `/lib`, `/bin`, `/etc`) **read-only**
3. Mount `~/local_dev` as the **only writable project area**
4. Mount tool-specific config/state dirs read-write (e.g., `~/.claude`, `~/.config/opencode`)
5. Isolate IPC/PID namespaces but **not** user namespace (preserves docker group membership)
6. Bind Docker socket and tmux socket for container and multiplexer access

## Editing Guidelines

- These are `bash` scripts using `set -euo pipefail` — maintain strict error handling.
- When adding new bind mounts, decide read-only (`--ro-bind`) vs read-write (`--bind`) based on whether the tool needs to write there.
- If a bind source directory might not exist, `mkdir -p` it before the `bwrap` call (see `opencode-bw` for the pattern).
- Both scripts use `exec bwrap` — the shell process is replaced, so nothing runs after the bwrap invocation.
