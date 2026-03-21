# Research Findings: Claude Code Hooks API, OpenCode Comparison & Improvement Opportunities

## Context

Evaluated [shanraisshan/claude-code-hooks](https://github.com/shanraisshan/claude-code-hooks) (179 stars) — a comprehensive reference/demo covering all 23 Claude Code hooks. Then performed deep research into OpenCode's hook/event system to map what can and cannot be done in OpenCode vs Claude Code. This document captures findings relevant to bw-AICode and identifies concrete improvement opportunities.

---

## Part 1: Hooks API Findings

### All 23 Hook Events (as of Claude Code v2.1.78)

| # | Hook | When it fires | Matcher field |
|:-:|------|---------------|---------------|
| 1 | `PreToolUse` | Before tool calls (can block) | `tool_name` |
| 2 | `PermissionRequest` | When Claude requests user permission | `tool_name` |
| 3 | `PostToolUse` | After successful tool calls | `tool_name` |
| 4 | `PostToolUseFailure` | After failed tool calls | `tool_name` |
| 5 | `UserPromptSubmit` | When user submits prompt, before processing | — (always fires) |
| 6 | `Notification` | When Claude sends notifications | `notification_type` |
| 7 | `Stop` | When Claude finishes responding | — (always fires) |
| 8 | `SubagentStart` | When subagent tasks start | `agent_type` |
| 9 | `SubagentStop` | When subagent tasks complete | `agent_type` |
| 10 | `PreCompact` | Before compact operation | `trigger` |
| 11 | `PostCompact` | After compact operation | `trigger` |
| 12 | `SessionStart` | Session start or resume | `source` |
| 13 | `SessionEnd` | Session ends | `reason` |
| 14 | `Setup` | On `/setup` command | — (always fires) |
| 15 | `TeammateIdle` | Teammate agent becomes idle | — (always fires) |
| 16 | `TaskCompleted` | Background task completes | — (always fires) |
| 17 | `ConfigChange` | Config file changes during session | `source` |
| 18 | `WorktreeCreate` | Worktree created | — (always fires) |
| 19 | `WorktreeRemove` | Worktree removed | — (always fires) |
| 20 | `InstructionsLoaded` | CLAUDE.md/rules loaded | `load_reason` |
| 21 | `Elicitation` | MCP server requests user input | `mcp_server_name` |
| 22 | `ElicitationResult` | User responds to MCP elicitation | `mcp_server_name` |
| 23 | `StopFailure` | Turn ends due to API error | `error` |

### 4 Hook Types

| Type | Description | Use case |
|------|-------------|----------|
| `command` | Runs shell command, JSON via stdin | What bw-AICode uses — deterministic rules |
| `prompt` | Single-turn Claude evaluation | Judgment-based decisions |
| `agent` | Multi-turn subagent with tool access | Complex verification (read files, run tests) |
| `http` | POST to URL (since v2.1.63) | External service integration |

### Decision Control Patterns (per hook)

| Hook | Control method | Values |
|------|---------------|--------|
| `PreToolUse` | `hookSpecificOutput.permissionDecision` | `allow`, `deny`, `ask` |
| `PreToolUse` | `hookSpecificOutput.autoAllow` | `true` — auto-approve future uses (v2.0.76) |
| `PermissionRequest` | `hookSpecificOutput.decision.behavior` | `allow`, `deny` |
| `PostToolUse` / `Stop` / etc. | Top-level `decision` | `block` |
| `UserPromptSubmit` | Modified `prompt` field via stdout | Returns transformed prompt |
| All hooks | `continue: false` + `stopReason` | Stops Claude entirely |
| All hooks | `additionalContext` | Injects context into conversation |
| All hooks | `systemMessage` | Warning shown to user |

### Undocumented / Lesser-Known Features

- **`asyncRewake`** (v2.1.72): Hook runs async but wakes model on exit code 2 (blocking error)
- **`autoAllow`** (v2.0.76): PreToolUse can auto-approve future uses of a tool for the session
- **`once: true`**: Hook fires only once per session (useful for SessionStart, PreCompact)
- **Agent frontmatter hooks**: Only 6 of 23 hooks fire in agent context: `PreToolUse`, `PostToolUse`, `PermissionRequest`, `PostToolUseFailure`, `Stop`, `SubagentStop`
- **`${CLAUDE_SKILL_DIR}`** (v2.1.69): Env var for skill's own directory
- **`${CLAUDE_PLUGIN_DATA}`** (v2.1.78): Plugin's persistent data directory
- **Hook deduplication**: Identical handlers in multiple settings locations run only once

### Common stdin JSON Fields (all hooks)

```
hook_event_name, session_id, transcript_path, cwd, permission_mode, agent_id, agent_type
```

### Valid `tool_name` Matcher Values

`Bash`, `Read`, `Edit`, `Write`, `Glob`, `Grep`, `Agent`, `WebFetch`, `WebSearch`, `mcp__<server>__<tool>` — full regex supported.

---

## Part 2: bw-AICode Current State

### What we already have

- **`PreToolUse` hook** (`hooks/bw-deny-files.sh`): Blocks access to sensitive files (.env, private keys, credentials, etc.)
- **Matcher**: `Read|Edit|Write|Bash|Grep` — correct regex against `tool_name`
- **Decision format**: `hookSpecificOutput.permissionDecision: "deny"` — confirmed as the current (non-deprecated) API
- **Per-project overrides**: `.bw-deny-files` with `+`/`-`/`!reset` syntax
- **Install script**: Registers hook in `~/.claude/settings.json` (user-level)
- **Bash command parsing**: Catches `cat`, `grep`, `rg`, redirections, etc. for denied files

### What we're missing

- No observability — denials are silent (no logging, no audit trail)
- No post-execution monitoring
- No session lifecycle hooks
- No hook configuration toggle system
- Bash parsing doesn't cover `Glob` tool (could reveal filenames of sensitive files)

---

## Part 3: Improvement Opportunities

### 1. Audit Logging for Deny Events (High value, low effort)

**Problem**: When `bw-deny-files.sh` blocks a file access, there's no record of it. No way to know what was attempted or how often.

**Solution**: Add JSONL logging to `bw-deny-files.sh` when a deny decision is made.

```bash
# Log to $BW_DENY_LOG_FILE (set by wrapper alongside BW_DENY_PATTERNS_FILE)
log_entry='{"ts":"'"$(date -Iseconds)"'","tool":"'"$TOOL_NAME"'","file":"'"$blocked_file"'","pattern":"'"$matched_pattern"'"}'
echo "$log_entry" >> "$BW_DENY_LOG_FILE"
```

**Where**: `hooks/bw-deny-files.sh` — add logging at each deny exit point.
**Files**: `hooks/bw-deny-files.sh`, `bw-common.sh` (set log path env var), `claude-bw` (bind log file into sandbox).

### 2. Add `Glob` to Hook Matcher (High value, low effort)

**Problem**: Current matcher is `Read|Edit|Write|Bash|Grep`. The `Glob` tool can reveal filenames matching sensitive patterns (e.g., `glob("**/.env*")` would list all .env files). Glob doesn't read contents, but exposes file existence/paths.

**Solution**: Add `Glob` to the matcher and check the `pattern` field from `tool_input` against deny patterns.

**Where**: `hooks/bw-deny-files.sh` (add Glob case), `install.sh` (update matcher regex).

### 3. `additionalContext` for Sandbox Awareness (Medium value, low effort)

**Problem**: Claude doesn't inherently know it's running in a sandbox. It may try operations that will fail (writing outside project dir, accessing system files read-write).

**Solution**: Use `SessionStart` hook or `UserPromptSubmit` hook to inject sandbox context via the `additionalContext` return field:

```json
{
  "additionalContext": "You are running inside a bwrap sandbox. Only the project directory is writable. Sensitive files (.env, keys, credentials) are blocked by deny hooks."
}
```

**Where**: New hook script or extend existing. Register in `settings.json` with `SessionStart` + `once: true`.

### 4. Hook Configuration Toggles (Medium value, medium effort)

**Problem**: Currently the only way to disable deny hooks is `--no-deny-files` CLI flag. No per-hook granularity, no persistent config.

**Solution**: Adopt the `hooks-config.json` + `hooks-config.local.json` pattern from claude-code-hooks. Would allow:
- Disabling audit logging without disabling denials
- Per-user overrides (`.local.json` is gitignored)
- Future extensibility for additional hooks

**Where**: New `hooks/config/` directory, read in `bw-deny-files.sh`.

### 5. `PostToolUse` Monitoring Hook (Lower value, medium effort)

**Problem**: No visibility into what tools execute inside the sandbox after they complete.

**Solution**: Add a `PostToolUse` hook that logs tool executions for audit purposes. Especially useful for `Bash` commands — log what commands ran, whether they succeeded, etc.

**Where**: New hook script, register in `install.sh`.

### 6. `StopFailure` / `SessionEnd` Cleanup Hook (Lower value, low effort)

**Problem**: If Claude's session ends abnormally (API error, rate limit), the sandbox cleanup trap may not fire predictably.

**Solution**: Register `StopFailure` and `SessionEnd` hooks as backup cleanup triggers, ensuring temp files (deny patterns, guard proxy) are cleaned up.

**Where**: Small addition to `install.sh`, potentially reuse existing `cleanup_bw` logic.

---

## Priority Ranking

| # | Improvement | Value | Effort | Recommendation |
|:-:|-------------|-------|--------|----------------|
| 1 | Audit logging for denials | High | Low | Do first — adds observability with minimal changes |
| 2 | Add `Glob` to matcher | High | Low | Quick security gap fix |
| 3 | Sandbox context injection | Medium | Low | Nice UX improvement, reduces wasted tool calls |
| 4 | Hook config toggles | Medium | Medium | Good for multi-user setups, future extensibility |
| 5 | PostToolUse monitoring | Lower | Medium | Useful for compliance-heavy environments |
| 6 | StopFailure/SessionEnd cleanup | Lower | Low | Defensive improvement, edge case |

---

## Part 4: OpenCode Hook/Event System — Deep Research

### Key Finding: OpenCode is Archived

OpenCode (github.com/opencode-ai/opencode) is now **archived**. Its successor is **Crush** (github.com/charmbracelet/crush, 21.7k stars), built by the same original author and the Charm team. Findings cover both.

### OpenCode Has NO User-Configurable Hook System

**There is no hooks API.** Period.

- **Issue #282** ("Add support for Hooks") was opened 2025-07-01 and remains open with 0 comments, no implementation.
- OpenCode's config schema (`opencode-schema.json`) has these top-level keys: `agents`, `contextPaths`, `data`, `debug`, `debugLSP`, `lsp`, `mcpServers`, `providers`, `tui`, `wd` — **no `hooks` key**.
- OpenCode has an internal pub/sub system (`internal/pubsub/`) with generic `CreatedEvent`, `UpdatedEvent`, `DeletedEvent` types — but these are purely internal, not exposed to users.
- **Crush** also has **no user-configurable hooks**. Its `internal/event/` package is purely PostHog telemetry analytics (`app initialized`, `prompt sent`, `tokens used`, etc.), not extensible by users.

### OpenCode's Permission System

OpenCode uses an **interactive TUI permission dialog** — its only access control mechanism.

**Permission service** (`internal/permission/permission.go`):
- `Request()` → blocks until user responds via TUI dialog
- Three user choices: **Allow** (once), **Allow for session** (persistent per tool+action+session+path), **Deny**
- Non-interactive mode (`-p` flag): `AutoApproveSession()` auto-approves all permissions
- No scriptable/programmable deny logic, no file-pattern matching

**Tools requiring permission in OpenCode:**
| Tool | Permission? | Notes |
|------|:-----------:|-------|
| `bash` | Yes | Except safe read-only commands (`ls`, `git status`, `git log`, etc.) |
| `edit` | Yes | create, delete, replace |
| `write` | Yes | |
| `patch` | Yes | per file: create/update/delete |
| `fetch` | Yes | |
| MCP tools | Yes | all MCP tool calls |
| `view` | **No** | read-only |
| `glob` | **No** | |
| `grep` | **No** | |
| `ls` | **No** | |
| `sourcegraph` | **No** | |
| `diagnostics` | **No** | |

**Crush enhancements:**
- Added `permissions.allowed_tools` config: a list of `"toolname"` or `"toolname:action"` strings that auto-approve without prompting (an **allowlist**, not a denylist)
- Added `SetSkipRequests(bool)` for YOLO mode (`-y` flag)
- Added `options.disabled_tools`: disable/hide tools from agent entirely
- Added `options.skills_paths`: paths to "Agent Skills" (folders with `SKILL.md` per agentskills.io spec)
- Still **no hooks configuration**

### CRITICAL: `OPENCODE_PERMISSION` Env Var is NOT Consumed by OpenCode

**bw-AICode's `opencode-bw.sh` sets `--setenv OPENCODE_PERMISSION "$OPENCODE_PERMISSION_JSON"` inside the sandbox.** However, searching every `.go` file in the OpenCode repository confirms that `OPENCODE_PERMISSION` does **not appear anywhere in OpenCode's source code**.

This means:
- The deny pattern JSON (`{"read": {"**/.env": "deny", ...}, "edit": {...}, "*": "allow"}`) is injected into the sandbox environment but **OpenCode never reads it**
- **Sensitive file deny patterns are NOT enforced for OpenCode at the application level**
- The bwrap filesystem sandbox (read-only system dirs, writable only in project dir) still provides protection, but `.env` files within the writable project directory can be freely read by OpenCode
- The README (line 98) states "OpenCode: Permission rules are injected via `OPENCODE_PERMISSION`" — **this is incorrect/ineffective**

**Impact**: For Claude Code, deny patterns work because the `PreToolUse` hook actually intercepts and blocks tool calls. For OpenCode, setting an env var that OpenCode doesn't read provides **zero additional protection** beyond the bwrap sandbox itself.

---

## Part 5: Claude Code → OpenCode Hook Mapping (Full Comparison)

### Can it be replicated?

| # | Claude Code Hook | OpenCode/Crush Equivalent | Can Replicate? | Notes |
|:-:|-----------------|---------------------------|:--------------:|-------|
| 1 | **PreToolUse** (inspect/block before tool runs) | Permission dialog (interactive only) | **Partial** | Permission blocks destructive tools but cannot run custom logic, inspect params, or deny based on file patterns. Not scriptable. |
| 2 | **PermissionRequest** (on permission prompt) | — | **No** | No external notification when permission is requested |
| 3 | **PostToolUse** (inspect after tool runs) | — | **No** | No post-execution hook point |
| 4 | **PostToolUseFailure** (on tool failure) | — | **No** | Failures are only visible in TUI |
| 5 | **UserPromptSubmit** (intercept/transform prompts) | — | **No** | No way to intercept or modify user input before processing |
| 6 | **Notification** | — | **No** | Internal pub/sub only |
| 7 | **Stop** (on response completion) | — | **No** | No lifecycle callbacks |
| 8 | **SubagentStart** | — | **No** | OpenCode has no subagent system |
| 9 | **SubagentStop** | — | **No** | OpenCode has no subagent system |
| 10 | **PreCompact** | — | **No** | OpenCode has auto-summarize but no hook for it |
| 11 | **PostCompact** | — | **No** | Same |
| 12 | **SessionStart** | — | **No** | No session lifecycle events exposed |
| 13 | **SessionEnd** | — | **No** | Same |
| 14 | **Setup** | — | **No** | OpenCode has `/init` but no hook for it |
| 15 | **TeammateIdle** | — | **No** | No team/agent system |
| 16 | **TaskCompleted** | — | **No** | No background task system |
| 17 | **ConfigChange** | — | **No** | No config change detection |
| 18 | **WorktreeCreate** | — | **No** | No worktree system |
| 19 | **WorktreeRemove** | — | **No** | No worktree system |
| 20 | **InstructionsLoaded** | — | **No** | Context files loaded silently |
| 21 | **Elicitation** | — | **No** | MCP elicitation not exposed |
| 22 | **ElicitationResult** | — | **No** | Same |
| 23 | **StopFailure** | — | **No** | API errors handled internally |

**Summary**: 0 of 23 hooks can be fully replicated. Only PreToolUse has a partial analog (interactive TUI permission dialog), but it's not programmable, not file-pattern aware, and not scriptable.

### What CAN Be Done for OpenCode (Alternative Approaches)

Since OpenCode has no hook system, bw-AICode must rely on **alternative enforcement mechanisms**:

| Approach | What it protects | Strength | Limitation |
|----------|-----------------|----------|------------|
| **bwrap filesystem isolation** | System dirs, other users' files | Strong — OS-level enforcement | Cannot block reads within writable project dir |
| **File permissions (chmod)** | Specific files in project dir | Strong — OS-level enforcement | Requires per-file setup, not pattern-based |
| **Crush `permissions.allowed_tools`** | Entire tool categories | Moderate — config-based allowlist | Allowlist only, no file-pattern deny, Crush only (not OpenCode) |
| **Crush `options.disabled_tools`** | Hide tools entirely | Strong — tool not available to agent | Too coarse — disabling `view` blocks ALL file reads |
| **Context file instructions** | Behavioral guidance via `AGENTS.md` / `opencode.md` | Weak — advisory, LLM can ignore | Not a security boundary, just a prompt instruction |
| **MCP server wrapper** | Custom tool with built-in deny logic | Strong — full control | High effort, requires reimplementing tools as MCP |

### What CANNOT Be Done for OpenCode (Hard Gaps)

These Claude Code capabilities have **no viable workaround** in OpenCode/Crush:

1. **File-pattern deny lists** — Cannot block reading `.env` files within the writable project directory. The `OPENCODE_PERMISSION` env var is ignored. Only bwrap can help, but it operates at directory level, not file-pattern level.

2. **Bash command inspection** — Cannot inspect or block specific bash commands. OpenCode's permission system is binary: allow or deny the bash tool entirely.

3. **Audit logging** — No way to log what tools were used, what files were accessed, or what commands ran. No post-execution hooks.

4. **Context injection** — No way to programmatically inject context into the conversation. Must rely on static context files (`opencode.md`).

5. **Session lifecycle management** — No way to run code on session start/end for setup or cleanup.

6. **Prompt transformation** — No way to intercept, validate, or modify user prompts before they reach the LLM.

---

## Part 6: Revised Improvement Opportunities (Both Tools)

### For bw-AICode Generally

| # | Improvement | Value | Effort | Applies to |
|:-:|-------------|-------|--------|------------|
| 1 | **Fix `OPENCODE_PERMISSION` — it doesn't work** | **Critical** | Medium | OpenCode |
| 2 | Audit logging for deny events | High | Low | Claude Code |
| 3 | Add `Glob` to hook matcher | High | Low | Claude Code |
| 4 | Sandbox context injection | Medium | Low | Claude Code |
| 5 | Hook config toggles | Medium | Medium | Claude Code |
| 6 | PostToolUse monitoring | Lower | Medium | Claude Code |
| 7 | StopFailure/SessionEnd cleanup | Lower | Low | Claude Code |

### Options for Fixing OpenCode Deny Patterns (Item #1)

The `OPENCODE_PERMISSION` env var is a no-op. Options to actually enforce deny patterns for OpenCode:

**Option A: OS-level file permissions (Recommended)**
- Before launching bwrap, `chmod 000` the denied files, then restore after exit
- Pros: Works at OS level, no application cooperation needed, catches ALL tools
- Cons: Requires file ownership, modifies files temporarily, needs careful cleanup

**Option B: bwrap `--ro-bind` per denied file**
- Mount each denied file as read-only (empty/fake) inside the sandbox
- Pros: No file modification needed, bwrap-native
- Cons: Requires enumerating actual files matching patterns before launch, complex for glob patterns

**Option C: LD_PRELOAD / FUSE interception**
- Intercept `open()` syscalls for denied file patterns
- Pros: Transparent, catches everything
- Cons: High complexity, fragile, overkill for this use case

**Option D: Context file advisory (Weak fallback)**
- Add deny patterns to `opencode.md` or `AGENTS.md` as instructions
- Pros: Zero effort
- Cons: Not a security boundary — LLM can and will ignore it

**Option E: Remove `OPENCODE_PERMISSION` and document the gap**
- Remove the misleading code, document that OpenCode deny patterns rely solely on bwrap filesystem isolation
- Pros: Honest, no false sense of security
- Cons: Weaker security posture for OpenCode vs Claude Code

### Crush-Specific Opportunities (If Supporting Crush as OpenCode Successor)

| Opportunity | Feasibility | Notes |
|-------------|:-----------:|-------|
| Use `permissions.allowed_tools` as allowlist | Easy | Only allows listing specific tools, not file-pattern deny |
| Use `options.disabled_tools` to block dangerous tools | Easy | Too coarse for most use cases |
| Use `options.skills_paths` for custom tool wrappers | Medium | Agent Skills (agentskills.io) can package custom logic |
| Contribute hooks feature upstream | Hard | Would require Charm team buy-in, significant Go PR |
| Create wrapper MCP server with deny logic | Medium | Custom MCP that wraps file operations with deny checks |

---

## Part 7: Summary

### Claude Code: Strong Hook Ecosystem
- 23 hooks covering full lifecycle (pre/post tool use, session, agents, compaction, config, etc.)
- 4 hook types (command, prompt, agent, http) — from simple scripts to AI-powered evaluation
- Rich decision control (deny, allow, ask, context injection, prompt modification)
- bw-AICode's `PreToolUse` hook is correctly implemented and effective

### OpenCode/Crush: No Hook System
- Zero user-configurable hooks (feature request open, unimplemented)
- Interactive-only permission dialog (not scriptable, not pattern-aware)
- `OPENCODE_PERMISSION` env var in bw-AICode is **dead code** — OpenCode doesn't read it
- Must rely on OS-level enforcement (bwrap, file permissions) for security
- Crush adds `allowed_tools` config and `disabled_tools` but no hook equivalent

### Parity Gap
The security posture difference between Claude Code and OpenCode in bw-AICode is larger than documented. Claude Code gets defense-in-depth (bwrap + deny hooks). OpenCode gets only bwrap. The README's claim about `OPENCODE_PERMISSION` should be corrected.
