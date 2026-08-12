# pi-bw Wrapper Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a `pi-bw` bubblewrap sandbox wrapper for the pi coding agent, with sensitive-file deny enforcement via a pi TypeScript extension.

**Architecture:** `pi-bw.sh` follows the existing `opencode-bw.sh` skeleton (source `bw-common.sh`, parse flags, docker guard, bwrap). Deny patterns are enforced inside pi by `hooks/bw-deny-files.ts`, a pi extension whose `tool_call` handler returns `{ block: true, reason }`; it is installed globally to `~/.pi/agent/extensions/` and no-ops unless `BW_DENY_PATTERNS_FILE` is set (same env-gating pattern as the Claude hook).

**Tech Stack:** bash (strict mode), bubblewrap, TypeScript (pi extension API, run via Node 24 native type-stripping), `node --test` for unit tests.

**Spec:** `docs/superpowers/specs/2026-08-12-pi-bw-wrapper-design.md`

## Global Constraints

- All bash scripts use `set -euo pipefail`; keep strict-mode-safe idioms (no unguarded command substitutions that may fail).
- Bind entry format is `"mode source [dest]"` with modes `ro`, `rw`, `rw!`, `rw!PERM` (see `bw-common.sh:12-18`).
- Binds targeting paths under `/tmp` or `/run` MUST go in `OVERLAY_BINDS`, never `BINDS` (they'd be hidden by `--tmpfs /tmp` / `--tmpfs /run`).
- When cleanup is needed (guard proxy or deny patterns temp file), run foreground `bwrap` with `trap cleanup_bw EXIT`; otherwise `exec bwrap`.
- The deny reason string must be exactly: `bw-AICode: access to '<basename>' blocked (sensitive file)` (parity with `hooks/bw-deny-files.sh:46`).
- pi's built-in tool names are lowercase: `read`, `bash`, `edit`, `write`. Tool inputs: `read`/`write`/`edit` have `input.path` (string); `bash` has `input.command` (string).
- Unit tests run with `node --test <file>.ts` (Node v24 strips types natively; relative imports must include the `.ts` extension; `import type` is erased at runtime so the pi package need not be resolvable).
- E2E test directories must NOT live under `/tmp` — the project dir bind goes in `BINDS`, which `--tmpfs /tmp` would hide. Use `~/local_dev/pi-bw-test`.

---

### Task 1: Deny-matching logic in `hooks/bw-deny-files.ts`

The extension file contains exported pure functions (testable without pi) plus the default-export wiring (Task 2). This task builds the pure logic TDD-style.

**Files:**
- Create: `hooks/bw-deny-files.ts`
- Test: `hooks/bw-deny-files.test.ts`

**Interfaces:**
- Produces: `globToRegex(pattern: string): RegExp`, `loadPatterns(file: string): RegExp[]`, `findDenyMatch(filePath: string, regexes: RegExp[]): string | null`, `extractBashTargets(command: string): string[]`, `checkToolCall(event: ToolCallLike, regexes: RegExp[]): BlockResult`, types `ToolCallLike = { toolName: string; input: Record<string, unknown> }` and `BlockResult = { block: true; reason: string } | undefined`.

- [ ] **Step 1: Write the failing tests**

Create `hooks/bw-deny-files.test.ts`:

```typescript
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  globToRegex,
  findDenyMatch,
  extractBashTargets,
  checkToolCall,
} from "./bw-deny-files.ts";

// --- globToRegex ---

test("literal pattern matches only itself", () => {
  assert.ok(globToRegex(".env").test(".env"));
  assert.ok(!globToRegex(".env").test(".environment"));
  assert.ok(!globToRegex(".env").test("x.env"));
});

test("* matches any run of characters", () => {
  assert.ok(globToRegex("*.pem").test("server.pem"));
  assert.ok(!globToRegex("*.pem").test("server.pemx"));
  assert.ok(globToRegex(".env.*.local").test(".env.prod.local"));
  assert.ok(globToRegex("service-account*.json").test("service-account-42.json"));
});

test("? matches exactly one character", () => {
  assert.ok(globToRegex("id_?sa").test("id_rsa"));
  assert.ok(!globToRegex("id_?sa").test("id_rrsa"));
});

test("regex metacharacters in patterns are literal", () => {
  assert.ok(!globToRegex(".env").test("xenv"));  // "." must not be regex-any
  assert.ok(globToRegex("a+b").test("a+b"));
  assert.ok(!globToRegex("a+b").test("aab"));
});

// --- findDenyMatch ---

const REGEXES = [".env", "*.pem", "secrets.json"].map(globToRegex);

test("matches on basename regardless of directory", () => {
  assert.equal(findDenyMatch("/repo/config/.env", REGEXES), ".env");
  assert.equal(findDenyMatch("certs/server.pem", REGEXES), "server.pem");
  assert.equal(findDenyMatch("src/index.ts", REGEXES), null);
});

// --- extractBashTargets ---

test("extracts args of known read commands", () => {
  assert.deepEqual(extractBashTargets("cat .env"), [".env"]);
  assert.deepEqual(extractBashTargets("head -n 5 secrets.json"), ["5", "secrets.json"]);
});

test("skips flags", () => {
  assert.ok(!extractBashTargets("grep -r pattern").includes("-r"));
});

test("extracts targets after pipes and semicolons", () => {
  assert.ok(extractBashTargets("echo hi; cat .env").includes(".env"));
  assert.ok(extractBashTargets("sort x | tee out.txt").includes("out.txt"));
});

test("extracts redirection targets", () => {
  assert.ok(extractBashTargets("echo x > .env").includes(".env"));
  assert.ok(extractBashTargets("echo x >> log.pem").includes("log.pem"));
  assert.ok(extractBashTargets("wc -l < .env").includes(".env"));
});

test("unknown commands yield no command-arg targets", () => {
  assert.deepEqual(extractBashTargets("ls -la"), []);
});

// --- checkToolCall ---

function block(name: string) {
  return {
    block: true,
    reason: `bw-AICode: access to '${name}' blocked (sensitive file)`,
  };
}

test("blocks read/write/edit on denied path", () => {
  for (const toolName of ["read", "write", "edit"]) {
    assert.deepEqual(
      checkToolCall({ toolName, input: { path: "conf/.env" } }, REGEXES),
      block(".env"),
    );
  }
});

test("allows read on normal path", () => {
  assert.equal(
    checkToolCall({ toolName: "read", input: { path: "src/app.ts" } }, REGEXES),
    undefined,
  );
});

test("blocks bash commands touching denied files", () => {
  assert.deepEqual(
    checkToolCall({ toolName: "bash", input: { command: "cat .env" } }, REGEXES),
    block(".env"),
  );
  assert.deepEqual(
    checkToolCall({ toolName: "bash", input: { command: "echo x > certs/ca.pem" } }, REGEXES),
    block("ca.pem"),
  );
});

test("allows harmless bash commands", () => {
  assert.equal(
    checkToolCall({ toolName: "bash", input: { command: "ls -la && git status" } }, REGEXES),
    undefined,
  );
});

test("tolerates missing/non-string input fields", () => {
  assert.equal(checkToolCall({ toolName: "bash", input: {} }, REGEXES), undefined);
  assert.equal(checkToolCall({ toolName: "read", input: { path: 42 } }, REGEXES), undefined);
  assert.equal(checkToolCall({ toolName: "greet", input: { name: "x" } }, REGEXES), undefined);
});

test("custom tools with a string path field are also checked", () => {
  assert.deepEqual(
    checkToolCall({ toolName: "my_reader", input: { path: ".env" } }, REGEXES),
    block(".env"),
  );
});
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `node --test hooks/bw-deny-files.test.ts`
Expected: FAIL — cannot find module `./bw-deny-files.ts`.

- [ ] **Step 3: Implement the pure logic**

Create `hooks/bw-deny-files.ts` (default-export wiring comes in Task 2 — for now only the pure functions):

```typescript
// bw-deny-files.ts — pi extension that blocks access to sensitive files.
// Installed globally to ~/.pi/agent/extensions/ but only activates when
// BW_DENY_PATTERNS_FILE is set (inside the bw-AICode sandbox).
// Mirrors hooks/bw-deny-files.sh (the Claude Code PreToolUse hook).
import * as fs from "node:fs";
import * as path from "node:path";

export type ToolCallLike = { toolName: string; input: Record<string, unknown> };
export type BlockResult = { block: true; reason: string } | undefined;

// Commands whose file arguments are checked — keep in sync with bw-deny-files.sh
const READ_CMDS = ["cat", "head", "tail", "less", "more", "bat", "batcat", "tac", "nl", "rev", "strings", "xxd", "hexdump", "od", "file", "wc", "source", "\\."];
const SEARCH_CMDS = ["grep", "rg", "ag", "ack", "sed", "awk", "gawk", "perl", "ruby"];
const WRITE_CMDS = ["tee", "cp", "mv", "rm"];
const ALL_CMDS = [...READ_CMDS, ...SEARCH_CMDS, ...WRITE_CMDS].join("|");

// Convert an fnmatch-style glob (*, ?, [...]) to an anchored RegExp.
export function globToRegex(pattern: string): RegExp {
  let re = "";
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === "*") {
      re += ".*";
      i++;
    } else if (c === "?") {
      re += ".";
      i++;
    } else if (c === "[") {
      const end = pattern.indexOf("]", i + 2);
      if (end === -1) {
        re += "\\[";
        i++;
      } else {
        let cls = pattern.slice(i + 1, end);
        if (cls.startsWith("!")) cls = "^" + cls.slice(1);
        re += "[" + cls + "]";
        i = end + 1;
      }
    } else {
      re += c.replace(/[.+^${}()|\\\/\-]/g, "\\$&");
      i++;
    }
  }
  return new RegExp("^" + re + "$");
}

// Read deny patterns (one glob per line). Unreadable file → no patterns (fail open;
// the wrapper bind-mounts the file read-only, so this is the outside-sandbox path).
export function loadPatterns(file: string): RegExp[] {
  try {
    return fs
      .readFileSync(file, "utf8")
      .split("\n")
      .map((l) => l.trim())
      .filter(Boolean)
      .map(globToRegex);
  } catch {
    return [];
  }
}

// Basename glob matching, same semantics as the shell hook.
export function findDenyMatch(filePath: string, regexes: RegExp[]): string | null {
  const base = path.basename(filePath.trim());
  for (const re of regexes) {
    if (re.test(base)) return base;
  }
  return null;
}

// Extract candidate file tokens from a bash command: non-flag arguments of
// known read/search/write commands, plus >, >>, < redirection targets.
// Intentionally simple — covers common cases, not all edge cases (parity
// with the shell hook; bwrap remains the primary boundary).
export function extractBashTargets(command: string): string[] {
  const targets: string[] = [];
  const cmdRe = new RegExp(`(?:^|[|;&])\\s*(?:${ALL_CMDS})\\s+([^|;&]+)`, "g");
  for (const m of command.matchAll(cmdRe)) {
    for (const tok of m[1].split(/\s+/)) {
      if (!tok || tok.startsWith("-") || tok.startsWith(">") || tok.startsWith("<")) continue;
      targets.push(tok);
    }
  }
  for (const m of command.matchAll(/>{1,2}\s*([^\s|;&]+)/g)) targets.push(m[1]);
  for (const m of command.matchAll(/<\s*([^\s|;&]+)/g)) targets.push(m[1]);
  return targets;
}

function deny(name: string): BlockResult {
  return {
    block: true,
    reason: `bw-AICode: access to '${name}' blocked (sensitive file)`,
  };
}

// Decide whether a tool call must be blocked. Pure — used by the handler and tests.
export function checkToolCall(event: ToolCallLike, regexes: RegExp[]): BlockResult {
  if (event.toolName === "bash") {
    const command = event.input.command;
    if (typeof command !== "string") return undefined;
    for (const target of extractBashTargets(command)) {
      const hit = findDenyMatch(target, regexes);
      if (hit) return deny(hit);
    }
    return undefined;
  }
  // read/write/edit and any custom tool taking a file path
  const p = event.input.path;
  if (typeof p === "string") {
    const hit = findDenyMatch(p, regexes);
    if (hit) return deny(hit);
  }
  return undefined;
}
```

Note the test `head -n 5 secrets.json` expects `["5", "secrets.json"]` — the flag value `5` is extracted as a candidate token, exactly like the shell hook. That's harmless (a file literally named `5` matching a deny pattern is not a real case).

- [ ] **Step 4: Run tests to verify they pass**

Run: `node --test hooks/bw-deny-files.test.ts`
Expected: all tests PASS.

- [ ] **Step 5: Commit**

```bash
git add hooks/bw-deny-files.ts hooks/bw-deny-files.test.ts
git commit -m "feat: add deny-matching logic for pi deny-files extension"
```

---

### Task 2: Extension wiring (default export)

**Files:**
- Modify: `hooks/bw-deny-files.ts` (append default export)
- Test: manual smoke test with `pi -e`

**Interfaces:**
- Consumes: `loadPatterns`, `checkToolCall` from Task 1.
- Produces: pi extension default export — `default function (pi: ExtensionAPI): void`.

- [ ] **Step 1: Append the default export to `hooks/bw-deny-files.ts`**

Add at the top of the file (with the other imports):

```typescript
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
```

Add at the bottom:

```typescript
export default function (pi: ExtensionAPI) {
  // No-op outside the sandbox (same gate as the Claude Code hook)
  const denyFile = process.env.BW_DENY_PATTERNS_FILE;
  if (!denyFile) return;
  const regexes = loadPatterns(denyFile);
  if (regexes.length === 0) return;

  pi.on("tool_call", async (event) => {
    return checkToolCall(
      { toolName: event.toolName, input: event.input as Record<string, unknown> },
      regexes,
    );
  });
}
```

- [ ] **Step 2: Re-run unit tests (type-stripping must still parse the file)**

Run: `node --test hooks/bw-deny-files.test.ts`
Expected: all tests PASS (the `import type` is erased; the default export is inert under test).

- [ ] **Step 3: Smoke-test blocking with real pi (outside the sandbox, via `-e`)**

```bash
cd "$(mktemp -d)"
echo "SECRET=x" > .env
printf '.env\n*.pem\n' > /tmp/bw-deny-test-patterns.txt
BW_DENY_PATTERNS_FILE=/tmp/bw-deny-test-patterns.txt \
  pi -ne -e ~/local_dev/bw-AICode/hooks/bw-deny-files.ts \
  -p "Use the read tool to read the file .env and print its contents"
```

Expected: pi's output shows the read tool call failing with reason `bw-AICode: access to '.env' blocked (sensitive file)`; the secret value `SECRET=x` does NOT appear in the transcript. (`-ne` disables other extensions so only ours runs.) If the default local model isn't reachable, this step can be deferred to Task 6's E2E run.

Also verify the no-op gate — same command without `BW_DENY_PATTERNS_FILE` must print the file contents:

```bash
pi -ne -e ~/local_dev/bw-AICode/hooks/bw-deny-files.ts \
  -p "Use the read tool to read the file .env and print its contents"
```

Expected: output contains `SECRET=x`.

Cleanup: `rm /tmp/bw-deny-test-patterns.txt`

- [ ] **Step 4: Commit**

```bash
git add hooks/bw-deny-files.ts
git commit -m "feat: wire pi deny-files extension via tool_call handler"
```

---

### Task 3: `pi-bw.sh` wrapper script

**Files:**
- Create: `pi-bw.sh`

**Interfaces:**
- Consumes: `bw-common.sh` — `STARTDIR`, `COMMON_BINDS`, `COMMON_OVERLAY_BINDS`, `parse_bw_flags`, `load_deny_patterns` (sets `BW_DENY_PATTERNS_FILE`), `load_mcp_env_vars` (sets `BW_MCP_ENV_ARGS`), `add_docker_overlay_bind`, `build_bwrap_args`, `cleanup_bw`, `BW_DOCKER_HOST`, `BW_GUARD_PID`, `BW_NO_DENY_FILES`, `BW_TOOL_ARGS`, `BW_VENV_PATH`.
- Produces: executable `pi-bw.sh`, symlinked as `pi-bw` by Task 4.

- [ ] **Step 1: Write `pi-bw.sh`**

```bash
#!/bin/bash
# pi-bw — Run the pi coding agent sandboxed via bubblewrap
# Writable: current directory only. Everything else is read-only or invisible.
# pi has no permission-prompt system — bwrap is the enforcement layer, plus the
# bw-deny-files.ts extension (installed to ~/.pi/agent/extensions/ by install.sh).

set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
source "$SCRIPT_DIR/bw-common.sh"

# Locate pi on the host (lives under ~/.nvm, which isn't in the default sandbox
# PATH). Checked before parse_bw_flags so we fail before the docker guard starts.
if ! PI_BIN="$(command -v pi)"; then
  echo "Error: pi not found in PATH — install with: npm install -g @earendil-works/pi-coding-agent" >&2
  exit 1
fi
PI_BIN_DIR="$(dirname "$PI_BIN")"

parse_bw_flags "$@"

# Load sensitive file deny patterns (unless --no-deny-files)
if [[ "$BW_NO_DENY_FILES" != true ]]; then
  load_deny_patterns
fi

# Load MCP env vars from .env if needed
load_mcp_env_vars

# Tool-specific binds (added to common)
BINDS=(
  "${COMMON_BINDS[@]}"

  # pi + its node runtime (installed via nvm)
  "ro $HOME/.nvm"

  # pi config/state — rw! creates if missing
  "rw! $HOME/.pi"
)

# Symlinks directly under ~/.pi/agent/ can point outside bound paths
# (e.g. models.json -> a host-managed config repo). Bind resolved targets
# read-only so they don't dangle inside the sandbox.
for link in "$HOME/.pi/agent"/*; do
  [[ -L "$link" ]] || continue
  target="$(readlink -f "$link" || true)"
  if [[ -z "$target" || ! -e "$target" ]]; then
    echo "[bw] ⚠ skipping dangling symlink: $link" >&2
    continue
  fi
  case "$target" in
    "$HOME/.pi"|"$HOME/.pi"/*|"$STARTDIR"|"$STARTDIR"/*) continue ;;
  esac
  BINDS+=("ro $target")
done

# Overlay binds — placed after --tmpfs /tmp and --tmpfs /run
OVERLAY_BINDS=(
  "${COMMON_OVERLAY_BINDS[@]}"
)

add_docker_overlay_bind OVERLAY_BINDS

# Bind-mount deny patterns file into sandbox (read-only, under /tmp so it's an overlay)
if [[ -n "${BW_DENY_PATTERNS_FILE:-}" ]]; then
  OVERLAY_BINDS+=("ro $BW_DENY_PATTERNS_FILE")
fi

build_bwrap_args BINDS BWRAP_ARGS
build_bwrap_args OVERLAY_BINDS BWRAP_OVERLAY_ARGS

BWRAP_CMD=(
  bwrap
  "${BWRAP_ARGS[@]}"
  --proc /proc
  --dev /dev
  --tmpfs /dev/shm
  --tmpfs /tmp
  --tmpfs /run
  "${BWRAP_OVERLAY_ARGS[@]}"
  --symlink /run /var/run
  --setenv HOME "$HOME"
  --setenv PATH "${BW_VENV_PATH:+$BW_VENV_PATH/bin:}$PI_BIN_DIR:$HOME/.local/bin:$HOME/.npm-global/bin:/home/linuxbrew/.linuxbrew/bin:/usr/local/bin:/usr/bin:/bin:/snap/bin"
  --setenv SHELL /bin/bash
  ${SSH_AUTH_SOCK:+--ro-bind "$SSH_AUTH_SOCK" "$SSH_AUTH_SOCK"}
  ${SSH_AUTH_SOCK:+--setenv SSH_AUTH_SOCK "$SSH_AUTH_SOCK"}
  ${BW_VENV_PATH:+--setenv VIRTUAL_ENV "$BW_VENV_PATH"}
  ${BW_DENY_PATTERNS_FILE:+--setenv BW_DENY_PATTERNS_FILE "$BW_DENY_PATTERNS_FILE"}
  "${BW_MCP_ENV_ARGS[@]}"
  --setenv DOCKER_HOST "$BW_DOCKER_HOST"
  --chdir "$STARTDIR"
  --unshare-ipc
  --unshare-pid
  --die-with-parent
  pi "${BW_TOOL_ARGS[@]}"
)

if [[ -n "${BW_GUARD_PID:-}" || -n "${BW_DENY_PATTERNS_FILE:-}" ]]; then
  # Resources to clean up — use foreground bwrap so cleanup trap fires on exit
  trap cleanup_bw EXIT
  "${BWRAP_CMD[@]}"
else
  # Nothing to clean up — exec replaces this process
  exec "${BWRAP_CMD[@]}"
fi
```

Then: `chmod +x pi-bw.sh`

- [ ] **Step 2: Syntax and lint check**

Run: `bash -n pi-bw.sh && (command -v shellcheck >/dev/null && shellcheck pi-bw.sh || echo "shellcheck not installed — skipped")`
Expected: no syntax errors; no new shellcheck errors beyond patterns already present in `claude-bw.sh`/`opencode-bw.sh` (the `${VAR:+...}` array expansions produce known, accepted SC2206-style infos there).

- [ ] **Step 3: Smoke test — pi runs inside the sandbox**

```bash
cd ~/local_dev/bw-AICode
./pi-bw.sh --help
```

Expected: pi's usage text prints (proves `~/.nvm` bind + PATH work and bwrap launches). The `[bw] Docker: ...` guard summary appears first.

Also verify the symlink-target bind derivation:

```bash
./pi-bw.sh --version
```

Expected: prints pi's version (e.g. `0.84.1`) and exits cleanly.

- [ ] **Step 4: Commit**

```bash
git add pi-bw.sh
git commit -m "feat: add pi-bw sandbox wrapper for the pi coding agent"
```

---

### Task 4: `install.sh` updates

**Files:**
- Modify: `install.sh`

**Interfaces:**
- Consumes: `pi-bw.sh` (Task 3), `hooks/bw-deny-files.ts` (Tasks 1-2).
- Produces: `~/.local/bin/pi-bw` symlink; `~/.pi/agent/extensions/bw-deny-files.ts`.

- [ ] **Step 1: Edit `install.sh`**

Four changes:

1. `install.sh:18` — bump the step total:

```bash
total=8
```

2. `install.sh:45` — add `pi-bw.sh` to the wrapper loop:

```bash
for script in claude-bw.sh opencode-bw.sh pi-bw.sh; do
```

3. After the "Register PreToolUse hook in Claude settings" step (after `install.sh:125`, before the "Verify PATH" step) — insert a new step:

```bash
# --- Step 6: Install pi deny-files extension ---
step "Installing pi deny-files extension"
PI_EXT_DIR="$HOME/.pi/agent/extensions"
mkdir -p "$PI_EXT_DIR"
cp "$SCRIPT_DIR/hooks/bw-deny-files.ts" "$PI_EXT_DIR/bw-deny-files.ts"
ok "bw-deny-files.ts copied to $PI_EXT_DIR/"
```

Renumber the two comment headers that follow (`# --- Step 6: Verify PATH ---` → `# --- Step 7: Verify PATH ---`, `# --- Step 7: Checking dependencies ---` → `# --- Step 8: Checking dependencies ---`).

4. In the dependencies step, after the `opencode` check (`install.sh:150-154`), add:

```bash
if command -v pi &>/dev/null; then
  ok "pi found at $(command -v pi)"
else
  warn "pi not found — install pi before using pi-bw"
fi
```

Also update the closing line (`install.sh:175`) to mention the new wrapper:

```bash
echo -e "  ${GREEN}${BOLD}Done.${RESET} Run ${CYAN}claude-bw${RESET}, ${CYAN}opencode-bw${RESET} or ${CYAN}pi-bw${RESET} from your project directory"
```

- [ ] **Step 2: Run the installer and verify**

```bash
bash -n install.sh && ./install.sh
ls -la ~/.local/bin/pi-bw ~/.pi/agent/extensions/bw-deny-files.ts
```

Expected: installer completes with 8 steps, `pi-bw` symlink points at the repo's `pi-bw.sh`, extension file exists in `~/.pi/agent/extensions/`, dependency check shows `pi found`.

- [ ] **Step 3: Commit**

```bash
git add install.sh
git commit -m "feat: install pi-bw wrapper and pi deny-files extension"
```

---

### Task 5: Documentation updates

**Files:**
- Modify: `README.md`, `CLAUDE.md`

- [ ] **Step 1: Update `README.md`**

1. Scripts table (`README.md:19-20`) — add a row after opencode-bw:

```markdown
| `pi-bw.sh` | Sandbox wrapper for the [pi coding agent](https://www.npmjs.com/package/@earendil-works/pi-coding-agent). pi has no permission system; bwrap is the enforcement layer. |
```

2. Install symlink list (`README.md:35-36`) — add:

```markdown
- `pi-bw` -> `pi-bw.sh`
```

3. Usage block (`README.md:49-50`) — add:

```bash
pi-bw              # start pi sandboxed
```

4. Full Docker access block (`README.md:76-77`) — add:

```bash
pi-bw --full-docker            # same for pi
```

5. "How it works" list in the deny section (after the OpenCode bullet, `README.md:98`) — add:

```markdown
- **pi:** A `tool_call` extension (`~/.pi/agent/extensions/bw-deny-files.ts`, installed by `install.sh`) blocks `read`/`write`/`edit` calls on denied paths and scans `bash` commands. Activates only when `BW_DENY_PATTERNS_FILE` is set (i.e. inside the sandbox).
```

6. Disabling block (`README.md:124-125`) — add:

```bash
pi-bw --no-deny-files
```

- [ ] **Step 2: Update `CLAUDE.md`**

1. Project Overview first sentence — change `(Claude Code, OpenCode)` to `(Claude Code, OpenCode, pi)` and "two bubblewrap" to "three bubblewrap".

2. Files section — after the `opencode-bw` bullet, add:

```markdown
- **`pi-bw`** — Sandbox wrapper for the pi coding agent. Binds `~/.nvm` (pi's install location) read-only and resolves symlinks under `~/.pi/agent/` to extra read-only binds.
```

3. Files section — after the `hooks/bw-deny-files.sh` bullet, add:

```markdown
- **`hooks/bw-deny-files.ts`** — pi extension enforcing the same deny patterns via a `tool_call` handler. Installed to `~/.pi/agent/extensions/` by `install.sh`; unit tests run with `node --test hooks/bw-deny-files.test.ts`.
```

- [ ] **Step 3: Commit**

```bash
git add README.md CLAUDE.md
git commit -m "docs: document pi-bw wrapper and pi deny-files extension"
```

---

### Task 6: End-to-end verification

**Files:** none (verification only; uses the installed `pi-bw`).

- [ ] **Step 1: Set up a scratch project (NOT under /tmp)**

```bash
mkdir -p ~/local_dev/pi-bw-test && cd ~/local_dev/pi-bw-test
echo "SECRET=supersecret123" > .env
echo "hello world" > note.txt
```

- [ ] **Step 2: Denied read via the read tool**

```bash
pi-bw -p "Use the read tool to read the file .env and print its contents verbatim"
```

Expected: the tool call is blocked with reason `bw-AICode: access to '.env' blocked (sensitive file)`; `supersecret123` does not appear.

- [ ] **Step 3: Denied read via bash**

```bash
pi-bw -p "Run exactly this bash command and show me the raw output: cat .env"
```

Expected: blocked; `supersecret123` does not appear.

- [ ] **Step 4: Normal read works**

```bash
pi-bw -p "Use the read tool to read note.txt and print its contents"
```

Expected: output contains `hello world`.

- [ ] **Step 5: Writes outside the project fail (bwrap boundary)**

```bash
pi-bw -p "Run exactly this bash command and show me the raw output: touch ~/pi-bw-escape-test && echo CREATED"
```

Expected: the command fails with a read-only filesystem error; `CREATED` does not appear. Confirm on the host: `ls ~/pi-bw-escape-test` → No such file.

- [ ] **Step 6: --no-deny-files disables blocking**

```bash
pi-bw --no-deny-files -p "Use the read tool to read the file .env and print its contents verbatim"
```

Expected: output contains `supersecret123` (bwrap still confines writes; only the deny layer is off).

- [ ] **Step 7: Interactive sanity + models symlink**

```bash
pi-bw
```

Expected: TUI starts, the default model (from `models.json`, reached through the `~/.pi/agent/models.json` symlink) is available. Exit with Ctrl+C/Ctrl+D.

- [ ] **Step 8: Clean up**

```bash
rm -rf ~/local_dev/pi-bw-test
```

If any step fails, use superpowers:systematic-debugging before changing code.
