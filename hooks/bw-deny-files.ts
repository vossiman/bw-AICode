// bw-deny-files.ts — pi extension that blocks access to sensitive files.
// Installed globally to ~/.pi/agent/extensions/ but only activates when
// BW_DENY_PATTERNS_FILE is set (inside the bw-AICode sandbox).
// Mirrors hooks/bw-deny-files.sh (the Claude Code PreToolUse hook).
import * as fs from "node:fs";
import * as path from "node:path";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";

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
