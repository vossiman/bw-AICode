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
