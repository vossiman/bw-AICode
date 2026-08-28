#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export GOCACHE="${GOCACHE:-$(go env GOCACHE)}"
export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
TEST_HOME="$(mktemp -d)"
trap 'rm -rf "$TEST_HOME"' EXIT

run_install() {
  HOME="$TEST_HOME" bash "$ROOT/install.sh" >/dev/null
}

hook="$TEST_HOME/.claude/hooks/bw-deny-files.sh"
extension="$TEST_HOME/.pi/agent/extensions/bw-deny-files.ts"

# Fresh installs receive the repository copies.
run_install
cmp "$ROOT/hooks/bw-deny-files.sh" "$hook"
cmp "$ROOT/hooks/bw-deny-files.ts" "$extension"

# Copies marked as bw-AICode-owned are refreshed.
printf '%s\n' '# Managed by bw-AICode install.sh; safe to replace on upgrade.' stale > "$hook"
printf '%s\n' '// Managed by bw-AICode install.sh; safe to replace on upgrade.' stale > "$extension"
run_install
cmp "$ROOT/hooks/bw-deny-files.sh" "$hook"
cmp "$ROOT/hooks/bw-deny-files.ts" "$extension"

# Pre-marker bw-AICode installations are adopted and refreshed once.
printf '%s\n' '# Installed globally but only activates when BW_DENY_PATTERNS_FILE is set' stale > "$hook"
printf '%s\n' '// Mirrors hooks/bw-deny-files.sh' stale > "$extension"
run_install
cmp "$ROOT/hooks/bw-deny-files.sh" "$hook"
cmp "$ROOT/hooks/bw-deny-files.ts" "$extension"

# Foreign implementations—including aiCodingBaseSetup's hardened versions—win.
printf '%s\n' '# Managed by somebody else' hardened > "$hook"
printf '%s\n' '// Managed by somebody else' hardened > "$extension"
run_install
grep -qF hardened "$hook"
grep -qF hardened "$extension"

echo "install hook ownership tests: ok"
