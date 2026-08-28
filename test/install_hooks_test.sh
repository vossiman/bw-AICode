#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# install.sh builds bw-docker-guard, and Go defaults both caches under $HOME.
# Without these, the build writes a read-only module cache into TEST_HOME that
# the cleanup below cannot remove — which fails the run after the assertions
# have already passed. Go is optional here: the step only warns when absent,
# and hook ownership does not depend on it.
if command -v go &>/dev/null; then
  export GOCACHE="${GOCACHE:-$(go env GOCACHE)}"
  export GOMODCACHE="${GOMODCACHE:-$(go env GOMODCACHE)}"
fi

TEST_HOME="$(mktemp -d)"
cleanup() { chmod -R u+w "$TEST_HOME" 2>/dev/null || true; rm -rf "$TEST_HOME"; }
trap cleanup EXIT

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
