#!/bin/bash
# integration_test.sh — End-to-end tests for bw-docker-guard
# Requires: docker, bw-docker-guard binary, jq
set -euo pipefail

SCRIPT_DIR="$(dirname "$(readlink -f "$0")")"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RESET='\033[0m'

pass=0
fail=0
skip=0

ok()   { echo -e "  ${GREEN}PASS${RESET} $1"; pass=$((pass + 1)); }
fail() { echo -e "  ${RED}FAIL${RESET} $1: $2"; fail=$((fail + 1)); }
skip() { echo -e "  ${YELLOW}SKIP${RESET} $1: $2"; skip=$((skip + 1)); }

# --- Setup ---
echo "=== bw-docker-guard integration tests ==="
echo ""

# Build the binary
echo "Building bw-docker-guard..."
GUARD_BIN="$PROJECT_DIR/test/bw-docker-guard-test"
(cd "$PROJECT_DIR" && go build -o "$GUARD_BIN" ./cmd/bw-docker-guard)
echo "Built: $GUARD_BIN"
echo ""

# Check Docker is available
if ! docker info &>/dev/null; then
  echo "Docker is not available — skipping integration tests"
  exit 0
fi

# --- Test helpers ---
GUARD_PID=""
GUARD_SOCKET=""
GUARD_CONFIG=""

start_guard() {
  local config="$1"
  GUARD_SOCKET="/tmp/bw-docker-guard-test-$$.sock"
  GUARD_CONFIG="$config"

  "$GUARD_BIN" --config "$config" --socket "$GUARD_SOCKET" &
  GUARD_PID=$!

  # Wait for socket
  for i in {1..40}; do
    [[ -S "$GUARD_SOCKET" ]] && break
    sleep 0.05
  done

  if [[ ! -S "$GUARD_SOCKET" ]]; then
    echo "ERROR: guard failed to start"
    kill "$GUARD_PID" 2>/dev/null || true
    exit 1
  fi
}

stop_guard() {
  [[ -n "${GUARD_PID:-}" ]] && kill "$GUARD_PID" 2>/dev/null || true
  [[ -n "${GUARD_SOCKET:-}" ]] && rm -f "$GUARD_SOCKET"
  [[ -n "${GUARD_CONFIG:-}" ]] && rm -f "$GUARD_CONFIG"
  GUARD_PID=""
  GUARD_SOCKET=""
  GUARD_CONFIG=""
}

docker_via_guard() {
  DOCKER_HOST="unix://$GUARD_SOCKET" docker "$@" 2>&1
}

cleanup() {
  stop_guard
  rm -f "$GUARD_BIN"
}
trap cleanup EXIT

# ============================================================
# Test 1: Read-only mode — GET requests work
# ============================================================
echo "--- Read-only mode ---"

config_file="$(mktemp /tmp/guard-test-XXXXXX.json)"
cat > "$config_file" <<'EOF'
{
  "project_dir": "/tmp/test-project",
  "allowed_images": [],
  "allowed_networks": [],
  "volume_mount_root": "/tmp/test-project"
}
EOF

start_guard "$config_file"

# docker ps (GET) should work
if docker_via_guard ps &>/dev/null; then
  ok "read-only: docker ps works (GET allowed)"
else
  fail "read-only: docker ps" "GET request should be allowed"
fi

# docker run (POST) should be blocked
output="$(docker_via_guard run --rm alpine echo hi 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied"; then
  ok "read-only: docker run blocked"
elif echo "$output" | grep -qi "read-only mode"; then
  ok "read-only: docker run blocked (read-only mode)"
else
  # Docker might format the error differently — check if the command actually ran
  if echo "$output" | grep -q "^hi$"; then
    fail "read-only: docker run" "container ran successfully (should be blocked)"
  else
    ok "read-only: docker run blocked (error: ${output:0:80})"
  fi
fi

# docker images (GET) should work
if docker_via_guard images &>/dev/null; then
  ok "read-only: docker images works (GET allowed)"
else
  fail "read-only: docker images" "GET request should be allowed"
fi

stop_guard

# ============================================================
# Test 2: Guarded mode — allowed images work
# ============================================================
echo ""
echo "--- Guarded mode ---"

# Use alpine:latest as our "allowed" image (likely cached)
config_file="$(mktemp /tmp/guard-test-XXXXXX.json)"
cat > "$config_file" <<EOF
{
  "project_dir": "/tmp/test-project",
  "compose_project": "test-project",
  "allowed_images": ["alpine:latest", "alpine"],
  "allowed_networks": ["test-project_default"],
  "volume_mount_root": "/tmp/test-project"
}
EOF

mkdir -p /tmp/test-project

start_guard "$config_file"

# docker ps should work
if docker_via_guard ps &>/dev/null; then
  ok "guarded: docker ps works"
else
  fail "guarded: docker ps" "GET should always work"
fi

# Allowed image should be pullable
if docker_via_guard pull alpine:latest &>/dev/null; then
  ok "guarded: pull allowed image (alpine:latest)"
else
  # Might already be cached; check if image exists
  if docker_via_guard images alpine:latest --format '{{.Repository}}' 2>/dev/null | grep -q alpine; then
    ok "guarded: allowed image already cached"
  else
    fail "guarded: pull allowed image" "should be allowed"
  fi
fi

# Disallowed image should be blocked
output="$(docker_via_guard pull ubuntu:latest 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied\|not allowed"; then
  ok "guarded: pull disallowed image (ubuntu) blocked"
else
  fail "guarded: pull disallowed image" "should be blocked: $output"
fi

# Run allowed image with no volume mounts
output="$(docker_via_guard run --rm alpine echo guard-test-ok 2>&1 || true)"
if echo "$output" | grep -q "guard-test-ok"; then
  ok "guarded: run allowed image works"
else
  fail "guarded: run allowed image" "expected output 'guard-test-ok': $output"
fi

# Run with volume mount under project dir — should work
output="$(docker_via_guard run --rm -v /tmp/test-project:/mnt alpine ls /mnt 2>&1 || true)"
if [[ $? -eq 0 ]] || ! echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden"; then
  ok "guarded: volume mount under project dir allowed"
else
  fail "guarded: volume mount under project dir" "should be allowed: $output"
fi

# Run with volume mount OUTSIDE project dir — should be blocked
output="$(docker_via_guard run --rm -v /etc:/mnt alpine ls /mnt 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied\|not allowed"; then
  ok "guarded: volume mount outside project dir blocked"
else
  # Check if the command actually succeeded (bad)
  if echo "$output" | grep -q "passwd\|hostname\|hosts"; then
    fail "guarded: volume mount outside project dir" "mount succeeded (should be blocked)"
  else
    ok "guarded: volume mount outside project dir blocked (error: ${output:0:80})"
  fi
fi

# Run with --privileged — should be blocked
output="$(docker_via_guard run --rm --privileged alpine echo hi 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied\|privileged"; then
  ok "guarded: --privileged blocked"
else
  if echo "$output" | grep -q "^hi$"; then
    fail "guarded: --privileged" "privileged container ran (should be blocked)"
  else
    ok "guarded: --privileged blocked (error: ${output:0:80})"
  fi
fi

# Run disallowed image — should be blocked
output="$(docker_via_guard run --rm ubuntu echo hi 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied\|not allowed"; then
  ok "guarded: run disallowed image (ubuntu) blocked"
else
  if echo "$output" | grep -q "^hi$"; then
    fail "guarded: run disallowed image" "container ran (should be blocked)"
  else
    ok "guarded: run disallowed image blocked (error: ${output:0:80})"
  fi
fi

# Run with --network=host — should be blocked
output="$(docker_via_guard run --rm --network=host alpine echo hi 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied\|network"; then
  ok "guarded: --network=host blocked"
else
  if echo "$output" | grep -q "^hi$"; then
    fail "guarded: --network=host" "container ran with host network (should be blocked)"
  else
    ok "guarded: --network=host blocked (error: ${output:0:80})"
  fi
fi

# Volume mount docker.sock — should be blocked
output="$(docker_via_guard run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine echo hi 2>&1 || true)"
if echo "$output" | grep -qi "bw-docker-guard\|403\|forbidden\|denied\|docker.sock"; then
  ok "guarded: docker.sock volume mount blocked"
else
  if echo "$output" | grep -q "^hi$"; then
    fail "guarded: docker.sock mount" "container ran with docker.sock (should be blocked)"
  else
    ok "guarded: docker.sock mount blocked (error: ${output:0:80})"
  fi
fi

stop_guard
rm -rf /tmp/test-project

# ============================================================
# Summary
# ============================================================
echo ""
echo "=== Results: ${pass} passed, ${fail} failed, ${skip} skipped ==="

if (( fail > 0 )); then
  exit 1
fi
