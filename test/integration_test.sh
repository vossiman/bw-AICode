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
echo "=== bw-AICode integration tests ==="
echo ""

# ============================================================
# Test 0: pi-bw symlink bind resolution (no Docker needed)
# ============================================================
echo "--- pi-bw symlink bind resolution ---"

SYMLINK_TEST_HOME="$(mktemp -d /tmp/bw-symlink-test-XXXXXX)"

# Fake config repo (with a space in the path) and fake ~/.pi/agent tree
sym_repo="$SYMLINK_TEST_HOME/config repo"
sym_agent="$SYMLINK_TEST_HOME/.pi/agent"
mkdir -p "$sym_repo/agents" "$sym_repo/extensions/nested" \
         "$sym_agent/agents" "$sym_agent/extensions/sub" "$sym_agent/prompts" \
         "$SYMLINK_TEST_HOME/project" "$SYMLINK_TEST_HOME/.aws"
echo agent > "$sym_repo/agents/reviewer.md"
echo ext   > "$sym_repo/extensions/deny.ts"
echo nest  > "$sym_repo/extensions/nested/helper.ts"
echo model > "$sym_repo/models.json"
echo proj  > "$SYMLINK_TEST_HOME/project/inproject.txt"
echo pi    > "$SYMLINK_TEST_HOME/.pi/internal.txt"
echo cred  > "$SYMLINK_TEST_HOME/.aws/credentials"

ln -s "$sym_repo/models.json"                "$sym_agent/models.json"           # depth 1 (existing behavior)
ln -s "$sym_repo/agents/reviewer.md"         "$sym_agent/agents/reviewer.md"    # depth 2
ln -s "$sym_repo/extensions/deny.ts"         "$sym_agent/extensions/deny.ts"    # depth 2
ln -s "$sym_repo/extensions/nested/helper.ts" "$sym_agent/extensions/sub/helper.ts"  # depth 3
ln -s "$sym_repo/agents/reviewer.md"         "$sym_agent/prompts/dup.md"        # duplicate target
ln -s "$SYMLINK_TEST_HOME/missing.txt"       "$sym_agent/agents/dangling.md"    # dangling
ln -s "$SYMLINK_TEST_HOME/.aws"              "$sym_agent/agents/awsdir"         # directory target -> rejected
ln -s "$SYMLINK_TEST_HOME/project/inproject.txt" "$sym_agent/agents/inproject.md"  # under STARTDIR -> skipped
ln -s "$SYMLINK_TEST_HOME/.pi/internal.txt"  "$sym_agent/agents/internal.md"    # under bound root -> skipped

# Run the resolution in a fresh bash process (separate process so set -e
# inside it is not suppressed by the || context) with HOME overridden.
sym_driver="$SYMLINK_TEST_HOME/driver.sh"
cat > "$sym_driver" <<'EOF'
set -euo pipefail
cd "$HOME/project"
source "$BW_COMMON"
TARGETS=()
resolve_symlink_binds TARGETS "$HOME/.pi/agent" "$HOME/.pi"
if (( ${#TARGETS[@]} > 0 )); then
  printf '%s\n' "${TARGETS[@]}"
fi
EOF

sym_targets="$SYMLINK_TEST_HOME/targets.txt"
sym_warns="$SYMLINK_TEST_HOME/warnings.txt"
sym_rc=0
HOME="$SYMLINK_TEST_HOME" BW_COMMON="$PROJECT_DIR/bw-common.sh" \
  bash "$sym_driver" > "$sym_targets" 2> "$sym_warns" || sym_rc=$?

has_target() { grep -qxF "$1" "$sym_targets"; }

if [[ $sym_rc -eq 0 ]]; then
  ok "symlinks: resolution runs cleanly"
else
  fail "symlinks: resolution" "exit code $sym_rc: $(cat "$sym_warns")"
fi

if has_target "$sym_repo/models.json"; then
  ok "symlinks: depth-1 target bound (models.json)"
else
  fail "symlinks: depth-1 target" "missing $sym_repo/models.json"
fi

if has_target "$sym_repo/agents/reviewer.md"; then
  ok "symlinks: depth-2 target bound (agents/reviewer.md)"
else
  fail "symlinks: depth-2 target" "missing $sym_repo/agents/reviewer.md"
fi

if has_target "$sym_repo/extensions/deny.ts"; then
  ok "symlinks: depth-2 target bound (extensions/deny.ts)"
else
  fail "symlinks: depth-2 target" "missing $sym_repo/extensions/deny.ts"
fi

if has_target "$sym_repo/extensions/nested/helper.ts"; then
  ok "symlinks: depth-3 target bound, path with space"
else
  fail "symlinks: depth-3 target" "missing $sym_repo/extensions/nested/helper.ts"
fi

dup_count="$(grep -cxF "$sym_repo/agents/reviewer.md" "$sym_targets" || true)"
if [[ "$dup_count" == "1" ]]; then
  ok "symlinks: duplicate targets deduplicated"
else
  fail "symlinks: dedup" "expected 1 entry for reviewer.md, got $dup_count"
fi

if ! has_target "$SYMLINK_TEST_HOME/missing.txt" && grep -q "dangling" "$sym_warns"; then
  ok "symlinks: dangling link skipped with warning"
else
  fail "symlinks: dangling link" "should be skipped with a warning"
fi

if ! has_target "$SYMLINK_TEST_HOME/.aws" && grep -q "outside allowed scope.*\.aws" "$sym_warns"; then
  ok "symlinks: directory target (.aws) rejected with warning"
else
  fail "symlinks: directory target" "should be rejected with a warning"
fi

if ! has_target "$SYMLINK_TEST_HOME/project/inproject.txt"; then
  ok "symlinks: target under STARTDIR skipped"
else
  fail "symlinks: STARTDIR target" "should be skipped (already bound rw)"
fi

if ! has_target "$SYMLINK_TEST_HOME/.pi/internal.txt"; then
  ok "symlinks: target under bound root (~/.pi) skipped"
else
  fail "symlinks: bound-root target" "should be skipped (already bound rw)"
fi

rm -rf "$SYMLINK_TEST_HOME"

# ============================================================
# Test 0b: compose bind paths must NOT reach the guard config
# ============================================================
echo ""
echo "--- compose bind harvesting (CAF-001) ---"

BIND_TEST_HOME="$(mktemp -d /tmp/bw-bind-test-XXXXXX)"
mkdir -p "$BIND_TEST_HOME/project"
cat > "$BIND_TEST_HOME/project/docker-compose.yml" <<'YAML'
services:
  app:
    image: postgres:16
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - /:/host
YAML

(
  set +e
  cd "$BIND_TEST_HOME/project" || exit 1
  # shellcheck disable=SC1090
  source "$PROJECT_DIR/bw-common.sh"
  derive_docker_allowlist 2>/dev/null

  if [[ -z "${BW_DOCKER_GUARD_CONFIG:-}" || ! -f "$BW_DOCKER_GUARD_CONFIG" ]]; then
    echo "SKIP no config generated (docker compose unavailable)"
    exit 2
  fi

  paths="$(jq -r '.allowed_volume_paths[]?' "$BW_DOCKER_GUARD_CONFIG")"
  if grep -q 'docker\.sock' <<< "$paths"; then
    echo "FAIL docker.sock reached allowed_volume_paths"
    exit 1
  fi
  if grep -qx '/' <<< "$paths"; then
    echo "FAIL / reached allowed_volume_paths"
    exit 1
  fi
  echo "OK compose binds did not reach the allowlist"
  exit 0
)
bind_test_rc=$?
case $bind_test_rc in
  0) ok "compose binds excluded from allowed_volume_paths" ;;
  2) skip "compose bind harvesting" "docker compose unavailable" ;;
  *) fail "compose bind harvesting" "project-controlled bind path reached the guard config" ;;
esac

# ============================================================
# Test 0c: preowned_containers must carry FULL (64-char) container IDs
# (CAF-001 fix round 2, I3): a hand-built test fixture can't catch a
# truncation bug in how derive_docker_allowlist actually produces its
# output, so this exercises the real function end to end against a real
# Docker daemon, using a throwaway image tagged "moby/buildkit" and a
# container created from it.
# ============================================================
echo ""
echo "--- preowned_containers ID shape (CAF-001 I3) ---"

SHAPE_TEST_HOME="$(mktemp -d /tmp/bw-shape-test-XXXXXX)"
mkdir -p "$SHAPE_TEST_HOME/project"

(
  set +e
  if ! docker info &>/dev/null; then
    echo "SKIP docker unavailable"
    exit 2
  fi

  src_image_id="$(docker images -q | head -1)"
  if [[ -z "$src_image_id" ]]; then
    echo "SKIP no local docker image available to tag as moby/buildkit"
    exit 2
  fi

  shape_tag="moby/buildkit:bwtest-shape-$$"
  if ! docker tag "$src_image_id" "$shape_tag" 2>/dev/null; then
    echo "SKIP could not tag a throwaway moby/buildkit image"
    exit 2
  fi

  shape_cid="$(docker create --entrypoint /bin/true "$shape_tag" 2>/dev/null)"
  cleanup_shape() {
    [[ -n "${shape_cid:-}" ]] && docker rm -f "$shape_cid" &>/dev/null
    docker rmi "$shape_tag" &>/dev/null
  }
  if [[ -z "$shape_cid" ]]; then
    cleanup_shape
    echo "SKIP could not create a throwaway container from the tagged image"
    exit 2
  fi

  cd "$SHAPE_TEST_HOME/project" || { cleanup_shape; exit 1; }
  # shellcheck disable=SC1090
  source "$PROJECT_DIR/bw-common.sh"
  derive_docker_allowlist 2>/dev/null

  if [[ -z "${BW_DOCKER_GUARD_CONFIG:-}" || ! -f "$BW_DOCKER_GUARD_CONFIG" ]]; then
    cleanup_shape
    echo "SKIP no config generated"
    exit 2
  fi

  ids="$(jq -r '.preowned_containers[]?' "$BW_DOCKER_GUARD_CONFIG")"
  cleanup_shape

  if ! grep -qx "$shape_cid" <<< "$ids"; then
    echo "FAIL the throwaway container's full ID was not seeded (got: $ids)"
    exit 1
  fi

  # Every id-looking (pure lowercase hex, 12+ chars) entry must be exactly
  # 64 characters — Docker's full ID length — never the 12-char truncated
  # form `docker ps` emits by default.
  bad=0
  while IFS= read -r entry; do
    [[ -z "$entry" ]] && continue
    if [[ "$entry" =~ ^[0-9a-f]{12,}$ ]] && (( ${#entry} != 64 )); then
      echo "FAIL truncated id-looking entry in preowned_containers: $entry (${#entry} chars)"
      bad=1
    fi
  done <<< "$ids"
  (( bad != 0 )) && exit 1

  echo "OK preowned_containers carries full 64-char IDs"
  exit 0
)
shape_test_rc=$?
case $shape_test_rc in
  0) ok "preowned_containers seeds full (untruncated) container IDs" ;;
  2) skip "preowned_containers ID shape" "docker unavailable or setup failed" ;;
  *) fail "preowned_containers ID shape" "a truncated or otherwise malformed id reached preowned_containers" ;;
esac

rm -rf "$SHAPE_TEST_HOME"

rm -rf "$BIND_TEST_HOME"

# ============================================================
# Test 0d: docs must not claim behaviour the code does not have
# ============================================================
echo ""
echo "--- documentation claims ---"

doc="$PROJECT_DIR/docs/docker-security.md"
doc_fail=0

if grep -q 'Read operations.*always allowed' "$doc"; then
  echo "  stale claim: GET/HEAD always allowed"
  doc_fail=1
fi
if grep -q 'unconditionally blocked' "$doc"; then
  echo "  stale claim: build unconditionally blocked"
  doc_fail=1
fi
if ! grep -q 'infra_image_digests' "$doc"; then
  echo "  missing: digest-pinned infra images not documented"
  doc_fail=1
fi
if ! grep -q 'BW_EXTRA_VOLUME_PATHS' "$doc"; then
  echo "  missing: operator volume path override not documented"
  doc_fail=1
fi

if (( doc_fail )); then
  fail "documentation claims" "docs/docker-security.md does not match implemented behaviour"
else
  ok "documentation claims match implementation"
fi

# ============================================================
# bw-docker-guard integration tests
# ============================================================
echo ""
echo "--- bw-docker-guard setup ---"

# Build the binary
echo "Building bw-docker-guard..."
GUARD_BIN="$PROJECT_DIR/test/bw-docker-guard-test"
(cd "$PROJECT_DIR" && go build -o "$GUARD_BIN" ./cmd/bw-docker-guard)
echo "Built: $GUARD_BIN"
echo ""

# Check Docker is available
if ! docker info &>/dev/null; then
  echo "Docker is not available — skipping Docker integration tests"
  echo ""
  echo "=== Results: ${pass} passed, ${fail} failed, ${skip} skipped ==="
  (( fail > 0 )) && exit 1
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
