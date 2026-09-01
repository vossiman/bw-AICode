package ownership

import (
	"strings"
	"sync"
	"testing"
)

func TestTrackerAddAndCheck(t *testing.T) {
	tr := New()
	tr.Add("abc123def456full7890")

	if !tr.IsOwned("abc123def456full7890") {
		t.Error("expected full ID to be owned")
	}
	if tr.IsOwned("xyz789") {
		t.Error("expected xyz789 to NOT be owned")
	}
}

func TestTrackerRemove(t *testing.T) {
	tr := New()
	tr.Add("abc123def456")
	tr.Remove("abc123def456")

	if tr.IsOwned("abc123def456") {
		t.Error("expected abc123def456 to NOT be owned after removal")
	}
}

func TestTrackerPrefixMatch(t *testing.T) {
	tr := New()
	// A genuine Docker full ID: 64 lowercase hex characters. Short-ID
	// prefix matching only targets entries shaped like this (see
	// isFullContainerID / fix round 2, MINOR).
	fullID := "abc123def456" + strings.Repeat("0", 52)
	tr.Add(fullID)

	// Docker API sometimes uses short IDs (first 12 chars)
	if !tr.IsOwned("abc123def456") {
		t.Error("expected short ID to match full ID prefix")
	}
}

// Fix round 2, MINOR: a short hex query must not prefix-match an entry that
// merely LOOKS hex but isn't a genuine 64-char full ID. Without the
// isFullContainerID gate, a crafted 12+ character hex NAME (a legal Docker
// name) seeded or tracked at a length shorter than 64 could be used as a
// prefix-match target it was never meant to be.
func TestShortIDDoesNotMatchNonFullLengthHexEntry(t *testing.T) {
	tr := New()
	// 20 hex characters: passes isShortContainerID's shape check, but is not
	// a 64-character full ID.
	tr.Add("deadbeefcafe12345678")

	if tr.IsOwned("deadbeefcafe") {
		t.Error("a short hex query must not match a non-full-length hex-looking entry by prefix")
	}
}

// CAF-001 fix round 1, C1: was TestTrackerPrefixMatchReverse, which asserted
// that a query extending a stored (short) value resolves as owned. That
// reverse-direction match is exactly what let a request extend a seeded
// name (e.g. "buildx_buildkit_default_evil" extending seeded
// "buildx_buildkit_default") and inherit its ownership. Inverted: a longer
// query is never owned merely by having a shorter stored value as its
// prefix.
func TestTrackerNoReversePrefixMatch(t *testing.T) {
	tr := New()
	tr.Add("abc123def456")

	if tr.IsOwned("abc123def456full7890abcdef") {
		t.Error("a query must not own a stored value by extending it")
	}
}

func TestTrackerExecID(t *testing.T) {
	tr := New()
	tr.AddExecID("exec-abc123")

	if !tr.IsExecOwned("exec-abc123") {
		t.Error("expected exec ID to be owned")
	}
	if tr.IsExecOwned("exec-xyz789") {
		t.Error("expected exec-xyz789 to NOT be owned")
	}
}

func TestTrackerConcurrency(t *testing.T) {
	tr := New()
	var wg sync.WaitGroup

	// Concurrent adds
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			tr.Add(id)
		}(string(rune('a'+i%26)) + "container")
	}
	wg.Wait()

	// Concurrent reads
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(id string) {
			defer wg.Done()
			tr.IsOwned(id)
		}(string(rune('a'+i%26)) + "container")
	}
	wg.Wait()
}

func TestTrackerNameOwnership(t *testing.T) {
	tr := New()
	tr.Add("abc123def456full7890")
	tr.Add("my-container-name")

	if !tr.IsOwned("my-container-name") {
		t.Error("expected container name to be owned")
	}
	if !tr.IsOwned("abc123def456full7890") {
		t.Error("expected container ID to still be owned")
	}
	if tr.IsOwned("other-container") {
		t.Error("expected other-container to NOT be owned")
	}
}

func TestTrackerEmptyNotOwned(t *testing.T) {
	tr := New()
	if tr.IsOwned("anything") {
		t.Error("empty tracker should not own anything")
	}
	if tr.IsExecOwned("anything") {
		t.Error("empty tracker should not own any exec")
	}
}

func TestSeedMarksContainersOwned(t *testing.T) {
	tr := New()
	tr.Seed([]string{"buildx_buildkit_default", "abc123"})

	if !tr.IsOwned("buildx_buildkit_default") {
		t.Error("a seeded container should be owned")
	}
	if !tr.IsOwned("abc123") {
		t.Error("a seeded container ID should be owned")
	}
	if tr.IsOwned("buildx_buildkit_evil") {
		t.Error("a container that was not seeded must not be owned")
	}
}

// CAF-001 fix round 1, C1: a seeded name's EXTENSION must not resolve as
// owned. The old bidirectional prefix match (HasPrefix(id, full)) let any
// string that merely started with a seeded value inherit its ownership.
func TestSeedDoesNotOwnExtensionsOfSeededNames(t *testing.T) {
	tr := New()
	tr.Seed([]string{"buildx_buildkit_default"})

	if tr.IsOwned("buildx_buildkit_default_evil") {
		t.Error("an extension of a seeded name must not be owned")
	}
	if tr.IsOwned("buildx_buildkit_defaultX") {
		t.Error("an extension of a seeded name must not be owned")
	}
}

// Same bug class, but with hex strings so it can't be dismissed as caught
// only by the short-ID shape check: a longer hex string extending a seeded
// 12-char short hex ID must not resolve as owned merely by containing it as
// a prefix.
func TestSeedDoesNotOwnHexExtensionsOfShortSeededID(t *testing.T) {
	tr := New()
	tr.Seed([]string{"abc123def456"}) // 12-char hex "short ID"

	if tr.IsOwned("abc123def456ff") {
		t.Error("a longer hex string extending a seeded short ID must not be owned")
	}
}
