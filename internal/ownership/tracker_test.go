package ownership

import (
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
	tr.Add("abc123def456full7890abcdef")

	// Docker API sometimes uses short IDs (first 12 chars)
	if !tr.IsOwned("abc123def456") {
		t.Error("expected short ID to match full ID prefix")
	}
}

func TestTrackerPrefixMatchReverse(t *testing.T) {
	// When tracker has short ID and query is full ID
	tr := New()
	tr.Add("abc123def456")

	if !tr.IsOwned("abc123def456full7890abcdef") {
		t.Error("expected full ID to match short stored ID")
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

func TestTrackerEmptyNotOwned(t *testing.T) {
	tr := New()
	if tr.IsOwned("anything") {
		t.Error("empty tracker should not own anything")
	}
	if tr.IsExecOwned("anything") {
		t.Error("empty tracker should not own any exec")
	}
}
