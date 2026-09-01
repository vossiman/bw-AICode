package ownership

import (
	"strings"
	"sync"
)

// Tracker maintains a set of resource IDs that this proxy "owns"
// (created through it or belonging to the compose project).
type Tracker struct {
	mu         sync.RWMutex
	containers map[string]bool // full container IDs and names
	preowned   map[string]bool // subset of containers seeded host-side (infra), not created this session
	networks   map[string]bool // full network IDs
	execIDs    map[string]bool // exec instance IDs
}

func New() *Tracker {
	return &Tracker{
		containers: make(map[string]bool),
		preowned:   make(map[string]bool),
		networks:   make(map[string]bool),
		execIDs:    make(map[string]bool),
	}
}

func (t *Tracker) Add(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.containers[id] = true
}

// Seed marks containers as owned without them having been created through
// this session. Used for persistent Docker infrastructure containers whose
// IDs are resolved host-side at startup, never from caller-supplied names.
// Seeded containers are also recorded as "preowned" so callers can apply
// stricter rules to them (e.g. denying access in read-only mode) that don't
// apply to containers this session actually created.
func (t *Tracker) Seed(ids []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, id := range ids {
		t.containers[id] = true
		t.preowned[id] = true
	}
}

func (t *Tracker) Remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.containers, id)
}

// isHexRun reports whether s is entirely lowercase hex digits.
func isHexRun(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// isShortContainerID reports whether s could be a Docker short container ID:
// lowercase hex, at least 12 characters (Docker's short-ID length). Anything
// shorter or containing a non-hex character is treated as an opaque name,
// which must match exactly and can never own-by-prefix.
func isShortContainerID(s string) bool {
	return len(s) >= 12 && isHexRun(s)
}

// isFullContainerID reports whether s is shaped like a genuine Docker full
// container ID: exactly 64 lowercase hex characters. Only entries with this
// shape are eligible to be the prefix-match TARGET of a short ID (see
// idOwnedIn) — restricting the target this way means a short hex query can
// only ever resolve to a real, daemon-issued container ID, never to a
// shorter, human-chosen NAME that merely happens to look hex-ish (a crafted
// 12+ character hex name is a legal Docker name).
func isFullContainerID(s string) bool {
	return len(s) == 64 && isHexRun(s)
}

// idOwnedIn checks id against the given set: an exact match always owns; a
// short hex ID additionally owns if some full-ID-shaped entry (see
// isFullContainerID) in the set starts with it. The reverse (an entry
// owning by being a prefix of a longer id) is deliberately not supported:
// without it, a seeded name like "buildx_buildkit_default" would let any
// extension of that name ("buildx_buildkit_default_evil") resolve as owned,
// since the extension trivially has the seeded value as a prefix.
func idOwnedIn(set map[string]bool, id string) bool {
	if set[id] {
		return true
	}
	if isShortContainerID(id) {
		for full := range set {
			if isFullContainerID(full) && strings.HasPrefix(full, id) {
				return true
			}
		}
	}
	return false
}

// prefixOwnedIn is the network-ID equivalent of idOwnedIn, without the
// container-specific hex/length shape restriction (network short-ID prefixes
// in this codebase aren't constrained to Docker's hex ID format). Like
// idOwnedIn, only the forward direction is supported: a query never owns a
// stored value merely by being its extension.
func prefixOwnedIn(set map[string]bool, id string) bool {
	if set[id] {
		return true
	}
	for full := range set {
		if strings.HasPrefix(full, id) {
			return true
		}
	}
	return false
}

// IsOwned checks if the given ID (full or short) matches any owned container,
// whether created through this session or seeded host-side.
func (t *Tracker) IsOwned(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return idOwnedIn(t.containers, id)
}

// IsPreowned reports whether id matches a container that was seeded
// host-side (via Seed) rather than created through this session. Used to
// apply stricter rules to infra containers, such as denying access to them
// in read-only mode even though they are otherwise "owned".
func (t *Tracker) IsPreowned(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return idOwnedIn(t.preowned, id)
}

// AddExecID tracks exec instances.
func (t *Tracker) AddExecID(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.execIDs[id] = true
}

// AddNetwork tracks a network ID or name.
func (t *Tracker) AddNetwork(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.networks[id] = true
}

// RemoveNetwork removes a network from the tracker.
func (t *Tracker) RemoveNetwork(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.networks, id)
}

// IsNetworkOwned checks if the given ID (full or short) matches any owned network.
func (t *Tracker) IsNetworkOwned(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return prefixOwnedIn(t.networks, id)
}

// IsExecOwned checks if an exec instance was created through this proxy.
func (t *Tracker) IsExecOwned(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.execIDs[id]
}
