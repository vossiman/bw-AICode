package ownership

import (
	"strings"
	"sync"
)

// Tracker maintains a set of container IDs that this proxy "owns"
// (created through it or belonging to the compose project).
type Tracker struct {
	mu         sync.RWMutex
	containers map[string]bool // full container IDs
	execIDs    map[string]bool // exec instance IDs
}

func New() *Tracker {
	return &Tracker{
		containers: make(map[string]bool),
		execIDs:    make(map[string]bool),
	}
}

func (t *Tracker) Add(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.containers[id] = true
}

func (t *Tracker) Remove(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.containers, id)
}

// IsOwned checks if the given ID (full or short) matches any owned container.
func (t *Tracker) IsOwned(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	// Docker container IDs and names: check containers map
	// Exact match first
	if t.containers[id] {
		return true
	}

	// Prefix match: Docker uses 12-char short IDs
	for full := range t.containers {
		if strings.HasPrefix(full, id) || strings.HasPrefix(id, full) {
			return true
		}
	}
	return false
}

// AddExecID tracks exec instances.
func (t *Tracker) AddExecID(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.execIDs[id] = true
}

// IsExecOwned checks if an exec instance was created through this proxy.
func (t *Tracker) IsExecOwned(id string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.execIDs[id]
}
