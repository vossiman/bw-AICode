package guard

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/ownership"
)

func newTestValidator() (*Validator, *ownership.Tracker) {
	cfg := &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{"postgres:16", "mcp/postgres", "redis:7"},
		AllowedNetworks: []string{"mynet", "backend"},
		VolumeMountRoot: "/project",
	}
	tracker := ownership.New()
	v := NewValidator(cfg, tracker)
	return v, tracker
}

func newReadOnlyValidator() *Validator {
	cfg := &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{}, // empty = read-only
		AllowedNetworks: []string{},
		VolumeMountRoot: "/project",
	}
	tracker := ownership.New()
	return NewValidator(cfg, tracker)
}

func makeRequest(method, url, body string) *http.Request {
	var r *http.Request
	if body != "" {
		r = httptest.NewRequest(method, url, bytes.NewBufferString(body))
		r.Header.Set("Content-Type", "application/json")
	} else {
		r = httptest.NewRequest(method, url, nil)
	}
	return r
}

// Test 19 (inverted). Was TestValidateGETAlwaysAllowed, which asserted that
// every GET is allowed. A blanket GET allow is CAF-001's cross-container
// read: GET /containers/{any}/archive?path=/ exfiltrates files from
// containers belonging to other projects. The old assertion encoded the
// hole, so it is inverted here rather than deleted.
func TestReadsAreModelledNotBlanketAllowed(t *testing.T) {
	cfg := &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{"postgres:16"},
		VolumeMountRoot: "/project",
	}
	tracker := ownership.New()
	tracker.Add("mine123")
	v := NewValidator(cfg, tracker)

	allowedGlobals := []string{
		"/_ping", "/version", "/info",
		"/containers/json", "/images/json", "/networks", "/volumes",
		"/v1.45/containers/json", "/v1.45/version",
	}
	for _, u := range allowedGlobals {
		t.Run("GET "+u+" allowed", func(t *testing.T) {
			if d := v.Validate(makeRequest("GET", u, "")); !d.Allow {
				t.Errorf("GET %s should be allowed, got deny: %s", u, d.Reason)
			}
		})
		t.Run("HEAD "+u+" allowed", func(t *testing.T) {
			if d := v.Validate(makeRequest("HEAD", u, "")); !d.Allow {
				t.Errorf("HEAD %s should be allowed, got deny: %s", u, d.Reason)
			}
		})
	}

	t.Run("archive of an owned container is allowed", func(t *testing.T) {
		r := makeRequest("GET", "/v1.45/containers/mine123/archive?path=/etc", "")
		if d := v.Validate(r); !d.Allow {
			t.Errorf("owned container archive should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("archive of a foreign container is DENIED", func(t *testing.T) {
		r := makeRequest("GET", "/v1.45/containers/someoneelse/archive?path=/", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: cross-container archive read must be denied")
		}
	})

	t.Run("HEAD archive of a foreign container is DENIED", func(t *testing.T) {
		r := makeRequest("HEAD", "/v1.45/containers/someoneelse/archive?path=/", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: HEAD must be modelled the same as GET")
		}
	})

	t.Run("inspect of a foreign container is denied", func(t *testing.T) {
		r := makeRequest("GET", "/v1.45/containers/someoneelse/json", "")
		if d := v.Validate(r); d.Allow {
			t.Error("inspecting a foreign container must be denied")
		}
	})

	t.Run("logs of a foreign container is denied", func(t *testing.T) {
		r := makeRequest("GET", "/v1.45/containers/someoneelse/logs", "")
		if d := v.Validate(r); d.Allow {
			t.Error("reading a foreign container's logs must be denied")
		}
	})

	t.Run("export of a foreign container is denied", func(t *testing.T) {
		r := makeRequest("GET", "/v1.45/containers/someoneelse/export", "")
		if d := v.Validate(r); d.Allow {
			t.Error("exporting a foreign container's filesystem must be denied")
		}
	})

	t.Run("stats/changes/top of a foreign container are denied", func(t *testing.T) {
		for _, u := range []string{
			"/v1.45/containers/someoneelse/stats",
			"/v1.45/containers/someoneelse/changes",
			"/v1.45/containers/someoneelse/top",
		} {
			if d := v.Validate(makeRequest("GET", u, "")); d.Allow {
				t.Errorf("GET %s must be denied", u)
			}
		}
	})

	t.Run("unmodelled read endpoint is denied", func(t *testing.T) {
		r := makeRequest("GET", "/v1.45/secrets", "")
		if d := v.Validate(r); d.Allow {
			t.Error("an unmodelled read endpoint must be denied by default")
		}
	})

	// Volume names are host-wide visible through /volumes, /system/df
	// (Volumes[].Name) and /containers/json (Mounts[].Name). Denying any one
	// of those routes hides nothing, because /containers/json is what
	// `docker ps` needs and cannot go. Both routes below are allowed, and the
	// residual is closed by response filtering, not by this list.
	t.Run("volume list and inspect are both allowed", func(t *testing.T) {
		for _, u := range []string{"/v1.45/volumes", "/v1.45/volumes/myproj_data"} {
			if d := v.Validate(makeRequest("GET", u, "")); !d.Allow {
				t.Errorf("GET %s should be allowed, got deny: %s", u, d.Reason)
			}
		}
	})
}

// ReImageInspect must take (.+) to accept registry/repository image names,
// and .+ crosses "/". Without a canonical-path requirement, traversal
// reaches container inspect through the image route.
//
// Only the first three paths below are regression proof: they were probed
// against the pre-fix build (commit 8d2fd18) and returned
// allow("image inspect allowed"). The two after them, marked as such, were
// already denied there — ReImageInspect only matches a json|history suffix,
// so an /archive or /export target never reached it. They are coverage for
// the shape, not evidence of a closed hole.
func TestReadTraversalViaImageInspect(t *testing.T) {
	cfg := &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{"postgres:16"},
		VolumeMountRoot: "/project",
	}
	tracker := ownership.New()
	tracker.Add("mine123")
	v := NewValidator(cfg, tracker)

	for _, u := range []string{
		"/images/../containers/someoneelse/json",
		"/images/x/../../containers/someoneelse/json",
		"/v1.45/images/../containers/someoneelse/json",
		// Coverage only, already denied pre-fix (no json|history suffix):
		"/images/../containers/someoneelse/archive",
		"/v1.45/images/a/b/../../../containers/someoneelse/export",
	} {
		t.Run("GET "+u, func(t *testing.T) {
			if d := v.Validate(makeRequest("GET", u, "")); d.Allow {
				t.Errorf("traversal through the image route must be denied, got allow: %s", d.Reason)
			}
		})
	}

	// Real registry/repository names must still inspect fine: the fix is a
	// canonical-path requirement, not a tighter regex.
	for _, u := range []string{
		"/images/postgres/json",
		"/images/library/postgres/json",
		"/v1.45/images/ghcr.io/org/team/img/json",
		"/v1.45/images/ghcr.io/org/img/history",
	} {
		t.Run("GET "+u+" allowed", func(t *testing.T) {
			if d := v.Validate(makeRequest("GET", u, "")); !d.Allow {
				t.Errorf("GET %s should be allowed, got deny: %s", u, d.Reason)
			}
		})
	}
}

// The deny-by-default boundary of the read model: anything that is not an
// exact global path or an exactly-matched modelled route must deny, and no
// path trick may turn a foreign container read into a match.
func TestReadModelBoundary(t *testing.T) {
	cfg := &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{"postgres:16"},
		VolumeMountRoot: "/project",
	}
	tracker := ownership.New()
	tracker.Add("mine123")
	v := NewValidator(cfg, tracker)

	denied := []string{
		// Traversal: net/http hands us the path uncleaned, and the anchored
		// patterns match none of these.
		"/containers/../containers/someoneelse/archive",
		"/containers/mine123/../someoneelse/archive",
		"/v1.45/containers/mine123/archive/../../someoneelse/archive",
		// Percent-encoded separators and dot segments.
		"/containers/mine123%2f..%2fsomeoneelse/archive",
		"/containers/%2e%2e/someoneelse/archive",
		// Trailing slash and empty ID.
		"/version/",
		"/containers/json/",
		"/containers//archive",
		"/v1.45/containers/mine123/archive/",
		// Doubled and malformed version prefixes must not normalise into a
		// match, and must not be stripped into a global allow.
		"/v1.45/v1.45/containers/someoneelse/archive",
		"/v1./containers/mine123/archive",
		"/v../version",
		// Unmodelled reads.
		"/v1.45/secrets",
		"/swarm",
		"/nodes",
		"/tasks",
		"/plugins",
		"/images/search",
		"/containers/mine123/attach/ws",
		// Two entries that once sat in globalReadPaths without being real
		// routes; nothing turns on them, they are here so the map does not
		// quietly regrow them.
		"/build/cache",
		"/distribution",
		"/distribution/postgres/json",
	}
	for _, u := range denied {
		t.Run("GET "+u, func(t *testing.T) {
			if d := v.Validate(makeRequest("GET", u, "")); d.Allow {
				t.Errorf("GET %s must be denied, got allow: %s", u, d.Reason)
			}
		})
	}

	// A container whose *name* looks like an API version prefix is still
	// treated as a container name, not stripped away.
	t.Run("version-shaped container name is not stripped", func(t *testing.T) {
		if d := v.Validate(makeRequest("GET", "/containers/v1.45/json", "")); d.Allow {
			t.Errorf("a container named v1.45 is not owned; got allow: %s", d.Reason)
		}
	})

	// Owned reads still work with and without a version prefix.
	allowed := []string{
		"/containers/mine123/json",
		"/v1.45/containers/mine123/json",
		"/v1.45/containers/mine123/logs",
		"/v1.45/containers/mine123/stats",
		"/v1.45/containers/mine123/top",
		"/v1.45/containers/mine123/changes",
		"/v1.45/containers/mine123/export",
	}
	for _, u := range allowed {
		t.Run("GET "+u+" allowed", func(t *testing.T) {
			if d := v.Validate(makeRequest("GET", u, "")); !d.Allow {
				t.Errorf("GET %s should be allowed, got deny: %s", u, d.Reason)
			}
		})
	}
}

func TestStripVersion(t *testing.T) {
	tests := []struct{ in, want string }{
		{"/version", "/version"},
		{"/v1.45/version", "/version"},
		{"/v1.45.1/containers/json", "/containers/json"},
		{"/v1", "/"},
		{"/v1.45", "/"},
		{"/volumes", "/volumes"},
		{"/v1./containers/json", "/v1./containers/json"},
		{"/v../version", "/v../version"},
		{"/v1.45/v1.45/version", "/v1.45/version"},
		{"/containers/v1.45/json", "/containers/v1.45/json"},
	}
	for _, tt := range tests {
		if got := stripVersion(tt.in); got != tt.want {
			t.Errorf("stripVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// Test 20: Read-only mode denies all writes
func TestValidateReadOnlyMode(t *testing.T) {
	v := newReadOnlyValidator()

	tests := []struct {
		method string
		url    string
		body   string
	}{
		{"POST", "/containers/create", `{"Image": "postgres:16"}`},
		{"POST", "/v1.45/containers/create", `{"Image": "postgres:16"}`},
		{"DELETE", "/v1.45/containers/abc123", ""},
		{"POST", "/v1.45/images/create?fromImage=postgres:16", ""},
		{"PUT", "/something", ""},
	}

	for _, tt := range tests {
		t.Run(tt.method+" "+tt.url, func(t *testing.T) {
			r := makeRequest(tt.method, tt.url, tt.body)
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("read-only mode should deny %s %s", tt.method, tt.url)
			}
			if !strings.Contains(d.Reason, "read-only") {
				t.Errorf("reason should mention read-only, got: %s", d.Reason)
			}
		})
	}

	// GET should still work in read-only mode
	r := makeRequest("GET", "/containers/json", "")
	d := v.Validate(r)
	if !d.Allow {
		t.Errorf("GET should be allowed in read-only mode, got deny: %s", d.Reason)
	}
}

// Tests 1-10: Container create scenarios
func TestValidateContainerCreate(t *testing.T) {
	cfg := &config.Config{
		ProjectDir:      "/project",
		AllowedImages:   []string{"postgres:16", "mcp/postgres"},
		AllowedNetworks: []string{"mynet"},
		VolumeMountRoot: "/project",
	}
	tracker := ownership.New()
	v := NewValidator(cfg, tracker)

	tests := []struct {
		name   string
		body   string
		allow  bool
		reason string // substring to check in reason
	}{
		// Test 1: Allowed image
		{
			name:  "allowed image",
			body:  `{"Image": "postgres:16"}`,
			allow: true,
		},
		// Test 2: Disallowed image
		{
			name:   "disallowed image",
			body:   `{"Image": "alpine"}`,
			allow:  false,
			reason: "image",
		},
		// Test 3: Volume mount under project dir
		{
			name:  "volume mount under project dir",
			body:  `{"Image": "postgres:16", "HostConfig": {"Binds": ["/project/data:/var/lib/data"]}}`,
			allow: true,
		},
		// Named volume (not a path) — should be allowed
		{
			name:  "named volume (Docker-managed)",
			body:  `{"Image": "postgres:16", "HostConfig": {"Binds": ["myapp_data:/var/lib/data"]}}`,
			allow: true,
		},
		// Relative path under project dir — allowed
		{
			name:  "relative path under project dir",
			body:  `{"Image": "postgres:16", "HostConfig": {"Binds": ["./data:/var/lib/data"]}}`,
			allow: true,
		},
		// Relative path traversal outside project — denied
		{
			name:   "relative path traversal",
			body:   `{"Image": "postgres:16", "HostConfig": {"Binds": ["../../etc/passwd:/etc/passwd"]}}`,
			allow:  false,
			reason: "volume",
		},
		// Test 4: Volume mount outside project dir
		{
			name:   "volume mount outside project dir",
			body:   `{"Image": "postgres:16", "HostConfig": {"Binds": ["/etc/passwd:/etc/passwd"]}}`,
			allow:  false,
			reason: "volume",
		},
		// Test 5: Volume mounting docker.sock
		{
			name:   "volume mounting docker.sock",
			body:   `{"Image": "postgres:16", "HostConfig": {"Binds": ["/var/run/docker.sock:/var/run/docker.sock"]}}`,
			allow:  false,
			reason: "volume",
		},
		// Test 6: Privileged true
		{
			name:   "privileged container",
			body:   `{"Image": "postgres:16", "HostConfig": {"Privileged": true}}`,
			allow:  false,
			reason: "privileged",
		},
		// Test 7: PidMode host
		{
			name:   "pid mode host",
			body:   `{"Image": "postgres:16", "HostConfig": {"PidMode": "host"}}`,
			allow:  false,
			reason: "pid",
		},
		// Test 8: NetworkMode host
		{
			name:   "network mode host",
			body:   `{"Image": "postgres:16", "HostConfig": {"NetworkMode": "host"}}`,
			allow:  false,
			reason: "network mode",
		},
		// Test 9: CapAdd non-empty
		{
			name:   "cap add non-empty",
			body:   `{"Image": "postgres:16", "HostConfig": {"CapAdd": ["SYS_ADMIN"]}}`,
			allow:  false,
			reason: "capabilities",
		},
		// Test 10: Devices non-empty
		{
			name:   "devices non-empty",
			body:   `{"Image": "postgres:16", "HostConfig": {"Devices": [{"PathOnHost": "/dev/sda"}]}}`,
			allow:  false,
			reason: "device",
		},
		// Mounts array (newer Docker API). Docker only reads mounts from
		// HostConfig.Mounts, so both cases below post there; a top-level
		// Mounts key is a no-op and must never be what makes a test pass.
		{
			name:  "mount under project dir",
			body:  `{"Image": "postgres:16", "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/project/data", "Target": "/data"}]}}`,
			allow: true,
		},
		{
			name:   "mount outside project dir",
			body:   `{"Image": "postgres:16", "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/etc/secrets", "Target": "/secrets"}]}}`,
			allow:  false,
			reason: "volume",
		},
		// Round-2 fix: mount Type is now default-deny. "volume" (including an
		// inline local-driver bind of host root via VolumeOptions.DriverConfig)
		// must be denied outright, without needing to parse VolumeOptions at all.
		{
			name:   "mount type volume with inline local-driver host bind is denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"Mounts": [{"Type": "volume", "Target": "/host", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"type": "none", "device": "/", "o": "bind"}}}}]}}`,
			allow:  false,
			reason: "mount type",
		},
		{
			name:  "mount type tmpfs is allowed",
			body:  `{"Image": "postgres:16", "HostConfig": {"Mounts": [{"Type": "tmpfs", "Target": "/tmp/scratch"}]}}`,
			allow: true,
		},
		// Privileged false should be fine
		{
			name:  "privileged false is ok",
			body:  `{"Image": "postgres:16", "HostConfig": {"Privileged": false}}`,
			allow: true,
		},
		// Empty body (missing image)
		{
			name:   "missing image",
			body:   `{}`,
			allow:  false,
			reason: "image",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := makeRequest("POST", "/containers/create", tt.body)
			d := v.Validate(r)
			if d.Allow != tt.allow {
				t.Errorf("expected allow=%v, got allow=%v (reason: %s)", tt.allow, d.Allow, d.Reason)
			}
			if !tt.allow && tt.reason != "" {
				if !strings.Contains(strings.ToLower(d.Reason), strings.ToLower(tt.reason)) {
					t.Errorf("reason %q should contain %q", d.Reason, tt.reason)
				}
			}
		})
	}
}

// Test 23: Versioned URL works same as unversioned
func TestValidateContainerCreateVersioned(t *testing.T) {
	v, _ := newTestValidator()

	tests := []struct {
		name string
		url  string
	}{
		{"unversioned", "/containers/create"},
		{"v1.45", "/v1.45/containers/create"},
		{"v1.40", "/v1.40/containers/create"},
		{"v1.43.0", "/v1.43.0/containers/create"},
	}

	for _, tt := range tests {
		t.Run(tt.name+" allowed", func(t *testing.T) {
			r := makeRequest("POST", tt.url, `{"Image": "postgres:16"}`)
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("%s: expected allow, got deny: %s", tt.url, d.Reason)
			}
		})
		t.Run(tt.name+" denied", func(t *testing.T) {
			r := makeRequest("POST", tt.url, `{"Image": "evil:latest"}`)
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("%s: expected deny for disallowed image", tt.url)
			}
		})
	}
}

// Tests 11-13: Container lifecycle (start/stop/restart/kill) ownership checks
// Test 24: All lifecycle operations check ownership
func TestValidateContainerLifecycle(t *testing.T) {
	v, tracker := newTestValidator()
	tracker.Add("owned123abc")

	operations := []string{"start", "stop", "restart", "kill"}

	for _, op := range operations {
		// Test 11/13: Owned container operations → allow
		t.Run(op+" owned container", func(t *testing.T) {
			r := makeRequest("POST", "/v1.45/containers/owned123abc/"+op, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("%s owned container should be allowed, got deny: %s", op, d.Reason)
			}
		})

		// Test 12: Unowned container operations → deny
		t.Run(op+" unowned container", func(t *testing.T) {
			r := makeRequest("POST", "/v1.45/containers/unknown999/"+op, "")
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("%s unowned container should be denied", op)
			}
			if !strings.Contains(strings.ToLower(d.Reason), "not owned") {
				t.Errorf("reason should mention not owned, got: %s", d.Reason)
			}
		})

		// Unversioned URL also works
		t.Run(op+" unversioned owned", func(t *testing.T) {
			r := makeRequest("POST", "/containers/owned123abc/"+op, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("unversioned %s owned container should be allowed, got deny: %s", op, d.Reason)
			}
		})
	}
}

// DELETE container ownership check
func TestValidateContainerDelete(t *testing.T) {
	v, tracker := newTestValidator()
	tracker.Add("owned123abc")

	t.Run("delete owned container", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.45/containers/owned123abc", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("delete owned container should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("delete unowned container", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.45/containers/unknown999", "")
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("delete unowned container should be denied")
		}
	})

	t.Run("delete unversioned owned", func(t *testing.T) {
		r := makeRequest("DELETE", "/containers/owned123abc", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned delete owned container should be allowed, got deny: %s", d.Reason)
		}
	})
}

// Tests 14-16: Exec operations
func TestValidateExec(t *testing.T) {
	v, tracker := newTestValidator()
	tracker.Add("owned123abc")

	// Test 14: Exec on owned container → allow
	t.Run("exec on owned container", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/owned123abc/exec", `{"Cmd": ["sh"]}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("exec on owned container should be allowed, got deny: %s", d.Reason)
		}
	})

	// Test 15: Privileged exec → deny
	t.Run("privileged exec", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/owned123abc/exec", `{"Cmd": ["sh"], "Privileged": true}`)
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("privileged exec should be denied")
		}
		if !strings.Contains(strings.ToLower(d.Reason), "privileged") {
			t.Errorf("reason should mention privileged, got: %s", d.Reason)
		}
	})

	// Test 16: Exec on unowned container → deny
	t.Run("exec on unowned container", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/unknown999/exec", `{"Cmd": ["sh"]}`)
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("exec on unowned container should be denied")
		}
	})

	// Unversioned exec
	t.Run("exec unversioned owned", func(t *testing.T) {
		r := makeRequest("POST", "/containers/owned123abc/exec", `{"Cmd": ["sh"]}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned exec on owned container should be allowed, got deny: %s", d.Reason)
		}
	})
}

// Exec start checks exec ownership
func TestValidateExecStart(t *testing.T) {
	v, tracker := newTestValidator()
	tracker.AddExecID("exec123")

	t.Run("start owned exec", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/exec/exec123/start", `{}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("start owned exec should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("start unowned exec", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/exec/unknown999/start", `{}`)
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("start unowned exec should be denied")
		}
	})

	t.Run("start exec unversioned", func(t *testing.T) {
		r := makeRequest("POST", "/exec/exec123/start", `{}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned start owned exec should be allowed, got deny: %s", d.Reason)
		}
	})
}

// Tests 17-18: Image pull
func TestValidateImagePull(t *testing.T) {
	v, _ := newTestValidator()

	// Test 17: Allowed image pull
	t.Run("allowed image pull", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/images/create?fromImage=postgres:16", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("allowed image pull should be allowed, got deny: %s", d.Reason)
		}
	})

	// Test 18: Disallowed image pull
	t.Run("disallowed image pull", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/images/create?fromImage=alpine", "")
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("disallowed image pull should be denied")
		}
		if !strings.Contains(strings.ToLower(d.Reason), "image") {
			t.Errorf("reason should mention image, got: %s", d.Reason)
		}
	})

	// Unversioned
	t.Run("unversioned image pull", func(t *testing.T) {
		r := makeRequest("POST", "/images/create?fromImage=redis:7", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned allowed image pull should be allowed, got deny: %s", d.Reason)
		}
	})

	// Docker infrastructure image (moby/buildkit) is matched by content
	// digest, never by name (CAF-001). Pulling by name alone must NOT be
	// treated as infra unless it is also on the plain image allowlist.
	t.Run("buildkit digest-pinned image pull allowed", func(t *testing.T) {
		vDigest, _ := newTestValidator()
		digest := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		vDigest.config.InfraImageDigests = []string{digest}
		r := makeRequest("POST", "/v1.45/images/create?fromImage=moby/buildkit@"+digest, "")
		d := vDigest.Validate(r)
		if !d.Allow {
			t.Errorf("digest-pinned moby/buildkit pull should be allowed as docker infra image, got deny: %s", d.Reason)
		}
	})

	t.Run("buildkit name-only pull without digest denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/images/create?fromImage=docker.io/moby/buildkit:buildx-stable-1", "")
		d := v.Validate(r)
		if d.Allow {
			t.Error("CAF-001: an infra image pull without the pinned digest must be denied")
		}
	})
}

// Was TestValidateContainerCreateBuildkitInfra, which asserted that a
// privileged moby/buildkit create must be ALLOWED on the strength of its
// name alone. That is CAF-001 step 2. Inverted here.
func TestValidateContainerCreateInfraDigestOnly(t *testing.T) {
	digest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	cfg := &config.Config{
		ProjectDir:        "/project",
		AllowedImages:     []string{"postgres:16"},
		AllowedNetworks:   []string{"mynet"},
		VolumeMountRoot:   "/project",
		InfraImageDigests: []string{digest},
	}
	v := NewValidator(cfg, ownership.New())

	t.Run("self-minted infra NAME is denied", func(t *testing.T) {
		body := `{"Image": "docker.io/moby/buildkit:pwn", "HostConfig": {}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: an image named moby/buildkit without the pinned digest must be denied")
		}
	})

	t.Run("self-minted infra name with privileged is denied", func(t *testing.T) {
		body := `{"Image": "moby/buildkit:pwn", "HostConfig": {"Privileged": true}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: the escape chain's step 2 must be denied")
		}
	})

	// Was "real infra digest may be privileged". The infra Privileged
	// relaxation is gone: the digest pins the image's CONTENT, while the
	// COMMAND stays caller-supplied through Entrypoint, Cmd or Healthcheck,
	// so the relaxation was a root shell in a privileged container behind a
	// public registry digest. It bought nothing real either — bw-common.sh
	// seeds builders that already exist host-side, so the guard only has to
	// operate a privileged builder, never create one.
	t.Run("real infra digest may NOT be privileged", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"Privileged": true}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("a digest match must not relax Privileged for any image")
		}
	})

	t.Run("real infra digest may be created unprivileged", func(t *testing.T) {
		// The relaxation a digest match still buys: the image may be NAMED
		// without being in the allowlist. Without this control, the denies
		// throughout this test would pass vacuously.
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); !d.Allow {
			t.Errorf("a digest-matched infra image must still be creatable: %s", d.Reason)
		}
	})

	t.Run("real infra digest may NOT mount the host", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"Binds": ["/:/host"]}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("infra trust must relax Privileged only, never bind mounts")
		}
	})

	// Round-1 fix: HostConfig.Mounts (the field the real Docker Engine API
	// reads) was not checked at all — only a top-level Mounts key, which
	// Docker ignores. A digest-matched infra image could bind-mount host
	// root via HostConfig.Mounts and sail through every check.
	t.Run("real infra digest may NOT mount the host via HostConfig.Mounts", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"Mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}]}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: HostConfig.Mounts bind of / must be denied even for a digest-matched infra image")
		}
	})

	// Round-2 fix: mount Type was checked only for "bind"; "volume" with an
	// inline local-driver bind mounts the host without ever setting Source
	// or Type=="bind" (Docker builds the volume from VolumeOptions.DriverConfig).
	// This is the exact PoC from review: /:/host via a "local" driver bind
	// option, on the digest-matched infra image.
	t.Run("real infra digest may NOT mount the host via an inline volume-driver bind", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"Mounts": [{"Type": "volume", "Target": "/host", "VolumeOptions": {"DriverConfig": {"Name": "local", "Options": {"type": "none", "device": "/", "o": "bind"}}}}]}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: an inline local-driver volume bind of / must be denied even for a digest-matched infra image")
		}
	})

	t.Run("real infra digest may NOT add capabilities", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"CapAdd": ["SYS_ADMIN"]}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("infra trust must not permit CapAdd")
		}
	})

	t.Run("real infra digest may NOT use host pid namespace", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"PidMode": "host"}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("infra trust must not permit host pid namespace")
		}
	})

	// Round-1 fix: only the literal "host" value was checked; "container:<id>"
	// joins another container's namespace, a plausible pivot into the
	// genuinely-privileged buildkit container's namespace.
	t.Run("real infra digest may NOT join another container's pid namespace", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"PidMode": "container:some-other-id"}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: container:<id> pid namespace must be denied, not just literal host")
		}
	})

	// Round-2 fix: IpcMode also accepts "container:<id>", joining another
	// container's IPC namespace (and its shared memory) — including,
	// plausibly, the one container the guard permits to be privileged.
	t.Run("real infra digest may NOT join another container's IPC namespace", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"IpcMode": "container:some-other-id"}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: container:<id> IPC namespace must be denied, not just literal host")
		}
	})

	t.Run("real infra digest may NOT join another container's network namespace", func(t *testing.T) {
		body := `{"Image": "moby/buildkit@` + digest + `", "HostConfig": {"NetworkMode": "container:some-other-id"}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: container:<id> network namespace must be denied, not just literal host")
		}
	})

	t.Run("non-infra privileged container still denied", func(t *testing.T) {
		body := `{"Image": "postgres:16", "HostConfig": {"Privileged": true}}`
		r := makeRequest("POST", "/v1.45/containers/create", body)
		if d := v.Validate(r); d.Allow {
			t.Error("privileged non-infra container should be denied")
		}
	})
}

// Was TestValidateBuildkitContainerActions, which asserted that any
// container whose NAME starts with buildx_buildkit_ may be started and
// stopped without ownership. Inverted: only host-seeded containers are.
func TestBuildkitPrefixGrantsNothing(t *testing.T) {
	cfg := &config.Config{
		ProjectDir:         "/project",
		AllowedImages:      []string{"postgres:16"},
		VolumeMountRoot:    "/project",
		PreownedContainers: []string{"buildx_buildkit_default"},
	}
	tracker := ownership.New()
	tracker.Seed(cfg.PreownedContainers)
	v := NewValidator(cfg, tracker)

	t.Run("seeded buildkit container may be started", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/buildx_buildkit_default/start", "")
		if d := v.Validate(r); !d.Allow {
			t.Errorf("a host-seeded container should be actionable, got deny: %s", d.Reason)
		}
	})

	t.Run("unseeded container with the magic prefix is denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/buildx_buildkit_evil/start", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: the buildx_buildkit_ prefix must not grant ownership")
		}
	})

	t.Run("unseeded prefix container cannot be exec'd", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/buildx_buildkit_evil/exec", `{}`)
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: prefix must not grant exec")
		}
	})

	t.Run("unseeded prefix container cannot be deleted", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.45/containers/buildx_buildkit_evil", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001: prefix must not grant delete")
		}
	})

	t.Run("ordinary unowned container still denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/random_container/start", "")
		if d := v.Validate(r); d.Allow {
			t.Error("starting an unowned container should be denied")
		}
	})

	// C1 (fix round 1): an extension of a seeded name must not inherit its
	// ownership. The old bidirectional prefix match let
	// "buildx_buildkit_default_evil" resolve as owned because it starts
	// with the seeded "buildx_buildkit_default".
	t.Run("extension of a seeded name is denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/buildx_buildkit_default_evil/start", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001 C1: an extension of a seeded container name must not be owned")
		}
	})
}

// I1 (fix round 1): bw-common.sh now seeds both the container's full ID and
// its name, so a request addressed either way must resolve to the same
// seeded container.
func TestSeededContainerResolvesByFullAndShortID(t *testing.T) {
	fullID := strings.Repeat("a1", 32) // 64-char hex, Docker's full ID length
	shortID := fullID[:12]

	cfg := &config.Config{
		ProjectDir:         "/project",
		AllowedImages:      []string{"postgres:16"},
		VolumeMountRoot:    "/project",
		PreownedContainers: []string{fullID, "buildx_buildkit_default"},
	}
	tracker := ownership.New()
	tracker.Seed(cfg.PreownedContainers)
	v := NewValidator(cfg, tracker)

	t.Run("resolves by full ID", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/"+fullID+"/start", "")
		if d := v.Validate(r); !d.Allow {
			t.Errorf("a request by the seeded full ID should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("resolves by short ID", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/"+shortID+"/start", "")
		if d := v.Validate(r); !d.Allow {
			t.Errorf("a request by the seeded container's short ID should be allowed, got deny: %s", d.Reason)
		}
	})
}

// C2 (fix round 1): read-only mode must deny actions on infra (preowned)
// containers regardless of ownership. The old isDockerInfraContainer check
// enforced this floor explicitly; the seeding-based replacement dropped it,
// which would have let a read-only session exec into a seeded buildkit
// container. Calls the unexported validate methods directly so the read-only
// floor inside checkContainerUsable is exercised even though Validate's
// blanket read-only gate would also catch this case for POST/DELETE methods.
func TestReadOnlyDeniesPreownedContainerActions(t *testing.T) {
	cfg := &config.Config{
		ProjectDir:         "/project",
		AllowedImages:      []string{}, // empty = read-only
		VolumeMountRoot:    "/project",
		PreownedContainers: []string{"buildx_buildkit_default"},
	}
	tracker := ownership.New()
	tracker.Seed(cfg.PreownedContainers)
	v := NewValidator(cfg, tracker)

	t.Run("checkContainerUsable denies a preowned container in read-only mode", func(t *testing.T) {
		if d := v.checkContainerUsable("buildx_buildkit_default"); d == nil || d.Allow {
			t.Error("CAF-001 C2: read-only mode must deny actions on a preowned infra container")
		}
	})

	t.Run("exec create denies via the internal validator", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/buildx_buildkit_default/exec", `{}`)
		if d := v.validateContainerExec(r); d.Allow {
			t.Error("CAF-001 C2: exec on a preowned container must be denied in read-only mode")
		}
	})

	t.Run("end-to-end via Validate is also denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/containers/buildx_buildkit_default/exec", `{}`)
		if d := v.Validate(r); d.Allow {
			t.Error("read-only mode should deny exec end-to-end")
		}
	})
}

// T3: Build endpoint — the -t tag must be allowlisted, in every mode.
//
// Was TestValidateBuild, which asserted "build with any tag should be
// allowed in guarded mode". That is CAF-001 step 1: the tag is how the
// attacker mints an infra-looking image name. Inverted here.
func TestValidateBuildTagMustBeAllowlisted(t *testing.T) {
	v, _ := newTestValidator() // allows postgres:16, mcp/postgres, redis:7

	t.Run("build tagged as an allowlisted image is allowed", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build?t=postgres:16", "")
		if d := v.Validate(r); !d.Allow {
			t.Errorf("allowlisted build tag should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("build minting an infra name is denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build?t=moby/buildkit:pwn", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001 step 1: minting moby/buildkit via -t must be denied")
		}
	})

	t.Run("build with an arbitrary tag is denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build?t=custom:dev", "")
		if d := v.Validate(r); d.Allow {
			t.Error("a non-allowlisted build tag must be denied")
		}
	})

	t.Run("untagged build is denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build", "")
		if d := v.Validate(r); d.Allow {
			t.Error("an untagged build produces an uncheckable image and must be denied")
		}
	})

	t.Run("every tag is checked, not just the first", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build?t=postgres:16&t=moby/buildkit:pwn", "")
		if d := v.Validate(r); d.Allow {
			t.Error("a second, non-allowlisted tag must still be denied")
		}
	})

	t.Run("unversioned path is treated the same", func(t *testing.T) {
		r := makeRequest("POST", "/build?t=custom:dev", "")
		if d := v.Validate(r); d.Allow {
			t.Error("the /build path without an API version must be checked too")
		}
	})

	t.Run("build denied in read-only mode", func(t *testing.T) {
		rv := newReadOnlyValidator()
		r := makeRequest("POST", "/v1.45/build?t=postgres:16", "")
		if d := rv.Validate(r); d.Allow {
			t.Error("build should be denied in read-only mode")
		}
	})
}

func TestValidateImageLoadDenied(t *testing.T) {
	v, _ := newTestValidator()

	// A tar's embedded repo-tags cannot be checked without unpacking it, so
	// /images/load is the same minting primitive as an unconstrained build.
	t.Run("image load denied in guarded mode", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/images/load", "")
		if d := v.Validate(r); d.Allow {
			t.Error("CAF-001 step 1: /images/load can mint any tag and must be denied")
		}
	})

	t.Run("image load denied in read-only mode", func(t *testing.T) {
		rv := newReadOnlyValidator()
		r := makeRequest("POST", "/v1.45/images/load", "")
		if d := rv.Validate(r); d.Allow {
			t.Error("image load should be denied in read-only mode")
		}
	})
}

// Network create
func TestValidateNetworkCreate(t *testing.T) {
	v, _ := newTestValidator()

	t.Run("allowed network", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/networks/create", `{"Name": "mynet"}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("allowed network should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("disallowed network", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/networks/create", `{"Name": "evil_net"}`)
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("disallowed network should be denied")
		}
		if !strings.Contains(strings.ToLower(d.Reason), "network") {
			t.Errorf("reason should mention network, got: %s", d.Reason)
		}
	})

	t.Run("unversioned network create", func(t *testing.T) {
		r := makeRequest("POST", "/networks/create", `{"Name": "backend"}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned allowed network should be allowed, got deny: %s", d.Reason)
		}
	})
}

// DELETE network ownership check
func TestValidateNetworkDelete(t *testing.T) {
	v, tracker := newTestValidator()
	tracker.AddNetwork("net123fullid")
	tracker.AddNetwork("mynet")

	t.Run("delete owned network by ID", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.45/networks/net123fullid", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("delete owned network should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("delete owned network by name", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.50/networks/mynet", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("delete owned network by name should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("delete unowned network", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.45/networks/unknown999", "")
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("delete unowned network should be denied")
		}
		if !strings.Contains(strings.ToLower(d.Reason), "not owned") {
			t.Errorf("reason should mention not owned, got: %s", d.Reason)
		}
	})

	t.Run("delete network short ID prefix match", func(t *testing.T) {
		r := makeRequest("DELETE", "/v1.45/networks/net123full", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("delete network by short ID should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("delete network unversioned", func(t *testing.T) {
		r := makeRequest("DELETE", "/networks/net123fullid", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned delete owned network should be allowed, got deny: %s", d.Reason)
		}
	})
}

// Test 21: Unknown POST endpoint → deny
func TestValidateUnknownEndpoint(t *testing.T) {
	v, _ := newTestValidator()

	tests := []struct {
		name   string
		method string
		url    string
	}{
		{"POST unknown", "POST", "/v1.45/something/random"},
		{"PUT unknown", "PUT", "/v1.45/containers/abc/update"},
		{"DELETE unknown", "DELETE", "/v1.45/images/abc123"},
		{"POST unknown unversioned", "POST", "/something"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := makeRequest(tt.method, tt.url, "")
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("%s %s should be denied", tt.method, tt.url)
			}
			if !strings.Contains(strings.ToLower(d.Reason), "not allowed") {
				t.Errorf("reason should mention not allowed, got: %s", d.Reason)
			}
		})
	}
}

// Test 22: POST /volumes/create → deny
func TestValidateVolumesCreate(t *testing.T) {
	v, _ := newTestValidator()

	t.Run("volumes create denied", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/volumes/create", `{"Name": "myvolume"}`)
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("volumes/create should be denied")
		}
	})

	t.Run("volumes create unversioned denied", func(t *testing.T) {
		r := makeRequest("POST", "/volumes/create", `{"Name": "myvolume"}`)
		d := v.Validate(r)
		if d.Allow {
			t.Errorf("unversioned volumes/create should be denied")
		}
	})
}

// Verify body is re-buffered after reading
func TestValidateBodyReBuffered(t *testing.T) {
	v, _ := newTestValidator()

	body := `{"Image": "postgres:16"}`
	r := makeRequest("POST", "/v1.45/containers/create", body)
	_ = v.Validate(r)

	// Body should still be readable after Validate
	buf := new(bytes.Buffer)
	if r.Body != nil {
		_, err := buf.ReadFrom(r.Body)
		if err != nil {
			t.Fatalf("failed to read body after Validate: %v", err)
		}
	}
	if buf.String() != body {
		t.Errorf("body should be re-buffered, got %q, want %q", buf.String(), body)
	}
}

// Container create with invalid JSON should deny gracefully
func TestValidateContainerCreateInvalidJSON(t *testing.T) {
	v, _ := newTestValidator()

	r := makeRequest("POST", "/v1.45/containers/create", `{invalid json}`)
	d := v.Validate(r)
	if d.Allow {
		t.Errorf("invalid JSON body should be denied")
	}
}

// T2: VolumesFrom, SecurityOpt, UsernsMode/IpcMode/CgroupnsMode/UTSMode host denied
func TestValidateContainerCreateNewHostConfigFields(t *testing.T) {
	v, _ := newTestValidator()

	tests := []struct {
		name   string
		body   string
		reason string
	}{
		{
			name:   "VolumesFrom denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"VolumesFrom": ["other-container"]}}`,
			reason: "volumesfrom",
		},
		{
			name:   "SecurityOpt denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"SecurityOpt": ["apparmor=unconfined"]}}`,
			reason: "securityopt",
		},
		{
			name:   "UsernsMode host denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"UsernsMode": "host"}}`,
			reason: "user namespace",
		},
		{
			name:   "IpcMode host denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"IpcMode": "host"}}`,
			reason: "ipc",
		},
		{
			name:   "CgroupnsMode host denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"CgroupnsMode": "host"}}`,
			reason: "cgroup",
		},
		{
			name:   "UTSMode host denied",
			body:   `{"Image": "postgres:16", "HostConfig": {"UTSMode": "host"}}`,
			reason: "uts",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := makeRequest("POST", "/containers/create", tt.body)
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("expected deny for %s", tt.name)
			}
			if !strings.Contains(strings.ToLower(d.Reason), strings.ToLower(tt.reason)) {
				t.Errorf("reason %q should contain %q", d.Reason, tt.reason)
			}
		})
	}

	// Non-host values should be allowed
	t.Run("UsernsMode non-host allowed", func(t *testing.T) {
		r := makeRequest("POST", "/containers/create", `{"Image": "postgres:16", "HostConfig": {"UsernsMode": "private"}}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("non-host UsernsMode should be allowed, got deny: %s", d.Reason)
		}
	})

	t.Run("IpcMode non-host allowed", func(t *testing.T) {
		r := makeRequest("POST", "/containers/create", `{"Image": "postgres:16", "HostConfig": {"IpcMode": "private"}}`)
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("non-host IpcMode should be allowed, got deny: %s", d.Reason)
		}
	})
}

// T4: /attach, /wait, /logs, /resize — owned allowed, unowned denied
func TestValidateContainerAccess(t *testing.T) {
	v, tracker := newTestValidator()
	tracker.Add("owned123abc")

	// /logs is a GET in the Docker API and is now decided by the read model,
	// so it is exercised with its real method; POST /logs is not a route and
	// is denied by default.
	operations := []struct{ method, op string }{
		{"POST", "attach"},
		{"POST", "wait"},
		{"GET", "logs"},
		{"POST", "resize"},
	}

	for _, tc := range operations {
		method, op := tc.method, tc.op
		t.Run(op+" owned allowed", func(t *testing.T) {
			r := makeRequest(method, "/v1.45/containers/owned123abc/"+op, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("%s owned container should be allowed, got deny: %s", op, d.Reason)
			}
		})

		t.Run(op+" unowned denied", func(t *testing.T) {
			r := makeRequest(method, "/v1.45/containers/unknown999/"+op, "")
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("%s unowned container should be denied", op)
			}
			if !strings.Contains(strings.ToLower(d.Reason), "not owned") {
				t.Errorf("reason should mention not owned, got: %s", d.Reason)
			}
		})

		t.Run(op+" unversioned owned", func(t *testing.T) {
			r := makeRequest(method, "/containers/owned123abc/"+op, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("unversioned %s owned should be allowed, got deny: %s", op, d.Reason)
			}
		})
	}
}

// T5: Oversized body (>10MB) denied
func TestValidateOversizedBody(t *testing.T) {
	v, _ := newTestValidator()

	// Create a body larger than 10MB
	bigBody := `{"Image": "postgres:16", "data": "` + strings.Repeat("x", 11*1024*1024) + `"}`
	r := makeRequest("POST", "/containers/create", bigBody)
	d := v.Validate(r)
	if d.Allow {
		t.Errorf("oversized body should be denied")
	}
	if !strings.Contains(strings.ToLower(d.Reason), "body") {
		t.Errorf("reason should mention body, got: %s", d.Reason)
	}
}
