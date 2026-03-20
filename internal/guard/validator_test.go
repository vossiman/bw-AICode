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

// Test 19: GET requests always allowed
func TestValidateGETAlwaysAllowed(t *testing.T) {
	v, _ := newTestValidator()

	urls := []string{
		"/containers/json",
		"/v1.45/containers/json",
		"/images/json",
		"/v1.45/networks",
		"/volumes",
	}

	for _, u := range urls {
		t.Run("GET "+u, func(t *testing.T) {
			r := makeRequest("GET", u, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("GET %s should be allowed, got deny: %s", u, d.Reason)
			}
		})
		t.Run("HEAD "+u, func(t *testing.T) {
			r := makeRequest("HEAD", u, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("HEAD %s should be allowed, got deny: %s", u, d.Reason)
			}
		})
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
		// Mounts array (newer Docker API)
		{
			name:  "mount under project dir",
			body:  `{"Image": "postgres:16", "Mounts": [{"Type": "bind", "Source": "/project/data", "Target": "/data"}]}`,
			allow: true,
		},
		{
			name:   "mount outside project dir",
			body:   `{"Image": "postgres:16", "Mounts": [{"Type": "bind", "Source": "/etc/secrets", "Target": "/secrets"}]}`,
			allow:  false,
			reason: "volume",
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
}

// T3: Build endpoint — all builds allowed in guarded mode, denied in read-only
func TestValidateBuild(t *testing.T) {
	v, _ := newTestValidator()

	t.Run("build with tag allowed in guarded mode", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build?t=myimage:latest", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("build should be allowed in guarded mode, got deny: %s", d.Reason)
		}
	})

	t.Run("build without tag allowed in guarded mode", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("build without tag should be allowed in guarded mode, got deny: %s", d.Reason)
		}
	})

	t.Run("build unversioned allowed", func(t *testing.T) {
		r := makeRequest("POST", "/build?t=myimage:latest", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("unversioned build should be allowed in guarded mode, got deny: %s", d.Reason)
		}
	})

	t.Run("build with non-allowlisted tag allowed", func(t *testing.T) {
		r := makeRequest("POST", "/v1.45/build?t=custom:dev", "")
		d := v.Validate(r)
		if !d.Allow {
			t.Errorf("build with any tag should be allowed in guarded mode, got deny: %s", d.Reason)
		}
	})

	t.Run("build denied in read-only mode", func(t *testing.T) {
		rv := newReadOnlyValidator()
		r := makeRequest("POST", "/v1.45/build?t=myimage:latest", "")
		d := rv.Validate(r)
		if d.Allow {
			t.Errorf("build should be denied in read-only mode")
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

	operations := []string{"attach", "wait", "logs", "resize"}

	for _, op := range operations {
		t.Run(op+" owned allowed", func(t *testing.T) {
			r := makeRequest("POST", "/v1.45/containers/owned123abc/"+op, "")
			d := v.Validate(r)
			if !d.Allow {
				t.Errorf("%s owned container should be allowed, got deny: %s", op, d.Reason)
			}
		})

		t.Run(op+" unowned denied", func(t *testing.T) {
			r := makeRequest("POST", "/v1.45/containers/unknown999/"+op, "")
			d := v.Validate(r)
			if d.Allow {
				t.Errorf("%s unowned container should be denied", op)
			}
			if !strings.Contains(strings.ToLower(d.Reason), "not owned") {
				t.Errorf("reason should mention not owned, got: %s", d.Reason)
			}
		})

		t.Run(op+" unversioned owned", func(t *testing.T) {
			r := makeRequest("POST", "/containers/owned123abc/"+op, "")
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
