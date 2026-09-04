package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	err := os.WriteFile(path, []byte(`{
		"project_dir": "/home/user/myproject",
		"compose_project": "myproject",
		"allowed_images": ["postgres:16", "mcp/postgres"],
		"allowed_networks": ["myproject_default"],
		"volume_mount_root": "/home/user/myproject"
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error: %v", path, err)
	}
	if cfg.ProjectDir != "/home/user/myproject" {
		t.Errorf("ProjectDir = %q, want /home/user/myproject", cfg.ProjectDir)
	}
	if len(cfg.AllowedImages) != 2 {
		t.Errorf("AllowedImages len = %d, want 2", len(cfg.AllowedImages))
	}
}

func TestLoadConfigEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	err := os.WriteFile(path, []byte(`{
		"project_dir": "/home/user/myproject",
		"allowed_images": [],
		"allowed_networks": [],
		"volume_mount_root": "/home/user/myproject"
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if !cfg.IsReadOnly() {
		t.Error("expected IsReadOnly() == true for empty allowlist")
	}
}

func TestLoadConfigDefaultsVolumeMountRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	err := os.WriteFile(path, []byte(`{
		"project_dir": "/home/user/myproject"
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.VolumeMountRoot != "/home/user/myproject" {
		t.Errorf("VolumeMountRoot = %q, want project_dir value", cfg.VolumeMountRoot)
	}
}

func TestLoadConfigMissingProjectDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	err := os.WriteFile(path, []byte(`{"allowed_images": []}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	_, err = Load(path)
	if err == nil {
		t.Error("expected error for missing project_dir")
	}
}

func TestIsImageAllowed(t *testing.T) {
	cfg := &Config{AllowedImages: []string{"postgres:16", "mcp/postgres"}}

	if !cfg.IsImageAllowed("postgres:16") {
		t.Error("postgres:16 should be allowed")
	}
	if !cfg.IsImageAllowed("mcp/postgres") {
		t.Error("mcp/postgres should be allowed")
	}
	if cfg.IsImageAllowed("alpine") {
		t.Error("alpine should NOT be allowed")
	}
	// Different tag still matches by name (Docker pull sends name and tag separately)
	if !cfg.IsImageAllowed("postgres:16.2") {
		t.Error("postgres:16.2 should be allowed (same image name)")
	}
}

func TestIsImageAllowedDockerIOPrefix(t *testing.T) {
	cfg := &Config{AllowedImages: []string{"mcp/postgres", "library/redis"}}

	// docker.io/ prefix should match
	if !cfg.IsImageAllowed("docker.io/mcp/postgres") {
		t.Error("docker.io/mcp/postgres should match mcp/postgres")
	}
	// library/ prefix should match
	if !cfg.IsImageAllowed("docker.io/library/redis") {
		t.Error("docker.io/library/redis should match library/redis")
	}
	// still reject unknown images
	if cfg.IsImageAllowed("docker.io/evil/image") {
		t.Error("docker.io/evil/image should NOT be allowed")
	}
}

func TestIsImageAllowedTagDigestMatching(t *testing.T) {
	// Allowlist has full tag+digest references (from docker compose config)
	cfg := &Config{AllowedImages: []string{
		"langfuse/langfuse:3.163.0@sha256:5162f58ca7f4861154c38debd7f5de4e77f1f6522fd32170b4fcea8db668f61b",
		"postgres:18.3@sha256:a9abf4275f9e99bff8e6aed712b3b7dfec9cac1341bba01c1ffdfce9ff9fc34a",
	}}

	// Docker pull sends fromImage without tag — should match by name
	if !cfg.IsImageAllowed("docker.io/langfuse/langfuse") {
		t.Error("docker.io/langfuse/langfuse should match langfuse/langfuse:3.163.0@sha256:...")
	}
	if !cfg.IsImageAllowed("langfuse/langfuse") {
		t.Error("langfuse/langfuse should match langfuse/langfuse:3.163.0@sha256:...")
	}
	if !cfg.IsImageAllowed("postgres") {
		t.Error("postgres should match postgres:18.3@sha256:...")
	}
	// Still reject unknown images
	if cfg.IsImageAllowed("evil/image") {
		t.Error("evil/image should NOT be allowed")
	}
}

func TestIsNetworkAllowed(t *testing.T) {
	cfg := &Config{AllowedNetworks: []string{"myproject_default"}}

	if !cfg.IsNetworkAllowed("myproject_default") {
		t.Error("myproject_default should be allowed")
	}
	if cfg.IsNetworkAllowed("bridge") {
		t.Error("bridge should NOT be allowed")
	}
}

func TestIsVolumePathAllowed(t *testing.T) {
	// Use a real temp dir so symlink resolution works
	root := t.TempDir()
	subdir := filepath.Join(root, "src")
	os.MkdirAll(subdir, 0755)

	cfg := &Config{VolumeMountRoot: root}

	tests := []struct {
		path    string
		allowed bool
	}{
		{root, true},
		{filepath.Join(root, "src"), true},
		{filepath.Join(root, "data", "db"), true}, // non-existent subdir, still allowed
		{"/etc/passwd", false},
		{"/home/user/.ssh", false},
		{root + "-evil", false},
	}

	for _, tt := range tests {
		got := cfg.IsVolumePathAllowed(tt.path)
		if got != tt.allowed {
			t.Errorf("IsVolumePathAllowed(%q) = %v, want %v", tt.path, got, tt.allowed)
		}
	}
}

// T1: Symlink traversal — symlink outside project denied, real subdirs allowed
func TestIsVolumePathAllowedSymlinkTraversal(t *testing.T) {
	// Create a project dir and an "outside" dir
	projectDir := t.TempDir()
	outsideDir := t.TempDir()

	// Create a real subdir inside project
	realSub := filepath.Join(projectDir, "data")
	os.MkdirAll(realSub, 0755)

	// Create a symlink inside project that points outside
	symlinkPath := filepath.Join(projectDir, "escape")
	os.Symlink(outsideDir, symlinkPath)

	cfg := &Config{VolumeMountRoot: projectDir}

	// Real subdir should be allowed
	if !cfg.IsVolumePathAllowed(realSub) {
		t.Errorf("real subdir %q should be allowed", realSub)
	}

	// Symlink pointing outside should be denied
	if cfg.IsVolumePathAllowed(symlinkPath) {
		t.Errorf("symlink to outside %q should be denied", symlinkPath)
	}

	// Path through symlink should also be denied
	throughSymlink := filepath.Join(symlinkPath, "secret")
	if cfg.IsVolumePathAllowed(throughSymlink) {
		t.Errorf("path through symlink %q should be denied", throughSymlink)
	}
}

// T1: Socket paths denied
func TestIsVolumePathAllowedSocketPaths(t *testing.T) {
	projectDir := t.TempDir()
	cfg := &Config{VolumeMountRoot: projectDir}

	socketPaths := []string{
		"/var/run/docker.sock",
		"/run/docker.sock",
		"/var/run/podman.sock",
		"/run/podman.sock",
		"/some/path/docker.sock",
		"/some/path/docker.socket",
		"/some/path/podman.sock",
		"/some/path/podman.socket",
	}

	for _, sp := range socketPaths {
		if cfg.IsVolumePathAllowed(sp) {
			t.Errorf("socket path %q should be denied", sp)
		}
	}
}

// Was TestAllowedVolumePaths, which asserted that an entry in
// AllowedVolumePaths overrides the socket denial. That is the second half
// of CAF-001's socket path. Inverted here: sockets are denied unconditionally.
func TestSocketPathsAreNeverAllowed(t *testing.T) {
	cfg := &Config{
		VolumeMountRoot:    "/project",
		AllowedVolumePaths: []string{"/var/run/docker.sock", "/opt/shared"},
	}

	t.Run("docker.sock denied even when explicitly listed", func(t *testing.T) {
		if cfg.IsVolumePathAllowed("/var/run/docker.sock") {
			t.Error("CAF-001: an explicit allowlist entry must not override socket denial")
		}
	})

	t.Run("podman.sock denied", func(t *testing.T) {
		if cfg.IsVolumePathAllowed("/var/run/podman.sock") {
			t.Error("/var/run/podman.sock should be denied")
		}
	})

	t.Run("non-socket explicit path still allowed", func(t *testing.T) {
		if !cfg.IsVolumePathAllowed("/opt/shared") {
			t.Error("a non-socket explicit path should still be allowed")
		}
	})

	t.Run("path outside project and not listed is denied", func(t *testing.T) {
		if cfg.IsVolumePathAllowed("/etc/passwd") {
			t.Error("/etc/passwd should be denied")
		}
	})

	t.Run("path under project root still allowed", func(t *testing.T) {
		if !cfg.IsVolumePathAllowed("/project/data") {
			t.Error("/project/data should be allowed (under VolumeMountRoot)")
		}
	})

	t.Run("mounting the socket's parent directory is denied even when listed", func(t *testing.T) {
		cfg2 := &Config{
			VolumeMountRoot:    "/project",
			AllowedVolumePaths: []string{"/var/run"},
		}
		if cfg2.IsVolumePathAllowed("/var/run") {
			t.Error("/var/run should be denied: mounting it exposes the socket inside")
		}
	})
}

// Test that VolumeMountRoot symlinks are resolved in Load()
func TestLoadResolvesVolumeMountRoot(t *testing.T) {
	realDir := t.TempDir()
	parentDir := t.TempDir()
	symlinkPath := filepath.Join(parentDir, "link")
	os.Symlink(realDir, symlinkPath)

	configPath := filepath.Join(parentDir, "config.json")
	os.WriteFile(configPath, []byte(`{
		"project_dir": "`+realDir+`",
		"volume_mount_root": "`+symlinkPath+`"
	}`), 0644)

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}

	// VolumeMountRoot should have been resolved to the real path
	if cfg.VolumeMountRoot != realDir {
		t.Errorf("VolumeMountRoot = %q, want %q (resolved symlink)", cfg.VolumeMountRoot, realDir)
	}
}

func TestIsInfraImageRequiresExactDigest(t *testing.T) {
	realDigest := "sha256:1111111111111111111111111111111111111111111111111111111111111111"
	cfg := &Config{
		ProjectDir:        "/project",
		AllowedImages:     []string{"postgres:16"},
		InfraImageDigests: []string{realDigest},
	}

	t.Run("exact digest matches", func(t *testing.T) {
		if !cfg.IsInfraImage("moby/buildkit@" + realDigest) {
			t.Error("an image carrying the pinned digest should be infra")
		}
	})

	t.Run("registry prefix does not defeat the match", func(t *testing.T) {
		if !cfg.IsInfraImage("docker.io/moby/buildkit@" + realDigest) {
			t.Error("docker.io prefix should not change the digest match")
		}
	})

	t.Run("self-minted tag with the infra NAME is not infra", func(t *testing.T) {
		if cfg.IsInfraImage("moby/buildkit:pwn") {
			t.Error("CAF-001: a caller-chosen tag on the infra name must not be infra")
		}
	})

	t.Run("bare infra name is not infra", func(t *testing.T) {
		if cfg.IsInfraImage("moby/buildkit") {
			t.Error("a name without a digest must not be infra")
		}
	})

	t.Run("wrong digest is not infra", func(t *testing.T) {
		other := "sha256:2222222222222222222222222222222222222222222222222222222222222222"
		if cfg.IsInfraImage("moby/buildkit@" + other) {
			t.Error("an unpinned digest must not be infra")
		}
	})

	t.Run("empty digest list means nothing is infra", func(t *testing.T) {
		empty := &Config{ProjectDir: "/project"}
		if empty.IsInfraImage("moby/buildkit@" + realDigest) {
			t.Error("with no pinned digests nothing may be infra")
		}
	})
}

// --- BWAICODE-3: socket ancestors ---

func TestLoadRejectsSocketAncestorInAllowlist(t *testing.T) {
	for _, entry := range []string{"/var", "/", "/run", "/var/run/docker.sock"} {
		t.Run(entry, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.json")
			body := `{
				"project_dir": "` + dir + `",
				"allowed_images": ["postgres:16"],
				"allowed_volume_paths": ["` + entry + `"]
			}`
			if err := os.WriteFile(path, []byte(body), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Fatalf("Load accepted allowed_volume_paths entry %q; want a refusal", entry)
			}
		})
	}
}

func TestLoadRejectsSocketAncestorAsVolumeMountRoot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	body := `{
		"project_dir": "` + dir + `",
		"allowed_images": ["postgres:16"],
		"volume_mount_root": "/var"
	}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Fatal("Load accepted volume_mount_root /var; want a refusal")
	}
}

func TestLoadAcceptsOrdinaryPaths(t *testing.T) {
	dir := t.TempDir()
	extra := filepath.Join(dir, "extra")
	if err := os.MkdirAll(extra, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.json")
	body := `{
		"project_dir": "` + dir + `",
		"allowed_images": ["postgres:16"],
		"allowed_volume_paths": ["` + extra + `"]
	}`
	if err := os.WriteFile(path, []byte(body), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Fatalf("Load rejected an ordinary allowlist entry: %v", err)
	}
}

// An operator-allowlisted ancestor of the socket must lose even if Load is
// bypassed, i.e. the request path does not rely on the allowlist being sane.
func TestIsVolumePathAllowedDeniesSocketAncestor(t *testing.T) {
	cfg := &Config{
		VolumeMountRoot:    "/project",
		AllowedVolumePaths: []string{"/var", "/"},
	}
	for _, p := range []string{"/var", "/"} {
		if cfg.IsVolumePathAllowed(p) {
			t.Errorf("IsVolumePathAllowed(%q) = true; a directory containing the Docker socket must be denied", p)
		}
	}
}

// --- BWAICODE-2: build tags are matched exactly, against a separate list ---

func TestIsBuildTagAllowed(t *testing.T) {
	cfg := &Config{
		AllowedImages:   []string{"postgres:16", "mcp/postgres", "myproj-app"},
		BuildableImages: []string{"myproj-app", "myreg/web:1"},
	}

	allowed := []string{"myproj-app", "myproj-app:latest", "myreg/web:1"}
	for _, tag := range allowed {
		if !cfg.IsBuildTagAllowed(tag) {
			t.Errorf("IsBuildTagAllowed(%q) = false; a compose build service must be buildable", tag)
		}
	}

	// The BWAICODE-2 primitive: these all pass IsImageAllowed, and none of
	// them may be produced by a build.
	denied := []string{"postgres:16", "postgres:evil", "postgres", "mcp/postgres", "myreg/web:2", "myproj-app@sha256:abc"}
	for _, tag := range denied {
		if cfg.IsBuildTagAllowed(tag) {
			t.Errorf("IsBuildTagAllowed(%q) = true; a build must not mint a name that resolves elsewhere", tag)
		}
	}
}

func TestIsBuildTagAllowedEmptyListBuildsNothing(t *testing.T) {
	cfg := &Config{AllowedImages: []string{"postgres:16"}}
	if cfg.IsBuildTagAllowed("postgres:16") {
		t.Error("a project with no buildable services must not be able to build anything")
	}
}
