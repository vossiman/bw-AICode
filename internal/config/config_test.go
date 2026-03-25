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
	if cfg.IsImageAllowed("postgres:16.2") {
		t.Error("postgres:16.2 should NOT be allowed (strict match)")
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

// Test AllowedVolumePaths — explicitly allowed paths override socket checks
func TestAllowedVolumePaths(t *testing.T) {
	cfg := &Config{
		VolumeMountRoot:    "/project",
		AllowedVolumePaths: []string{"/var/run/docker.sock"},
	}

	// docker.sock allowed because it's in AllowedVolumePaths
	if !cfg.IsVolumePathAllowed("/var/run/docker.sock") {
		t.Error("/var/run/docker.sock should be allowed when in AllowedVolumePaths")
	}

	// Other socket paths still denied
	if cfg.IsVolumePathAllowed("/var/run/podman.sock") {
		t.Error("/var/run/podman.sock should be denied (not in AllowedVolumePaths)")
	}

	// Paths outside project and not in AllowedVolumePaths still denied
	if cfg.IsVolumePathAllowed("/etc/passwd") {
		t.Error("/etc/passwd should be denied")
	}

	// Paths under project still work
	if !cfg.IsVolumePathAllowed("/project/data") {
		t.Error("/project/data should be allowed (under VolumeMountRoot)")
	}
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
