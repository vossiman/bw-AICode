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
		"project_dir": "/home/user/local_dev/myproject",
		"compose_project": "myproject",
		"allowed_images": ["postgres:16", "mcp/postgres"],
		"allowed_networks": ["myproject_default"],
		"volume_mount_root": "/home/user/local_dev/myproject"
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load(%q) error: %v", path, err)
	}
	if cfg.ProjectDir != "/home/user/local_dev/myproject" {
		t.Errorf("ProjectDir = %q, want /home/user/local_dev/myproject", cfg.ProjectDir)
	}
	if len(cfg.AllowedImages) != 2 {
		t.Errorf("AllowedImages len = %d, want 2", len(cfg.AllowedImages))
	}
	if cfg.VolumeMountRoot != "/home/user/local_dev/myproject" {
		t.Errorf("VolumeMountRoot = %q, want /home/user/local_dev/myproject", cfg.VolumeMountRoot)
	}
}

func TestLoadConfigEmpty(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	err := os.WriteFile(path, []byte(`{
		"project_dir": "/home/user/local_dev/myproject",
		"allowed_images": [],
		"allowed_networks": [],
		"volume_mount_root": "/home/user/local_dev/myproject"
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
		"project_dir": "/home/user/local_dev/myproject"
	}`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load error: %v", err)
	}
	if cfg.VolumeMountRoot != "/home/user/local_dev/myproject" {
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
	cfg := &Config{VolumeMountRoot: "/home/user/local_dev/myproject"}

	tests := []struct {
		path    string
		allowed bool
	}{
		{"/home/user/local_dev/myproject", true},
		{"/home/user/local_dev/myproject/src", true},
		{"/home/user/local_dev/myproject/data/db", true},
		{"/home/user/local_dev/otherproject", false},
		{"/home/user/local_dev/myproject-evil", false},
		{"/", false},
		{"/etc/passwd", false},
		{"/var/run/docker.sock", false},
		{"/home/user/.ssh", false},
	}

	for _, tt := range tests {
		got := cfg.IsVolumePathAllowed(tt.path)
		if got != tt.allowed {
			t.Errorf("IsVolumePathAllowed(%q) = %v, want %v", tt.path, got, tt.allowed)
		}
	}
}
