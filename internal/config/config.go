package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	ProjectDir      string   `json:"project_dir"`
	ComposeProject  string   `json:"compose_project"`
	AllowedImages   []string `json:"allowed_images"`
	AllowedNetworks []string `json:"allowed_networks"`
	VolumeMountRoot string   `json:"volume_mount_root"`
}

// IsReadOnly returns true if no images are allowed (read-only mode).
func (c *Config) IsReadOnly() bool {
	return len(c.AllowedImages) == 0
}

// IsImageAllowed checks if the given image is in the allowlist.
func (c *Config) IsImageAllowed(image string) bool {
	for _, allowed := range c.AllowedImages {
		if image == allowed {
			return true
		}
	}
	return false
}

// IsNetworkAllowed checks if the given network name is in the allowlist.
func (c *Config) IsNetworkAllowed(name string) bool {
	for _, allowed := range c.AllowedNetworks {
		if name == allowed {
			return true
		}
	}
	return false
}

// IsVolumePathAllowed checks if the host path is under the volume mount root.
// It resolves symlinks and cleans paths before comparison.
func (c *Config) IsVolumePathAllowed(hostPath string) bool {
	if c.VolumeMountRoot == "" {
		return false
	}
	// Clean and resolve paths
	cleanPath := filepath.Clean(hostPath)
	cleanRoot := filepath.Clean(c.VolumeMountRoot)

	// Block docker socket mounts explicitly
	if strings.Contains(cleanPath, "docker.sock") {
		return false
	}

	if cleanPath == cleanRoot {
		return true
	}
	// Check prefix with trailing separator
	return strings.HasPrefix(cleanPath, cleanRoot+"/")
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.ProjectDir == "" {
		return nil, fmt.Errorf("project_dir is required")
	}
	if cfg.VolumeMountRoot == "" {
		cfg.VolumeMountRoot = cfg.ProjectDir
	}
	return &cfg, nil
}
