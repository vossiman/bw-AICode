package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Known Docker/Podman socket basenames that must never be volume-mounted.
var socketBasenames = map[string]bool{
	"docker.sock":    true,
	"docker.socket":  true,
	"podman.sock":    true,
	"podman.socket":  true,
}

// Known absolute paths to Docker/Podman sockets.
var knownSocketPaths = map[string]bool{
	"/var/run/docker.sock":  true,
	"/run/docker.sock":      true,
	"/var/run/podman.sock":  true,
	"/run/podman.sock":      true,
}

type Config struct {
	ProjectDir         string   `json:"project_dir"`
	ComposeProject     string   `json:"compose_project"`
	AllowedImages      []string `json:"allowed_images"`
	AllowedNetworks    []string `json:"allowed_networks"`
	VolumeMountRoot    string   `json:"volume_mount_root"`
	AllowedVolumePaths []string `json:"allowed_volume_paths"`
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

// isSocketPath returns true if the path refers to a known Docker/Podman socket.
func isSocketPath(cleanPath string) bool {
	if knownSocketPaths[cleanPath] {
		return true
	}
	return socketBasenames[filepath.Base(cleanPath)]
}

// IsVolumePathAllowed checks if the host path is under the volume mount root
// or matches an explicitly allowed volume path.
// It resolves symlinks and cleans paths before comparison.
func (c *Config) IsVolumePathAllowed(hostPath string) bool {
	if c.VolumeMountRoot == "" && len(c.AllowedVolumePaths) == 0 {
		return false
	}

	cleanPath := filepath.Clean(hostPath)

	// Resolve symlinks for comparison
	resolved, err := filepath.EvalSymlinks(cleanPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			resolved = resolveExistingAncestor(cleanPath)
		} else {
			return false
		}
	}

	// Check explicitly allowed volume paths first (these override socket checks).
	// Compare against both clean and resolved paths to handle symlinks like /var/run -> /run.
	for _, allowed := range c.AllowedVolumePaths {
		if cleanPath == allowed || resolved == allowed {
			return true
		}
	}

	// Block known socket paths (only if not explicitly allowed above)
	if isSocketPath(cleanPath) || isSocketPath(resolved) {
		return false
	}

	if c.VolumeMountRoot == "" {
		return false
	}

	root := c.VolumeMountRoot
	if resolved == root {
		return true
	}
	return strings.HasPrefix(resolved, root+"/")
}

// resolveExistingAncestor walks up from path until it finds an existing
// ancestor, resolves that ancestor's symlinks, then re-appends the remaining
// tail. This catches cases like /project/symlink/child where symlink exists
// and points outside the project, but child doesn't exist under the target.
func resolveExistingAncestor(path string) string {
	parent := filepath.Dir(path)
	if parent == path {
		// Reached root — return as-is
		return path
	}
	resolved, err := filepath.EvalSymlinks(parent)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			resolved = resolveExistingAncestor(parent)
		} else {
			return path
		}
	}
	return filepath.Join(resolved, filepath.Base(path))
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

	// Resolve VolumeMountRoot symlinks once so comparisons are consistent
	resolved, err := filepath.EvalSymlinks(cfg.VolumeMountRoot)
	if err == nil {
		cfg.VolumeMountRoot = resolved
	}

	// Resolve AllowedVolumePaths symlinks
	for i, p := range cfg.AllowedVolumePaths {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			cfg.AllowedVolumePaths[i] = r
		}
	}

	return &cfg, nil
}
