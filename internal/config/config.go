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
	"docker.sock":   true,
	"docker.socket": true,
	"podman.sock":   true,
	"podman.socket": true,
}

// Known absolute paths to Docker/Podman sockets.
var knownSocketPaths = map[string]bool{
	"/var/run/docker.sock": true,
	"/run/docker.sock":     true,
	"/var/run/podman.sock": true,
	"/run/podman.sock":     true,
}

// socketParentDirs are directories whose contents are the sockets above:
// mounting the directory itself exposes the socket inside it just as
// surely as mounting the socket path directly.
var socketParentDirs = map[string]bool{
	"/var/run": true,
	"/run":     true,
}

type Config struct {
	ProjectDir         string   `json:"project_dir"`
	ComposeProject     string   `json:"compose_project"`
	AllowedImages      []string `json:"allowed_images"`
	AllowedNetworks    []string `json:"allowed_networks"`
	VolumeMountRoot    string   `json:"volume_mount_root"`
	AllowedVolumePaths []string `json:"allowed_volume_paths"`
	// InfraImageDigests are exact content digests ("sha256:...") of Docker's
	// own infrastructure images (buildkit). Resolved host-side by
	// bw-common.sh, never from project-controlled input. A digest names
	// content, so unlike a name it cannot be minted by the caller.
	InfraImageDigests []string `json:"infra_image_digests"`
	// PreownedContainers are IDs/names of persistent Docker infrastructure
	// containers, resolved host-side by bw-common.sh. Seeded into the
	// ownership tracker at startup.
	PreownedContainers []string `json:"preowned_containers"`
}

// IsReadOnly returns true if no images are allowed (read-only mode).
func (c *Config) IsReadOnly() bool {
	return len(c.AllowedImages) == 0
}

// normalizeImage strips the default Docker Hub registry prefix so that
// "docker.io/mcp/postgres" matches allowlist entry "mcp/postgres" and vice versa.
func normalizeImage(image string) string {
	image = strings.TrimPrefix(image, "docker.io/")
	image = strings.TrimPrefix(image, "library/")
	return image
}

// imageNameOnly returns the image name without tag or digest
// (e.g. "langfuse/langfuse:3.163.0@sha256:abc" -> "langfuse/langfuse").
func imageNameOnly(image string) string {
	if i := strings.IndexAny(image, ":@"); i != -1 {
		return image[:i]
	}
	return image
}

// NormalizeImageName strips Docker Hub prefixes and tag/digest, returning just
// the image name (e.g. "docker.io/moby/buildkit:v0.12" -> "moby/buildkit").
func NormalizeImageName(image string) string {
	return imageNameOnly(normalizeImage(image))
}

// imageDigest returns the digest portion of an image reference
// ("moby/buildkit@sha256:abc" -> "sha256:abc"), or "" if there is none.
func imageDigest(image string) string {
	if i := strings.Index(image, "@"); i != -1 {
		return image[i+1:]
	}
	return ""
}

// IsInfraImage reports whether the reference carries an explicit content
// digest that exactly matches a host-resolved infrastructure digest.
//
// Deliberately strict: a reference without a digest is never infra, however
// closely its name resembles one. This is the CAF-001 fix: the old
// name-based check let a caller mint "moby/buildkit:anything" and inherit
// infrastructure trust.
func (c *Config) IsInfraImage(image string) bool {
	digest := imageDigest(image)
	if digest == "" {
		return false
	}
	for _, allowed := range c.InfraImageDigests {
		if digest == allowed {
			return true
		}
	}
	return false
}

// IsImageAllowed checks if the given image is in the allowlist.
// Comparison is normalized: "docker.io/mcp/postgres" matches "mcp/postgres".
// An image without a tag (e.g. from a Docker pull fromImage param) matches an
// allowlist entry that has a tag/digest, as long as the name portion matches.
func (c *Config) IsImageAllowed(image string) bool {
	norm := normalizeImage(image)
	for _, allowed := range c.AllowedImages {
		normAllowed := normalizeImage(allowed)
		if norm == normAllowed {
			return true
		}
		// Allow matching by name only: a request for "langfuse/langfuse"
		// should match allowlist entry "langfuse/langfuse:3.163.0@sha256:..."
		if imageNameOnly(norm) == imageNameOnly(normAllowed) {
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

// isSocketPath returns true if the path refers to a known Docker/Podman
// socket, a directory that would expose one if mounted, or the rootless
// runtime directory a per-user daemon socket lives under.
func isSocketPath(cleanPath string) bool {
	if knownSocketPaths[cleanPath] {
		return true
	}
	if socketParentDirs[cleanPath] {
		return true
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" && cleanPath == filepath.Clean(xdg) {
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

	// Socket paths are denied unconditionally. This check deliberately runs
	// BEFORE AllowedVolumePaths: an explicit entry used to override it, which
	// turned any path reaching the allowlist into a socket mount (CAF-001).
	if isSocketPath(cleanPath) || isSocketPath(resolved) {
		return false
	}

	// Check explicitly allowed volume paths. Compare against both clean and
	// resolved paths to handle symlinks like /var/run -> /run.
	for _, allowed := range c.AllowedVolumePaths {
		if cleanPath == allowed || resolved == allowed {
			return true
		}
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
