package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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

// socketAncestorCandidates are the paths whose exposure the ancestor check
// guards: every known socket, plus the rootless runtime dir resolved at call
// time. Sorted so an error message names the same socket every run.
func socketAncestorCandidates() []string {
	out := make([]string, 0, len(knownSocketPaths)+1)
	for p := range knownSocketPaths {
		out = append(out, p)
	}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		out = append(out, filepath.Join(filepath.Clean(xdg), "docker.sock"))
	}
	sort.Strings(out)
	return out
}

// socketAncestor returns the first known socket path that lives beneath
// cleanPath, or "" if none does.
//
// isSocketPath only recognises an enumerated set: the socket paths themselves,
// their immediate parent dirs, the basename and the rootless runtime dir. It
// says false for "/var" and for "/", both of which expose /var/run/docker.sock
// to anything that mounts them. Those were denied only because they lost the
// AllowedVolumePaths and VolumeMountRoot comparisons further down, i.e. by the
// allowlist being sane rather than by the socket rule. An operator who put
// "/var" in BW_EXTRA_VOLUME_PATHS re-opened full daemon access and nothing
// said so. This closes the gap by treating containment the same as identity.
func socketAncestor(cleanPath string) string {
	prefix := cleanPath
	if prefix != "/" {
		prefix += "/"
	}
	for _, sock := range socketAncestorCandidates() {
		if strings.HasPrefix(sock, prefix) {
			return sock
		}
	}
	return ""
}

type Config struct {
	ProjectDir      string   `json:"project_dir"`
	ComposeProject  string   `json:"compose_project"`
	AllowedImages   []string `json:"allowed_images"`
	AllowedNetworks []string `json:"allowed_networks"`
	// BuildableImages are the tags POST /build may produce: the compose
	// services that actually declare a build: section, resolved host-side by
	// bw-common.sh. A strict subset of AllowedImages.
	//
	// It is separate from AllowedImages because AllowedImages matches by NAME
	// (see IsImageAllowed), so gating builds on it let a build tagged exactly
	// "postgres:16" shadow the registry image in the local cache and be run
	// by any later create (BWAICODE-2). A name only a build produces cannot
	// shadow anything.
	BuildableImages    []string `json:"buildable_images"`
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
//
// The "library/" strip is conditional on what follows being a SINGLE
// component. "library" is Docker Hub's official-images namespace and a Hub
// repository path is exactly namespace/name, so "library/alpine" and "alpine"
// are the same repository (verified against docker 29.7.2: tagging
// "library/bwtest:v1" produces the image "bwtest:v1"). A longer path is not
// that: "library/acme/widget" and "acme/widget" are two DISTINCT repositories
// on the same daemon, verified the same way. Stripping unconditionally made
// them compare equal, which turned the exact build-tag match into a way to
// mint a tag that is not in BuildableImages.
func normalizeImage(image string) string {
	image = strings.TrimPrefix(image, "docker.io/")
	if rest, ok := strings.CutPrefix(image, "library/"); ok && !strings.Contains(rest, "/") {
		image = rest
	}
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

// canonicalTag normalizes a build tag for exact comparison: it drops the
// Docker Hub prefix and makes the implicit ":latest" explicit, so that
// "proj-app" and "proj-app:latest", the same image to the daemon, compare
// equal. A reference carrying a digest is left alone.
func canonicalTag(ref string) string {
	ref = normalizeImage(ref)
	if strings.Contains(ref, "@") {
		return ref
	}
	// A colon in the last path segment is the tag; a colon earlier is a
	// registry port ("localhost:5000/img").
	last := ref
	if i := strings.LastIndex(ref, "/"); i != -1 {
		last = ref[i+1:]
	}
	if !strings.Contains(last, ":") {
		return ref + ":latest"
	}
	return ref
}

// IsBuildTagAllowed reports whether a POST /build may produce this tag.
//
// Matching is EXACT (modulo the implicit ":latest"), never by name. That is
// the whole point: IsImageAllowed matches by name so an untagged pull can
// resolve, and gating builds on it meant a build tagged "postgres:16" was
// allowed because "postgres" was allowlisted, and then shadowed the registry
// image in the local cache for every later create (BWAICODE-2).
func (c *Config) IsBuildTagAllowed(tag string) bool {
	norm := canonicalTag(tag)
	for _, allowed := range c.BuildableImages {
		if norm == canonicalTag(allowed) {
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

	// A directory that CONTAINS a socket is denied on the same grounds; see
	// socketAncestor. Load() already refuses such an entry in the allowlist,
	// so this is the second layer, covering a VolumeMountRoot or a resolved
	// symlink target that reaches one at request time.
	if socketAncestor(cleanPath) != "" || socketAncestor(resolved) != "" {
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

	// Refuse an allowlist that would expose a Docker socket, LOUDLY and at
	// load time. The request path denies these too, but silently and one
	// request at a time; an operator who wrote "/var" into
	// BW_EXTRA_VOLUME_PATHS should be told that the entry cannot be honoured
	// rather than watch every mount fail for no stated reason.
	if err := validateNoSocketExposure(&cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// validateNoSocketExposure rejects a VolumeMountRoot or AllowedVolumePaths
// entry that is a Docker/Podman socket, a directory holding one, or an
// ancestor of one.
func validateNoSocketExposure(cfg *Config) error {
	check := func(field, path string) error {
		clean := filepath.Clean(path)
		if isSocketPath(clean) {
			return fmt.Errorf("%s %q is a Docker socket path and cannot be mounted", field, path)
		}
		if sock := socketAncestor(clean); sock != "" {
			return fmt.Errorf("%s %q contains the Docker socket %q and cannot be mounted", field, path, sock)
		}
		return nil
	}
	if err := check("volume_mount_root", cfg.VolumeMountRoot); err != nil {
		return err
	}
	for _, p := range cfg.AllowedVolumePaths {
		if err := check("allowed_volume_paths entry", p); err != nil {
			return err
		}
	}
	return nil
}
