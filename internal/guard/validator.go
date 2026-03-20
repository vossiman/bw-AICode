package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/ownership"
)

// maxBodySize is the maximum request body size the guard will read (10 MB).
const maxBodySize = 10 * 1024 * 1024

// Decision represents the result of validating a Docker API request.
type Decision struct {
	Allow  bool
	Reason string
}

// Validator inspects Docker API requests and returns allow/deny decisions.
type Validator struct {
	config  *config.Config
	tracker *ownership.Tracker
}

// NewValidator creates a new Validator with the given config and ownership tracker.
func NewValidator(cfg *config.Config, tracker *ownership.Tracker) *Validator {
	return &Validator{config: cfg, tracker: tracker}
}

// deviceMapping mirrors Docker's DeviceMapping struct for JSON parsing.
type deviceMapping struct {
	PathOnHost        string `json:"PathOnHost"`
	PathInContainer   string `json:"PathInContainer"`
	CgroupPermissions string `json:"CgroupPermissions"`
}

// containerCreateRequest is the subset of fields we inspect from container create.
type containerCreateRequest struct {
	Image      string `json:"Image"`
	HostConfig struct {
		Binds         []string        `json:"Binds"`
		Privileged    bool            `json:"Privileged"`
		PidMode       string          `json:"PidMode"`
		NetworkMode   string          `json:"NetworkMode"`
		UsernsMode    string          `json:"UsernsMode"`
		IpcMode       string          `json:"IpcMode"`
		CgroupnsMode  string          `json:"CgroupnsMode"`
		UTSMode       string          `json:"UTSMode"`
		CapAdd        []string        `json:"CapAdd"`
		Devices       []deviceMapping `json:"Devices"`
		VolumesFrom   []string        `json:"VolumesFrom"`
		SecurityOpt   []string        `json:"SecurityOpt"`
	} `json:"HostConfig"`
	Mounts []struct {
		Type   string `json:"Type"`
		Source string `json:"Source"`
		Target string `json:"Target"`
	} `json:"Mounts"`
}

// execCreateRequest is the subset of fields we inspect from exec create.
type execCreateRequest struct {
	Privileged bool `json:"Privileged"`
}

// networkCreateRequest is the subset of fields we inspect from network create.
type networkCreateRequest struct {
	Name string `json:"Name"`
}

func allow(reason string) Decision {
	return Decision{Allow: true, Reason: reason}
}

func deny(reason string) Decision {
	return Decision{Allow: false, Reason: reason}
}

// readBody reads the request body (up to maxBodySize) and re-buffers it so the
// proxy can still forward it. Returns an error if the body exceeds the limit.
func readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, maxBodySize+1)
	bodyBytes, err := io.ReadAll(limited)
	r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	if err != nil {
		return bodyBytes, err
	}
	if int64(len(bodyBytes)) > maxBodySize {
		return nil, fmt.Errorf("request body exceeds %d byte limit", maxBodySize)
	}
	return bodyBytes, nil
}

// Validate inspects the given HTTP request and decides whether to allow or deny it.
func (v *Validator) Validate(r *http.Request) Decision {
	// 1. GET/HEAD → always allow
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return allow("read-only request")
	}

	// 2. Read-only mode → deny all write operations
	if v.config.IsReadOnly() {
		return deny("read-only mode: all write operations blocked")
	}

	path := r.URL.Path

	// 3. Route by URL pattern
	switch {
	case ReContainerCreate.MatchString(path):
		return v.validateContainerCreate(r)

	case ReContainerExec.MatchString(path):
		return v.validateContainerExec(r)

	case ReContainerAction.MatchString(path):
		return v.validateContainerAction(path)

	case r.Method == http.MethodDelete && ReContainerDelete.MatchString(path):
		return v.validateContainerDelete(path)

	case ReExecStart.MatchString(path):
		return v.validateExecStart(path)

	case ReImagesCreate.MatchString(path):
		return v.validateImageCreate(r)

	case ReBuild.MatchString(path):
		return v.validateBuild(r)

	case ReNetworkCreate.MatchString(path):
		return v.validateNetworkCreate(r)

	case ReContainerAttach.MatchString(path):
		return v.validateContainerAccess(path, ReContainerAttach, "attach")

	case ReContainerWait.MatchString(path):
		return v.validateContainerAccess(path, ReContainerWait, "wait")

	case ReContainerLogs.MatchString(path):
		return v.validateContainerAccess(path, ReContainerLogs, "logs")

	case ReContainerResize.MatchString(path):
		return v.validateContainerAccess(path, ReContainerResize, "resize")

	default:
		return deny("operation not allowed")
	}
}

func (v *Validator) validateContainerCreate(r *http.Request) Decision {
	bodyBytes, err := readBody(r)
	if err != nil {
		return deny(fmt.Sprintf("failed to read request body: %v", err))
	}

	var req containerCreateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		return deny(fmt.Sprintf("failed to parse request body: %v", err))
	}

	// Check image allowlist
	if !v.config.IsImageAllowed(req.Image) {
		return deny(fmt.Sprintf("image %q is not in the allowlist", req.Image))
	}

	// Check bind mounts (HostConfig.Binds)
	for _, bind := range req.HostConfig.Binds {
		hostPath := strings.SplitN(bind, ":", 2)[0]
		// Named volumes (e.g. "myapp_data:/data") are Docker-managed, not host
		// filesystem paths. They don't contain "/" and don't start with "." or "~".
		if !strings.HasPrefix(hostPath, "/") && !strings.HasPrefix(hostPath, ".") &&
			!strings.HasPrefix(hostPath, "~") && !strings.Contains(hostPath, "/") {
			continue
		}
		// Resolve relative paths against project directory
		if !filepath.IsAbs(hostPath) {
			hostPath = filepath.Join(v.config.ProjectDir, hostPath)
		}
		if !v.config.IsVolumePathAllowed(hostPath) {
			return deny(fmt.Sprintf("volume mount path %q is not allowed", hostPath))
		}
	}

	// Check Mounts array (newer Docker API)
	for _, mount := range req.Mounts {
		if mount.Type == "bind" {
			if !v.config.IsVolumePathAllowed(mount.Source) {
				return deny(fmt.Sprintf("volume mount path %q is not allowed", mount.Source))
			}
		}
	}

	// Check privileged mode
	if req.HostConfig.Privileged {
		return deny("privileged containers are not allowed")
	}

	// Check PidMode
	if req.HostConfig.PidMode == "host" {
		return deny("host pid namespace is not allowed")
	}

	// Check NetworkMode
	if req.HostConfig.NetworkMode == "host" {
		return deny("host network mode is not allowed")
	}

	// Check UsernsMode
	if req.HostConfig.UsernsMode == "host" {
		return deny("host user namespace is not allowed")
	}

	// Check IpcMode
	if req.HostConfig.IpcMode == "host" {
		return deny("host IPC mode is not allowed")
	}

	// Check CgroupnsMode
	if req.HostConfig.CgroupnsMode == "host" {
		return deny("host cgroup namespace is not allowed")
	}

	// Check UTSMode
	if req.HostConfig.UTSMode == "host" {
		return deny("host UTS mode is not allowed")
	}

	// Check CapAdd
	if len(req.HostConfig.CapAdd) > 0 {
		return deny(fmt.Sprintf("adding capabilities is not allowed: %v", req.HostConfig.CapAdd))
	}

	// Check Devices
	if len(req.HostConfig.Devices) > 0 {
		return deny("device mappings are not allowed")
	}

	// Check VolumesFrom
	if len(req.HostConfig.VolumesFrom) > 0 {
		return deny("VolumesFrom is not allowed")
	}

	// Check SecurityOpt
	if len(req.HostConfig.SecurityOpt) > 0 {
		return deny("SecurityOpt is not allowed")
	}

	return allow("container create allowed")
}

func (v *Validator) validateContainerAction(path string) Decision {
	matches := ReContainerAction.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]
	action := matches[3]

	if !v.tracker.IsOwned(containerID) {
		return deny(fmt.Sprintf("container %q is not owned by this session", containerID))
	}

	return allow(fmt.Sprintf("container %s allowed", action))
}

func (v *Validator) validateContainerDelete(path string) Decision {
	matches := ReContainerDelete.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]

	if !v.tracker.IsOwned(containerID) {
		return deny(fmt.Sprintf("container %q is not owned by this session", containerID))
	}

	return allow("container delete allowed")
}

func (v *Validator) validateContainerExec(r *http.Request) Decision {
	matches := ReContainerExec.FindStringSubmatch(r.URL.Path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]

	if !v.tracker.IsOwned(containerID) {
		return deny(fmt.Sprintf("container %q is not owned by this session", containerID))
	}

	bodyBytes, err := readBody(r)
	if err != nil {
		return deny(fmt.Sprintf("failed to read request body: %v", err))
	}

	if len(bodyBytes) > 0 {
		var req execCreateRequest
		if err := json.Unmarshal(bodyBytes, &req); err != nil {
			return deny(fmt.Sprintf("failed to parse exec request body: %v", err))
		}
		if req.Privileged {
			return deny("privileged exec is not allowed")
		}
	}

	return allow("exec allowed")
}

func (v *Validator) validateExecStart(path string) Decision {
	matches := ReExecStart.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	execID := matches[2]

	if !v.tracker.IsExecOwned(execID) {
		return deny(fmt.Sprintf("exec %q is not owned by this session", execID))
	}

	return allow("exec start allowed")
}

func (v *Validator) validateBuild(r *http.Request) Decision {
	// Builds are allowed in guarded mode (images are in the allowlist).
	// Building an image is safe — the danger is in running containers with
	// bad mounts/privileges, which is validated separately at container create.
	// In read-only mode, builds are blocked.
	if v.config.IsReadOnly() {
		return deny("build is not allowed in read-only mode")
	}
	return allow("build allowed")
}

func (v *Validator) validateImageCreate(r *http.Request) Decision {
	fromImage := r.URL.Query().Get("fromImage")
	if fromImage == "" {
		return deny("image pull requires fromImage parameter")
	}

	if !v.config.IsImageAllowed(fromImage) {
		return deny(fmt.Sprintf("image %q is not in the allowlist", fromImage))
	}

	return allow("image pull allowed")
}

func (v *Validator) validateNetworkCreate(r *http.Request) Decision {
	bodyBytes, err := readBody(r)
	if err != nil {
		return deny(fmt.Sprintf("failed to read request body: %v", err))
	}

	var req networkCreateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		return deny(fmt.Sprintf("failed to parse network create body: %v", err))
	}

	if !v.config.IsNetworkAllowed(req.Name) {
		return deny(fmt.Sprintf("network %q is not in the allowlist", req.Name))
	}

	return allow("network create allowed")
}

// validateContainerAccess checks ownership for container endpoints that take
// a container ID in position 2 of the regex match (attach, wait, logs, resize).
func (v *Validator) validateContainerAccess(path string, re *regexp.Regexp, operation string) Decision {
	matches := re.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]

	if !v.tracker.IsOwned(containerID) {
		return deny(fmt.Sprintf("container %q is not owned by this session", containerID))
	}

	return allow(fmt.Sprintf("container %s allowed", operation))
}
