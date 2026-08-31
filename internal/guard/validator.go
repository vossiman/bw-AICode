package guard

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	pathpkg "path"
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

// mountEntry mirrors one entry of Docker's HostConfig.Mounts.
type mountEntry struct {
	Type   string `json:"Type"`
	Source string `json:"Source"`
	Target string `json:"Target"`
}

// logConfig mirrors HostConfig.LogConfig.
type logConfig struct {
	Type string `json:"Type"`
}

// hostConfigFields is the subset of HostConfig this guard reads. Fields that
// are merely *permitted* are deliberately NOT here: they are listed in
// hostConfigKnownKeys instead, which is what decides whether a key may appear
// at all. See validateHostConfigKeys for the reasoning.
type hostConfigFields struct {
	Binds             []string          `json:"Binds"`
	Mounts            []mountEntry      `json:"Mounts"`
	Privileged        bool              `json:"Privileged"`
	PidMode           string            `json:"PidMode"`
	NetworkMode       string            `json:"NetworkMode"`
	UsernsMode        string            `json:"UsernsMode"`
	IpcMode           string            `json:"IpcMode"`
	CgroupnsMode      string            `json:"CgroupnsMode"`
	UTSMode           string            `json:"UTSMode"`
	CapAdd            []string          `json:"CapAdd"`
	Devices           []deviceMapping   `json:"Devices"`
	VolumesFrom       []string          `json:"VolumesFrom"`
	SecurityOpt       []string          `json:"SecurityOpt"`
	DeviceCgroupRules []string          `json:"DeviceCgroupRules"`
	DeviceRequests    []json.RawMessage `json:"DeviceRequests"`
	ContainerIDFile   string            `json:"ContainerIDFile"`
	Cgroup            string            `json:"Cgroup"`
	CgroupParent      string            `json:"CgroupParent"`
	VolumeDriver      string            `json:"VolumeDriver"`
	Links             []string          `json:"Links"`
	LogConfig         logConfig         `json:"LogConfig"`

	// MaskedPaths and ReadonlyPaths are POINTERS on purpose. The daemon
	// applies its own defaults only when these are absent (JSON null); a
	// non-nil EMPTY array replaces the defaults with nothing, which unmasks
	// /proc/kcore and drops the read-only bind over /proc/sys — i.e.
	// host-global writes such as /proc/sys/kernel/core_pattern. `docker run
	// --security-opt systempaths=unconfined` is translated client-side into
	// exactly that, and sends SecurityOpt as an empty array, so the
	// SecurityOpt length check below never sees it. A plain value type could
	// not tell `null` (the normal case, sent by every docker run) from `[]`
	// (the attack), so nil-vs-non-nil is the whole check.
	MaskedPaths   *[]string `json:"MaskedPaths"`
	ReadonlyPaths *[]string `json:"ReadonlyPaths"`
}

// containerCreateRequest is the subset of fields we inspect from container create.
type containerCreateRequest struct {
	Image string `json:"Image"`
	// Entrypoint and Cmd are RawMessage because the API accepts both a
	// string and a string array for each. Only their emptiness matters here
	// (see the infra-trust check in validateContainerCreate).
	Entrypoint json.RawMessage  `json:"Entrypoint"`
	Cmd        json.RawMessage  `json:"Cmd"`
	HostConfig hostConfigFields `json:"HostConfig"`
}

// createKnownKeys is the set of TOP-LEVEL container-create keys this guard has
// reasoned about. Anything else is denied. See validateHostConfigKeys for why
// the policy is inverted this way.
//
// None of these can reach the host on their own: they configure the process
// inside the container. Host access is a HostConfig concern.
var createKnownKeys = map[string]bool{
	"Image":      true, // checked against the image allowlist
	"HostConfig": true, // checked field by field, below
	"Entrypoint": true, // checked when infra digest trust is in play
	"Cmd":        true, // checked when infra digest trust is in play

	// Container-internal process configuration. Every one of these is
	// confined to the container's own namespaces.
	"Hostname":     true, // container's own hostname
	"Domainname":   true, // container's own domain
	"User":         true, // uid/gid inside the container
	"AttachStdin":  true, // stream plumbing
	"AttachStdout": true, // stream plumbing
	"AttachStderr": true, // stream plumbing
	"Tty":          true, // stream plumbing
	"OpenStdin":    true, // stream plumbing
	"StdinOnce":    true, // stream plumbing
	"Env":          true, // environment of the container process
	"Labels":       true, // metadata only
	"WorkingDir":   true, // path inside the container
	"Healthcheck":  true, // a command run inside the container
	"ArgsEscaped":  true, // Windows arg quoting flag
	"StopSignal":   true, // signal name
	"StopTimeout":  true, // seconds
	"Shell":        true, // shell for the image's SHELL form
	"OnBuild":      true, // build metadata, inert at run time
	"ExposedPorts": true, // metadata; actual publishing is HostConfig.PortBindings

	// Anonymous volumes: Docker-managed, created under
	// /var/lib/docker/volumes. No caller-supplied host path.
	"Volumes": true,

	// Deprecated container-level MAC address (moved into NetworkingConfig).
	"MacAddress":      true,
	"NetworkDisabled": true,

	// Per-endpoint network settings (aliases, static IPs, driver opts).
	// Note this does NOT gate WHICH network is joined: that is
	// HostConfig.NetworkMode, which is checked only for the host/container:
	// forms, so joining another project's user-defined network is a
	// pre-existing residual of this guard, unchanged here.
	"NetworkingConfig": true,
}

// hostConfigKnownKeys is the set of HostConfig keys this guard has reasoned
// about. A key that is not here causes a DENY.
//
// This inversion is the point. The guard used to enumerate the DANGEROUS
// HostConfig fields and deny those, which meant every field it had not heard
// of was silently permitted. The same host escape was then found six separate
// times on this branch (Binds; HostConfig.Mounts read from the wrong struct
// level; a Type:"volume" inline driver bind; a named-volume bind;
// MaskedPaths/ReadonlyPaths; DeviceCgroupRules) — each one found only after
// the previous had been closed. The rule is now "a create body may only
// contain fields we have reasoned about", so a field added by a future Docker
// API version is denied until someone reasons about it.
//
// Every entry below carries the reason it is here. Entries marked "checked"
// have an explicit value check in validateContainerCreate; the rest are
// permitted as sent.
//
// Note that the Docker CLI marshals the WHOLE HostConfig struct, zero values
// included (verified against docker 29.7.2: a bare `docker create alpine`
// sends 62 HostConfig keys). So this list must cover the benign ones or every
// ordinary docker run would be denied; presence of a key is not itself a
// signal, which is why the dangerous ones are checked by VALUE.
var hostConfigKnownKeys = map[string]bool{
	// --- checked by value in validateContainerCreate ---
	"Binds":             true, // host paths, checked against the volume allowlist
	"Mounts":            true, // default-deny on mount Type; bind sources checked
	"Privileged":        true, // denied except for a digest-pinned infra image
	"PidMode":           true, // host/container: forms denied
	"NetworkMode":       true, // host/container: forms denied
	"UsernsMode":        true, // host denied
	"IpcMode":           true, // host/container: forms denied
	"CgroupnsMode":      true, // host denied
	"UTSMode":           true, // host denied
	"CapAdd":            true, // any added capability denied
	"Devices":           true, // any host device mapping denied
	"DeviceCgroupRules": true, // denied: raw block-device access (CAP_MKNOD is a default cap)
	"DeviceRequests":    true, // denied: device passthrough (GPUs) by another name
	"VolumesFrom":       true, // denied: inherits another container's mounts
	"SecurityOpt":       true, // denied: seccomp/apparmor/no-new-privileges tampering
	"MaskedPaths":       true, // denied when non-null: empties the /proc mask set
	"ReadonlyPaths":     true, // denied when non-null: empties the /proc read-only set
	"ContainerIDFile":   true, // denied when non-empty: a host path the daemon writes to
	"Cgroup":            true, // denied when non-empty: CgroupSpec takes a container:<id> form
	"CgroupParent":      true, // denied when non-empty: places the container in an arbitrary cgroup
	"VolumeDriver":      true, // denied when non-empty: selects a third-party volume plugin
	"Links":             true, // denied when non-empty: legacy wiring to another project's container
	"LogConfig":         true, // driver Type restricted; see logDriverAllowed

	// --- permitted as sent ---

	// Restrictions, not powers: these can only reduce what the container may do.
	"CapDrop":        true, // drops capabilities
	"ReadonlyRootfs": true, // read-only container rootfs

	// Resource limits. Cgroup accounting only; they grant no access to
	// anything outside the container.
	"CpuShares":          true,
	"Memory":             true,
	"NanoCpus":           true,
	"CpuPeriod":          true,
	"CpuQuota":           true,
	"CpuRealtimePeriod":  true,
	"CpuRealtimeRuntime": true,
	"CpusetCpus":         true,
	"CpusetMems":         true,
	"CpuCount":           true,
	"CpuPercent":         true,
	"MemoryReservation":  true,
	"MemorySwap":         true,
	"MemorySwappiness":   true,
	"OomKillDisable":     true,
	"OomScoreAdj":        true, // daemon clamps this to the -1000..1000 range
	"PidsLimit":          true,
	"Ulimits":            true,
	"ShmSize":            true,
	"IOMaximumIOps":      true,
	"IOMaximumBandwidth": true,
	// Blkio throttling. The *Device variants name a host device, but only to
	// rate-limit it; they confer no access to it (Devices/DeviceCgroupRules
	// are what would, and both are denied).
	"BlkioWeight":          true,
	"BlkioWeightDevice":    true,
	"BlkioDeviceReadBps":   true,
	"BlkioDeviceWriteBps":  true,
	"BlkioDeviceReadIOps":  true,
	"BlkioDeviceWriteIOps": true,

	// Lifecycle and stream plumbing.
	"AutoRemove":    true, // docker run --rm
	"RestartPolicy": true, // restart on failure
	"ConsoleSize":   true, // tty dimensions
	"Init":          true, // run tini as pid 1

	// Networking exposed to the container. Publishing a host port is a real
	// (accepted) power: it can occupy a port on the host's network stack.
	// It cannot read or write the host filesystem, and the container can
	// reach the network regardless, so it is permitted as the product needs
	// it for ordinary compose work.
	"PortBindings":    true,
	"PublishAllPorts": true,
	"ExtraHosts":      true, // /etc/hosts entries inside the container
	"Dns":             true, // resolver config inside the container
	"DnsOptions":      true,
	"DnsSearch":       true,

	// Supplementary GIDs for the container process. Only meaningful against
	// files the container can already see; the docker socket cannot be
	// mounted (IsVolumePathAllowed denies it unconditionally).
	"GroupAdd": true,

	// In-container tmpfs mounts. No host source, same reasoning as the
	// Type:"tmpfs" arm of the Mounts switch.
	"Tmpfs": true,

	// Windows-only container isolation mode; inert on Linux.
	"Isolation": true,

	// Deliberately ABSENT, and therefore denied: Sysctls (kernel knobs),
	// Runtime (selects an alternative OCI runtime), StorageOpt (graph driver
	// options), Annotations (steers runtime plugins), KernelMemoryTCP and
	// KernelMemory (deprecated), Capabilities (whole-set replacement),
	// Ulimits aside every other field a future API version adds. None of
	// these are needed for project work through this guard; if one turns out
	// to be, add it here WITH the reasoning, not silently.
}

// logDriverAllowed are the logging drivers HostConfig.LogConfig may select.
// The remaining drivers (syslog, fluentd, gelf, splunk, awslogs, ...) take an
// address option, which makes the DAEMON connect somewhere of the caller's
// choosing — including a unix socket path on the host — and stream data to it.
// Nothing in project work needs that.
var logDriverAllowed = map[string]bool{
	"":          true, // the daemon's configured default; what the CLI sends
	"json-file": true,
	"local":     true,
	"journald":  true,
	"none":      true,
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
	// 1. Reads are modelled explicitly, not blanket-allowed. A blanket GET
	//    allow made GET /containers/{any}/archive a cross-container file
	//    read (CAF-001).
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		return v.validateRead(r)
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

	case ReImagesLoad.MatchString(path):
		return v.validateImageLoad(r)

	case ReBuild.MatchString(path):
		return v.validateBuild(r)

	case r.Method == http.MethodDelete && ReNetworkDelete.MatchString(path):
		return v.validateNetworkDelete(path)

	case ReNetworkCreate.MatchString(path):
		return v.validateNetworkCreate(r)

	case ReContainerAttach.MatchString(path):
		return v.validateContainerSession(path, ReContainerAttach, "attach")

	case ReContainerWait.MatchString(path):
		return v.validateContainerAccess(path, ReContainerWait, "wait")

	// /containers/{id}/logs is a GET and is handled by validateRead; it has
	// no write form, so it is deliberately absent from this switch.

	case ReContainerResize.MatchString(path):
		return v.validateContainerAccess(path, ReContainerResize, "resize")

	default:
		return deny(fmt.Sprintf("operation not allowed: %s %s", r.Method, path))
	}
}

func (v *Validator) validateContainerCreate(r *http.Request) Decision {
	bodyBytes, err := readBody(r)
	if err != nil {
		return deny(fmt.Sprintf("failed to read request body: %v", err))
	}

	// Unknown fields fail CLOSED. This runs before any other check, so a
	// field nobody has reasoned about cannot reach the daemon at all.
	if d := checkKnownKeys(bodyBytes); d != nil {
		return *d
	}

	var req containerCreateRequest
	if err := json.Unmarshal(bodyBytes, &req); err != nil {
		return deny(fmt.Sprintf("failed to parse request body: %v", err))
	}

	// Infra images are matched by content digest (see config.IsInfraImage).
	// Infra trust relaxes exactly one field, Privileged, because buildkit
	// genuinely requires it. Every other HostConfig check below still runs.
	infraImage := !v.config.IsReadOnly() && v.config.IsInfraImage(req.Image)
	if !v.config.IsImageAllowed(req.Image) && !infraImage {
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

	// Check HostConfig.Mounts (the real Docker Engine API field; the engine
	// ignores a top-level Mounts key entirely, so that field is not checked).
	//
	// Default-deny on mount Type: only "bind" (validated identically to
	// Binds, resolving a relative Source against ProjectDir first) and
	// "tmpfs" (no host source, harmless) are permitted. Everything else is
	// denied outright — most importantly "volume", which can mount host root
	// via an inline local-driver bind (VolumeOptions.DriverConfig with
	// options like {"type":"none","device":"/","o":"bind"}) without ever
	// setting Source or Type=="bind". Also denied: "npipe", "cluster", an
	// empty Type, an unrecognised Type, and any case variant. Enumerating
	// dangerous shapes lost twice already (Binds, then top-level Mounts);
	// this makes an unknown future mount type fail closed instead of
	// silently passing.
	for _, mount := range req.HostConfig.Mounts {
		switch mount.Type {
		case "bind":
			hostPath := mount.Source
			if !filepath.IsAbs(hostPath) {
				hostPath = filepath.Join(v.config.ProjectDir, hostPath)
			}
			if !v.config.IsVolumePathAllowed(hostPath) {
				return deny(fmt.Sprintf("volume mount path %q is not allowed", hostPath))
			}
		case "tmpfs":
			// No host source; nothing to check.
		default:
			return deny(fmt.Sprintf("mount type %q is not allowed", mount.Type))
		}
	}

	// Check privileged mode.
	//
	// Infra digest trust pins the image's CONTENT, never the COMMAND: the
	// caller still supplies Entrypoint and Cmd. Without the check below,
	// {"Image":"moby/buildkit@sha256:<pinned>","Entrypoint":["/bin/sh","-c",…],
	// "HostConfig":{"Privileged":true}} was allowed — the legitimate image
	// running arbitrary code as root in a privileged container, which is
	// exactly what this guard exists to prevent. The digest is not a secret
	// either: GET /images/json is a global read and returns RepoDigests.
	// So the relaxation applies only to the image's OWN entrypoint.
	if req.HostConfig.Privileged {
		if !infraImage {
			return deny("privileged containers are not allowed")
		}
		if !isEmptyJSON(req.Entrypoint) || !isEmptyJSON(req.Cmd) {
			return deny("a privileged infra image must run its own entrypoint: Entrypoint and Cmd must be absent")
		}
	}

	// Check PidMode. "host" joins the host pid namespace directly; a
	// "container:<id>" value joins another container's namespace, which is
	// just as dangerous if that container happens to be privileged (e.g. the
	// digest-matched buildkit infra container).
	if req.HostConfig.PidMode == "host" || strings.HasPrefix(req.HostConfig.PidMode, "container:") {
		return deny("host pid namespace is not allowed")
	}

	// Check NetworkMode (same host / container: reasoning as PidMode above).
	if req.HostConfig.NetworkMode == "host" || strings.HasPrefix(req.HostConfig.NetworkMode, "container:") {
		return deny("host network mode is not allowed")
	}

	// Check UsernsMode
	if req.HostConfig.UsernsMode == "host" {
		return deny("host user namespace is not allowed")
	}

	// Check IpcMode. "host" joins the host IPC namespace directly; a
	// "container:<id>" value joins another container's IPC namespace (and
	// hence its shared memory) — including, plausibly, the one container the
	// guard permits to be privileged. UTSMode, CgroupnsMode and UsernsMode
	// have no "container:" form in the engine, so those are left as-is.
	if req.HostConfig.IpcMode == "host" || strings.HasPrefix(req.HostConfig.IpcMode, "container:") {
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

	// Check MaskedPaths / ReadonlyPaths. Non-nil (i.e. the key was sent as
	// anything other than null) is the deny condition, empty array included —
	// an empty array is precisely the attack, because it REPLACES the
	// daemon's default /proc masks with nothing. `docker run --security-opt
	// systempaths=unconfined` produces it client-side, together with an
	// EMPTY SecurityOpt, so the check above cannot see it. Verified against
	// docker 29.7.2: with these emptied, /proc/sys is writable
	// (/proc/sys/kernel/core_pattern is host-global) and /proc/kcore is the
	// real kcore. No caller has a legitimate reason to shrink the mask set
	// through this guard.
	if req.HostConfig.MaskedPaths != nil {
		return deny("MaskedPaths is not allowed: it replaces the daemon's default /proc masks")
	}
	if req.HostConfig.ReadonlyPaths != nil {
		return deny("ReadonlyPaths is not allowed: it replaces the daemon's default /proc read-only set")
	}

	// Check DeviceCgroupRules. Devices (above) is denied, but the device
	// cgroup is the only thing standing between a container and raw block
	// devices: CAP_MKNOD is in Docker's DEFAULT capability set, so a rule
	// like "b 8:* rwm" plus mknod is enough to read the host's disks.
	// Verified against docker 29.7.2 with Devices=[] and CapAdd=[], so
	// neither existing check fires.
	if len(req.HostConfig.DeviceCgroupRules) > 0 {
		return deny("DeviceCgroupRules is not allowed: it grants raw host device access")
	}

	// DeviceRequests is device passthrough under another name (it is how
	// --gpus is expressed).
	if len(req.HostConfig.DeviceRequests) > 0 {
		return deny("DeviceRequests is not allowed: device passthrough")
	}

	// ContainerIDFile is a HOST path the daemon writes the container ID into.
	if req.HostConfig.ContainerIDFile != "" {
		return deny("ContainerIDFile is not allowed: the daemon would write to a caller-chosen host path")
	}

	// Cgroup is a CgroupSpec and takes a "container:<id>" form, i.e. another
	// container's cgroup — the same pivot shape the namespace fields have.
	if req.HostConfig.Cgroup != "" {
		return deny("Cgroup is not allowed")
	}

	// CgroupParent places the container under an arbitrary cgroup path.
	if req.HostConfig.CgroupParent != "" {
		return deny("CgroupParent is not allowed")
	}

	// VolumeDriver selects a third-party volume plugin for the container's
	// volumes, which is a mount source this guard cannot reason about.
	if req.HostConfig.VolumeDriver != "" {
		return deny("VolumeDriver is not allowed")
	}

	// Links is legacy wiring into another (possibly another project's)
	// container, by name.
	if len(req.HostConfig.Links) > 0 {
		return deny("Links is not allowed")
	}

	// A logging driver that takes an address makes the DAEMON connect to a
	// caller-chosen endpoint, host unix sockets included, and stream to it.
	if !logDriverAllowed[req.HostConfig.LogConfig.Type] {
		return deny(fmt.Sprintf("log driver %q is not allowed", req.HostConfig.LogConfig.Type))
	}

	return allow("container create allowed")
}

// isEmptyJSON reports whether a RawMessage is absent or carries no content:
// missing, null, an empty array, or an empty string. Entrypoint and Cmd may
// each be either a string or a string array in the Docker API.
func isEmptyJSON(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s == "" || s == "null" || s == "[]" || s == `""`
}

// checkKnownKeys enforces the fail-closed field policy on a container-create
// body: every top-level key must be in createKnownKeys and every HostConfig
// key must be in hostConfigKnownKeys. A key that is on neither list is denied,
// so a Docker API field this guard has never reasoned about cannot be used
// until someone adds it to a list along with the reason.
//
// Returns nil when the body is acceptable, or a deny Decision to return.
func checkKnownKeys(bodyBytes []byte) *Decision {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(bodyBytes, &top); err != nil {
		d := deny(fmt.Sprintf("failed to parse request body: %v", err))
		return &d
	}
	for key := range top {
		if !createKnownKeys[key] {
			d := deny(fmt.Sprintf("container create field %q is not permitted: "+
				"this guard denies fields it has not reasoned about", key))
			return &d
		}
	}

	raw, ok := top["HostConfig"]
	if !ok || string(raw) == "null" {
		return nil
	}
	var hc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &hc); err != nil {
		d := deny(fmt.Sprintf("failed to parse HostConfig: %v", err))
		return &d
	}
	for key := range hc {
		if !hostConfigKnownKeys[key] {
			d := deny(fmt.Sprintf("HostConfig field %q is not permitted: "+
				"this guard denies fields it has not reasoned about", key))
			return &d
		}
	}
	return nil
}

// checkContainerUsable returns a non-nil deny Decision if containerID may
// not be acted on: either it isn't owned at all, or it is owned only because
// it was seeded host-side (infrastructure, e.g. buildkit) and the session is
// in read-only mode. Read-only mode never grants access to infra containers,
// even though they are otherwise "owned" for ordinary sessions — this is the
// floor the old isDockerInfraContainer name check used to enforce.
func (v *Validator) checkContainerUsable(containerID string) *Decision {
	if !v.tracker.IsOwned(containerID) {
		d := deny(fmt.Sprintf("container %q is not owned by this session", containerID))
		return &d
	}
	if v.config.IsReadOnly() && v.tracker.IsPreowned(containerID) {
		d := deny(fmt.Sprintf("container %q is Docker infrastructure and read-only mode blocks all actions on it", containerID))
		return &d
	}
	return nil
}

// checkNotPreowned returns a deny Decision if containerID was seeded
// host-side. Seeded containers are Docker's own infrastructure — in practice
// the buildkit builder, which RUNS PRIVILEGED. Seeding exists so the session
// can manage that container's lifecycle (start/stop/inspect), not so it can
// get a shell inside it: `docker exec buildx_buildkit_default sh` is root in
// a privileged container, which is a host escape with no create call at all.
// A privileged exec BODY is already denied, but the CONTAINER's privilege is
// what matters here, so the route itself is closed in EVERY mode.
func (v *Validator) checkNotPreowned(containerID, operation string) *Decision {
	if v.tracker.IsPreowned(containerID) {
		d := deny(fmt.Sprintf("container %q was seeded host-side (Docker infrastructure); %s into it is not allowed",
			containerID, operation))
		return &d
	}
	return nil
}

func (v *Validator) validateContainerAction(path string) Decision {
	matches := ReContainerAction.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]
	action := matches[3]

	if d := v.checkContainerUsable(containerID); d != nil {
		return *d
	}

	return allow(fmt.Sprintf("container %s allowed", action))
}

func (v *Validator) validateContainerDelete(path string) Decision {
	matches := ReContainerDelete.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]

	if d := v.checkContainerUsable(containerID); d != nil {
		return *d
	}

	return allow("container delete allowed")
}

func (v *Validator) validateContainerExec(r *http.Request) Decision {
	matches := ReContainerExec.FindStringSubmatch(r.URL.Path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]

	if d := v.checkContainerUsable(containerID); d != nil {
		return *d
	}
	if d := v.checkNotPreowned(containerID, "exec"); d != nil {
		return *d
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
	if v.config.IsReadOnly() {
		return deny("build is not allowed in read-only mode")
	}

	// The resulting tag is the whole point: an unconstrained -t is how a
	// caller mints an image name that later inherits trust at create time.
	// Compose build-only services are already in the allowlist as
	// "<project>-<service>" (bw-common.sh), so real builds pass this.
	tags := r.URL.Query()["t"]
	if len(tags) == 0 {
		return deny("build requires an explicit -t tag so the result can be checked against the allowlist")
	}
	for _, tag := range tags {
		if !v.config.IsImageAllowed(tag) {
			return deny(fmt.Sprintf("build tag %q is not in the allowlist", tag))
		}
	}

	return allow("build allowed")
}

func (v *Validator) validateImageLoad(r *http.Request) Decision {
	// A tar carries its own repo-tags, which cannot be checked without
	// unpacking the stream. That makes /images/load an unconstrained image
	// minting primitive, the same hole as an untagged build. Denied in every
	// mode; use --full-docker when a real image import is needed.
	return deny("image load is not allowed: a tar's tags cannot be checked against the allowlist")
}

func (v *Validator) validateImageCreate(r *http.Request) Decision {
	fromImage := r.URL.Query().Get("fromImage")
	if fromImage == "" {
		return deny("image pull requires fromImage parameter")
	}

	infraImage := !v.config.IsReadOnly() && v.config.IsInfraImage(fromImage)
	if !v.config.IsImageAllowed(fromImage) && !infraImage {
		return deny(fmt.Sprintf("image %q is not in the allowlist", fromImage))
	}

	return allow("image pull allowed")
}

func (v *Validator) validateNetworkDelete(path string) Decision {
	matches := ReNetworkDelete.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	networkID := matches[2]

	if !v.tracker.IsNetworkOwned(networkID) {
		return deny(fmt.Sprintf("network %q is not owned by this session", networkID))
	}

	return allow("network delete allowed")
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

// globalReadPaths are read endpoints that carry no per-container payload and
// are allowed wholesale. Anything not listed is denied by default.
//
// They are not free: each one discloses host-wide *names* — of containers,
// images, networks and volumes belonging to other projects. That residual is
// accepted because the CLI cannot work without them, and closing it needs
// ownership-filtered response bodies rather than a route decision.
//
// Volume names in particular are visible three separate ways: /volumes,
// /system/df (its Volumes[] carries Name and Mountpoint for every volume on
// the host) and /containers/json (its Mounts[].Name). /containers/json is
// what `docker ps` runs on and cannot be removed, so dropping the other two
// hides nothing from anyone. Removing routes is not the lever here; response
// filtering is. Do not re-derive a mitigation from this list.
var globalReadPaths = map[string]bool{
	"/_ping":   true,
	"/version": true,
	"/info":    true,
	// /events discloses STRICTLY MORE than /containers/json, not the same:
	// it is a continuous stream, so on top of the same host-wide inventory
	// it leaks event timing and the action detail, including
	// "exec_create: <cmd>" — that is other projects' exec command lines and
	// whatever was passed as arguments. It is kept anyway, deliberately,
	// because compose's attach path depends on it and the only real fix is
	// filtering the stream by ownership. Accepted, not equivalent.
	"/events":          true,
	"/containers/json": true,
	"/images/json":     true,
	"/networks":        true,
	"/system/df":       true,
	// /volumes is the volume LIST. It was briefly removed here on the theory
	// that it gated the enumeration half of BWAICODE-4 (a Binds entry with
	// no slash is treated as a named volume and never validated). It does
	// not: /system/df and /containers/json, both above and both required,
	// return the same volume names. The removal closed nothing and broke
	// `docker volume ls`, so it is restored.
	"/volumes": true,
	// Deliberately NOT here:
	//
	//   /build/cache — not a Docker route at all (the builder endpoint is
	//     POST /build/prune), so listing it allowed nothing and only
	//     suggested it did.
	//
	//   /distribution/{name}/json — a per-image registry probe. It is a
	//     path with a parameter, so no exact entry here could ever match it
	//     anyway; it stays unmodelled and therefore denied.
}

// validateRead decides GET/HEAD requests. Global list endpoints are allowed;
// per-container reads require the same ownership the write path requires.
// Anything the model does not recognise is denied.
func (v *Validator) validateRead(r *http.Request) Decision {
	// RawPath is set only when the request's escaped path differs from the
	// decoded URL.Path, i.e. the caller percent-encoded something. Docker's
	// own clients never do that for these routes, while an attacker would
	// use it to make the guard and the daemon disagree about where one path
	// segment ends (%2f as a separator, %2e%2e as a dot segment). Refuse the
	// ambiguity rather than pick a side.
	if r.URL.RawPath != "" && r.URL.RawPath != r.URL.Path {
		return deny(fmt.Sprintf("percent-encoded read path is not allowed: %s %s", r.Method, r.URL.RawPath))
	}

	// Go's net/http does not clean URL.Path for a plain http.Handler (only
	// ServeMux cleans, by redirecting), so traversal arrives verbatim. Most
	// patterns below take [^/]+ for the ID and so cannot be traversed, but
	// ReImageInspect has to take (.+) to accept registry/repository names
	// with slashes ("ghcr.io/org/img"), and .+ crosses path separators:
	// GET /images/../containers/{foreign}/json matched it and was allowed.
	// Rather than break real image names, require the path to be already
	// clean. Any "..", any "." segment and any doubled or trailing slash is
	// refused here, before routing.
	if cleaned := pathpkg.Clean(r.URL.Path); cleaned != r.URL.Path {
		return deny(fmt.Sprintf("read path is not canonical: %s %s", r.Method, r.URL.Path))
	}

	// Match on the version-stripped path.
	path := stripVersion(r.URL.Path)

	// After stripping exactly one well-formed prefix, nothing version-shaped
	// may remain: that means either a doubled prefix or a malformed one
	// ("/v1./…", "/v../…"). The read patterns below carry their own loose
	// `(/v[\d.]+)?` group, so without this check such a residue would still
	// match them; the daemon would route the same path somewhere else
	// entirely. Deny instead of guessing.
	if reLooseVersionPrefix.MatchString(path) {
		return deny(fmt.Sprintf("malformed API version prefix in read path: %s %s", r.Method, r.URL.Path))
	}

	if globalReadPaths[path] {
		return allow("global read allowed")
	}

	switch {
	case ReContainerArchive.MatchString(path):
		// The CAF-001 leak: GET *and* HEAD, since HEAD on this endpoint
		// discloses a path's existence and its stat metadata.
		return v.validateContainerAccess(path, ReContainerArchive, "archive read")
	case ReContainerJSON.MatchString(path):
		return v.validateContainerAccess(path, ReContainerJSON, "inspect")
	case ReContainerLogs.MatchString(path):
		return v.validateContainerAccess(path, ReContainerLogs, "logs")
	case ReContainerStats.MatchString(path):
		return v.validateContainerAccess(path, ReContainerStats, "stats")
	case ReContainerChanges.MatchString(path):
		return v.validateContainerAccess(path, ReContainerChanges, "changes")
	case ReContainerTop.MatchString(path):
		return v.validateContainerAccess(path, ReContainerTop, "top")
	case ReContainerExport.MatchString(path):
		return v.validateContainerAccess(path, ReContainerExport, "export")
	case ReExecInspect.MatchString(path):
		// docker exec reads the exit code from here; gate it on the same
		// exec ownership /exec/{id}/start uses.
		matches := ReExecInspect.FindStringSubmatch(path)
		if !v.tracker.IsExecOwned(matches[2]) {
			return deny(fmt.Sprintf("exec %q is not owned by this session", matches[2]))
		}
		return allow("exec inspect allowed")
	case ReImageInspect.MatchString(path):
		// Image metadata is not per-container data, and /images/json above
		// already lists every image on the host.
		return allow("image inspect allowed")
	case ReNetworkDelete.MatchString(path):
		// Same shape as /networks/{id} inspect; network metadata is not
		// per-container data, so allow the read.
		return allow("network inspect allowed")
	case ReVolumeInspect.MatchString(path):
		// Volume metadata is not per-container data, and its Mountpoint is
		// under /var/lib/docker/volumes, which IsVolumePathAllowed rejects.
		// Compose resolves named volumes through this route. Volume *names*
		// are host-wide visible regardless (see globalReadPaths), so this
		// route is not a gate on anything.
		return allow("volume inspect allowed")
	default:
		return deny(fmt.Sprintf("read endpoint not allowed: %s %s", r.Method, r.URL.Path))
	}
}

// validateContainerAccess checks ownership for container endpoints that take
// a container ID in position 2 of the regex match (attach, wait, logs, resize).
func (v *Validator) validateContainerAccess(path string, re *regexp.Regexp, operation string) Decision {
	matches := re.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	containerID := matches[2]

	if d := v.checkContainerUsable(containerID); d != nil {
		return *d
	}

	return allow(fmt.Sprintf("container %s allowed", operation))
}

// validateContainerSession is validateContainerAccess plus the seeded-container
// rule: routes that hand the caller a shell or a stdio stream INSIDE the
// container (exec, attach) are denied on host-seeded infrastructure
// containers, because those run privileged. Lifecycle and read routes keep
// using validateContainerAccess.
func (v *Validator) validateContainerSession(path string, re *regexp.Regexp, operation string) Decision {
	matches := re.FindStringSubmatch(path)
	if matches == nil {
		return deny("operation not allowed")
	}
	if d := v.checkNotPreowned(matches[2], operation); d != nil {
		return *d
	}
	return v.validateContainerAccess(path, re, operation)
}
