package guard

import "regexp"

// Exported URL patterns for Docker API routes (with optional version prefix).
// Used by both the validator and the proxy for response interception.
var (
	ReContainerCreate  = regexp.MustCompile(`^(/v[\d.]+)?/containers/create$`)
	ReContainerAction  = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/(start|stop|restart|kill)$`)
	ReContainerDelete  = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)$`)
	ReContainerExec    = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/exec$`)
	ReContainerAttach  = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/attach$`)
	ReContainerWait    = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/wait$`)
	ReContainerLogs    = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/logs$`)
	ReContainerResize  = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/resize$`)
	ReExecStart        = regexp.MustCompile(`^(/v[\d.]+)?/exec/([^/]+)/start$`)
	ReImagesCreate     = regexp.MustCompile(`^(/v[\d.]+)?/images/create$`)
	ReBuild            = regexp.MustCompile(`^(/v[\d.]+)?/build$`)
	ReNetworkCreate    = regexp.MustCompile(`^(/v[\d.]+)?/networks/create$`)
)
