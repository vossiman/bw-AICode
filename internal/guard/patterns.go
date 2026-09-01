package guard

import "regexp"

// Exported URL patterns for Docker API routes (with optional version prefix).
// Used by both the validator and the proxy for response interception.
var (
	ReContainerCreate = regexp.MustCompile(`^(/v[\d.]+)?/containers/create$`)
	ReContainerAction = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/(start|stop|restart|kill)$`)
	ReContainerDelete = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)$`)
	ReContainerExec   = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/exec$`)
	ReContainerAttach = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/attach$`)
	ReContainerWait   = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/wait$`)
	ReContainerLogs   = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/logs$`)
	ReContainerResize = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/resize$`)
	ReExecStart       = regexp.MustCompile(`^(/v[\d.]+)?/exec/([^/]+)/start$`)
	ReImagesCreate    = regexp.MustCompile(`^(/v[\d.]+)?/images/create$`)
	ReImagesLoad      = regexp.MustCompile(`^(/v[\d.]+)?/images/load$`)
	ReBuild           = regexp.MustCompile(`^(/v[\d.]+)?/build$`)
	ReNetworkCreate   = regexp.MustCompile(`^(/v[\d.]+)?/networks/create$`)
	ReNetworkDelete   = regexp.MustCompile(`^(/v[\d.]+)?/networks/([^/]+)$`)

	// Read patterns. Every per-container read below carries the container ID
	// in submatch 2, so validateContainerAccess can gate it on the same
	// ownership check the write path uses.
	ReContainerJSON    = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/json$`)
	ReContainerArchive = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/archive$`)
	ReContainerStats   = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/stats$`)
	ReContainerChanges = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/changes$`)
	ReContainerTop     = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/top$`)
	ReContainerExport  = regexp.MustCompile(`^(/v[\d.]+)?/containers/([^/]+)/export$`)
	ReImageInspect     = regexp.MustCompile(`^(/v[\d.]+)?/images/(.+)/(json|history)$`)
	ReVolumeInspect    = regexp.MustCompile(`^(/v[\d.]+)?/volumes/([^/]+)$`)
	ReExecInspect      = regexp.MustCompile(`^(/v[\d.]+)?/exec/([^/]+)/json$`)

	// reVersionPrefix matches a *well-formed* Docker API version prefix only:
	// "/v" followed by dot-separated digit groups, and then either a path
	// separator or end of string. Submatch 1 is that separator (or empty).
	//
	// Deliberately stricter than `^/v[\d.]+`: "/v1." , "/v.." and "/v." are
	// not versions, and leaving them unstripped means the resulting path
	// matches no read pattern and is denied. Failing closed on a malformed
	// prefix is the right direction; the loose form would silently strip
	// garbage and could let a crafted prefix steer matching.
	reVersionPrefix = regexp.MustCompile(`^/v[0-9]+(?:\.[0-9]+)*(/|$)`)

	// reLooseVersionPrefix is the loose form the read patterns embed. It is
	// used only to detect a version-shaped residue left after stripVersion,
	// which means the path had a doubled or malformed prefix.
	reLooseVersionPrefix = regexp.MustCompile(`^/v[\d.]+`)
)

// stripVersion removes a leading Docker API version prefix so that
// "/v1.45/version" and "/version" compare equal. Paths without a prefix, or
// with a malformed one, are returned unchanged. Only one prefix is removed:
// a doubled prefix ("/v1.45/v1.45/...") leaves a residue that matches no
// read pattern, so it is denied rather than normalised into a match.
func stripVersion(path string) string {
	m := reVersionPrefix.FindStringSubmatchIndex(path)
	if m == nil {
		return path
	}
	// m[2]:m[3] is submatch 1: "/" when more path follows, "" at end of string.
	rest := path[m[2]:]
	if rest == "" {
		return "/"
	}
	return rest
}
