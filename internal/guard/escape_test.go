package guard

import (
	"strings"
	"testing"

	"github.com/vossi/bw-docker-guard/internal/config"
	"github.com/vossi/bw-docker-guard/internal/ownership"
)

// The host-escape chain from
// docs/superpowers/specs/2026-08-31-codex-audit-remediation-design.md §2 was:
//
//	1. POST /build?t=moby/buildkit:pwn was allowed unconditionally, minting a
//	   trusted image NAME for free.
//	2. NormalizeImageName stripped tag AND digest, so the minted name matched
//	   the infra allowlist.
//	3. validateContainerCreate returned allow on an infra match BEFORE it
//	   looked at Binds, Mounts, Privileged, namespaces, CapAdd, Devices,
//	   VolumesFrom or SecurityOpt.
//	4. Start and exec needed no bypass at all: the container was genuinely
//	   session-owned by then.
//
// The branch closes that chain in several independent places. This file is the
// regression gate: each link is asserted dead ON ITS OWN, so a failure names
// the link that regressed instead of just saying "the chain works again".
//
// Positive controls are deliberately interleaved. A deny assertion passes
// vacuously if the fixture never matched in the first place (a typo'd digest,
// an image that was never allowlisted), and this repo's history is precisely
// tests that passed while the hole was open.

// escapeDigest is the pinned infra digest for these tests: 64 hex characters,
// the real shape of a sha256 content digest.
const escapeDigest = "sha256:" + "1111111111111111111111111111111111111111111111111111111111111111"

// seededFullID is a genuine, daemon-issued-looking full container ID (64 hex).
const seededFullID = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

// seededHexName is a 12-hex-character container NAME. Docker accepts it as a
// name, and it is short-ID shaped, which is exactly what makes it dangerous as
// a prefix-match target.
const seededHexName = "deadbeefcafe"

func escapeConfig() *config.Config {
	return &config.Config{
		ProjectDir:         "/project",
		AllowedImages:      []string{"postgres:16", "myproj-app"},
		AllowedNetworks:    []string{"mynet"},
		VolumeMountRoot:    "/project",
		InfraImageDigests:  []string{escapeDigest},
		PreownedContainers: []string{seededFullID, "buildx_buildkit_default", seededHexName},
	}
}

func escapeValidator() (*config.Config, *ownership.Tracker, *Validator) {
	cfg := escapeConfig()
	tracker := ownership.New()
	tracker.Seed(cfg.PreownedContainers)
	return cfg, tracker, NewValidator(cfg, tracker)
}

// createBody wraps a HostConfig fragment in a container-create body using an
// allowlisted image, so that any denial comes from the HostConfig field under
// test and not from the image check.
func createBody(hostConfig string) string {
	return `{"Image": "postgres:16", "HostConfig": ` + hostConfig + `}`
}

func TestCAF001EscapeChainIsDead(t *testing.T) {
	cfg, _, v := escapeValidator()

	// ---------------------------------------------------------------
	// LINK 1 — minting a trusted image name.
	// ---------------------------------------------------------------

	t.Run("link1_build_cannot_mint_an_infra_name", func(t *testing.T) {
		// Guards: validateBuild requires -t and checks every tag against the
		// image allowlist. This is the original entry point of the chain.
		for _, url := range []string{
			"/v1.45/build?t=moby/buildkit:pwn",
			"/v1.45/build?t=moby/buildkit",
			"/v1.45/build?t=docker.io/moby/buildkit:pwn",
		} {
			if d := v.Validate(makeRequest("POST", url, "")); d.Allow {
				t.Errorf("link 1 open: build minted a trusted name via %s", url)
			}
		}
	})

	t.Run("link1_build_without_a_tag_is_denied", func(t *testing.T) {
		// Guards: an untagged build is an unconstrained minting primitive,
		// because the resulting name is never checked against the allowlist.
		if d := v.Validate(makeRequest("POST", "/v1.45/build", "")); d.Allow {
			t.Error("link 1 open: untagged build allowed")
		}
	})

	t.Run("link1_one_bad_tag_among_good_ones_is_denied", func(t *testing.T) {
		// Guards: validateBuild iterates ALL tags. Checking only the first
		// would let `-t myproj-app -t moby/buildkit:pwn` through.
		r := makeRequest("POST", "/v1.45/build?t=myproj-app&t=moby/buildkit:pwn", "")
		if d := v.Validate(r); d.Allow {
			t.Error("link 1 open: only the first -t tag is checked")
		}
	})

	t.Run("link1_images_load_is_denied", func(t *testing.T) {
		// Guards: a tar carries its own repo-tags, which cannot be checked
		// without unpacking the stream, so /images/load is the same minting
		// primitive by another route.
		if d := v.Validate(makeRequest("POST", "/v1.45/images/load", "")); d.Allow {
			t.Error("link 1 open: images/load can mint any tag")
		}
	})

	t.Run("link1_images_create_cannot_pull_an_infra_name", func(t *testing.T) {
		// Guards: the pull path applies the same digest-only infra rule as
		// create; a bare infra NAME must not be pullable.
		r := makeRequest("POST", "/v1.45/images/create?fromImage=moby/buildkit", "")
		if d := v.Validate(r); d.Allow {
			t.Error("link 1 open: infra image pullable by name")
		}
	})

	t.Run("link1_positive_allowlisted_build_still_works", func(t *testing.T) {
		// Positive control: without this, every link-1 deny above could be
		// passing because builds are denied wholesale.
		if d := v.Validate(makeRequest("POST", "/v1.45/build?t=myproj-app", "")); !d.Allow {
			t.Errorf("regression: allowlisted compose build denied: %s", d.Reason)
		}
	})

	// ---------------------------------------------------------------
	// LINK 2 — the name/digest confusion that made a minted name "infra".
	//
	// These assert on config.IsInfraImage directly as well as through the
	// validator, because the loosening this guards against (== becoming
	// HasPrefix or Contains) is invisible at the validator level for most
	// inputs. Task 1's own tests would ALL still pass under such a change.
	// ---------------------------------------------------------------

	t.Run("link2_digest_is_required_a_name_is_never_infra", func(t *testing.T) {
		// Guards: IsInfraImage returns false for any reference without an "@"
		// digest, however closely the name resembles a real infra image.
		for _, ref := range []string{
			"moby/buildkit",
			"moby/buildkit:pwn",
			"docker.io/moby/buildkit:v0.12",
			"moby/buildkit:" + escapeDigest, // digest smuggled in as a TAG
		} {
			if cfg.IsInfraImage(ref) {
				t.Errorf("link 2 open: %q treated as infra without a digest", ref)
			}
		}
	})

	t.Run("link2_digest_comparison_is_exact_not_a_prefix", func(t *testing.T) {
		// Guards: the `==` in IsInfraImage. Each case below WOULD match under
		// a loosened comparison, and each must not match.
		cases := []struct{ name, ref, breaks string }{
			{
				name:   "pinned digest plus one extra character",
				ref:    "moby/buildkit@" + escapeDigest + "1",
				breaks: "strings.HasPrefix(digest, allowed)",
			},
			{
				name:   "proper prefix of the pinned digest",
				ref:    "moby/buildkit@" + escapeDigest[:len(escapeDigest)-1],
				breaks: "strings.HasPrefix(allowed, digest) / strings.Contains",
			},
			{
				name:   "pinned digest embedded in a longer value",
				ref:    "moby/buildkit@x" + escapeDigest + "x",
				breaks: "strings.Contains(digest, allowed)",
			},
			{
				name:   "pinned digest with the algorithm prefix dropped",
				ref:    "moby/buildkit@" + strings.TrimPrefix(escapeDigest, "sha256:"),
				breaks: "strings.HasSuffix / strings.Contains",
			},
			{
				name:   "digest of the right length but different content",
				ref:    "moby/buildkit@sha256:" + strings.Repeat("2", 64),
				breaks: "any length-only check",
			},
		}
		for _, tc := range cases {
			if cfg.IsInfraImage(tc.ref) {
				t.Errorf("link 2 open (%s): %q matched; a loosened comparison (%s) would do this",
					tc.name, tc.ref, tc.breaks)
			}
			// And the same through the validator: a false infra match would
			// let Privileged through on a non-allowlisted image.
			body := `{"Image": "` + tc.ref + `", "HostConfig": {"Privileged": true}}`
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("link 2 open (%s): privileged create allowed for %q", tc.name, tc.ref)
			}
		}
	})

	t.Run("link2_positive_the_exact_pinned_digest_IS_infra", func(t *testing.T) {
		// Positive control. Every deny above is vacuous if the fixture digest
		// never matched anything. This also pins the one relaxation infra
		// trust actually buys: Privileged, which buildkit genuinely needs.
		ref := "moby/buildkit@" + escapeDigest
		if !cfg.IsInfraImage(ref) {
			t.Fatalf("fixture broken: %q is not recognised as infra, so the deny cases above prove nothing", ref)
		}
		body := `{"Image": "` + ref + `", "HostConfig": {"Privileged": true}}`
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); !d.Allow {
			t.Fatalf("regression: real infra image cannot run privileged: %s", d.Reason)
		}
	})

	// ---------------------------------------------------------------
	// LINK 3 — infra trust must not short-circuit the HostConfig checks.
	//
	// The old code returned allow on an infra match before it looked at any
	// of these. Every field below is re-asserted against the REAL pinned
	// digest, i.e. against a container that genuinely is infra.
	// ---------------------------------------------------------------

	infraRef := "moby/buildkit@" + escapeDigest

	t.Run("link3_infra_trust_does_not_skip_hostconfig_checks", func(t *testing.T) {
		// Guards: the early `return allow` for infra images. Privileged is
		// the ONLY field infra trust relaxes; each of these must still deny.
		cases := []struct{ name, hostConfig string }{
			{"host root bind", `{"Binds": ["/:/host"]}`},
			{"host etc bind", `{"Binds": ["/etc:/hostetc"]}`},
			{"HostConfig.Mounts bind of host root", `{"Mounts": [{"Type": "bind", "Source": "/", "Target": "/host"}]}`},
			{"pid host", `{"PidMode": "host"}`},
			{"network host", `{"NetworkMode": "host"}`},
			{"ipc host", `{"IpcMode": "host"}`},
			{"userns host", `{"UsernsMode": "host"}`},
			{"cgroupns host", `{"CgroupnsMode": "host"}`},
			{"uts host", `{"UTSMode": "host"}`},
			{"cap add", `{"CapAdd": ["SYS_ADMIN"]}`},
			{"devices", `{"Devices": [{"PathOnHost": "/dev/sda", "PathInContainer": "/dev/sda", "CgroupPermissions": "rwm"}]}`},
			{"volumes from", `{"VolumesFrom": ["othercontainer"]}`},
			{"security opt", `{"SecurityOpt": ["apparmor=unconfined"]}`},
		}
		for _, tc := range cases {
			body := `{"Image": "` + infraRef + `", "HostConfig": ` + tc.hostConfig + `}`
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("link 3 open: infra trust bypassed the %s check", tc.name)
			}
		}
	})

	// ---------------------------------------------------------------
	// The host-mount escape, all four spellings.
	//
	// This is the one that kept coming back. Each spelling below was found
	// only after the previous one had been closed, so they are asserted
	// separately and named for what they are.
	// ---------------------------------------------------------------

	t.Run("mount_spelling1_plain_Binds_host_path", func(t *testing.T) {
		// Guards: the HostConfig.Binds loop in validateContainerCreate.
		for _, bind := range []string{"/:/host", "/etc:/hostetc", "/home:/h", "/project/../:/host"} {
			body := createBody(`{"Binds": ["` + bind + `"]}`)
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("host-mount spelling 1 open: Binds %q allowed", bind)
			}
		}
	})

	t.Run("mount_spelling2_HostConfig_Mounts_bind", func(t *testing.T) {
		// Guards: the HostConfig.Mounts loop. The guard originally read a
		// TOP-LEVEL "Mounts" field, which the Docker Engine API ignores
		// entirely, so this spelling sailed straight past it.
		for _, src := range []string{"/", "/etc", "/home"} {
			body := createBody(`{"Mounts": [{"Type": "bind", "Source": "` + src + `", "Target": "/host"}]}`)
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("host-mount spelling 2 open: HostConfig.Mounts bind of %q allowed", src)
			}
		}
	})

	t.Run("mount_spelling3_volume_type_with_inline_bind_driver", func(t *testing.T) {
		// Guards: the default-deny on mount Type. This mounts host root with
		// Source EMPTY and Type "volume", so every check that keyed off
		// Source or off Type=="bind" saw nothing to object to.
		body := createBody(`{"Mounts": [{"Type": "volume", "Source": "", "Target": "/host",
			"VolumeOptions": {"DriverConfig": {"Name": "local",
			"Options": {"type": "none", "device": "/", "o": "bind"}}}}]}`)
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
			t.Error("host-mount spelling 3 open: Type=volume with an inline bind DriverConfig allowed")
		}
	})

	t.Run("mount_spelling4_named_volume_bind_is_a_KNOWN_RESIDUAL", func(t *testing.T) {
		// RESIDUAL, NOT CLOSED. Tracked as BWAICODE-4.
		//
		// A Binds entry with no slash in the host portion is treated as a
		// Docker-managed named volume and is not validated at all. That means
		// `docker run -v somevol:/host` still attaches another project's
		// named volume. It is only NOT a host-root escape because creating
		// such a volume with a bind DriverConfig goes through POST /volumes/
		// create, which the write model denies (unmodelled route).
		//
		// The mitigation that IS in place: /volumes (the LIST) was removed
		// from globalReadPaths, so a caller cannot enumerate volume names to
		// pick a target. That is defence in depth, not a fix.
		//
		// This subtest asserts the CURRENT behaviour honestly. If it starts
		// failing, BWAICODE-4 was fixed: delete this subtest and move the
		// case up to the closed spellings above.
		body := createBody(`{"Binds": ["somevol:/host"]}`)
		d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body))
		if !d.Allow {
			t.Errorf("BWAICODE-4 appears to be FIXED (named-volume bind now denied: %s) — "+
				"update this gate to assert the closure instead of the residual", d.Reason)
		}

		// The one thing that IS closed: the enumeration step. /volumes must
		// not be listable, so a caller cannot discover a name to bind.
		if d := v.Validate(makeRequest("GET", "/v1.45/volumes", "")); d.Allow {
			t.Error("BWAICODE-4 mitigation open: /volumes list allowed, so named volumes are enumerable")
		}
	})

	t.Run("mount_unknown_or_empty_type_is_denied", func(t *testing.T) {
		// Guards: the `default:` arm of the mount Type switch. Enumerating
		// dangerous shapes lost twice already; an unrecognised or future
		// mount type must fail closed.
		cases := []struct{ name, mount string }{
			{"empty type", `{"Source": "/project/data", "Target": "/data"}`},
			{"explicit empty type", `{"Type": "", "Source": "/project/data", "Target": "/data"}`},
			{"unknown type", `{"Type": "quantum", "Source": "/project/data", "Target": "/data"}`},
			{"npipe", `{"Type": "npipe", "Source": "//./pipe/docker_engine", "Target": "/p"}`},
			{"cluster", `{"Type": "cluster", "Source": "csi-vol", "Target": "/c"}`},
			{"case variant of bind", `{"Type": "Bind", "Source": "/", "Target": "/host"}`},
			{"case variant of BIND", `{"Type": "BIND", "Source": "/", "Target": "/host"}`},
			{"volume type generally", `{"Type": "volume", "Source": "somevol", "Target": "/v"}`},
		}
		for _, tc := range cases {
			body := createBody(`{"Mounts": [` + tc.mount + `]}`)
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("mount default-deny open: %s allowed", tc.name)
			}
		}
	})

	t.Run("mount_positive_project_bind_and_tmpfs_still_work", func(t *testing.T) {
		// Positive control for the two mount shapes that are meant to pass.
		// Without these, the deny cases above would still pass if mounts were
		// denied wholesale, and ordinary compose work would be broken.
		body := createBody(`{"Binds": ["/project/data:/data"]}`)
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); !d.Allow {
			t.Errorf("regression: in-project bind denied: %s", d.Reason)
		}
		body = createBody(`{"Mounts": [{"Type": "bind", "Source": "/project/data", "Target": "/data"}]}`)
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); !d.Allow {
			t.Errorf("regression: in-project HostConfig.Mounts bind denied: %s", d.Reason)
		}
		body = createBody(`{"Mounts": [{"Type": "tmpfs", "Target": "/tmp"}]}`)
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); !d.Allow {
			t.Errorf("regression: tmpfs mount denied: %s", d.Reason)
		}
	})

	t.Run("mount_docker_socket_is_denied_even_when_allowlisted", func(t *testing.T) {
		// Guards: config.IsVolumePathAllowed runs the socket check BEFORE
		// AllowedVolumePaths. An explicit allowlist entry used to override it,
		// which turned the allowlist itself into a socket mount.
		sockCfg := &config.Config{
			ProjectDir:         "/project",
			AllowedImages:      []string{"postgres:16"},
			VolumeMountRoot:    "/project",
			AllowedVolumePaths: []string{"/var/run/docker.sock", "/run", "/var/run"},
		}
		sv := NewValidator(sockCfg, ownership.New())
		for _, bind := range []string{
			"/var/run/docker.sock:/var/run/docker.sock",
			"/run/docker.sock:/sock",
			"/var/run:/hostrun",
			"/run:/hostrun",
		} {
			body := createBody(`{"Binds": ["` + bind + `"]}`)
			if d := sv.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("socket mount reachable through the explicit allowlist: %q", bind)
			}
			body = createBody(`{"Mounts": [{"Type": "bind", "Source": "` +
				strings.SplitN(bind, ":", 2)[0] + `", "Target": "/host"}]}`)
			if d := sv.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("socket mount reachable via HostConfig.Mounts: %q", bind)
			}
		}
	})

	// ---------------------------------------------------------------
	// The namespace pivot. Joining the host namespace escapes directly;
	// joining "container:<id>" escapes via whichever container the guard
	// permits to be privileged, i.e. the digest-matched buildkit one.
	// ---------------------------------------------------------------

	t.Run("namespace_pivot_host_and_container_forms_denied", func(t *testing.T) {
		for _, field := range []string{"PidMode", "NetworkMode", "IpcMode"} {
			for _, value := range []string{
				"host",
				"container:" + seededFullID,
				"container:buildx_buildkit_default",
				"container:someothercontainer",
				"container:",
			} {
				body := createBody(`{"` + field + `": "` + value + `"}`)
				if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
					t.Errorf("namespace pivot open: %s=%q allowed", field, value)
				}
			}
		}
		// The remaining host-namespace fields have no "container:" form in
		// the engine, but "host" must still deny.
		for _, field := range []string{"UsernsMode", "CgroupnsMode", "UTSMode"} {
			body := createBody(`{"` + field + `": "host"}`)
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/create", body)); d.Allow {
				t.Errorf("namespace pivot open: %s=host allowed", field)
			}
		}
	})

	// ---------------------------------------------------------------
	// LINK 4 — ownership. The original chain needed no bypass here, because
	// the attacker's container was genuinely session-owned. These assert the
	// bypasses found in later review rounds are closed.
	// ---------------------------------------------------------------

	t.Run("link4_a_name_alone_does_not_grant_ownership", func(t *testing.T) {
		// Guards: the removal of the isDockerInfraContainer NAME check. A
		// container merely CALLED buildx_buildkit_* must not be actionable.
		for _, path := range []string{
			"/v1.45/containers/buildx_buildkit_evil/start",
			"/v1.45/containers/buildx_buildkit_evil/stop",
			"/v1.45/containers/buildx_buildkit_evil/kill",
			"/v1.45/containers/buildx_buildkit_evil/exec",
			"/v1.45/containers/buildx_buildkit_evil/attach",
			"/v1.45/containers/buildx_buildkit_evil/wait",
			"/v1.45/containers/buildx_buildkit_evil/resize",
			"/v1.45/containers/buildx_buildkit_evil",
		} {
			method := "POST"
			if !strings.Contains(strings.TrimPrefix(path, "/v1.45/containers/"), "/") {
				method = "DELETE"
			}
			if d := v.Validate(makeRequest(method, path, `{}`)); d.Allow {
				t.Errorf("link 4 open: %s %s allowed on a name alone", method, path)
			}
		}
	})

	t.Run("link4_a_seeded_name_does_not_own_its_extensions", func(t *testing.T) {
		// Guards: idOwnedIn supports only the forward direction. Without
		// that, a seeded name would own every string that has it as a prefix.
		for _, id := range []string{
			"buildx_buildkit_default_evil",
			"buildx_buildkit_defaultevil",
			"buildx_buildkit_default/../evil",
			seededHexName + "99",           // hex extension of a seeded hex NAME
			seededHexName + "aaaaaaaaaaaa", // still not a full ID
		} {
			if d := v.Validate(makeRequest("POST", "/v1.45/containers/"+id+"/start", `{}`)); d.Allow {
				t.Errorf("link 4 open: %q owned as an extension of a seeded entry", id)
			}
		}
	})

	t.Run("link4_a_hex_shaped_NAME_is_not_a_prefix_match_target", func(t *testing.T) {
		// Guards: isFullContainerID. A short hex ID is allowed to resolve by
		// prefix, but ONLY against an entry shaped like a genuine 64-hex
		// daemon-issued container ID. A hex-looking NAME is a legal Docker
		// name and must never be a prefix-match TARGET — otherwise any short
		// hex string that happens to prefix such a name resolves as owned,
		// which is ownership by guessing rather than by knowing an ID.
		hexName := "deadbeefcafe1234abcd" // 20 hex chars: a legal name, not an ID
		nameCfg := &config.Config{
			ProjectDir:         "/project",
			AllowedImages:      []string{"postgres:16"},
			VolumeMountRoot:    "/project",
			PreownedContainers: []string{hexName},
		}
		nameTracker := ownership.New()
		nameTracker.Seed(nameCfg.PreownedContainers)
		nv := NewValidator(nameCfg, nameTracker)

		// Fixture control: the exact seeded name is owned (it was seeded
		// host-side). Without this, the denies below could pass vacuously.
		if d := nv.Validate(makeRequest("POST", "/v1.45/containers/"+hexName+"/start", `{}`)); !d.Allow {
			t.Fatalf("fixture broken: seeded name not owned (%s); the denies below prove nothing", d.Reason)
		}
		// A 12+ hex-char query that is a PREFIX of the seeded name must not
		// resolve to it: the name is not a full container ID.
		for _, id := range []string{
			hexName[:12],
			hexName[:16],
			hexName[:len(hexName)-1],
		} {
			if d := nv.Validate(makeRequest("POST", "/v1.45/containers/"+id+"/start", `{}`)); d.Allow {
				t.Errorf("link 4 open: %q prefix-matched a hex-shaped NAME (%q) that is not a full container ID", id, hexName)
			}
		}
		// And nothing that merely EXTENDS the seeded name.
		for _, id := range []string{hexName + "0", hexName + "0123456789ab"} {
			if d := nv.Validate(makeRequest("POST", "/v1.45/containers/"+id+"/start", `{}`)); d.Allow {
				t.Errorf("link 4 open: %q owned as an extension of a hex-shaped NAME", id)
			}
		}
	})

	t.Run("link4_short_id_resolution_still_works_for_real_full_ids", func(t *testing.T) {
		// Positive control and the documented boundary: `docker start <12 hex>`
		// must keep working against a genuine 64-hex seeded ID...
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/"+seededFullID[:12]+"/start", `{}`)); !d.Allow {
			t.Errorf("regression: short-ID resolution broken: %s", d.Reason)
		}
		// ...but a short hex string that prefixes nothing owned must deny.
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/bbbbbbbbbbbb/start", `{}`)); d.Allow {
			t.Error("link 4 open: an arbitrary short hex ID was owned")
		}
	})

	t.Run("link4_unowned_containers_and_execs_are_denied", func(t *testing.T) {
		// Guards: checkContainerUsable on every write route, and exec
		// ownership on /exec/{id}/start.
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/othersproject/start", `{}`)); d.Allow {
			t.Error("link 4 open: unowned container startable")
		}
		if d := v.Validate(makeRequest("POST", "/v1.45/containers/othersproject/exec", `{}`)); d.Allow {
			t.Error("link 4 open: unowned container exec allowed")
		}
		if d := v.Validate(makeRequest("POST", "/v1.45/exec/notmine/start", "")); d.Allow {
			t.Error("link 4 open: unowned exec startable")
		}
	})

	t.Run("link4_privileged_exec_on_an_owned_container_is_denied", func(t *testing.T) {
		// Guards: exec is checked for Privileged even once ownership passes,
		// so an owned infra container is not a privilege ladder.
		body := `{"Privileged": true}`
		r := makeRequest("POST", "/v1.45/containers/"+seededFullID+"/exec", body)
		if d := v.Validate(r); d.Allow {
			t.Error("link 4 open: privileged exec allowed on an owned container")
		}
	})

	// ---------------------------------------------------------------
	// The cross-container read. A blanket GET allow made
	// GET /containers/{any}/archive?path=/ a host-wide file read.
	// ---------------------------------------------------------------

	t.Run("read_cross_container_archive_denied_for_GET_and_HEAD", func(t *testing.T) {
		// Guards: validateRead routes archive through the same ownership
		// check the write path uses. HEAD matters too: it discloses a path's
		// existence and stat metadata.
		for _, method := range []string{"GET", "HEAD"} {
			r := makeRequest(method, "/v1.45/containers/othersproject/archive?path=/etc/shadow", "")
			if d := v.Validate(r); d.Allow {
				t.Errorf("cross-container exfiltration open: %s archive allowed", method)
			}
		}
	})

	t.Run("read_all_per_container_reads_require_ownership", func(t *testing.T) {
		// Guards: every per-container read endpoint, not just archive.
		for _, suffix := range []string{"json", "logs", "stats", "changes", "top", "export", "archive"} {
			for _, method := range []string{"GET", "HEAD"} {
				r := makeRequest(method, "/v1.45/containers/othersproject/"+suffix, "")
				if d := v.Validate(r); d.Allow {
					t.Errorf("cross-container read open: %s /containers/{unowned}/%s allowed", method, suffix)
				}
			}
		}
		// Exec inspect is gated on exec ownership, not container ownership.
		if d := v.Validate(makeRequest("GET", "/v1.45/exec/notmine/json", "")); d.Allow {
			t.Error("cross-session read open: exec inspect allowed for an unowned exec")
		}
	})

	t.Run("read_unrecognised_paths_deny_rather_than_fall_through", func(t *testing.T) {
		// Guards: the `default: deny` in validateRead, plus the canonical-path
		// and version-prefix pre-checks. A blanket GET allow is exactly what
		// made the archive read reachable, so anything unmodelled must deny.
		for _, path := range []string{
			"/v1.45/secrets",
			"/v1.45/swarm",
			"/v1.45/nodes",
			"/v1.45/configs",
			"/v1.45/volumes",                          // list deliberately removed
			"/v1.45/distribution/moby/buildkit/json",  // unmodelled per-image probe
			"/v1.45/images/../containers/other/json",  // traversal into a per-container read
			"/v1.45/containers/other/json/../../json", // dot segments
			"/v1.45//containers/other/json",           // doubled slash
			"/v1.45/v1.45/containers/other/json",      // doubled version prefix
			"/v1./containers/other/json",              // malformed version prefix
			"/v../containers/other/json",
		} {
			for _, method := range []string{"GET", "HEAD"} {
				if d := v.Validate(makeRequest(method, path, "")); d.Allow {
					t.Errorf("read fall-through open: %s %s allowed", method, path)
				}
			}
		}
	})

	t.Run("read_percent_encoded_paths_are_denied", func(t *testing.T) {
		// Guards: the RawPath check. Percent-encoding is how a caller makes
		// the guard and the daemon disagree about segment boundaries.
		for _, raw := range []string{
			"/v1.45/images/%2e%2e/containers/other/json",
			"/v1.45/containers/other%2fjson",
		} {
			if d := v.Validate(makeRequest("GET", raw, "")); d.Allow {
				t.Errorf("read fall-through open: percent-encoded %s allowed", raw)
			}
		}
	})

	t.Run("read_positive_owned_reads_and_global_lists_still_work", func(t *testing.T) {
		// Positive control: the read model must not have been reduced to
		// "deny everything", which would make every read assertion vacuous.
		if d := v.Validate(makeRequest("GET", "/v1.45/containers/"+seededFullID+"/json", "")); !d.Allow {
			t.Errorf("regression: owned container inspect denied: %s", d.Reason)
		}
		for _, path := range []string{"/_ping", "/v1.45/version", "/v1.45/containers/json", "/v1.45/images/json", "/v1.45/networks"} {
			if d := v.Validate(makeRequest("GET", path, "")); !d.Allow {
				t.Errorf("regression: global read %s denied: %s", path, d.Reason)
			}
		}
	})

	// ---------------------------------------------------------------
	// Whole-chain and ordinary-work checks.
	// ---------------------------------------------------------------

	t.Run("chain_end_to_end_cannot_start", func(t *testing.T) {
		// The literal chain from the spec, in order, as a reader's summary.
		// The per-link subtests above are what actually localise a break.
		steps := []struct {
			name, method, url, body string
		}{
			{"1. mint moby/buildkit via build -t", "POST", "/v1.45/build?t=moby/buildkit:pwn", ""},
			{"2. create privileged host-mounting container from the minted name", "POST",
				"/v1.45/containers/create",
				`{"Image": "moby/buildkit:pwn", "HostConfig": {"Privileged": true, "Binds": ["/:/host"]}}`},
			{"3. start it by its infra-looking name", "POST", "/v1.45/containers/buildx_buildkit_evil/start", `{}`},
			{"4. exec into it", "POST", "/v1.45/containers/buildx_buildkit_evil/exec", `{}`},
		}
		for _, s := range steps {
			if d := v.Validate(makeRequest(s.method, s.url, s.body)); d.Allow {
				t.Errorf("escape chain reopened at step %q", s.name)
			}
		}
	})

	t.Run("ordinary_project_work_still_functions", func(t *testing.T) {
		// The gate is worthless if it passes by breaking the product.
		checks := []struct {
			name, method, url, body string
		}{
			{"create an allowlisted container with an in-project bind", "POST", "/v1.45/containers/create",
				createBody(`{"Binds": ["/project/data:/data"]}`)},
			{"create with a named volume (BWAICODE-4 residual, see above)", "POST", "/v1.45/containers/create",
				createBody(`{"Binds": ["myproj_data:/data"]}`)},
			{"build an allowlisted compose image", "POST", "/v1.45/build?t=myproj-app", ""},
			{"pull an allowlisted image", "POST", "/v1.45/images/create?fromImage=postgres:16", ""},
			{"create an allowlisted network", "POST", "/v1.45/networks/create", `{"Name": "mynet"}`},
			{"start an owned container", "POST", "/v1.45/containers/" + seededFullID + "/start", `{}`},
		}
		for _, c := range checks {
			if d := v.Validate(makeRequest(c.method, c.url, c.body)); !d.Allow {
				t.Errorf("regression: %s denied: %s", c.name, d.Reason)
			}
		}
	})
}
