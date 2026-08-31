# Docker Security in bw-AICode

## Overview

The bwrap sandbox isolates AI coding tools from the host filesystem — but Docker access is a special case. The Docker socket (`/var/run/docker.sock`) is effectively equivalent to root access on the host, because anyone who can create containers can mount arbitrary host paths. This document explains how bw-AICode handles Docker access, the security tradeoffs involved, and the rationale behind the current design.

## The Docker escape problem

Any process with access to the Docker socket can escape any container or sandbox:

```bash
# This gives you a root shell on the host, bypassing all bwrap restrictions
docker run -it --rm -v /:/host alpine chroot /host
```

Volume mounts (`-v`) let a container map any host path into itself. There is no way to restrict which paths can be mounted through the Docker API — it's all-or-nothing. This means:

- **Docker socket access = root on the host**
- No amount of bwrap bind-mount restrictions matter if the sandboxed process can talk to Docker unrestricted
- The Docker API has no built-in concept of "allow container creation but restrict volume mounts"

## Two modes of Docker access

bw-AICode provides two modes, selected at launch time:

### Default: read-only proxy

```bash
claude-bw          # uses proxy
opencode-bw        # uses proxy
```

The sandbox connects to Docker through a socket proxy (`docker-compose.yml`) instead of the real socket. Inside the sandbox, `DOCKER_HOST=tcp://127.0.0.1:2375`.

The proxy (`lscr.io/linuxserver/socket-proxy`) is configured to block all write operations:

```yaml
POST: 0      # blocks all POST requests
PUT: 0       # blocks all PUT requests
DELETE: 0    # blocks all DELETE requests
```

**What works:** `docker ps`, `docker images`, `docker inspect`, `docker network ls` — any read-only inspection command.

**What's blocked:** `docker run`, `docker build`, `docker exec`, `docker rm`, `docker stop` — anything that creates, modifies, or destroys resources.

This is the secure default. The AI tool can observe Docker state but cannot act on it.

### `--full-docker`: unrestricted socket access

```bash
claude-bw --full-docker
opencode-bw --full-docker
```

This bind-mounts the real Docker socket (`/run/docker.sock`) read-write into the sandbox and sets `DOCKER_HOST=unix:///var/run/docker.sock`. All Docker operations work, including `docker run` with arbitrary volume mounts.

**Security tradeoff:** The AI tool can escape the bwrap sandbox via Docker. The filesystem restrictions enforced by bwrap (only the current directory writable, system dirs read-only) can be bypassed by creating a container that mounts host paths.

## Why the proxy can't safely allow `docker run`

The linuxserver/socket-proxy supports granular endpoint controls:

| Environment variable | Controls | Works with `POST=0`? |
|---|---|---|
| `ALLOW_START=1` | `POST /containers/{id}/start` | Yes |
| `ALLOW_STOP=1` | `POST /containers/{id}/stop` | Yes |
| `CONTAINERS=1` | `/containers` (list, inspect, create) | Create needs `POST=1` |
| `IMAGES=1` | `/images` (list, inspect, pull) | Pull needs `POST=1` |
| `NETWORKS=1` | `/networks` | Read-only with `POST=0` |
| `EXEC=1` | `/exec` and `/containers/{id}/exec` | Needs `POST=1` |

`docker run` decomposes into multiple API calls:

1. `POST /images/create` — pull the image (if not cached)
2. `POST /containers/create` — create a container (with full config including volume mounts)
3. `POST /containers/{id}/start` — start the container
4. `POST /containers/{id}/attach` — attach stdin/stdout

Steps 1 and 2 require `POST=1`. The `ALLOW_START` flag can handle step 3 independently, but you can't start a container that was never created.

**The critical gap:** The proxy operates at the HTTP endpoint level. It can allow or deny requests to `/containers/create`, but it **cannot inspect the request body** to reject dangerous volume mounts like `-v /:/host`. Once you enable `POST=1` with `CONTAINERS=1`, the AI tool can create containers with arbitrary configurations.

This means enabling `docker run` through the proxy provides **no meaningful security benefit** over mounting the raw socket. Either way, the AI can escape the sandbox.

### Proxy configuration comparison

| Configuration | `docker run` works? | Sandbox escape possible? |
|---|---|---|
| `POST=0` (current default) | No | No |
| `POST=1, CONTAINERS=1` | Yes | Yes — via volume mounts |
| `--full-docker` (raw socket) | Yes | Yes — via volume mounts |

The middle row is security theater — it looks more restricted but provides no actual protection against the escape vector that matters.

## MCP servers and Docker

Many MCP (Model Context Protocol) servers are packaged as Docker images and use the **stdio transport** pattern:

```json
{
  "mcpServers": {
    "postgres": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "--network", "my-network", "mcp/postgres", "connection-string"]
    }
  }
}
```

The AI tool spawns `docker run -i --rm` as a child process, communicates with the MCP server over stdin/stdout, and the container exits when the session ends. Each MCP interaction is a fresh `docker run` invocation.

This is fundamentally different from a long-running service — you **cannot** pre-start MCP containers outside the sandbox and have the AI tool connect to them later, because the stdio transport requires the AI tool to be the parent process of the container.

**Consequence:** If your project uses Docker-based MCPs, the guard proxy automatically detects them and allows the required `docker run` operations. No flags needed.

## bw-docker-guard: the allowlist proxy

`bw-docker-guard` is a Go HTTP reverse proxy that sits between the sandbox and the Docker socket, replacing the linuxserver/socket-proxy. It provides a meaningful middle ground by inspecting Docker API request bodies and enforcing a derived allowlist.

### Three Docker modes (auto-selected)

| Project has | Mode | How it works |
|---|---|---|
| No compose file or Docker MCPs | **Read-only** | `bw-docker-guard` with empty allowlist — all writes blocked |
| `docker-compose.yml` or Docker MCPs | **Guarded** | `bw-docker-guard` with derived allowlist — scoped Docker access |
| `--full-docker` flag | **Unrestricted** | Raw Docker socket mounted — no proxy |

### Allowlist derivation

At launch, the wrapper script scans the project directory and generates an allowlist. The allowlist is **locked for the session** — if the AI modifies config files during the session, the allowlist does not change.

Sources scanned:
- Docker Compose files (`docker-compose.yml`, `compose.yml`, etc.) — resolved via `docker compose config`
- MCP server configs (`.mcp.json`, `.claude/settings.local.json`, `claude_desktop_config.json`) — Docker-based entries

From these, the proxy extracts: allowed images, allowed networks, compose project name.

### Security enforcement

The proxy is **deny-by-default**. Only explicitly modeled operations are allowed:

- **Read operations** (GET/HEAD): modelled explicitly, not blanket-allowed.
  A fixed set of host-wide endpoints that carry no per-container payload is
  allowed (`/_ping`, `/version`, `/info`, `/events`, `/containers/json`,
  `/images/json`, `/networks`, `/volumes`, `/system/df`, plus image, network
  and volume inspect-by-name). Per-container reads (`/containers/{id}/` `json`,
  `archive`, `logs`, `stats`, `changes`, `top`, `export`) require the **same
  ownership check the write path uses**, and so does exec inspect. The
  request path must be canonical and unescaped; anything the model does not
  recognise is denied.
  Accepted residual: those host-wide endpoints disclose the *names* of other
  projects' containers, images, networks and volumes, though not their
  contents. `/events` discloses **strictly more** than `/containers/json` —
  being a stream, it also leaks event timing and action detail, including
  `exec_create: <cmd>`, i.e. other projects' exec command lines and their
  arguments. Volume names are visible three separate ways: `/volumes`,
  `/system/df` (`Volumes[].Name` and `Mountpoint`) and `/containers/json`
  (`Mounts[].Name`). Because `/containers/json` is what `docker ps` runs on
  and cannot be removed, dropping either of the other two hides nothing —
  the route list is not the control here. Closing any of this requires
  **ownership-filtered response bodies**, which the guard does not do today:
  it validates requests and forwards responses untouched.
- **Container create**: image must be in the allowlist, or match an
  infrastructure image by content **digest** (see "Two kinds of trust"
  below). Mount `Type` is default-deny: only a validated `bind` (path must
  resolve, symlinks included, under the project directory or an operator-set
  extra path) and a harmless `tmpfs` are permitted — `volume`, `npipe`,
  `cluster`, and a `volume`-typed mount carrying an inline bind
  `DriverConfig` are all rejected. Dangerous flags are rejected
  unconditionally, for every image including infra images:
  `--pid=host`, `--network=host`, `--userns=host`, `--ipc=host`
  (including `container:<id>` pivoting to a host-namespaced container),
  `--cgroupns=host`, `--uts=host`, `--cap-add`, `--device`,
  `--device-cgroup-rule`, `--gpus`, `--volumes-from`, `--security-opt`,
  `--security-opt systempaths=unconfined` (which the CLI sends as empty
  `MaskedPaths`/`ReadonlyPaths` arrays, not as a `SecurityOpt` entry).
  **`Privileged` is rejected outright, for every image, with no exception.**
  **Any `HostConfig` field the guard has not explicitly reasoned about is
  denied**, rather than passed through; see "Unknown fields fail closed".
- **Container lifecycle** (start/stop/restart/kill/attach/wait/resize/exec/rm):
  only on containers owned by this session — ownership comes from containers
  created through the proxy, plus a host-side `docker ps` snapshot seeded at
  session start (`preowned_containers`), matched on full container ID or
  name. There is no name-prefix shortcut. **`exec` and `attach` are denied
  on seeded containers in every mode**: seeding exists so the session can
  manage buildkit's lifecycle, and that container runs privileged, so a
  shell inside it is a host escape.
- **Image pull**: only allowlisted images, or an infra image matched by
  digest.
- **Build**: requires every `-t` tag to be in the allowlist; an untagged
  build is denied outright, because an untagged result can't be checked.
  `/images/load` is denied in every mode: a loaded tar carries its own
  repo-tags, which can't be checked without unpacking the stream, so it is
  an unconstrained image-minting primitive with no cheaper fix than denial.
  Use `--full-docker` if you genuinely need either.
- **Network create/delete**: only allowlisted networks.
- **Everything else**: blocked (Swarm, secrets, plugins, volume create, etc.)

### Two kinds of trust, and why

The guard distinguishes facts the **caller** supplies from facts the **host**
resolves. Only the latter grants privilege.

- **Infrastructure images** (`infra_image_digests` in the guard config) are
  matched by content digest, resolved host-side via `docker image inspect`
  at session start, never by name or tag. A digest names content, so a
  caller cannot mint one by choosing a string. Matching an infra digest now
  buys exactly one thing: **the image may be named without being in the
  allowlist.** It relaxes no `HostConfig` field at all.

  It used to relax `Privileged`. That was removed, not repaired. A digest
  pins what the image *is*, while the command it runs stays caller-chosen —
  first through `Entrypoint` and `Cmd`, and when those were required to be
  absent, through `Healthcheck`, which the daemon also executes and whose
  output comes back through `docker inspect`. Commands have more spellings
  than a guard can enumerate; the privilege has one. The digest is not a
  secret either (`GET /images/json` returns `RepoDigests`, and it is a public
  registry digest regardless), so the relaxation amounted to a root shell in
  a privileged container for anyone who could read an image list.

  Nothing needed it. `bw-common.sh` resolves buildkit builders that already
  exist **host-side** and seeds them as pre-owned, so the guard only ever has
  to *operate* a privileged builder, never create one.
- **Pre-existing infrastructure containers** are seeded into the ownership
  tracker from a host-side `docker ps` snapshot (`preowned_containers`) at
  startup, matched by full container ID or name — not by a
  `buildx_buildkit_`-style name prefix a caller could reproduce.
- **Bind mount paths outside the project directory** come only from the
  operator's own `BW_EXTRA_VOLUME_PATHS` environment variable
  (colon-separated, set in the host shell that launches the sandbox, never
  read from the project). They are no longer harvested from the project's
  `docker-compose.yml`, because the project directory is the untrusted
  input the guard exists to constrain. An explicit `-v` naming a Docker
  socket path is refused even when the caller lists it, and even when it
  falls inside an otherwise-allowed path.

### Unknown fields fail closed

Container create is validated against an explicit list of fields the guard
has reasoned about (`createKnownKeys` and `hostConfigKnownKeys` in
`internal/guard/validator.go`). A body carrying any other key is denied.

This inverts what the guard used to do. It enumerated the *dangerous*
`HostConfig` fields and denied those, which meant every field it had not
heard of was silently permitted — and the same host escape was then found
six separate times, each one only after the previous had been closed:
`Binds`; `HostConfig.Mounts` read from the wrong struct level; a
`Type: "volume"` inline driver bind; a named-volume bind; empty
`MaskedPaths`/`ReadonlyPaths`; and `DeviceCgroupRules`.

The trade is deliberate. When a future Docker version adds a `HostConfig`
field, the guard denies creates that use it until someone adds it to the
list *with the reason it is safe*. A denied create the day the API changes
is a much cheaper failure than a permitted escape nobody notices. Each
entry in those lists carries a one-line comment saying why it is there;
fields deliberately left out (`Sysctls`, `Runtime`, `StorageOpt`,
`Annotations`, …) are named in a comment too, so "not listed" reads as a
decision rather than an oversight.

`internal/guard/escape_test.go` pins this with verbatim container-create
bodies captured from a real `docker create` and `docker compose create`
(the CLI marshals all 62 `HostConfig` keys on every call, zero values
included), so a list that is too narrow fails the test suite rather than
the user's build.

### What stops working, plainly

Two of the changes above have costs an operator will hit. Neither is a bug.

**The buildx `docker-container` driver does not work through the guard for
BUILDS.** That driver builds by exec'ing into the builder container (a real
build traces four `exec` calls), and `exec` on a host-seeded container is now
denied in every mode. The builder can still be started, stopped and inspected;
it just cannot be used to build. The casualty is the workflows that driver
exists for: **multi-platform builds (`--platform linux/amd64,linux/arm64`) and
cache export/import (`--cache-to` / `--cache-from`)**. Plain `docker build` and
`docker compose build` use the default `docker` driver, which goes through
`POST /build`, and are unaffected. Run a docker-container build outside the
sandbox, or with `--full-docker`.

**The fail-closed field policy denies flags that used to work.** Today that
means `--sysctl`, `--runtime`, `--storage-opt` and `--annotation` (all
`omitempty`, so they only appear in a body when actually used), plus
`--cidfile`, `--cgroup-parent`, `--volume-driver`, `--link` and the
address-taking log drivers. **Compose `sysctls:` is common**, so this is the
one most likely to bite. If a project genuinely needs one, the fix is to add
it to `hostConfigKnownKeys` with the reasoning, in a reviewed change — not to
widen the policy.

### What the guard blocks

| Escape vector | How it's blocked |
|---|---|
| Arbitrary volume mount (`-v /:/host`) | Only mounts resolving under the project directory (or `BW_EXTRA_VOLUME_PATHS`) are allowed |
| Symlink traversal (`-v /project/link-to-root:/host`) | `filepath.EvalSymlinks` resolves before the path check |
| `Type: volume` mount with an inline bind `DriverConfig` (`{"type":"none","device":"/","o":"bind"}`) | Mount `Type` is default-deny; only `bind` and `tmpfs` pass |
| Privileged container | `Privileged` rejected for every image, no exception |
| Command smuggled into a trusted image (`Entrypoint`, `Cmd`, `Healthcheck`) | Nothing the guard can create is privileged, so a command is only ever a command in a confined container |
| `--security-opt systempaths=unconfined` (empty `MaskedPaths`/`ReadonlyPaths`) | Both fields denied when present as anything but `null` |
| Raw host block devices via `--device-cgroup-rule` + `mknod` | `DeviceCgroupRules` and `DeviceRequests` denied |
| Shell in the privileged buildkit builder (`docker exec buildx_buildkit_default sh`) | `exec` and `attach` denied on host-seeded containers in every mode |
| A `HostConfig` field nobody has reasoned about | Unknown create fields are denied, not passed through |
| Host PID/network/user/IPC (including `container:<id>` pivot)/cgroup/UTS namespace | Host values rejected for every image, infra included |
| Arbitrary image | Only allowlisted images pulled or run, or infra images matched by digest |
| Minting an infra-looking image via build or load | Build tags must be allowlisted (untagged build denied); `/images/load` denied outright |
| Capability escalation, devices, volumes-from, security-opt | Rejected for every image, infra included |
| Exec into a non-project container | Ownership tracking, seeded host-side, no name-prefix exemption |
| Cross-container file read (`/containers/{id}/archive`, `/logs`, `/stats`, …) | Per-container reads require the same ownership check writes use |
| Docker/Podman socket in container | Socket paths denied by basename and absolute path, ahead of any explicit allowlist entry |
| Oversized request body | 10 MB limit on write requests |

### What it doesn't protect against

- Supply-chain attacks (malicious upstream images that are legitimately allowlisted)
- Network exfiltration from allowed containers (the same risk as the AI tool
  having network access at all)
- Anything reachable through an allowlisted container's own privileges
- Bugs in the proxy implementation. This is a filtering proxy, not a kernel
  boundary. It was rewritten in 2026-08 after an audit (CAF-001) found a
  three-step host escape built entirely from caller-chosen names; treat it
  as defence in depth behind the container boundary, not as the boundary
  itself.

### Known residuals (open, not hidden)

These are real gaps in the current implementation, tracked as tickets rather
than silently accepted:

- **BWAICODE-4 — named-volume binds are not validated.** A `Binds` entry
  with no slash in the host portion (`Binds: ["somevol:/host"]`) is treated
  as a Docker-managed named volume and skips validation entirely. If a
  host-backed named volume already exists (created before the guard ever
  saw a request, since `POST /volumes/create` is itself denied as an
  unmodelled route), attaching it still reaches host data. A regression
  gate deliberately locks in this permissive behaviour today and fails the
  build the moment it is fixed, specifically so the fix can't land silently
  — see `internal/guard/escape_test.go`,
  `mount_spelling4_named_volume_bind_is_a_KNOWN_RESIDUAL`.
- **Volume names are host-wide visible** via `/volumes`, `/system/df`
  (`Volumes[].Name`, `Mountpoint`) and `/containers/json`
  (`Mounts[].Name`) — all three needed for basic `docker ps`/`docker volume
  ls` to work. Removing routes closes nothing, because `/containers/json`
  alone already discloses the same names and can't be removed; only
  ownership-filtered response bodies would close this, and the guard
  forwards response bodies untouched today.
- **`/events` discloses strictly more than `/containers/json`.** As a
  stream it also leaks event timing and action detail, including
  `exec_create: <cmd>` — other projects' exec command lines and arguments,
  not just their existence.
- **BWAICODE-2 — the image allowlist matches by name, not content.** A
  build tagged exactly `postgres:16` (an allowlisted name) poisons the
  local image cache under that name even though its content differs from
  the real `postgres:16`. This is a name allowlist, not a content-integrity
  guarantee; only the separate digest-matched infra path carries that
  stronger property.
- **BWAICODE-3 — socket denial doesn't cover ancestor directories.** The
  check rejects the Docker/Podman socket path itself and its known
  basenames, but not a bind of an ancestor directory such as `/var` that
  would contain the socket anyway.
- **Validate-time symlink resolution is TOCTOU-racy against daemon-time
  mounting.** The guard resolves symlinks when it validates a request, but
  the daemon resolves and mounts the path later; a path that is swapped out
  from under the check between those two moments is not caught.

### Architecture

Each session gets its own `bw-docker-guard` instance:

```
Wrapper script starts
  ├── Derives allowlist from project config
  ├── Starts bw-docker-guard on /tmp/bw-docker-guard-$$.sock
  ├── Bind-mounts the socket into the bwrap sandbox
  ├── Sets DOCKER_HOST=unix:///run/bw-docker-guard.sock
  └── Runs bwrap (AI tool session)
      └── On exit: kills bw-docker-guard, cleans up socket
```

The proxy is ephemeral — starts with the session, dies with the session. No persistent service to manage.
