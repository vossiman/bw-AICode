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

**Security tradeoff:** The AI tool can escape the bwrap sandbox via Docker. The filesystem restrictions enforced by bwrap (only `~/local_dev` writable, system dirs read-only) can be bypassed by creating a container that mounts host paths.

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

**Consequence:** If your project uses Docker-based MCPs, you must use `--full-docker`:

```bash
claude-bw --full-docker     # for projects with Docker-based MCPs
```

## Current decision: `--full-docker` for Docker-dependent workflows

The chosen approach is:

- **Default mode (proxy)** for projects that don't need Docker write access — maximum security
- **`--full-docker` flag** for projects that need `docker run` (MCPs, dev containers, etc.) — accepts the security tradeoff explicitly

This is honest about the security model: either Docker is read-only, or it's fully accessible. There is no useful middle ground with the current proxy architecture.

## Future option: allowlist wrapper

A stronger solution would be a host-side helper service that:

1. Accepts `docker run` requests from the sandbox
2. Validates the image against an allowlist (e.g., only `mcp/postgres`, `mcp/sqlite`)
3. Validates volume mounts against a path allowlist (e.g., only paths under `~/local_dev`)
4. Rejects `--privileged`, `--pid=host`, `--network=host`, and other escape-enabling flags
5. Delegates approved requests to the real Docker socket

This would give MCP support with actual security guarantees — the AI tool could run approved containers but couldn't use Docker as an escape vector. This is not currently implemented.
