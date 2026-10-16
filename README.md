<h1 align="center">cautem-gateway</h1>

<p align="center">
  <strong>RPC control plane and relay</strong><br>
  OpenShell and cautem RPC APIs with HTTP health, auth bootstrap, and streaming relay transport.
</p>
<p align="center">
  <a href="https://github.com/cautem/quarshell-gateway/actions/workflows/ci.yml"><img src="https://github.com/cautem/quarshell-gateway/actions/workflows/ci.yml/badge.svg" alt="CI"></a>
  <a href="https://pkg.go.dev/github.com/cautem/quarshell-gateway"><img src="https://pkg.go.dev/badge/github.com/cautem/quarshell-gateway.svg" alt="Go Reference"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache--2.0-blue.svg" alt="License"></a>
  <a href="https://github.com/cautem/quarshell-gateway"><img src="https://img.shields.io/badge/Go-1.27+-00ADD8?logo=go" alt="Go Version"></a>

  <a href="https://github.com/cautem/quarshell-gateway/actions/workflows/images-gateway.yml"><img src="https://github.com/cautem/quarshell-gateway/actions/workflows/images-gateway.yml/badge.svg" alt="images-gateway"></a>
</p>
<p align="center">
  <sub>Part of the <a href="https://github.com/cautem">cautem / cautem</a> ecosystem</sub>
</p>

---

## Overview

Use the [gateway guide](https://cautem.github.io/sandbox.dev/guides/gateway/) for setup and the [OpenShell compatibility page](https://cautem.github.io/sandbox.dev/reference/openshell-compatibility/) for the current supported scope.

**cautem-gateway** is the optional control-plane daemon. Client management workflows use authenticated RPC. HTTP remains for health, browser/auth bootstrap, and relay/stream transport.

### Key Features

| Category | Capabilities |
|----------|--------------|
| **Registry** | Sandbox upsert / list / delete |
| **Policy** | Base + effective policy over Control RPC; provider attach via OpenShell RPC |
| **Proposals** | Store / approve / reject (`policy.local` sync) |
| **Relay** | Stream and exec relay for guests |
| **Image** | `ghcr.io/cautem/cautem/gateway` |

---

## Installation

```bash
go build -o cautem-gateway ./cmd/cautem-gateway
./cautem-gateway --listen 127.0.0.1:7443
```

**Requirements:** Go 1.27+

**Container:** `ghcr.io/cautem/cautem/gateway:latest`

---

## Quick Start

```bash
./cautem-gateway --listen 127.0.0.1:7443 &
cautem gateway add http://127.0.0.1:7443 --local --name local
cautem gateway select local
curl -s http://127.0.0.1:7443/healthz
```

### HTTP API (selected)

| Method | Path | Role |
|--------|------|------|
| GET | `/healthz` | liveness |

The HTTP contract is documented in [`api/openapi.yaml`](./api/openapi.yaml).
It covers health and bootstrap flows plus the bounded, authenticated rootfs
upload endpoint used after OpenShell `BeginRootfsTarStaging`. Other management
operations use the generated Control RPC or pinned OpenShell RPC contract.
No general REST compatibility layer is maintained for beta clients.

The separate `cautem.control.v1` Connect API serves authenticated UI and SDK
clients on the gateway listener. Its source schema and generated Go/Connect/
TypeScript clients are maintained in the independent
[`cautem-proto`](https://github.com/cautem/quarshell-proto) module and consumed as
dependencies here. Lifecycle mutations require a client-generated
`request_id`; reuse the same ID when retrying, then call `GetOperation` with that
ID to reconcile a lost response. An operation left running across a gateway
restart is reported as `uncertain` because the server cannot infer whether the
backend completed the side effect. The control API also exposes workspace-
filtered service/template summaries and admin operation and audit history.
These summaries omit backend routing addresses and template environment values.

Provider profile reads and writes use `cautem.control.v1`; the service
preserves the full cautem YAML profile and uses resource-version checks for
updates. Global profiles require platform admin access, and workspace profiles
require provider scopes plus workspace membership.

The browser console is in the separate [`cautem-ui`](https://github.com/cautem/quarshell-ui) module. It uses the generated TypeScript
Connect client and OIDC authorization-code flow with PKCE. The same-origin
Compose Console serves the production static bundle and supports sandbox
lifecycle actions, workspace policy/provider management, terminal, bounded
workspace file transfer, and authenticated HTTP/WebSocket service access
including noVNC. See the [UI README](https://github.com/cautem/quarshell-ui/blob/main/README.md) for its security and
runtime limits and the [shared-server guide](./compose/SHARED-SERVER.md) for
single-instance OIDC deployment.

Durable registry state defaults to `$XDG_STATE_HOME/cautem/gateway/state.json`.
For PostgreSQL, set `OPENSHELL_DB_URL` or pass `--db-url`; the URL is rejected
from TOML. The first PostgreSQL start imports an existing `state.json` and
keeps a timestamped `.migrated-*` copy. A stable Gateway `--name` selects its
database row and advisory lock. Store PostgreSQL registry data and its backups
as sensitive because they include
local auth material and credential refresh metadata. Workspace files, encrypted
credential blobs, and archived logs still live in `DataDir`; active relay and
browser service sessions live in memory. Keep one Gateway replica and back up
the database and data volume together. The Compose backup/restore scripts
snapshot and restore both stores while the Gateway is stopped. Workspace admins
can set aggregate CPU, memory, GPU, sandbox-count, and connected GUI-session
quotas; see the [shared-server guide](./compose/SHARED-SERVER.md) for limits and
operations. CLI-managed sandbox log tails
are retained for up to 7 days, with a limit of 64 archived sandboxes and 1 MiB
per sandbox. Archived logs are workspace-scoped and can be read with
`cautem logs <name>` after deletion; they cannot be followed live.

---

## Package Structure

| Path | Purpose |
|------|---------|
| `cmd/cautem-gateway` | Daemon entrypoint |
| `internal/` | HTTP handlers, state, relay |


---

## Related

| Resource | Link |
|----------|------|
| Roadmap | [ROADMAP.md](./ROADMAP.md) |
| Organization | [https://github.com/cautem](https://github.com/cautem) |
| Organization overview | [github.com/cautem](https://github.com/cautem) |
| pkg.go.dev | [`github.com/cautem/quarshell-gateway`](https://pkg.go.dev/github.com/cautem/quarshell-gateway) |

## License

[Apache-2.0](./LICENSE) © cautem

## OpenShell gateway TOML

The daemon reads `--config gateway.toml`, then `OPENSHELL_GATEWAY_CONFIG`,
then an optional `$XDG_CONFIG_HOME/openshell/gateway.toml`
(`~/.config/openshell/gateway.toml` fallback). Explicit missing files fail.
Supported values follow flag > environment > file precedence.

Current startup applies the main bind address, installation name in logs,
simple log levels, SSH session TTL, the local auth switch, TLS certificate/key
paths, and `disable_tls`. Referenced paths remain literal and relative to the
process working directory. `disable_tls=true` ignores the TLS table at runtime.

This support is partial. Full OpenShell deployment files still require missing
driver, storage, identity, middleware, interceptor, telemetry, and auxiliary
listener consumers. Supplied unsupported settings fail before the daemon
creates state or opens listeners. The loader also rejects unknown/duplicate
keys, invalid required fields/enums, and a database URL embedded in TOML.
Without an OpenShell file, the existing cautem defaults still apply.
