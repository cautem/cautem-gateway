# Gateway API contract

`openapi.yaml` documents the remaining HTTP contract: health and browser/local
auth bootstrap. Sandbox inventory, logs, secret delivery, policy proposals,
provider/config/catalog/workspace management, identity, command execution, and
SSH session management use RPC. SSH byte streams and supervisor relay remain
transport endpoints outside OpenAPI. The route inventory was reviewed against
`NewHandler` and its mounted handlers on 2026-10-09.

The documented `/healthz` route is the gateway listener's JSON liveness
response. Operational endpoints are deliberately outside this API contract:

| Registered surface | Why it is excluded |
| --- | --- |
| `/readyz`, `/health`, and the health-listener `/healthz` | Separate health listener; probe-only endpoints, including a distinct empty-body `/healthz`. |
| `/metrics` | Separate Prometheus metrics listener. |
| `/debug/loglevel` and `/debug/loglevel/…` | Operator diagnostics, not a client API. |
| `relayproto.PathSSHConnect`, `relayproto.PathSupervisorConnect`, and `relayproto.PathSupervisorRelay` | Upgrade/streaming relay transport, documented by the relay protocol rather than OpenAPI. |
| `/v1/relay/{name}/exec` and related legacy relay aliases | Compatibility transport retained for older SDK callers. |
| OpenShell RPC and gRPC health methods | The pinned OpenShell Proto contract is authoritative for RPC and runtime lifecycle. |

Documented remaining `/v1` paths include local and OIDC auth. The integration
contract test covers the documented HTTP operations. Security-specific RPC
and relay integration coverage is being migrated from the removed REST
management routes.

Sandbox runtime lifecycle is defined by the pinned OpenShell Proto contract under
`../../tools/upstream/openshell/proto/openshell.proto` in the workspace.

Validate the contract with the same Redocly CLI version used in CI:

```bash
npx --yes @redocly/cli@2.60.0 lint api/openapi.yaml --config api/redocly.yaml
```

Before generating SDKs, compare the generated client with the existing public
Go/Python facades, especially auth, error mapping, YAML, and streaming routes.
Keep runtime lifecycle operations on the pinned OpenShell Proto contract rather
than duplicating them here.

## Control API and generated clients

`../cautem-proto/proto/cautem/control/v1/console.proto` in the independent
`cautem-proto` module is the single source for the `cautem.control.v1`
user-facing API. It defines console, sandbox,
operations/audit, catalog, policy proposal, provider profile, and partial
provider-credential services. Policy reads/writes and bounded revision history
also use `PolicyService`. The gateway's Connect
handlers serve this contract over Connect, native gRPC, and gRPC-Web; Go Proto,
gRPC, and Connect code is generated from the same file. The TypeScript client
uses Connect-Web with the same generated messages and services. The `/v1` REST
paths and pinned OpenShell service remain separate contracts.

Provider profile methods carry the full cautem YAML document so cautem
egress and credential metadata survive round trips. Updates require the current
resource version; global profile access is limited to platform admins, while
workspace profile access checks provider scopes and membership.

The client API authenticates a user principal and checks workspace membership
for sandbox reads. Sandbox supervisor tokens cannot call it. Sandbox responses
are redacted summaries: `registry_status` is a registry field, and
`runtime_status_available=false` until observed runtime state is joined. The
inventory includes only the ID, image, and labels needed by clients; list
filters and cursors bind the label selector as well as workspace and other
filters. The capability response reports lifecycle available only when a compute runtime is
configured. Sandbox watches start with a
full snapshot and use per-stream
sequence numbers; reconnecting clients replace their state from the new
snapshot.

The initial read-only browser console lives in [`../ui/`](../ui/). It uses OIDC
authorization code with PKCE and keeps the access token in memory. It currently
shows the authorized inventory and bounded log tail. Production static hosting
and same-origin proxy wiring remain deployment work; the UI README documents
the OIDC client and audience requirements.

Sandbox log reads require access to the sandbox's workspace. `GetSandboxLogs`
supports a timestamp lower bound and exact source/level filters; the API caps a
history response at 1000 lines, caps each message at 64 KiB, and excludes
structured log fields, which may contain credentials. Log message text is application output and should be
treated as sensitive by clients. Log cursors refer to the in-memory ring only;
after retention loss or a gateway restart, clients must accept a RESET and
replace their displayed tail. Watches have a shared concurrency cap and a
30-minute maximum lifetime.

Control actions require workspace write permission. Each authenticated action
attempt and result is stored as a bounded durable audit event without request
bodies or backend error text. Success responses follow backend and registry
completion; failures use safe RPC status messages. Sandbox names are
gateway-wide unique, so duplicate creates return `already_exists`. Durable
operation records use idempotent request IDs and let clients reconcile a lost
response; in-flight work becomes uncertain after restart. Operation history
and audit listing are admin-only.

`ListServices`, `ListTemplates`, and `ListWorkspaces`/`GetWorkspace` return
workspace-visible summaries. `ListPolicyProposals`/`GetPolicyProposal` expose
proposal review data without the review token. Catalog and policy reads check
workspace authorization on every call.

The Go Proto, native gRPC, and Connect clients are imported from
`github.com/cautem/cautem-proto`; the Gateway does not generate copies of the
contract. Generate and validate clients in the protocol module:

```bash
cd ../cautem-proto
buf lint
buf generate --template buf.gen.yaml
buf generate --template typescript/buf.gen.yaml
npm ci --prefix typescript
npm run build --prefix typescript
```

The TypeScript browser client is consumed by the UI as
`@cautem/control-client`. Gateway integration coverage exercises gRPC and
gRPC-Web against the same handlers.
