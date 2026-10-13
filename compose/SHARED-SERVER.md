# Shared Gateway deployment

The first shared deployment is a single Gateway process with OIDC and separate
workspaces. It serves the Console and API from one origin, stores control-plane
state on the persistent Compose volume, and uses the Docker compute overlay on a
dedicated Linux host. The Compose overlay is for rootful Docker; a Podman server
needs its own socket path and callback configuration.

## Identity and workspace administration

Configure a public OIDC authorization-code client with PKCE. Register
`https://gateway.example/auth/callback` and `https://gateway.example/` as redirect
URIs as required by the IdP. Set `CAUTEM_OIDC_ISSUER`,
`CAUTEM_OIDC_AUDIENCE`, and `CAUTEM_OIDC_CLIENT_ID` in the Compose environment.
The default role claim is `realm_access.roles`; the default platform admin and
user roles are `openshell-admin` and `openshell-user`. Map these to the IdP's
role claim or override the role claim and role names in the Gateway configuration.

Keep the Gateway API port bound to loopback on the host. Terminate HTTPS at the
host's ingress or reverse proxy and send the Console origin to port 7444. Do not
publish the development Vite server. The Compose `ui` profile provides the
same-origin static Console and preserves HTTP and WebSocket proxying.

After OIDC login as a platform admin, create workspaces and invite members with
the CLI:

```bash
cautem gateway add https://gateway.example --name shared
cautem gateway select shared
cautem gateway login
cautem workspace create --name team-a
cautem workspace member add --workspace team-a --subject 'user-id-from-oidc' --role user
cautem workspace member add --workspace team-a --subject 'admin-id-from-oidc' --role admin
```

Membership checks happen in the Gateway for each workspace API, terminal,
file, service, and display request. The Console does not yet include a workspace
membership editor; use the CLI or authenticated workspace API for provisioning.

## Compute boundary

Run one Gateway replica. By default, durable registry state lives in the
owner-only `state.json` file. To store that registry in PostgreSQL, provide
`OPENSHELL_DB_URL` from a secret manager or the ignored Compose `.env` file, or
pass `--db-url`; do not put the URL in the TOML file. Give each Gateway
installation a stable `--name`, use a
PostgreSQL database with TLS and restricted credentials, and back up both the
database and the Gateway data volume. On first start, the Gateway imports an
existing `state.json` into PostgreSQL and archives it as
`state.json.migrated-<timestamp>`. PostgreSQL holds a session advisory lock for
the installation name, so a second active writer for the same installation
fails to start.

PostgreSQL stores the registry snapshot, including local auth material and
credential refresh metadata. Protect it as sensitive data and encrypt backups.
Workspace files, encrypted credential blobs, TLS and secret files, and archived
logs remain in `DataDir`; service sessions and active relay state live in
memory. The current deployment supports one Gateway process. PostgreSQL does
not provide multi-replica availability or coordinated recovery for those
filesystem and in-memory resources. Configure a reverse proxy with TLS and
restrict the management API to Console/CLI clients.

Workspace admins can set aggregate CPU (cores), memory (GiB), GPU count,
concurrent sandbox, and concurrent GUI session limits in the Console. Zero
means unlimited. CPU, memory, and GPU use the allocations recorded for active
sandboxes and are checked before create/start. The Gateway rejects a resource
limit change when it cannot account for active allocations. GUI sessions count
connected noVNC WebSockets and release their slot when the connection closes.
Quota accounting uses the single Gateway process and its durable workspace
records; do not run multiple Gateway replicas.

The optional metrics listener exports total active sandbox/resource allocations
and quota rejection/update counters without workspace-name labels. Bind that
listener to a private monitoring network; its metrics are aggregate across all
workspaces.

The Kubernetes compute driver now provisions workspace namespaces, default-deny
and paired runtime NetworkPolicies, Agent Sandbox workloads with PVC-backed
workspaces, and a separate Cautem proxy companion. It is experimental: this
workspace has not verified a complete Gateway-to-workload session on a target
cluster. Kubernetes compute also requires the Agent Sandbox controller,
digest-pinned `CAUTEM_KUBERNETES_PROXY_IMAGE` and
`CAUTEM_KUBERNETES_RUNTIME_IMAGE`, a reachable
`CAUTEM_KUBERNETES_GRPC_ENDPOINT`, persistent storage, and a CNI that enforces
NetworkPolicy. Follow the live traffic and runtime checks in the
[packaging guide](../packaging/README.md) before enabling it. The Helm chart
does not yet install the Agent Sandbox controller or configure its RBAC. Use
the Docker/Podman backend for this shared-server pilot; run one Gateway process.

Kubernetes policy updates replace immutable Secret generations. Updating policy
on a running sandbox restarts its workload and proxy Pods, then waits for the
supervisor to report the new revision. A sandbox that is already stopped keeps
the new policy for its next start.

The Docker Engine socket gives the Gateway container control over containers on
the host. Run it on a dedicated machine, restrict who can administer the
Gateway, and keep sandbox workloads away from the host network and host mounts.
Do not mount `/var/run/docker.sock` into sandbox containers.

For the Compose Docker overlay, bind the Gateway callback to the host's Docker
bridge IP in `.env` (usually `172.17.0.1`) and apply
`docker-compose.compute.docker.yml`. The callback listens on that private bridge
address so sandbox proxy sidecars can reach the Gateway. Confirm the address on
the target Linux host and keep it off public interfaces.

## Backup and restore

Back up the complete Gateway data volume, including the encrypted credential
store, auth material, and archived logs. When PostgreSQL is configured, the
backup also includes a custom-format `pg_dump` of the registry database. Both
snapshots are taken while the Gateway is stopped. Keep an externally supplied
`CAUTEM_SECRETS_KEK` in a separate secret manager; a backup without its original
KEK cannot decrypt provider credentials. The scripts restart the Gateway after
a successful backup:

```bash
cautem-gateway/compose/backup.sh /secure/backups/gateway-2026-10-13.tar.gz
cautem-gateway/compose/restore.sh /secure/backups/gateway-2026-10-13.tar.gz
```

Restore validates the manifest and archive paths, checks that the selected
file/PostgreSQL mode matches the running Gateway configuration, and creates a
fresh pre-restore snapshot. It replaces the data volume and, in PostgreSQL
mode, restores the registry dump. If restore fails after changing data, the
Gateway stays stopped and the script prints the pre-restore snapshot path.
Keep the IdP configuration, TLS certificates, Compose `.env`, database
connection secret, and KEK backed up separately. Test restores with a
disposable Compose project before using a snapshot for recovery.

## Current limits

This mode supports multiple OIDC users, isolated workspace authorization, and
aggregate quotas on one Gateway instance. It does not provide multi-replica
availability, target-cluster Kubernetes runtime validation, or GPU rendering
validation. The per-workspace quotas do not replace host-level capacity
planning or backups.
