# Packaging status

The gateway image and Compose setup are maintained in [`cautem-gateway/`](../cautem-gateway/): use its [Dockerfile](../cautem-gateway/Dockerfile) and [Compose guide](../cautem-gateway/compose/README.md).

`helm/cautem/` deploys the Gateway and optional PostgreSQL connection Secret.
It does not install the Agent Sandbox controller or configure the Kubernetes
compute driver's RBAC. The driver has an experimental Agent Sandbox backend;
the chart is not a complete Kubernetes compute installation. The chart accepts
an optional existing Secret for the Gateway PostgreSQL registry URL:

Any Kubernetes deployment that enables the Agent Sandbox compute work must use
a CNI that enforces `networking.k8s.io/v1` NetworkPolicy (for example Calico or
Cilium). The default Minikube CNI in the current development profile does not
enforce NetworkPolicy: a live client/server probe still connected after a
default-deny policy was installed. API object creation alone is not an
isolation check.

Before enabling the Kubernetes compute backend in a target cluster, install
the Agent Sandbox controller, configure scoped Gateway permissions and PVC
storage, and run the live traffic probe from `cautem-driver` against that
cluster. Require it to pass:

```sh
CAUTEM_TEST_KUBERNETES=1 GOTOOLCHAIN=go1.27.2 go test ./internal/kubernetes \
  -run '^TestLiveNetworkPolicyEnforcement$' -count=1 -v
```

The probe checks that default-deny blocks traffic, a one-sided allow remains
blocked, and only matching pod/port ingress and egress rules restore the
connection. Run it after CNI upgrades as well as before first deployment. The
live Agent Sandbox create test checks API admission and the gated resource
sequence; it uses placeholder images and does not prove that the published
Cautem runtime and proxy images start or that the Gateway relay works end to
end. Complete those checks on the target cluster before production use.

```yaml
database:
  existingSecret: cautem-gateway-postgres
  uriKey: uri
```

The Secret is injected as `OPENSHELL_DB_URL`, and the Helm release name is used
as the stable single-writer installation key. Keep the persistent data volume:
workspace files, encrypted credential blobs, and archived logs still use
`DataDir`. This chart has not been verified as a production installation path.

Earlier Homebrew and Snap drafts were not usable with the independent repository layout. They are retained in the local workspace backup, outside this active tree, until a release process can build and test them from published dependencies.
