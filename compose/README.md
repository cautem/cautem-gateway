# Compose — local production control plane (+ optional OIDC)

Runs **cautem-gateway** with a durable volume for `state.json` + encrypted provider secrets.
The image build uses sibling module checkouts and `go.work`; run these commands from the
multi-repo workspace root, not from a standalone gateway checkout.
Optional **Dex** IdP via Compose profile `oidc` (`cautem gateway login` PKCE).
The installable browser console is available with profile `ui` at
`http://127.0.0.1:7444`; API requests and the OIDC callback share that origin.
Set `CAUTEM_GATEWAY_PORT` or `CAUTEM_CONSOLE_PORT` when the default host ports
are already in use.

For a shared Linux host, use the dedicated [shared server guide](SHARED-SERVER.md).
The optional Docker compute overlay mounts the host Docker socket and must only
run on a dedicated sandbox machine.

```bash
# from workspace root — local-dev token auth
docker compose -f cautem-gateway/compose/docker-compose.yml up -d --build
cautem gateway add http://127.0.0.1:7443 --local --name local
cautem gateway select local
cautem doctor
```

Start the browser console with the gateway:

```bash
docker compose -f cautem-gateway/compose/docker-compose.yml --profile ui up -d --build
open http://127.0.0.1:7444
```

## OIDC (Dex)

```bash
docker compose -f cautem-gateway/compose/docker-compose.yml \
  -f cautem-gateway/compose/docker-compose.oidc.yml --profile oidc up -d --build

cautem gateway add http://127.0.0.1:7443 --local --name local \
  --oidc-issuer http://127.0.0.1:5556/dex \
  --oidc-client-id cautem-cli \
  --oidc-allow-insecure-http

cautem gateway login
# browser → Dex → admin@example.com / password
cautem whoami          # idp=oidc
cautem gateway logout
```

Host networking overlay makes JWT `iss` (`http://127.0.0.1:5556/dex`) reachable for both CLI and gateway JWKS.
CLI PKCE callback is fixed at `http://127.0.0.1:18765/callback` (registered in `dex/config.yaml`).

Add `--profile ui` to install the console alongside Dex, then open
`http://127.0.0.1:7444` and sign in with the configured browser client. Dex's
local client includes the console callback at `/auth/callback`.

## Docker compute (dedicated Linux host)

The default Compose stack runs the control plane and Console without granting
the Gateway access to the host container engine. To enable sandbox creation on
a dedicated Linux Docker host, bind the Docker bridge address in `.env` (usually
`172.17.0.1`) and apply the compute overlay:

```bash
cp cautem-gateway/compose/.env.example cautem-gateway/compose/.env
# Set CAUTEM_GATEWAY_BIND_IP=172.17.0.1 and the OIDC/KEK values in .env.
docker compose \
  -f cautem-gateway/compose/docker-compose.yml \
  -f cautem-gateway/compose/docker-compose.compute.docker.yml \
  --profile ui up -d --build
```

The private Gateway callback is bound to the Docker bridge IP so sandbox proxy
sidecars can reach it through `host.cautem.internal`. Keep that address off
public interfaces. Verify the host bridge address before setting it; it varies
when Docker is configured with a custom bridge subnet. The overlay gives the
Gateway container full control over the host Docker daemon.

## Secrets KEK (do this once)

Without `CAUTEM_SECRETS_KEK`, the gateway generates `secrets.kek` inside the volume. That survives container recreate **as long as the named volume is kept**. If the volume is removed (`docker compose down -v`), ciphertext becomes unreadable unless the same KEK is restored.

Pin a KEK:

```bash
python3 -c 'import os,base64; print(base64.b64encode(os.urandom(32)).decode())'
cp cautem-gateway/compose/.env.example cautem-gateway/compose/.env
# edit .env → CAUTEM_SECRETS_KEK=…
docker compose -f cautem-gateway/compose/docker-compose.yml up -d
```

Rotation runbook: [Credentials](https://cautem.github.io/sandbox.dev/guides/credentials/).

## Tasks

```bash
task gateway:up
task gateway:down
```

Full agent path: [Docker guide](https://cautem.github.io/sandbox.dev/providers/docker/).
