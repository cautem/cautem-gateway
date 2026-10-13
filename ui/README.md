# cautem control console

This is the browser console for the `cautem.control.v1` Connect API. Sign in
with OIDC, inspect workspace sandboxes and observed runtime status, manage
sandbox lifecycle operations, review policy proposals, edit workspace/global
policies, and manage provider profiles and write-only credentials.

## Run locally

From the workspace root, build the generated client first, then start the UI:

```bash
npm ci --prefix cautem-proto/typescript
npm run check --prefix cautem-proto/typescript
npm ci --prefix cautem-gateway/ui
npm run dev --prefix cautem-gateway/ui
```

Vite proxies `/v1/auth/oidc` and Connect requests to `https://127.0.0.1:7443`
by default and accepts the local gateway's development certificate. Point it at
another gateway with `CAUTEM_GATEWAY_TARGET`. This proxy setting is for local
development only.

Configure the gateway with its OIDC issuer, audience, and browser `client_id`.
Register the UI origin's `/auth/callback` URL as a redirect URI for a public
authorization-code client with PKCE enabled. The identity provider must allow
browser discovery/token requests from the UI origin and issue an access token
whose audience matches the gateway's configured audience. Open the UI on the
same origin as the gateway proxy.

The access token is kept in tab-scoped session storage so a page reload can
restore the signed-in view; signing out removes it, and closing the tab discards
the session. The authorization-code state verifier uses the OIDC library's
temporary browser state storage so the redirect can complete. The UI never
calls local login or receives the gateway owner token, supervisor tokens, or
driver credentials.

The UI includes a web app manifest and can be installed from browsers that
support desktop web apps. The manifest includes 192 px and 512 px PNG icons and
uses `standalone` display mode. In Chrome or Edge on Windows, macOS, and Linux,
use the install action in the address bar. On macOS Sonoma 14 or newer, Safari
can add the site to the Dock. The same responsive client remains available as a
normal browser tab.

## Interactive terminal

Select a running sandbox and open its terminal from the details panel. The
gateway starts `/bin/sh` on the sandbox PTY over the existing SSH relay. The
WebSocket handshake must come from the UI origin; the browser sends its OIDC
access token in the first WebSocket message, never in the URL. Gateway access
checks require `sandbox:write` and a workspace role that permits sandbox
changes. The gateway repeats those checks once per second and closes the PTY
when the token expires, workspace membership is removed, or the sandbox stops.

The same-origin reverse proxy must preserve the public `Host` (including its
port) and pass WebSocket `Upgrade` and `Connection` headers. The provided Nginx
configuration does this for `/v1/` routes.

The workspace file panel lists directories and uploads or downloads files up to
16 MiB. Paths are relative to `/workspace`; the gateway rejects traversal and
the sandbox helper refuses symlinks. File operations require a running sandbox
and Python 3 in its image. Official base, GUI, and GPU images include it.

The service panel lists the selected sandbox's exposed services and can expose,
remove, and open an HTTP service. Opening a service creates an opaque HttpOnly
cookie scoped to that service's proxy path; the session lasts at most five
minutes and no longer than the user's OIDC token or mTLS certificate. The
proxy checks workspace membership and sandbox state on each HTTP request and
every second for an open WebSocket. It strips gateway credentials before
forwarding and scopes application cookies to the service path. The service
session is never put in a URL.

For a noVNC display, expose port `6080` with the **Expose noVNC** action or use
`cautem service expose <sandbox> 6080 novnc`. The UI opens `vnc.html` and routes
its WebSocket through the authenticated gateway path; the VNC password is not
added to the URL. A password protected display may still prompt for its password
inside noVNC. The service runs under a path prefix, so applications that build
absolute root URLs may need a configured base path.

## Current boundary

The `ui` Compose profile builds a pinned Nginx image that serves the static
bundle and proxies `/v1/`, `/healthz`, and Connect RPCs to the gateway on the
same origin. The SPA fallback serves `/auth/callback`. For a public deployment,
terminate TLS at the ingress and keep the UI and gateway routes on one origin.
Do not expose a development Vite proxy.

The UI presents `registry_status` as registry data and reports runtime health
only when the gateway has observed it. Sandbox lifecycle actions use durable
operation IDs and the live watch replaces local state from its reconnect
snapshot. Every action is checked by the gateway against the selected
workspace. The console supports terminal, workspace file transfer, and
authenticated service/display access. Workspace membership administration is
available through the Gateway workspace API and CLI; the console does not yet
provide a membership editor. Hardware GPU rendering remains experimental and
has not been verified on an NVIDIA host.
