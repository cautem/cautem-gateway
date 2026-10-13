import { expect, test, type Page, type Route } from "@playwright/test";
import { createServer, type Server } from "node:http";
import { create, fromBinary, toBinary } from "@bufbuild/protobuf";
import { createHash, generateKeyPairSync, sign as signJWT } from "node:crypto";
import {
  ApprovePolicyProposalResponseSchema,
  CreateSandboxResponseSchema,
  DeleteSandboxResponseSchema,
  GetConsoleCapabilitiesResponseSchema,
  GetGlobalPolicyResponseSchema,
  GetOverviewResponseSchema,
  GetOperationResponseSchema,
  GetProviderProfileResponseSchema,
  GetSandboxLogsResponseSchema,
  GetSandboxPolicyResponseSchema,
  GetViewerResponseSchema,
  ImportProviderProfileResponseSchema,
  ListPolicyProposalsResponseSchema,
  ListProviderProfilesResponseSchema,
  ListServicesResponseSchema,
  ListSandboxPolicyRevisionsResponseSchema,
  ListSandboxesResponseSchema,
  ListWorkspacesResponseSchema,
  RejectPolicyProposalResponseSchema,
  StartSandboxResponseSchema,
  StopSandboxResponseSchema,
  UpdateProviderCredentialsResponseSchema,
  UpdateGlobalPolicyResponseSchema,
  UpdateProviderProfileResponseSchema,
  UpdateSandboxPolicyResponseSchema,
  StopSandboxRequestSchema,
  DeleteSandboxRequestSchema,
  UpdateWorkspaceQuotaRequestSchema,
  UpdateWorkspaceQuotaResponseSchema,
  type UpdateWorkspaceQuotaRequest,
} from "@cautem/control-client";

const issuer = "http://identity.test/dex";
const clientID = "console-test";
const denyCreateForPage = new WeakMap<Page, () => void>();
const workspaceQuotaRequestForPage = new WeakMap<Page, () => UpdateWorkspaceQuotaRequest | null>();
let uploadServer: Server;
let uploadEndpoint = "";
let uploadedPayload = "";

test.beforeAll(async () => {
  uploadServer = createServer((request, response) => {
    response.setHeader("Access-Control-Allow-Origin", "http://127.0.0.1:4173");
    response.setHeader("Access-Control-Allow-Methods", "PUT, OPTIONS");
    response.setHeader("Access-Control-Allow-Headers", "authorization,content-type");
    if (request.method === "OPTIONS") {
      response.writeHead(204).end();
      return;
    }
    if (request.method !== "PUT" || request.url !== "/files/upload") {
      response.writeHead(404).end();
      return;
    }
    const chunks: Buffer[] = [];
    request.on("data", (chunk: Buffer | string) => chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk)));
    request.on("end", () => {
      uploadedPayload = Buffer.concat(chunks).toString();
      response.writeHead(204).end();
    });
  });
  await new Promise<void>((resolve, reject) => {
    uploadServer.once("error", reject);
    uploadServer.listen(0, "127.0.0.1", resolve);
  });
  const address = uploadServer.address();
  if (!address || typeof address === "string") throw new Error("Could not determine upload test server address");
  uploadEndpoint = `http://127.0.0.1:${address.port}/files/upload`;
});

test.afterAll(async () => {
  if (uploadServer?.listening) await new Promise<void>((resolve, reject) => uploadServer.close((error) => error ? reject(error) : resolve()));
});

test.beforeEach(async ({ page }, testInfo) => {
  await mockGateway(page, testInfo.title !== "starts OIDC authorization with PKCE");
});

test("publishes installable desktop web app metadata", async ({ page }) => {
  await page.goto("/");
  await expect(page.locator('link[rel="manifest"]')).toHaveAttribute("href", "/manifest.webmanifest");

  const response = await page.request.get("http://127.0.0.1:4173/manifest.webmanifest");
  expect(response.ok()).toBeTruthy();
  const manifest = await response.json() as { display: string; start_url: string; icons: { src: string; sizes: string; type: string }[] };
  expect(manifest.display).toBe("standalone");
  expect(manifest.start_url).toBe("/");
  expect(manifest.icons.map((icon) => icon.sizes)).toEqual(expect.arrayContaining(["192x192", "512x512"]));

  for (const icon of manifest.icons) {
    const iconResponse = await page.request.get(`http://127.0.0.1:4173${icon.src}`);
    expect(iconResponse.ok()).toBeTruthy();
    expect(iconResponse.headers()["content-type"]).toContain(icon.type);
  }
});

test("starts OIDC authorization with PKCE", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("button", { name: /sign in/i })).toBeVisible();

  await page.route(`${issuer}/.well-known/openid-configuration`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      issuer,
      authorization_endpoint: `${issuer}/authorize`,
      token_endpoint: `${issuer}/token`,
      jwks_uri: `${issuer}/keys`,
      response_types_supported: ["code"],
      subject_types_supported: ["public"],
      id_token_signing_alg_values_supported: ["RS256"],
      code_challenge_methods_supported: ["S256"],
    }),
  }));
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const jwk = { ...(publicKey.export({ format: "jwk" }) as Record<string, string>), kid: "console-test-key", use: "sig", alg: "RS256" };
  await page.route(`${issuer}/keys`, (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:4173" },
    body: JSON.stringify({ keys: [jwk] }),
  }));
  await page.route(`${issuer}/authorize**`, (route) => route.fulfill({ status: 200, body: "Identity provider" }));
  await page.route(`${issuer}/token`, async (route) => {
    const form = new URLSearchParams(route.request().postData() ?? "");
    const verifier = form.get("code_verifier") ?? "";
    expect(createHash("sha256").update(verifier).digest("base64url")).toBe(authorization.searchParams.get("code_challenge"));
    expect(form.get("grant_type")).toBe("authorization_code");
    const idToken = signedToken(privateKey, {
      iss: issuer,
      sub: "alice@example.test",
      aud: clientID,
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      nonce: authorization.searchParams.get("nonce"),
    });
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      headers: { "Access-Control-Allow-Origin": "http://127.0.0.1:4173" },
      body: JSON.stringify({ access_token: "test-access-token", token_type: "Bearer", expires_in: 3600, scope: "openid profile", id_token: idToken }),
    });
  });
  await page.getByRole("button", { name: /sign in/i }).click();
  await page.waitForURL(new RegExp(`${issuer.replaceAll(".", "\\.")}/authorize`));

  const authorization = new URL(page.url());
  expect(authorization.searchParams.get("response_type")).toBe("code");
  expect(authorization.searchParams.get("client_id")).toBe(clientID);
  expect(authorization.searchParams.get("redirect_uri")).toBe("http://127.0.0.1:4173/auth/callback");
  expect(authorization.searchParams.get("code_challenge_method")).toBe("S256");
  expect(authorization.searchParams.get("code_challenge")).toMatch(/^[A-Za-z0-9_-]{43}$/);

  await page.goto(`http://127.0.0.1:4173/auth/callback?code=test-code&state=${encodeURIComponent(authorization.searchParams.get("state") ?? "")}`);
  await expect(page.getByRole("heading", { name: "Sandboxes" })).toBeVisible();
  await expect(page.getByText("alice@example.test").first()).toBeVisible();
  await expect(page).toHaveURL("http://127.0.0.1:4173/");
});

test("restores the tab session and opens workspace policy and provider screens", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sandboxes" })).toBeVisible();
  await expect(page.getByText("running", { exact: true }).first()).toBeVisible();

  await page.reload();
  await expect(page.getByRole("heading", { name: "Sandboxes" })).toBeVisible();

  await page.getByRole("button", { name: "Policies" }).click();
  await expect(page.getByRole("heading", { name: "Policies" })).toBeVisible();
  await expect(page.getByText("Allow package mirror")).toBeVisible();
  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Approve" }).click();
  await expect(page.getByText("No pending proposals in this workspace.")).toBeVisible();

  await page.getByRole("button", { name: "Providers" }).click();
  await expect(page.getByRole("heading", { name: "Providers" })).toBeVisible();
  await expect(page.getByLabel("Provider profile YAML", { exact: true })).toHaveValue(/id: github/);
  await page.getByLabel("Provider name").fill("github");
  await page.getByLabel("Credential key").fill("GITHUB_TOKEN");
  await page.getByLabel("Secret value").fill("secret-value");
  await page.getByRole("button", { name: "Save credential" }).click();
  await expect(page.getByText("Updated GITHUB_TOKEN for github.")).toBeVisible();
});

test("workspace admins can update aggregate resource quotas", async ({ page }) => {
  await page.goto("/");
  await page.getByRole("button", { name: "Workspace" }).click();
  await expect(page.getByRole("heading", { name: "Workspace limits" })).toBeVisible();
  await expect(page.getByText("1.00 cores", { exact: true })).toBeVisible();

  await page.getByLabel("CPU cores").fill("4.5");
  await page.getByLabel("Memory GiB").fill("16.25");
  await page.getByLabel("GPUs").fill("1");
  await page.getByLabel("Concurrent sandboxes").fill("8");
  await page.getByLabel("Concurrent GUI sessions").fill("3");
  await page.getByRole("button", { name: "Save limits" }).click();

  await expect(page.getByText("Saved resource limits for default.")).toBeVisible();
  await expect.poll(() => workspaceQuotaRequestForPage.get(page)?.()).toMatchObject({
    name: "default",
    expectedResourceVersion: 1n,
    quota: {
      cpuMillicores: 4500n,
      memoryBytes: 17448304640n,
      gpuCount: 1,
      concurrentSandboxes: 8,
      concurrentGuiSessions: 3,
    },
  });
});

test("creates, stops, and deletes a sandbox through the workspace API", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sandboxes" })).toBeVisible();

  await page.getByRole("button", { name: "New sandbox" }).click();
  await page.getByLabel("Sandbox name").fill("browser-box");
  await page.getByLabel("Container image").fill("alpine:3.22");
  await page.getByRole("button", { name: "Create sandbox" }).click();
  await expect(page.getByRole("row", { name: /browser-box/ })).toBeVisible();

  await page.getByRole("row", { name: /browser-box/ }).click();
  await expect(page.getByText("Runtime status", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Stop", exact: true }).click();
  await expect(page.getByRole("button", { name: "Start", exact: true })).toBeEnabled();

  page.on("dialog", (dialog) => void dialog.accept());
  await page.getByRole("button", { name: "Delete", exact: true }).click();
  await expect(page.getByRole("row", { name: /browser-box/ })).toHaveCount(0);
});

test("opens an authenticated sandbox terminal and sends interactive input", async ({ page }) => {
  const receivedInput: string[] = [];
  await page.routeWebSocket("**/v1/sandboxes/web-demo/terminal", (socket) => {
    socket.onMessage((message) => {
      const frame = JSON.parse(String(message)) as { type: string; token?: string; data?: string };
      if (frame.type === "auth") {
        expect(frame.token).toBe("test-access-token");
        socket.send(JSON.stringify({ type: "ready" }));
      } else if (frame.type === "stdin") {
        receivedInput.push(frame.data ?? "");
        socket.send(JSON.stringify({ type: "stdout", data: btoa("terminal output\r\n") }));
      }
    });
  });

  await page.goto("/");
  await page.getByRole("row", { name: /web-demo/ }).click();
  await page.getByRole("button", { name: "Open terminal" }).click();
  await expect(page.getByRole("status")).toHaveText("Connected");
  await expect(page.getByTestId("sandbox-terminal")).toBeVisible();

  await page.locator(".terminal-window .xterm").click();
  await page.keyboard.type("echo terminal-ready");
  await page.keyboard.press("Enter");
  await expect.poll(() => receivedInput.join("")).toContain("echo terminal-ready");
});

test("opens a noVNC service with a scoped session and no password in the URL", async ({ page }) => {
  let sessionCount = 0;
  await page.route("**/v1/sandboxes/web-demo/services/novnc/session", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    headers: { "Set-Cookie": "cautem_service_session=service-ticket; Path=/v1/sandboxes/web-demo/services/novnc/proxy/; HttpOnly; SameSite=Strict" },
    body: JSON.stringify({ url: "/v1/sandboxes/web-demo/services/novnc/proxy/", expiresAt: new Date(Date.now() + 60_000).toISOString() }),
  }).then(() => { sessionCount++; }));
  await page.route("**/v1/sandboxes/web-demo/services/novnc/proxy/vnc.html**", (route) => route.fulfill({ status: 200, contentType: "text/html", body: "<title>noVNC</title>" }));
  await page.goto("/");
  await page.getByRole("row", { name: /web-demo/ }).click();
  const popupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Open display" }).click();
  const popup = await popupPromise;
  await expect(popup).toHaveURL(/\/vnc\.html\?/);
  const destination = new URL(popup.url());
  expect(destination.searchParams.get("autoconnect")).toBe("true");
  expect(destination.searchParams.get("path")).toBe("ws://127.0.0.1:4173/v1/sandboxes/web-demo/services/novnc/proxy/websockify");
  expect(destination.href).not.toContain("password");
  const reconnectPopupPromise = page.waitForEvent("popup");
  await page.getByRole("button", { name: "Open display" }).click();
  const reconnectPopup = await reconnectPopupPromise;
  await expect(reconnectPopup).toHaveURL(/\/vnc\.html\?/);
  expect(sessionCount).toBe(2);
});

test("exposes and removes sandbox services from the browser console", async ({ page }) => {
  let exposed: unknown;
  let removed = false;
  await page.route("**/v1/sandboxes/web-demo/services", async (route) => {
    expect(route.request().method()).toBe("POST");
    expect(route.request().headers().authorization).toBe("Bearer test-access-token");
    exposed = JSON.parse(route.request().postData() ?? "{}");
    await route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ name: "web", port: 3000 }) });
  });
  await page.route("**/v1/sandboxes/web-demo/services/novnc", async (route) => {
    expect(route.request().method()).toBe("DELETE");
    expect(route.request().headers().authorization).toBe("Bearer test-access-token");
    removed = true;
    await route.fulfill({ status: 204 });
  });
  await page.goto("/");
  await page.getByRole("row", { name: /web-demo/ }).click();
  await page.getByRole("textbox", { name: "Service" }).fill("web");
  await page.getByRole("spinbutton", { name: "Port" }).fill("3000");
  await page.getByRole("button", { name: "Expose", exact: true }).click();
  await expect.poll(() => exposed).toEqual({ name: "web", port: 3000 });
  await page.getByRole("button", { name: "Remove novnc service" }).click();
  await expect.poll(() => removed).toBeTruthy();
});

test("browses, uploads, and downloads files in the sandbox workspace", async ({ page }) => {
  let uploadedFile = "";
  uploadedPayload = "";
  await page.route("**/v1/sandboxes/web-demo/files**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    if (request.method() === "PUT") {
      expect(request.headers().authorization).toBe("Bearer test-access-token");
      uploadedFile = url.searchParams.get("path") ?? "";
      return route.continue({ url: uploadEndpoint });
    }
    if (request.method() === "OPTIONS") {
      return route.continue({ url: uploadEndpoint });
    }
    if (url.pathname.endsWith("/files/download")) {
      expect(url.searchParams.get("path")).toBe("src/main.go");
      return route.fulfill({ status: 200, headers: { "Content-Disposition": "attachment; filename=main.go" }, body: "package main" });
    }
    const path = url.searchParams.get("path");
    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(path === "src"
        ? { entries: [{ name: "main.go", kind: "file", sizeBytes: 12, modifiedAtUnixMs: Date.now() }, ...(uploadedFile ? [{ name: "upload.txt", kind: "file", sizeBytes: 14, modifiedAtUnixMs: Date.now() }] : [])], truncated: false }
        : { entries: [{ name: "README.md", kind: "file", sizeBytes: 25, modifiedAtUnixMs: Date.now() }, { name: "src", kind: "directory", sizeBytes: 0, modifiedAtUnixMs: Date.now() }], truncated: false }),
    });
  });
  await page.goto("/");
  await page.getByRole("row", { name: /web-demo/ }).click();
  await expect(page.getByText("README.md")).toBeVisible();
  await page.locator(".file-name.directory").filter({ hasText: "src" }).click();
  await expect(page.getByText("main.go")).toBeVisible();
  await page.getByLabel("Upload workspace file").setInputFiles({ name: "upload.txt", mimeType: "text/plain", buffer: Buffer.from("upload content") });
  await expect.poll(() => uploadedFile).toBe("src/upload.txt");
  await expect.poll(() => uploadedPayload).toBe("upload content");
  await expect(page.getByText("upload.txt")).toBeVisible();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("button", { name: "Download main.go" }).click();
  const download = await downloadPromise;
  expect(download.suggestedFilename()).toBe("main.go");
});

test("shows a workspace permission error from a denied create action", async ({ page }) => {
  denyCreateForPage.get(page)?.();
  await page.goto("/");
  await page.getByRole("button", { name: "New sandbox" }).click();
  await page.getByLabel("Sandbox name").fill("denied-box");
  await page.getByLabel("Container image").fill("alpine:3.22");
  await page.getByRole("button", { name: "Create sandbox" }).click();
  await expect(page.getByText("sandbox write access denied")).toBeVisible();
});

test("keeps navigation available in the installed mobile layout", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("button", { name: "Workspace" })).toBeVisible();
  await page.getByRole("button", { name: "Policies" }).click();
  await expect(page.getByRole("heading", { name: "Policies" })).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
});

async function mockGateway(page: Page, restoreSession = true) {
  let sandboxes = [sandbox("web-demo", "running")];
  let proposals = [{
    id: "proposal-1", sandboxName: "web-demo", status: "pending", intentSummary: "Allow package mirror",
    ruleName: "package-mirror", ruleYaml: "host: packages.example.test", rationale: "Needed for builds.",
    securityNotes: "Review host scope.", confidence: 0.95, hosts: ["packages.example.test"], rejectionReason: "",
    validationResult: "valid", securityFlagged: false, createdAtUnixMs: BigInt(Date.now()), decidedAtUnixMs: 0n,
  }];
  let profileVersion = 1n;
  let workspaceResourceVersion = 1n;
  let workspaceQuota = { cpuMillicores: 2000n, memoryBytes: 8n << 30n, gpuCount: 2, concurrentSandboxes: 10, concurrentGuiSessions: 4 };
  let lastWorkspaceQuotaRequest: UpdateWorkspaceQuotaRequest | null = null;
  let denyCreate = false;
  denyCreateForPage.set(page, () => { denyCreate = true; });
  workspaceQuotaRequestForPage.set(page, () => lastWorkspaceQuotaRequest);

  const workspaceSummary = () => ({
    name: "default", callerRole: "owner", memberCount: 1, resourceVersion: workspaceResourceVersion,
    updatedAtUnixMs: BigInt(Date.now()), canManageQuota: true,
    quota: workspaceQuota,
    usage: { cpuMillicores: 1000n, memoryBytes: 2n << 30n, gpuCount: 1, activeSandboxes: 2, activeGuiSessions: 1, allocationUnknownSandboxes: 0 },
  });

  if (restoreSession) {
    await page.addInitScript(({ authIssuer, authClientID }) => {
      window.sessionStorage.setItem(`oidc.user:${authIssuer}:${authClientID}`, JSON.stringify({
        access_token: "test-access-token",
        token_type: "Bearer",
        scope: "openid profile",
        profile: { sub: "alice@example.test" },
        expires_at: Math.floor(Date.now() / 1000) + 3600,
      }));
    }, { authIssuer: issuer, authClientID: clientID });
  }

  await page.route("**/v1/auth/oidc", (route) => route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({ issuer, audience: "cautem-test", client_id: clientID, mode: "oidc" }),
  }));

  await page.route("**/cautem.control.v1.**", async (route) => {
    const method = new URL(route.request().url()).pathname.split("/").at(-1) ?? "";
    const row = sandboxes[0];
    switch (method) {
      case "GetViewer": return binary(route, GetViewerResponseSchema, { subject: "alice@example.test", roles: ["workspace_admin"], scopes: ["sandbox:write"], identityProvider: "oidc" });
      case "GetOverview": return binary(route, GetOverviewResponseSchema, { gatewayId: "gateway-test", workspace: "default", sandboxCount: BigInt(sandboxes.length), registryRunningCount: BigInt(sandboxes.filter((item) => item.registryStatus === "running").length), snapshotAtUnixMs: BigInt(Date.now()), runtimeStatusAvailable: true });
      case "GetOperation": return binary(route, GetOperationResponseSchema, {});
      case "ListSandboxes": return binary(route, ListSandboxesResponseSchema, { sandboxes, nextPageToken: "" });
      case "ListWorkspaces": return binary(route, ListWorkspacesResponseSchema, { workspaces: [workspaceSummary()] });
      case "UpdateWorkspaceQuota": {
        lastWorkspaceQuotaRequest = fromBinary(UpdateWorkspaceQuotaRequestSchema, route.request().postDataBuffer() ?? new Uint8Array());
        workspaceQuota = lastWorkspaceQuotaRequest.quota ?? workspaceQuota;
        workspaceResourceVersion++;
        return binary(route, UpdateWorkspaceQuotaResponseSchema, { workspace: workspaceSummary() });
      }
      case "ListServices": return binary(route, ListServicesResponseSchema, { services: [{ name: "novnc", sandboxName: "web-demo", port: 6080, updatedAtUnixMs: BigInt(Date.now()) }] });
      case "GetConsoleCapabilities": return binary(route, GetConsoleCapabilitiesResponseSchema, { sandboxLifecycleAvailable: true, sandboxWatchAvailable: false, computeDrivers: ["docker"] });
      case "GetSandboxLogs": return binary(route, GetSandboxLogsResponseSchema, { lines: [], cursor: 0n });
      case "GetGlobalPolicy": return binary(route, GetGlobalPolicyResponseSchema, { policyYaml: "", resourceVersion: 1n });
      case "UpdateGlobalPolicy": return binary(route, UpdateGlobalPolicyResponseSchema, { resourceVersion: 2n });
      case "ListPolicyProposals": return binary(route, ListPolicyProposalsResponseSchema, { proposals, nextAfterId: "" });
      case "ApprovePolicyProposal": {
        const approved = { ...proposals[0], status: "approved" };
        proposals = [];
        return binary(route, ApprovePolicyProposalResponseSchema, { proposal: approved });
      }
      case "RejectPolicyProposal": {
        const rejected = { ...proposals[0], status: "rejected" };
        proposals = [];
        return binary(route, RejectPolicyProposalResponseSchema, { proposal: rejected });
      }
      case "GetSandboxPolicy": return binary(route, GetSandboxPolicyResponseSchema, { policyYaml: "version: 1\nnetwork_policies: {}\n", resourceVersion: 1n, policyRevision: 1n });
      case "UpdateSandboxPolicy": return binary(route, UpdateSandboxPolicyResponseSchema, { effectivePolicyYaml: "version: 1\nnetwork_policies: {}\n", strippedProviderRules: 0, policyRevision: 2n });
      case "ListSandboxPolicyRevisions": return binary(route, ListSandboxPolicyRevisionsResponseSchema, { revisions: [] });
      case "ListProviderProfiles": return binary(route, ListProviderProfilesResponseSchema, { profiles: [{ id: "github", category: "vcs", source: "custom", scope: "workspace", resourceVersion: profileVersion }] });
      case "GetProviderProfile": return binary(route, GetProviderProfileResponseSchema, { profileYaml: `id: github\nresource_version: ${profileVersion}\n`, source: "custom", resourceVersion: profileVersion });
      case "UpdateProviderProfile": profileVersion++; return binary(route, UpdateProviderProfileResponseSchema, { resourceVersion: profileVersion });
      case "ImportProviderProfile": return binary(route, ImportProviderProfileResponseSchema, { importedId: "imported-provider" });
      case "UpdateProviderCredentials": return binary(route, UpdateProviderCredentialsResponseSchema, { updatedKeys: ["GITHUB_TOKEN"] });
      case "CreateSandbox": {
        if (denyCreate) {
          denyCreate = false;
          return route.fulfill({ status: 403, contentType: "application/json", body: JSON.stringify({ code: "permission_denied", message: "sandbox write access denied" }) });
        }
        const created = sandbox("browser-box", "running");
        sandboxes = [...sandboxes, created];
        return binary(route, CreateSandboxResponseSchema, { sandbox: created, completed: true, operationId: "operation-create" });
      }
      case "StopSandbox": {
        const request = fromBinary(StopSandboxRequestSchema, route.request().postDataBuffer() ?? new Uint8Array());
        sandboxes = sandboxes.map((item) => item.name === request.name ? sandbox(item.name, "stopped") : item);
        return binary(route, StopSandboxResponseSchema, { sandbox: sandbox(request.name, "stopped"), completed: true, operationId: "operation-stop" });
      }
      case "StartSandbox": return binary(route, StartSandboxResponseSchema, { sandbox: sandbox(row?.name ?? "web-demo", "running"), completed: true, operationId: "operation-start" });
      case "DeleteSandbox": {
        const request = fromBinary(DeleteSandboxRequestSchema, route.request().postDataBuffer() ?? new Uint8Array());
        sandboxes = sandboxes.filter((item) => item.name !== request.name);
        return binary(route, DeleteSandboxResponseSchema, { deleted: true, operationId: "operation-delete" });
      }
      default: throw new Error(`Unexpected control RPC: ${method}`);
    }
  });
}

function sandbox(name: string, status: string) {
  return {
    name, workspace: "default", registryStatus: status, computeDriver: "docker", resourceVersion: 2n,
    updatedAtUnixMs: BigInt(Date.now()), runtimeStatusAvailable: true, id: `id-${name}`, image: "alpine:3.22",
    labels: {}, runtimeStatus: status,
  };
}

function signedToken(privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"], claims: Record<string, unknown>) {
  const header = Buffer.from(JSON.stringify({ alg: "RS256", kid: "console-test-key", typ: "JWT" })).toString("base64url");
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signingInput = `${header}.${payload}`;
  const signature = signJWT("RSA-SHA256", Buffer.from(signingInput), privateKey).toString("base64url");
  return `${signingInput}.${signature}`;
}

async function binary(route: Route, schema: any, value: any) {
  await route.fulfill({ status: 200, headers: { "Content-Type": "application/proto" }, body: Buffer.from(toBinary(schema, create(schema, value))) });
}
