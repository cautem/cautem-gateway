import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState, type FormEvent } from "react";
import { createRoot } from "react-dom/client";
import { Code, ConnectError, type Interceptor } from "@connectrpc/connect";
import { createControlClients, createControlTransport, SandboxWatchEventKind, type SandboxSummary, type WorkspaceSummary } from "@cautem/control-client";
import type { User } from "oidc-client-ts";
import { completeSignIn, currentUser, signIn, signOut } from "./auth";
import { PolicyPanel, ProvidersPanel, WorkspaceQuotaPanel } from "./panels";
import { ServicesPanel, type BrowserService } from "./ServicesPanel";
import { FilesPanel } from "./FilesPanel";
const TerminalPanel = lazy(() => import("./TerminalPanel").then((module) => ({ default: module.TerminalPanel })));
import "@fontsource-variable/space-grotesk";
import "@fontsource-variable/manrope";
import "@fontsource/ibm-plex-mono/400.css";
import "./style.css";
import "./actions.css";
import "./panels.css";

function ControlApp() {
  const [user, setUser] = useState<User | null>(null);
  const [authError, setAuthError] = useState("");
  const [loadingAuth, setLoadingAuth] = useState(true);
  const [rows, setRows] = useState<SandboxSummary[]>([]);
  const [viewer, setViewer] = useState<{ subject: string; roles: string[] } | null>(null);
  const [overview, setOverview] = useState<{ sandboxCount: bigint; registryRunningCount: bigint; workspace: string } | null>(null);
  const [workspaces, setWorkspaces] = useState<WorkspaceSummary[]>([]);
  const [nextPageToken, setNextPageToken] = useState("");
  const [capabilities, setCapabilities] = useState<{ lifecycle: boolean; watch: boolean }>({ lifecycle: false, watch: false });
  const [selected, setSelected] = useState<SandboxSummary | null>(null);
  const [sandboxServices, setSandboxServices] = useState<BrowserService[]>([]);
  const [servicesRevision, setServicesRevision] = useState(0);
  const [logs, setLogs] = useState<{ timestampUnixMs: bigint; level: string; source: string; message: string }[]>([]);
  const [workspace, setWorkspace] = useState("");
  const [filter, setFilter] = useState("");
  const [busy, setBusy] = useState(false);
  const [actionBusy, setActionBusy] = useState("");
  const [createOpen, setCreateOpen] = useState(false);
  const [createName, setCreateName] = useState("");
  const [createImage, setCreateImage] = useState("ghcr.io/cautem/cautem/sandboxes/base:latest");
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState<"sandboxes" | "policies" | "providers" | "workspace">("sandboxes");
  const [error, setError] = useState("");
  const refreshGeneration = useRef(0);

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        if (window.location.pathname === "/auth/callback") {
          const callbackUser = await completeSignIn();
          if (alive) setUser(callbackUser);
        } else {
          const existing = await currentUser();
          if (alive) setUser(existing);
        }
      } catch (err) {
        if (alive) setAuthError(message(err));
      } finally {
        if (alive) setLoadingAuth(false);
      }
    })();
    return () => { alive = false; };
  }, []);

  const clients = useMemo(() => {
    if (!user?.access_token) return null;
    const bearer: Interceptor = (next) => async (request) => {
      request.header.set("Authorization", `Bearer ${user.access_token}`);
      return next(request);
    };
    return createControlClients(createControlTransport({ baseUrl: window.location.origin, interceptors: [bearer] }));
  }, [user]);

  const refresh = useCallback(async () => {
    if (!clients) return;
    const generation = ++refreshGeneration.current;
    setBusy(true); setError("");
    try {
      const [identity, summary, listed, workspaceList, featureSet] = await Promise.all([
        clients.console.getViewer({}),
        clients.console.getOverview({ workspace }),
        clients.sandboxes.listSandboxes({ workspace, pageSize: 100 }),
        clients.catalog.listWorkspaces({}),
        clients.console.getConsoleCapabilities({}),
      ]);
      if (generation !== refreshGeneration.current) return;
      setViewer({ subject: identity.subject, roles: identity.roles });
      setCapabilities({ lifecycle: featureSet.sandboxLifecycleAvailable, watch: featureSet.sandboxWatchAvailable });
      setWorkspaces(workspaceList.workspaces);
      setWorkspace((current) => current || workspaceList.workspaces[0]?.name || "default");
      setOverview({ sandboxCount: summary.sandboxCount, registryRunningCount: summary.registryRunningCount, workspace: summary.workspace });
      setRows(listed.sandboxes);
      setNextPageToken(listed.nextPageToken);
      setSelected((current) => current ? listed.sandboxes.find((row) => row.name === current.name) ?? null : null);
    } catch (err) {
      if (generation === refreshGeneration.current) setError(apiError(err));
    } finally { if (generation === refreshGeneration.current) setBusy(false); }
  }, [clients, workspace]);

  useEffect(() => {
    if (!clients || !capabilities.watch) return;
    let alive = true;
    let controller: AbortController | undefined;
    let retryDelay = 1000;
    const run = async () => {
      while (alive) {
        controller = new AbortController();
        try {
          for await (const event of clients.sandboxes.watchSandboxes({ workspace }, { signal: controller.signal })) {
            if (!alive) break;
            if (event.kind === SandboxWatchEventKind.RESET) {
              setRows([]);
              setSelected(null);
              setNextPageToken("");
            } else if (event.kind === SandboxWatchEventKind.UPSERT && event.sandbox) {
              setRows((current) => {
                const next = current.filter((row) => row.name !== event.sandbox!.name);
                next.push(event.sandbox!);
                return next.sort((a, b) => a.name.localeCompare(b.name));
              });
              setSelected((current) => current?.name === event.sandbox!.name ? event.sandbox! : current);
            } else if (event.kind === SandboxWatchEventKind.DELETE) {
              setRows((current) => current.filter((row) => row.name !== event.deletedName));
              setSelected((current) => current?.name === event.deletedName ? null : current);
            } else if (event.kind === SandboxWatchEventKind.SYNCED) {
              retryDelay = 1000;
            }
          }
        } catch (err) {
          if (!alive || controller.signal.aborted) break;
          if (err instanceof ConnectError && err.code === Code.Unauthenticated) {
            setError("Session expired. Sign in again.");
            break;
          }
        }
        if (!alive) break;
        await new Promise((resolve) => window.setTimeout(resolve, retryDelay));
        retryDelay = Math.min(retryDelay * 2, 15000);
      }
    };
    void run();
    return () => { alive = false; controller?.abort(); };
  }, [clients, capabilities.watch, workspace]);

  useEffect(() => {
    void refresh();
    return () => { refreshGeneration.current++; };
  }, [refresh]);

  const logout = useCallback(async () => {
    refreshGeneration.current++;
    await signOut();
    setUser(null);
    setViewer(null);
    setOverview(null);
    setWorkspaces([]);
    setRows([]);
    setNextPageToken("");
    setSelected(null);
    setSandboxServices([]);
    setLogs([]);
    setError("");
    setBusy(false);
    setCapabilities({ lifecycle: false, watch: false });
    setNotice("");
    setPage("sandboxes");
  }, []);

  const createSandbox = useCallback(async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!clients || !capabilities.lifecycle) return;
    const name = createName.trim();
    const image = createImage.trim();
    if (!/^[a-z0-9](?:[a-z0-9-]{0,17}[a-z0-9])?$/.test(name)) {
      setError("Use a lowercase DNS name with up to 19 letters, numbers, or hyphens.");
      return;
    }
    if (!image) { setError("Container image is required."); return; }
    const requestId = crypto.randomUUID();
    setActionBusy("create"); setError(""); setNotice("");
    try {
      const result = await clients.sandboxes.createSandbox({ workspace: workspace || "default", name, image, requestId });
      setCreateOpen(false);
      setCreateName("");
      setNotice(`Created ${name} · operation ${result.operationId}`);
      await refresh();
    } catch (err) {
      setError(apiError(err));
      await reconcileOperation(clients, workspace || "default", requestId, setNotice);
    } finally { setActionBusy(""); }
  }, [clients, capabilities.lifecycle, createName, createImage, workspace, refresh]);

  const runAction = useCallback(async (action: "start" | "stop" | "delete") => {
    if (!clients || !selected || !capabilities.lifecycle || actionBusy) return;
    if (action === "delete" && !window.confirm(`Delete sandbox “${selected.name}” from workspace “${selected.workspace}”? This removes its sandbox data.`)) return;
    const requestId = crypto.randomUUID();
    const targetWorkspace = selected.workspace || workspace || "default";
    setActionBusy(action); setError(""); setNotice("");
    try {
      let operationId = "";
      if (action === "start") {
        const result = await clients.sandboxes.startSandbox({ workspace: targetWorkspace, name: selected.name, expectedResourceVersion: selected.resourceVersion, requestId });
        operationId = result.operationId;
      } else if (action === "stop") {
        const result = await clients.sandboxes.stopSandbox({ workspace: targetWorkspace, name: selected.name, expectedResourceVersion: selected.resourceVersion, requestId });
        operationId = result.operationId;
      } else {
        const result = await clients.sandboxes.deleteSandbox({ workspace: targetWorkspace, name: selected.name, expectedResourceVersion: selected.resourceVersion, requestId });
        operationId = result.operationId;
        setSelected(null);
      }
      setNotice(`${action === "delete" ? "Deleted" : `${action === "start" ? "Started" : "Stopped"}`} ${selected.name} · operation ${operationId}`);
      await refresh();
    } catch (err) {
      setError(apiError(err));
      await reconcileOperation(clients, targetWorkspace, requestId, setNotice);
      await refresh();
    } finally { setActionBusy(""); }
  }, [clients, selected, capabilities.lifecycle, actionBusy, workspace, refresh]);

  const loadMore = useCallback(async () => {
    if (!clients || !nextPageToken) return;
    const generation = refreshGeneration.current;
    setBusy(true);
    try {
      const page = await clients.sandboxes.listSandboxes({ workspace, pageSize: 100, pageToken: nextPageToken });
      if (generation !== refreshGeneration.current) return;
      setRows((existing) => existing.concat(page.sandboxes));
      setNextPageToken(page.nextPageToken);
    } catch (err) { if (generation === refreshGeneration.current) setError(apiError(err)); }
    finally { if (generation === refreshGeneration.current) setBusy(false); }
  }, [clients, nextPageToken, workspace]);

  useEffect(() => {
    if (!clients || !selected) { setLogs([]); return; }
    let alive = true;
    clients.sandboxes.getSandboxLogs({ workspace, name: selected.name, limit: 120 })
      .then((result) => { if (alive) setLogs(result.lines); })
      .catch((err: unknown) => { if (alive) setError(apiError(err)); });
    return () => { alive = false; };
  }, [clients, selected, workspace]);

  useEffect(() => {
    if (!clients || !selected) { setSandboxServices([]); return; }
    let alive = true;
    clients.catalog.listServices({ workspace: selected.workspace || workspace || "default" })
      .then((result) => {
        if (alive) setSandboxServices(result.services.filter((item) => item.sandboxName === selected.name).map((item) => ({
          name: item.name, sandboxName: item.sandboxName, port: item.port,
        })));
      })
      .catch((err: unknown) => { if (alive) setError(apiError(err)); });
    return () => { alive = false; };
  }, [clients, selected, servicesRevision, workspace]);

  const visibleRows = rows.filter((row) => `${row.name} ${row.image} ${row.computeDriver} ${row.registryStatus}`.toLowerCase().includes(filter.toLowerCase()));
  const observedRuntimeRows = rows.filter((row) => row.runtimeStatusAvailable);
  const workspaceRecord = workspaces.find((item) => item.name === (workspace || "default"));
  const canManageQuota = workspaceRecord?.canManageQuota ?? false;

  if (loadingAuth) return <main className="auth-stage"><div className="auth-card"><Brand /><p className="quiet">Connecting to your gateway…</p></div></main>;
  if (!user) return <main className="auth-stage"><div className="auth-card"><Brand /><div className="eyebrow">CONTROL CONSOLE</div><h1>Your sandbox fleet,<br />in one place.</h1><p className="auth-copy">Sign in with your organization identity to inspect the resources available to you.</p>{authError && <div className="callout error">{authError}</div>}<button className="primary-button" onClick={() => void signIn().catch((e) => setAuthError(message(e)))}>Sign in <span>↗</span></button><p className="auth-foot">Access is checked by the gateway for every request.</p></div></main>;

  return <div className="shell">
    <aside className="rail"><Brand compact /><div className="rail-label">WORKSPACE</div><label className="workspace-select"><span className="workspace-dot" /><select value={workspace || "default"} onChange={(event) => { refreshGeneration.current++; setSelected(null); setRows([]); setNextPageToken(""); setWorkspace(event.target.value); }} aria-label="Select workspace">{(workspaces.length ? workspaces.map((item) => item.name) : ["default"]).map((name) => <option key={name} value={name}>{name}</option>)}</select><span className="chevron">⌄</span></label><div className="rail-label nav-label">CONTROL</div><button className={`nav-link ${page === "sandboxes" ? "active" : ""}`} onClick={() => { setPage("sandboxes"); setSelected(null); }}><span className="nav-icon">▦</span>Sandboxes<span className="nav-count">{rows.length}</span></button><button className={`nav-link ${page === "policies" ? "active" : ""}`} onClick={() => { setPage("policies"); setSelected(null); }}><span className="nav-icon">⌁</span>Policies</button><button className={`nav-link ${page === "providers" ? "active" : ""}`} onClick={() => { setPage("providers"); setSelected(null); }}><span className="nav-icon">◈</span>Providers</button>{canManageQuota && <button className={`nav-link ${page === "workspace" ? "active" : ""}`} onClick={() => { setPage("workspace"); setSelected(null); }}><span className="nav-icon">◫</span>Workspace</button>}<div className="rail-bottom"><div className="gateway-mark"><span className="pulse" />GATEWAY ONLINE</div><div className="profile"><div className="avatar">{(viewer?.subject ?? user.profile.sub ?? "U").slice(0, 1).toUpperCase()}</div><div className="profile-copy"><strong>{viewer?.subject ?? user.profile.sub ?? "Signed in"}</strong><span>{viewer?.roles.join(", ") || "viewer"}</span></div><button aria-label="Sign out" className="icon-button" onClick={() => void logout().catch((err: unknown) => setError(apiError(err)))}>↗</button></div></div></aside>
    <main className="main" id="fleet">
      <header className="topbar"><div className="crumb">cautem <span>/</span> {page === "sandboxes" ? "Sandboxes" : page === "policies" ? "Policies" : page === "providers" ? "Providers" : "Workspace"}</div><div className="topbar-right"><span className="sync-note"><span className="sync-dot" />Registry snapshot</span><button className="refresh-button" onClick={() => void refresh()} disabled={busy}><span className={busy ? "spin" : ""}>↻</span> Refresh</button></div></header>
      {page === "sandboxes" ? <>
      <section className="intro"><div><div className="eyebrow">FLEET LEDGER <span>·</span> {overview?.workspace || workspace || "DEFAULT WORKSPACE"}</div><h1>Sandboxes</h1><p>Resources visible in this workspace, as recorded by the gateway.</p></div><div className="intro-tools">{capabilities.lifecycle && <button className="create-button" onClick={() => { setCreateOpen(true); setError(""); }}>New sandbox <span>＋</span></button>}<div className="intro-stamp"><span className="stamp-glyph">C</span><span>cautem<br />CONTROL PLANE</span></div></div></section>
      <section className="metric-strip" aria-label="Workspace summary"><div className="metric"><span className="metric-label">REGISTERED SANDBOXES</span><strong>{overview?.sandboxCount.toString() ?? "—"}</strong></div><div className="metric"><span className="metric-label">REGISTRY MARKED RUNNING</span><strong>{overview?.registryRunningCount.toString() ?? "—"}</strong></div><div className="metric metric-note"><span className="metric-label">RUNTIME STATUS</span><strong><i className="status-dash" />{rows.length && observedRuntimeRows.length === rows.length ? "Observed" : observedRuntimeRows.length ? "Partial" : "Unavailable"}</strong><small>Compute driver inspection · loaded rows</small></div><div className="metric-signal"><div className="signal-line"><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /><i /></div><span>REGISTRY SIGNAL · {rows.length ? "RECEIVED" : "AWAITING DATA"}</span></div></section>
      {error && <div className="callout error global-error">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
      {notice && <div className="callout success global-error">{notice}<button onClick={() => setNotice("")}>Dismiss</button></div>}
      <section className="ledger"><div className="ledger-head"><div><div className="eyebrow">RESOURCE INVENTORY</div><h2>Workspace resources <span>{visibleRows.length.toString().padStart(2, "0")}</span></h2></div><label className="search"><span>⌕</span><input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter by name, image, status" aria-label="Filter sandboxes"/><kbd>⌘ K</kbd></label></div>
        <div className="table-wrap"><table><thead><tr><th>NAME / ID</th><th>REGISTRY STATE</th><th>RUNTIME STATUS</th><th>COMPUTE</th><th>IMAGE</th><th>UPDATED</th><th /></tr></thead><tbody>{visibleRows.map((row) => <tr key={`${row.workspace}/${row.name}`} className={selected?.name === row.name ? "selected-row" : ""} onClick={() => setSelected(row)} tabIndex={0} onKeyDown={(e) => { if (e.key === "Enter") setSelected(row); }}><td><div className="sandbox-name"><span className={`state-bar ${stateTone(row.registryStatus)}`} /><div><strong>{row.name}</strong><small>{row.id || `${row.workspace}/${row.name}`}</small></div></div></td><td><span className={`state-pill ${stateTone(row.registryStatus)}`}><i />{row.registryStatus || "unknown"}</span></td><td><span className={`state-pill ${stateTone(row.runtimeStatus)}`}><i />{row.runtimeStatusAvailable ? row.runtimeStatus : "unavailable"}</span></td><td className="mono">{row.computeDriver || "—"}</td><td className="image-cell">{row.image || "—"}</td><td className="mono">{formatTime(row.updatedAtUnixMs)}</td><td className="row-arrow">↗</td></tr>)}</tbody></table>
          {!visibleRows.length && <div className="empty-state"><span>⌁</span><strong>{rows.length ? "No matching sandboxes" : busy ? "Loading registry" : "No sandboxes in this workspace"}</strong><p>{rows.length ? "Try a shorter filter." : "When resources are registered, they will appear here."}</p></div>}
        </div><div className="table-foot"><span>Showing {visibleRows.length}{nextPageToken ? "+" : ""} resources</span>{nextPageToken ? <button className="text-button" disabled={busy} onClick={() => void loadMore()}>Load next page →</button> : <span>Source: gateway registry <i className="foot-dot" /></span>}</div>
      </section>
      </> : page === "policies" ? <PolicyPanel clients={clients!} workspace={workspace || "default"} sandboxes={rows} /> : page === "providers" ? <ProvidersPanel clients={clients!} workspace={workspace || "default"} /> : <WorkspaceQuotaPanel clients={clients!} workspace={workspace || "default"} workspaceRecord={workspaceRecord} onUpdated={() => void refresh()} />}
    </main>
    {page === "sandboxes" && selected && <><button className="scrim" aria-label="Close sandbox details" onClick={() => setSelected(null)} /><aside className="detail-panel"><div className="detail-top"><div><div className="eyebrow">SANDBOX RECORD</div><div className="detail-title">{selected.name}</div></div><button className="icon-button close-button" aria-label="Close details" onClick={() => setSelected(null)}>×</button></div><span className={`state-pill ${stateTone(selected.registryStatus)}`}><i />registry: {selected.registryStatus || "unknown"}</span><div className="detail-section"><div className="eyebrow">IDENTITY</div><dl><dt>Workspace</dt><dd>{selected.workspace}</dd><dt>Resource ID</dt><dd>{selected.id || "—"}</dd><dt>Version</dt><dd>{selected.resourceVersion.toString()}</dd><dt>Updated</dt><dd>{formatTime(selected.updatedAtUnixMs)}</dd><dt>Compute driver</dt><dd>{selected.computeDriver || "—"}</dd><dt>Runtime status</dt><dd>{selected.runtimeStatusAvailable ? selected.runtimeStatus : "Unavailable"}</dd></dl></div><div className="detail-section"><div className="eyebrow">IMAGE</div><div className="image-detail">{selected.image || "No image recorded"}</div></div>{capabilities.lifecycle && <div className="detail-section"><div className="eyebrow">LIFECYCLE</div><div className="sandbox-actions"><button disabled={!!actionBusy || stateTone(selected.runtimeStatusAvailable ? selected.runtimeStatus : selected.registryStatus) === "green"} onClick={() => void runAction("start")}>{actionBusy === "start" ? "Starting…" : "Start"}</button><button disabled={!!actionBusy || stateTone(selected.runtimeStatusAvailable ? selected.runtimeStatus : selected.registryStatus) !== "green"} onClick={() => void runAction("stop")}>{actionBusy === "stop" ? "Stopping…" : "Stop"}</button><button className="danger-action" disabled={!!actionBusy} onClick={() => void runAction("delete")}>{actionBusy === "delete" ? "Deleting…" : "Delete"}</button></div><p className="action-caption">Actions are checked against workspace permissions by the gateway.</p></div>}<div className="detail-section"><div className="eyebrow">INTERACTIVE TERMINAL</div><p className="action-caption">Commands run inside {selected.name}; workspace access is rechecked while the terminal is open.</p><Suspense fallback={<p className="action-caption">Loading terminal…</p>}><TerminalPanel sandboxName={selected.name} accessToken={user.access_token} enabled={stateTone(selected.runtimeStatusAvailable ? selected.runtimeStatus : selected.registryStatus) === "green"} /></Suspense></div><div className="detail-section"><ServicesPanel sandboxName={selected.name} accessToken={user.access_token} services={sandboxServices} enabled={stateTone(selected.runtimeStatusAvailable ? selected.runtimeStatus : selected.registryStatus) === "green"} onChanged={() => setServicesRevision((value) => value + 1)} /></div><div className="detail-section"><FilesPanel sandboxName={selected.name} accessToken={user.access_token} enabled={stateTone(selected.runtimeStatusAvailable ? selected.runtimeStatus : selected.registryStatus) === "green"} /></div><div className="detail-section"><div className="log-heading"><div><div className="eyebrow">RECENT LOGS</div><span>Gateway buffer · latest 120</span></div><button className="text-button" onClick={() => void refresh()}>Reload</button></div><div className="log-window">{logs.length ? logs.map((line, i) => <div className="log-line" key={`${line.timestampUnixMs}-${i}`}><time>{new Date(Number(line.timestampUnixMs)).toLocaleTimeString([], { hour12: false })}</time><b className={`log-level ${line.level.toLowerCase()}`}>{line.level || "INFO"}</b><span>{line.message}</span></div>) : <div className="logs-empty">No buffered log lines.</div>}</div><p className="log-caption">Structured log fields are omitted. The buffer is in memory and may reset.</p></div><div className="runtime-note"><span>i</span><p>{selected.runtimeStatusAvailable ? "Runtime status observed from the configured compute driver." : "Runtime health is not available from this compute driver."}</p></div></aside></>}
    {page === "sandboxes" && createOpen && <div className="modal-backdrop" onMouseDown={(event) => { if (event.target === event.currentTarget && !actionBusy) setCreateOpen(false); }}><section className="create-modal" role="dialog" aria-modal="true" aria-labelledby="create-title"><div className="detail-top"><div><div className="eyebrow">WORKSPACE · {workspace || "default"}</div><h2 id="create-title">Create sandbox</h2></div><button className="icon-button" aria-label="Close create dialog" disabled={!!actionBusy} onClick={() => setCreateOpen(false)}>×</button></div><form onSubmit={(event) => void createSandbox(event)}><label>Sandbox name<input required maxLength={19} pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?" value={createName} onChange={(event) => setCreateName(event.target.value)} placeholder="my-sandbox" autoFocus /></label><label>Container image<input required maxLength={1024} value={createImage} onChange={(event) => setCreateImage(event.target.value)} /></label><p>Creation uses the gateway runtime and workspace policy. The gateway records an operation for recovery if the connection drops.</p><div className="modal-actions"><button type="button" disabled={!!actionBusy} className="cancel-button" onClick={() => setCreateOpen(false)}>Cancel</button><button className="create-button" disabled={!!actionBusy}>{actionBusy === "create" ? "Creating…" : "Create sandbox"}</button></div></form></section></div>}
  </div>;
}

function Brand({ compact = false }: { compact?: boolean }) { return <div className={`brand ${compact ? "brand-compact" : ""}`}><span className="brand-symbol"><i /><i /><i /></span><span>cautem<small>{compact ? "CONTROL" : ""}</small></span></div>; }
function message(err: unknown) { return err instanceof Error ? err.message : "An unexpected error occurred."; }
function apiError(err: unknown) { return err instanceof ConnectError ? (err.code === Code.Unauthenticated ? "Session expired. Sign in again." : err.message) : message(err); }
async function reconcileOperation(clients: ReturnType<typeof createControlClients>, workspace: string, requestId: string, setNotice: (value: string) => void) {
  try {
    const result = await clients.operations.getOperation({ workspace, requestId });
    if (result.operation) setNotice(`Request status: ${result.operation.state} · operation ${result.operation.id}`);
  } catch { /* Preserve the original action error when the operation cannot be read. */ }
}
function stateTone(status: string) { return status.toLowerCase() === "running" ? "green" : status.toLowerCase() === "stopped" ? "amber" : "neutral"; }
function formatTime(ms: bigint) { return ms ? new Date(Number(ms)).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "—"; }

createRoot(document.getElementById("root")!).render(<ControlApp />);
