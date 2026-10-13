import { useEffect, useState, type FormEvent } from "react";
import { ConnectError, Code } from "@connectrpc/connect";
import { createControlClients, type SandboxSummary, type WorkspaceSummary } from "@cautem/control-client";

type ControlClients = ReturnType<typeof createControlClients>;

export function PolicyPanel({ clients, workspace, sandboxes }: { clients: ControlClients; workspace: string; sandboxes: SandboxSummary[] }) {
  const [sandboxName, setSandboxName] = useState("");
  const [sandboxPolicy, setSandboxPolicy] = useState("");
  const [policyRevision, setPolicyRevision] = useState(0n);
  const [revisions, setRevisions] = useState<{ revision: bigint; updatedAtUnixMs: bigint; bytes: number; status: string }[]>([]);
  const [proposals, setProposals] = useState<{ id: string; sandboxName: string; status: string; intentSummary: string; ruleName: string; ruleYaml: string; rationale: string; securityNotes: string; securityFlagged: boolean; createdAtUnixMs: bigint }[]>([]);
  const [globalPolicy, setGlobalPolicy] = useState("");
  const [globalVersion, setGlobalVersion] = useState(0n);
  const [canManageGlobal, setCanManageGlobal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  useEffect(() => {
    setSandboxName((current) => sandboxes.some((row) => row.name === current) ? current : sandboxes[0]?.name ?? "");
  }, [sandboxes]);

  useEffect(() => {
    let alive = true;
    void clients.policy.getGlobalPolicy({})
      .then((result) => {
        if (!alive) return;
        setCanManageGlobal(true);
        setGlobalPolicy(result.policyYaml);
        setGlobalVersion(result.resourceVersion);
      })
      .catch((err: unknown) => {
        if (!alive) return;
        setCanManageGlobal(false);
        if (!(err instanceof ConnectError) || err.code !== Code.PermissionDenied) setError(userError(err));
      });
    return () => { alive = false; };
  }, [clients]);

  useEffect(() => {
    let alive = true;
    setError("");
    const proposalsRequest = clients.policy.listPolicyProposals({ workspace, status: "pending", pageSize: 50 });
    const policyRequest = sandboxName
      ? clients.policy.getSandboxPolicy({ workspace, sandboxName, view: "base" })
      : Promise.resolve(null);
    const revisionsRequest = sandboxName
      ? clients.policy.listSandboxPolicyRevisions({ workspace, sandboxName })
      : Promise.resolve(null);
    void Promise.all([proposalsRequest, policyRequest, revisionsRequest]).then(([proposalResult, policyResult, revisionResult]) => {
      if (!alive) return;
      setProposals(proposalResult.proposals);
      setSandboxPolicy(policyResult?.policyYaml ?? "");
      setPolicyRevision(policyResult?.policyRevision ?? 0n);
      setRevisions(revisionResult?.revisions ?? []);
    }).catch((err: unknown) => { if (alive) setError(userError(err)); });
    return () => { alive = false; };
  }, [clients, workspace, sandboxName]);

  async function saveSandboxPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!sandboxName) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await clients.policy.updateSandboxPolicy({ workspace, sandboxName, basePolicyYaml: sandboxPolicy, expectedPolicyRevision: policyRevision });
      setPolicyRevision(result.policyRevision);
      setNotice(`Saved ${sandboxName} policy revision ${result.policyRevision}.`);
      const history = await clients.policy.listSandboxPolicyRevisions({ workspace, sandboxName });
      setRevisions(history.revisions);
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  async function saveGlobalPolicy(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!window.confirm("Apply this policy to every sandbox in the gateway?")) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await clients.policy.updateGlobalPolicy({ policyYaml: globalPolicy, expectedResourceVersion: globalVersion, clear: false });
      setGlobalVersion(result.resourceVersion);
      setNotice(`Saved gateway policy revision ${result.resourceVersion}.`);
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  async function decideProposal(id: string, approve: boolean) {
    const verb = approve ? "Approve" : "Reject";
    if (!window.confirm(`${verb} policy proposal ${id}?`)) return;
    setBusy(true); setError(""); setNotice("");
    try {
      if (approve) await clients.policy.approvePolicyProposal({ workspace, id });
      else await clients.policy.rejectPolicyProposal({ workspace, id, reason: "Rejected from the control console." });
      setProposals((current) => current.filter((item) => item.id !== id));
      setNotice(`Proposal ${approve ? "approved" : "rejected"}.`);
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  async function viewRevision(revision: bigint) {
    if (!sandboxName) return;
    setError("");
    try {
      const result = await clients.policy.getSandboxPolicyRevision({ workspace, sandboxName, revision });
      setSandboxPolicy(result.policyYaml);
      setNotice(`Viewing saved policy revision ${revision}. Save uses the current revision and will reject stale edits.`);
    } catch (err) { setError(userError(err)); }
  }

  return <section className="workspace-panel">
    <div className="intro"><div><div className="eyebrow">WORKSPACE · {workspace}</div><h1>Policies</h1><p>Review policy proposals and edit workspace sandbox policy.</p></div></div>
    {error && <div className="callout error">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
    {notice && <div className="callout success">{notice}<button onClick={() => setNotice("")}>Dismiss</button></div>}
    <div className="panel-grid">
      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">POLICY PROPOSALS</div><h2>Awaiting review <span>{proposals.length}</span></h2></div></div>
        {proposals.length ? <div className="proposal-list">{proposals.map((proposal) => <article className="proposal" key={proposal.id}><div className="proposal-meta"><span>{proposal.sandboxName}</span><time>{formatTime(proposal.createdAtUnixMs)}</time></div><h3>{proposal.intentSummary || proposal.ruleName || "Policy change"}</h3>{proposal.rationale && <p>{proposal.rationale}</p>}{proposal.securityNotes && <p className="security-note">Security review: {proposal.securityNotes}</p>}{proposal.securityFlagged && <span className="warning-tag">Security flagged</span>}{proposal.ruleYaml && <pre>{proposal.ruleYaml}</pre>}<div className="panel-actions"><button disabled={busy} onClick={() => void decideProposal(proposal.id, false)}>Reject</button><button className="panel-primary" disabled={busy} onClick={() => void decideProposal(proposal.id, true)}>Approve</button></div></article>)}</div> : <p className="panel-empty">No pending proposals in this workspace.</p>}
      </section>

      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">SANDBOX POLICY</div><h2>Editable base layer</h2></div><select aria-label="Sandbox policy target" value={sandboxName} onChange={(event) => setSandboxName(event.target.value)}>{sandboxes.map((row) => <option key={row.name} value={row.name}>{row.name}</option>)}</select></div>
        {sandboxName ? <form onSubmit={(event) => void saveSandboxPolicy(event)}><textarea className="yaml-editor" aria-label="Sandbox policy YAML" spellCheck={false} value={sandboxPolicy} onChange={(event) => setSandboxPolicy(event.target.value)} /><div className="editor-footer"><span>Revision {policyRevision.toString()} · {new TextEncoder().encode(sandboxPolicy).length.toLocaleString()} bytes</span><button className="panel-primary" disabled={busy || !sandboxPolicy.trim()}>Save policy</button></div></form> : <p className="panel-empty">Create or select a sandbox to manage its policy.</p>}
        {revisions.length > 0 && <div className="revision-list"><div className="eyebrow">REVISION HISTORY</div>{revisions.map((revision) => <button key={revision.revision.toString()} onClick={() => void viewRevision(revision.revision)}><span>Revision {revision.revision.toString()} · {revision.status}</span><time>{formatTime(revision.updatedAtUnixMs)}</time></button>)}</div>}
      </section>

      {canManageGlobal && <section className="panel-card global-policy-card"><div className="panel-heading"><div><div className="eyebrow">PLATFORM ADMIN</div><h2>Gateway-wide policy</h2></div><span>Version {globalVersion.toString()}</span></div><form onSubmit={(event) => void saveGlobalPolicy(event)}><textarea className="yaml-editor" aria-label="Gateway-wide policy YAML" spellCheck={false} value={globalPolicy} onChange={(event) => setGlobalPolicy(event.target.value)} /><div className="editor-footer"><span>Applies to every sandbox on this gateway.</span><button className="panel-primary" disabled={busy || !globalPolicy.trim()}>Apply globally</button></div></form></section>}
    </div>
  </section>;
}

export function ProvidersPanel({ clients, workspace }: { clients: ControlClients; workspace: string }) {
  const [profiles, setProfiles] = useState<{ id: string; category: string; source: string; scope: string; resourceVersion: bigint }[]>([]);
  const [selectedID, setSelectedID] = useState("");
  const [profileYAML, setProfileYAML] = useState("");
  const [profileSource, setProfileSource] = useState("");
  const [profileVersion, setProfileVersion] = useState(0n);
  const [importID, setImportID] = useState("");
  const [importYAML, setImportYAML] = useState("");
  const [credentialProvider, setCredentialProvider] = useState("");
  const [credentialKey, setCredentialKey] = useState("");
  const [credentialValue, setCredentialValue] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  async function refreshProfiles(selectID = selectedID) {
    const result = await clients.providerProfiles.listProviderProfiles({ workspace });
    setProfiles(result.profiles);
    const next = result.profiles.some((item) => item.id === selectID) ? selectID : result.profiles[0]?.id ?? "";
    setSelectedID(next);
  }

  useEffect(() => {
    let alive = true;
    void clients.providerProfiles.listProviderProfiles({ workspace }).then((result) => {
      if (!alive) return;
      setProfiles(result.profiles);
      setSelectedID((current) => result.profiles.some((item) => item.id === current) ? current : result.profiles[0]?.id ?? "");
    }).catch((err: unknown) => { if (alive) setError(userError(err)); });
    return () => { alive = false; };
  }, [clients, workspace]);

  useEffect(() => {
    if (!selectedID) { setProfileYAML(""); setProfileSource(""); setProfileVersion(0n); return; }
    let alive = true;
    void clients.providerProfiles.getProviderProfile({ workspace, id: selectedID }).then((result) => {
      if (!alive) return;
      setProfileYAML(result.profileYaml);
      setProfileSource(result.source);
      setProfileVersion(result.resourceVersion);
    }).catch((err: unknown) => { if (alive) setError(userError(err)); });
    return () => { alive = false; };
  }, [clients, workspace, selectedID]);

  async function saveProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const profileWorkspace = selected?.scope === "platform" ? "" : workspace;
      const result = await clients.providerProfiles.updateProviderProfile({ workspace: profileWorkspace, id: selectedID, expectedResourceVersion: profileVersion, profileYaml: profileYAML });
      setProfileVersion(result.resourceVersion);
      setNotice(`Saved provider profile ${selectedID}.`);
      await refreshProfiles(selectedID);
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  async function deleteProfile() {
    if (!selectedID || !window.confirm(`Delete custom provider profile ${selectedID}?`)) return;
    setBusy(true); setError(""); setNotice("");
    try {
      const profileWorkspace = selected?.scope === "platform" ? "" : workspace;
      await clients.providerProfiles.deleteProviderProfile({ workspace: profileWorkspace, id: selectedID });
      setNotice(`Deleted provider profile ${selectedID}.`);
      await refreshProfiles("");
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  async function importProfile(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await clients.providerProfiles.importProviderProfile({ workspace, id: importID.trim(), profileYaml: importYAML });
      setImportID(""); setImportYAML("");
      setNotice(`Imported provider profile ${result.importedId}.`);
      await refreshProfiles(result.importedId);
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  async function saveCredential(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setBusy(true); setError(""); setNotice("");
    try {
      const result = await clients.providerCredentials.updateProviderCredentials({ workspace, providerName: credentialProvider.trim(), credentials: { [credentialKey.trim()]: credentialValue } });
      setCredentialValue("");
      setNotice(`Updated ${result.updatedKeys.join(", ") || "provider credential"} for ${credentialProvider.trim()}.`);
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  const selected = profiles.find((item) => item.id === selectedID);
  const editable = profileSource === "custom";

  return <section className="workspace-panel">
    <div className="intro"><div><div className="eyebrow">WORKSPACE · {workspace}</div><h1>Providers</h1><p>Inspect profile definitions and update credentials through the workspace API.</p></div></div>
    {error && <div className="callout error">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
    {notice && <div className="callout success">{notice}<button onClick={() => setNotice("")}>Dismiss</button></div>}
    <div className="panel-grid providers-grid">
      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">PROVIDER CATALOG</div><h2>Profiles <span>{profiles.length}</span></h2></div><select aria-label="Provider profile" value={selectedID} onChange={(event) => setSelectedID(event.target.value)}>{profiles.map((profile) => <option key={profile.id} value={profile.id}>{profile.id} · {profile.source}</option>)}</select></div>
        {selected ? <><div className="profile-tags"><span>{selected.category || "provider"}</span><span>{selected.scope || "platform"}</span><span>{profileSource}</span></div><form onSubmit={(event) => void saveProfile(event)}><textarea className="yaml-editor provider-editor" aria-label="Provider profile YAML" spellCheck={false} readOnly={!editable} value={profileYAML} onChange={(event) => setProfileYAML(event.target.value)} /><div className="editor-footer"><span>{editable ? `Version ${profileVersion.toString()}` : "Built-in profile · read only"}</span>{editable && <div className="panel-actions"><button type="button" className="danger-outline" disabled={busy} onClick={() => void deleteProfile()}>Delete</button><button className="panel-primary" disabled={busy}>Save profile</button></div>}</div></form></> : <p className="panel-empty">No provider profiles are available in this workspace.</p>}
      </section>

      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">CUSTOM PROFILE</div><h2>Import a profile</h2></div></div><form onSubmit={(event) => void importProfile(event)}><label className="panel-field">Profile ID<input required maxLength={63} value={importID} onChange={(event) => setImportID(event.target.value)} placeholder="my-provider" /></label><textarea className="yaml-editor provider-editor" aria-label="New provider profile YAML" spellCheck={false} required value={importYAML} onChange={(event) => setImportYAML(event.target.value)} placeholder={'id: my-provider\nname: My Provider\n'} /><div className="editor-footer"><span>Workspace scoped · up to 1 MiB</span><button className="panel-primary" disabled={busy}>Import profile</button></div></form></section>

      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">SECRET UPDATE</div><h2>Provider credentials</h2></div></div><p className="panel-help">Secret values are write-only in this console. The gateway checks workspace access and keeps values out of profile reads.</p><form onSubmit={(event) => void saveCredential(event)}><label className="panel-field">Provider name<input required maxLength={128} value={credentialProvider} onChange={(event) => setCredentialProvider(event.target.value)} placeholder="github" /></label><label className="panel-field">Credential key<input required maxLength={128} value={credentialKey} onChange={(event) => setCredentialKey(event.target.value)} placeholder="GITHUB_TOKEN" /></label><label className="panel-field">Secret value<input required type="password" autoComplete="new-password" value={credentialValue} onChange={(event) => setCredentialValue(event.target.value)} /></label><div className="editor-footer"><span>Values are never fetched back</span><button className="panel-primary" disabled={busy}>Save credential</button></div></form></section>
    </div>
  </section>;
}

export function WorkspaceQuotaPanel({ clients, workspace, workspaceRecord, onUpdated }: { clients: ControlClients; workspace: string; workspaceRecord?: WorkspaceSummary; onUpdated: () => void }) {
  const [cpuCores, setCPUCores] = useState("");
  const [memoryGiB, setMemoryGiB] = useState("");
  const [gpuCount, setGPUCount] = useState("");
  const [concurrentSandboxes, setConcurrentSandboxes] = useState("");
  const [concurrentGUISessions, setConcurrentGUISessions] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const quota = workspaceRecord?.quota;
  const usage = workspaceRecord?.usage;

  useEffect(() => {
    setCPUCores(quota?.cpuMillicores ? (Number(quota.cpuMillicores) / 1000).toString() : "");
    setMemoryGiB(quota?.memoryBytes ? (Number(quota.memoryBytes) / 1024 ** 3).toString() : "");
    setGPUCount(quota?.gpuCount ? quota.gpuCount.toString() : "");
    setConcurrentSandboxes(quota?.concurrentSandboxes ? quota.concurrentSandboxes.toString() : "");
    setConcurrentGUISessions(quota?.concurrentGuiSessions ? quota.concurrentGuiSessions.toString() : "");
  }, [workspace, workspaceRecord?.resourceVersion]);

  async function saveQuota(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!workspaceRecord?.canManageQuota) return;
    const cpu = cpuCores.trim() ? Number(cpuCores) : 0;
    const memory = memoryGiB.trim() ? Number(memoryGiB) : 0;
    const gpu = gpuCount.trim() ? Number(gpuCount) : 0;
    const sandboxes = concurrentSandboxes.trim() ? Number(concurrentSandboxes) : 0;
    const gui = concurrentGUISessions.trim() ? Number(concurrentGUISessions) : 0;
    if (![cpu, memory, gpu, sandboxes, gui].every((value) => Number.isFinite(value) && value >= 0) ||
        ![gpu, sandboxes, gui].every(Number.isInteger) || cpu * 1000 > Number.MAX_SAFE_INTEGER || memory * 1024 ** 3 > Number.MAX_SAFE_INTEGER ||
        [gpu, sandboxes, gui].some((value) => value > 100000)) {
      setError("Enter non-negative limits. CPU and memory can be fractional; GPU and session limits must be whole numbers.");
      return;
    }
    setBusy(true); setError(""); setNotice("");
    try {
      await clients.workspaceAdmin.updateWorkspaceQuota({
        name: workspace,
        expectedResourceVersion: workspaceRecord.resourceVersion,
        quota: {
          cpuMillicores: BigInt(Math.ceil(cpu * 1000)),
          memoryBytes: BigInt(Math.ceil(memory * 1024 ** 3)),
          gpuCount: gpu,
          concurrentSandboxes: sandboxes,
          concurrentGuiSessions: gui,
        },
      });
      setNotice(`Saved resource limits for ${workspace}.`);
      onUpdated();
    } catch (err) { setError(userError(err)); }
    finally { setBusy(false); }
  }

  return <section className="workspace-panel">
    <div className="intro"><div><div className="eyebrow">WORKSPACE · {workspace}</div><h1>Workspace limits</h1><p>Set aggregate compute and interactive desktop capacity for this workspace.</p></div></div>
    {error && <div className="callout error">{error}<button onClick={() => setError("")}>Dismiss</button></div>}
    {notice && <div className="callout success">{notice}<button onClick={() => setNotice("")}>Dismiss</button></div>}
    <div className="workspace-quota-layout">
      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">AGGREGATE QUOTA</div><h2>Capacity limits</h2></div><span>Zero means unlimited</span></div>
        <form onSubmit={(event) => void saveQuota(event)}>
          <label className="panel-field">CPU cores<input type="number" min="0" step="0.001" value={cpuCores} onChange={(event) => setCPUCores(event.target.value)} placeholder="Unlimited" /></label>
          <label className="panel-field">Memory GiB<input type="number" min="0" step="0.01" value={memoryGiB} onChange={(event) => setMemoryGiB(event.target.value)} placeholder="Unlimited" /></label>
          <label className="panel-field">GPUs<input type="number" min="0" step="1" value={gpuCount} onChange={(event) => setGPUCount(event.target.value)} placeholder="Unlimited" /></label>
          <label className="panel-field">Concurrent sandboxes<input type="number" min="0" step="1" value={concurrentSandboxes} onChange={(event) => setConcurrentSandboxes(event.target.value)} placeholder="Unlimited" /></label>
          <label className="panel-field">Concurrent GUI sessions<input type="number" min="0" step="1" value={concurrentGUISessions} onChange={(event) => setConcurrentGUISessions(event.target.value)} placeholder="Unlimited" /></label>
          <div className="editor-footer"><span>Updates use workspace version {workspaceRecord?.resourceVersion.toString() ?? "0"}</span><button className="panel-primary" disabled={busy || !workspaceRecord?.canManageQuota}>{busy ? "Saving…" : "Save limits"}</button></div>
        </form>
      </section>
      <section className="panel-card"><div className="panel-heading"><div><div className="eyebrow">CURRENT USAGE</div><h2>Allocated capacity</h2></div></div>
        <dl className="quota-usage">
          <dt>CPU</dt><dd>{usage ? `${(Number(usage.cpuMillicores) / 1000).toFixed(2)} cores` : "—"}</dd>
          <dt>Memory</dt><dd>{usage ? `${(Number(usage.memoryBytes) / 1024 ** 3).toFixed(2)} GiB` : "—"}</dd>
          <dt>GPUs</dt><dd>{usage?.gpuCount ?? "—"}</dd>
          <dt>Active sandboxes</dt><dd>{usage?.activeSandboxes ?? "—"}</dd>
          <dt>GUI sessions</dt><dd>{usage?.activeGuiSessions ?? "—"}</dd>
        </dl>
        {!!usage?.allocationUnknownSandboxes && <p className="quota-warning">Resource allocations are unavailable for {usage.allocationUnknownSandboxes} active managed sandbox record(s). CPU, memory, or GPU limits cannot be lowered until those allocations are known or the sandboxes stop.</p>}
        <p className="panel-help">CPU, memory, and GPU are summed across active sandbox records. GUI sessions count connected noVNC WebSockets and release when the connection closes.</p>
      </section>
    </div>
  </section>;
}

function userError(err: unknown) {
  if (err instanceof ConnectError && err.code === Code.Unauthenticated) return "Session expired. Sign in again.";
  return err instanceof Error ? err.message : "Request failed. Try again.";
}

function formatTime(ms: bigint) {
  return ms ? new Date(Number(ms)).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", hour12: false }) : "—";
}
