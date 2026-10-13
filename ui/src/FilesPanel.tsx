import { useEffect, useState, type ChangeEvent } from "react";

interface FileEntry {
  name: string;
  kind: "file" | "directory" | "symlink" | "other";
  sizeBytes: number;
  modifiedAtUnixMs: number;
}

interface DirectoryResult {
  entries: FileEntry[];
  truncated: boolean;
}

interface FilesPanelProps {
  sandboxName: string;
  accessToken: string;
  enabled: boolean;
}

export function FilesPanel({ sandboxName, accessToken, enabled }: FilesPanelProps) {
  const [path, setPath] = useState("");
  const [result, setResult] = useState<DirectoryResult>({ entries: [], truncated: false });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [refreshVersion, setRefreshVersion] = useState(0);

  useEffect(() => {
    let alive = true;
    if (!enabled) { setResult({ entries: [], truncated: false }); return; }
    setLoading(true);
    setError("");
    const query = path ? `?path=${encodeURIComponent(path)}` : "";
    void fetch(`/v1/sandboxes/${encodeURIComponent(sandboxName)}/files${query}`, {
      headers: { Authorization: `Bearer ${accessToken}` },
      credentials: "same-origin",
    }).then(async (response) => {
      if (!response.ok) throw new Error(response.status === 403 ? "Workspace file access was denied." : "Could not read this directory.");
      return await response.json() as DirectoryResult;
    }).then((directory) => {
      if (alive) setResult(directory);
    }).catch((err: unknown) => {
      if (alive) setError(err instanceof Error ? err.message : "Could not read this directory.");
    }).finally(() => { if (alive) setLoading(false); });
    return () => { alive = false; };
  }, [accessToken, enabled, path, refreshVersion, sandboxName]);

  async function upload(event: ChangeEvent<HTMLInputElement>) {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (!file) return;
    if (file.size > 16 * 1024 * 1024) {
      setError("Uploads are limited to 16 MiB.");
      return;
    }
    setBusy(true);
    setError("");
    try {
      const relative = joinPath(path, file.name);
      const response = await fetch(fileEndpoint(sandboxName, "files", relative), {
        method: "PUT",
        credentials: "same-origin",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/octet-stream" },
        body: file,
      });
      if (!response.ok) throw new Error(response.status === 413 ? "Uploads are limited to 16 MiB." : "Could not upload this file.");
      setRefreshVersion((current) => current + 1);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not upload this file.");
    } finally {
      setBusy(false);
    }
  }

  async function download(entry: FileEntry) {
    setBusy(true);
    setError("");
    try {
      const response = await fetch(fileEndpoint(sandboxName, "files/download", joinPath(path, entry.name)), {
        headers: { Authorization: `Bearer ${accessToken}` },
        credentials: "same-origin",
      });
      if (!response.ok) throw new Error(response.status === 413 ? "Downloads are limited to 16 MiB." : "Could not download this file.");
      const objectURL = URL.createObjectURL(await response.blob());
      const anchor = document.createElement("a");
      anchor.href = objectURL;
      anchor.download = entry.name;
      anchor.click();
      window.setTimeout(() => URL.revokeObjectURL(objectURL), 1000);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not download this file.");
    } finally {
      setBusy(false);
    }
  }

  const breadcrumbs = path ? path.split("/") : [];
  return <section className="sandbox-files" aria-label="Sandbox files">
    <div className="files-heading"><div><div className="eyebrow">WORKSPACE FILES</div><p className="action-caption">Workspace directory · uploads and downloads up to 16 MiB.</p></div>
      {enabled && <label className="file-upload-button">Upload<input type="file" aria-label="Upload workspace file" disabled={busy} onChange={(event) => void upload(event)} /></label>}
    </div>
    <nav className="file-breadcrumbs" aria-label="Workspace path">
      <button type="button" onClick={() => setPath("")}>/workspace</button>
      {breadcrumbs.map((segment, index) => <span key={`${segment}-${index}`}><i>/</i><button type="button" onClick={() => setPath(breadcrumbs.slice(0, index + 1).join("/"))}>{segment}</button></span>)}
    </nav>
    {error && <p className="callout error file-error" role="alert">{error}</p>}
    {!enabled ? <p className="files-empty">Start this sandbox to browse its workspace.</p> : loading ? <p className="files-empty" role="status">Loading directory…</p> : result.entries.length ? <ul className="file-list">
      {result.entries.map((entry) => <li key={entry.name}>
        {entry.kind === "directory" ? <button type="button" className="file-name directory" disabled={busy} onClick={() => setPath(joinPath(path, entry.name))}><span>▸</span>{entry.name}</button> : <span className={`file-name ${entry.kind}`}><span>{entry.kind === "file" ? "·" : "⊘"}</span>{entry.name}</span>}
        <small>{entry.kind === "file" ? formatSize(entry.sizeBytes) : entry.kind}</small>
        {entry.kind === "file" && <button type="button" className="file-download" disabled={busy} onClick={() => void download(entry)} aria-label={`Download ${entry.name}`}>↓</button>}
      </li>)}
    </ul> : <p className="files-empty">This directory is empty.</p>}
    {result.truncated && <p className="action-caption">Showing the first 1,000 entries.</p>}
  </section>;
}

function fileEndpoint(sandbox: string, suffix: string, relative: string) {
  return `/v1/sandboxes/${encodeURIComponent(sandbox)}/${suffix}?path=${encodeURIComponent(relative)}`;
}

function joinPath(parent: string, child: string) { return parent ? `${parent}/${child}` : child; }
function formatSize(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}
