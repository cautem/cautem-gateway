import { useState, type FormEvent } from "react";

export interface BrowserService {
  name: string;
  sandboxName: string;
  port: number;
}

interface ServicesPanelProps {
  sandboxName: string;
  accessToken: string;
  services: BrowserService[];
  enabled: boolean;
  onChanged: () => void;
}

export function ServicesPanel({ sandboxName, accessToken, services, enabled, onChanged }: ServicesPanelProps) {
  const [opening, setOpening] = useState("");
  const [mutating, setMutating] = useState(false);
  const [error, setError] = useState("");
  const [serviceName, setServiceName] = useState("");
  const [port, setPort] = useState("8080");

  async function openService(service: BrowserService) {
    const popup = window.open("about:blank", "_blank");
    if (!popup) {
      setError("Allow pop-ups to open this sandbox service.");
      return;
    }
    popup.opener = null;
    setOpening(service.name);
    setError("");
    try {
      const endpoint = `/v1/sandboxes/${encodeURIComponent(sandboxName)}/services/${encodeURIComponent(service.name)}/session`;
      const response = await fetch(endpoint, {
        method: "POST",
        credentials: "same-origin",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new Error(response.status === 403 ? "Workspace access to this service was denied." : "Could not open this service.");
      const session = await response.json() as { url?: unknown };
      if (typeof session.url !== "string" || !session.url.startsWith("/v1/")) throw new Error("Gateway returned an invalid service address.");
      const destination = new URL(session.url, window.location.origin);
      if (destination.origin !== window.location.origin) throw new Error("Gateway returned an external service address.");
      if (isDisplayService(service)) {
        destination.pathname += "vnc.html";
        destination.searchParams.set("autoconnect", "true");
        destination.searchParams.set("resize", "scale");
        const wsScheme = window.location.protocol === "https:" ? "wss:" : "ws:";
        destination.searchParams.set("path", `${wsScheme}//${window.location.host}${session.url}websockify`);
      }
      popup.location.replace(destination.toString());
    } catch (err) {
      popup.close();
      setError(err instanceof Error ? err.message : "Could not open this service.");
    } finally {
      setOpening("");
    }
  }

  async function expose(name: string, targetPort: number) {
    setMutating(true);
    setError("");
    try {
      const response = await fetch(`/v1/sandboxes/${encodeURIComponent(sandboxName)}/services`, {
        method: "POST",
        credentials: "same-origin",
        headers: { Authorization: `Bearer ${accessToken}`, "Content-Type": "application/json" },
        body: JSON.stringify({ name, port: targetPort }),
      });
      if (!response.ok) throw new Error(response.status === 409 ? "That service name is already in use." : response.status === 403 ? "Workspace access was denied." : "Could not expose this service.");
      setServiceName("");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not expose this service.");
    } finally {
      setMutating(false);
    }
  }

  async function remove(service: BrowserService) {
    setMutating(true);
    setError("");
    try {
      const response = await fetch(`/v1/sandboxes/${encodeURIComponent(sandboxName)}/services/${encodeURIComponent(service.name)}`, {
        method: "DELETE",
        credentials: "same-origin",
        headers: { Authorization: `Bearer ${accessToken}` },
      });
      if (!response.ok) throw new Error(response.status === 403 ? "Workspace access was denied." : "Could not remove this service.");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Could not remove this service.");
    } finally {
      setMutating(false);
    }
  }

  function submitExpose(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const targetPort = Number(port);
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(serviceName) || !Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) {
      setError("Enter a DNS service name and a port from 1 to 65535.");
      return;
    }
    void expose(serviceName, targetPort);
  }

  return <section className="browser-services" aria-label="Sandbox services">
    <div className="services-heading">
      <div><div className="eyebrow">PUBLISHED SERVICES</div><p className="action-caption">HTTP and WebSocket access is checked by the gateway.</p></div>
      <span className="services-count">{services.length.toString().padStart(2, "0")}</span>
    </div>
    <form className="service-expose-form" onSubmit={submitExpose}>
      <label>Service <input value={serviceName} onChange={(event) => setServiceName(event.target.value)} placeholder="web" maxLength={63} /></label>
      <label>Port <input value={port} onChange={(event) => setPort(event.target.value)} inputMode="numeric" type="number" min="1" max="65535" /></label>
      <button type="submit" disabled={!enabled || mutating}>Expose</button>
    </form>
    <button type="button" className="expose-display" disabled={!enabled || mutating} onClick={() => void expose("novnc", 6080)}>Expose noVNC on port 6080</button>
    {!services.length ? <p className="services-empty">No services have been exposed for this sandbox.</p> : <ul>
      {services.map((service) => {
        const display = isDisplayService(service);
        return <li key={service.name}>
          <div className="service-copy"><strong>{display ? "noVNC display" : service.name}</strong><span>{display ? "Remote desktop" : `Port ${service.port}`}</span></div>
          <div className="service-actions"><button type="button" disabled={!enabled || opening !== "" || mutating} onClick={() => void openService(service)}>{opening === service.name ? "Opening…" : display ? "Open display ↗" : "Open ↗"}</button><button type="button" className="remove-service" disabled={mutating} onClick={() => void remove(service)} aria-label={`Remove ${service.name} service`}>×</button></div>
        </li>;
      })}
    </ul>}
    {!enabled && services.length > 0 && <p className="action-caption">Start this sandbox before opening a service.</p>}
    {error && <p className="callout error service-error" role="alert">{error}</p>}
  </section>;
}

function isDisplayService(service: BrowserService) {
  const name = service.name.toLowerCase();
  return service.port === 6080 || name === "display" || name === "novnc" || name === "gui";
}
