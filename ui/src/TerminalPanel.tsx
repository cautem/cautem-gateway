import { useEffect, useRef, useState } from "react";
import { FitAddon } from "@xterm/addon-fit";
import { Terminal } from "@xterm/xterm";
import "@xterm/xterm/css/xterm.css";
import "./terminal.css";

interface TerminalPanelProps {
  sandboxName: string;
  accessToken: string;
  enabled: boolean;
}

interface TerminalEvent {
  type: "ready" | "stdout" | "stderr" | "exit" | "error";
  data?: string;
  exitCode?: number;
  message?: string;
}

export function TerminalPanel({ sandboxName, accessToken, enabled }: TerminalPanelProps) {
  const [open, setOpen] = useState(false);
  const [state, setState] = useState("Closed");
  const host = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open || !host.current) return;

    const terminal = new Terminal({
      cursorBlink: true,
      fontFamily: "IBM Plex Mono Variable, monospace",
      fontSize: 12,
      scrollback: 2000,
      theme: { background: "#14262d", foreground: "#d3e2dc", cursor: "#72c5a6", selectionBackground: "#35544e" },
    });
    const fit = new FitAddon();
    terminal.loadAddon(fit);
    terminal.open(host.current);
    host.current.querySelector(".xterm-helper-textarea")?.setAttribute("aria-label", `Terminal input for sandbox ${sandboxName}`);
    fit.fit();
    const socketURL = new URL(`/v1/sandboxes/${encodeURIComponent(sandboxName)}/terminal`, window.location.href);
    socketURL.protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const socket = new WebSocket(socketURL);
    let ready = false;
    setState("Connecting");

    socket.addEventListener("open", () => {
      socket.send(JSON.stringify({ type: "auth", token: accessToken, cols: terminal.cols, rows: terminal.rows }));
    });
    socket.addEventListener("message", (message: MessageEvent<string>) => {
      let event: TerminalEvent;
      try { event = JSON.parse(message.data) as TerminalEvent; }
      catch { setState("Invalid terminal response"); socket.close(); return; }
      if (event.type === "ready") {
        ready = true;
        setState("Connected");
        terminal.focus();
      } else if (event.type === "stdout" || event.type === "stderr") {
        if (event.data) terminal.write(decodeBase64(event.data));
      } else if (event.type === "exit") {
        ready = false;
        setState(`Exited (${event.exitCode ?? 0})`);
      } else if (event.type === "error") {
        ready = false;
        const messageText = event.message || "Terminal session failed.";
        setState(messageText);
        terminal.writeln(`\r\n\x1b[31m${messageText}\x1b[0m`);
      }
    });
    socket.addEventListener("close", () => {
      ready = false;
      setState((current) => current === "Connected" ? "Disconnected" : current);
    });
    socket.addEventListener("error", () => setState("Could not connect to terminal."));

    const input = terminal.onData((data) => {
      if (ready && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "stdin", data }));
    });
    const resize = terminal.onResize(({ cols, rows }) => {
      if (ready && socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "resize", cols, rows }));
    });
    const observer = new ResizeObserver(() => fit.fit());
    observer.observe(host.current);

    return () => {
      ready = false;
      observer.disconnect();
      input.dispose();
      resize.dispose();
      socket.close();
      terminal.dispose();
    };
  }, [accessToken, open, sandboxName]);

  return <section className="terminal-panel" aria-label="Interactive terminal">
    <div className="terminal-toolbar">
      <span className={`terminal-indicator ${state === "Connected" ? "online" : ""}`} />
      <span className="terminal-state" role="status">{state}</span>
      <button type="button" className="text-button" disabled={!enabled && !open} onClick={() => setOpen((value) => !value)}>
        {open ? "Close terminal" : "Open terminal"}
      </button>
    </div>
    {open && <div className="terminal-window" data-testid="sandbox-terminal" ref={host} />}
    {!enabled && <p className="terminal-help">Start this sandbox before opening a terminal.</p>}
  </section>;
}

function decodeBase64(value: string): Uint8Array {
  const binary = atob(value);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}
