import { useEffect, useState, type ReactNode } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { AppShell } from "@/components/layout/AppShell";
import { Button } from "@/components/ui/Button";
import ClientShare from "@/pages/ClientShare";
import Dashboard from "@/pages/Dashboard";
import Projects from "@/pages/Projects";
import Reports from "@/pages/Reports";
import Settings from "@/pages/Settings";
import { useConfig } from "@/stores/config";

function isTauriRuntime(): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  return Boolean((window as any).__TAURI__ || (window as any).__TAURI_INTERNALS__);
}

function apiBaseUrl(): string {
  const { serverUrl, serverPort } = useConfig.getState();
  const raw = serverUrl.trim().replace(/\/+$/, "");
  try {
    const parsed = new URL(raw);
    if (!parsed.port) {
      parsed.port = String(serverPort);
    }
    return parsed.toString().replace(/\/+$/, "");
  } catch {
    return `${raw}:${serverPort}`;
  }
}

type AuthState = "loading" | "locked" | "unconfigured" | "ready";

function WebLoginGate({ children }: { children: ReactNode }) {
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [authState, setAuthState] = useState<AuthState>("loading");

  useEffect(() => {
    if (isTauriRuntime()) {
      setAuthState("ready");
      return;
    }

    let cancelled = false;
    const check = async () => {
      try {
        const response = await fetch(`${apiBaseUrl()}/api/web-auth/status`, {
          method: "GET",
          credentials: "include",
        });
        if (!response.ok) {
          throw new Error(`auth status failed: ${response.status}`);
        }
        const payload = await response.json() as { configured?: boolean; authenticated?: boolean };
        if (cancelled) {
          return;
        }
        if (!payload.configured) {
          setAuthState("unconfigured");
          return;
        }
        setAuthState(payload.authenticated ? "ready" : "locked");
      } catch {
        if (!cancelled) {
          setAuthState("locked");
        }
      }
    };

    void check();
    return () => {
      cancelled = true;
    };
  }, []);

  if (isTauriRuntime()) {
    return <>{children}</>;
  }

  if (authState === "loading") {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center p-6">
        <div className="w-full max-w-md rounded-xl border border-border bg-surface-1/80 p-6 shadow-xl">
          <h1 className="text-lg font-semibold text-text-primary">PentaForge</h1>
          <p className="mt-2 text-xs text-text-muted">Checking web access policy...</p>
        </div>
      </div>
    );
  }

  if (authState === "unconfigured") {
    return (
      <div className="min-h-screen bg-surface-0 flex items-center justify-center p-6">
        <div className="w-full max-w-md rounded-xl border border-border bg-surface-1/80 p-6 shadow-xl">
          <h1 className="text-lg font-semibold text-text-primary">PentaForge Web Locked</h1>
          <p className="mt-2 text-xs text-text-muted">
            Browser access is blocked until `WEB_UI_PASSWORD` is set in `server/.env`.
          </p>
          <p className="mt-2 text-xs text-text-secondary font-mono">
            WEB_UI_PASSWORD=change-me
          </p>
        </div>
      </div>
    );
  }

  if (authState === "ready") {
    return <>{children}</>;
  }

  return (
    <div className="min-h-screen bg-surface-0 flex items-center justify-center p-6">
      <div className="w-full max-w-sm rounded-xl border border-border bg-surface-1/80 p-6 shadow-xl">
        <h1 className="text-lg font-semibold text-text-primary">PentaForge</h1>
        <p className="mt-1 text-xs text-text-muted">
          Web access is protected. Enter password to continue.
        </p>
        <label className="mt-4 block text-xs text-text-secondary">Password</label>
        <input
          type="password"
          value={password}
          onChange={(event) => {
            setPassword(event.target.value);
            setError("");
          }}
          className="mt-2 w-full rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary focus:outline-none focus:ring-2 focus:ring-pf-500/40"
        />
        {error && <p className="mt-2 text-xs text-red-400">{error}</p>}
        <Button
          className="mt-4 w-full"
          onClick={async () => {
            try {
              const response = await fetch(`${apiBaseUrl()}/api/web-auth/login`, {
                method: "POST",
                credentials: "include",
                headers: {
                  "Content-Type": "application/json",
                },
                body: JSON.stringify({ password }),
              });
              if (!response.ok) {
                throw new Error("invalid credentials");
              }
              setPassword("");
              setError("");
              setAuthState("ready");
            } catch {
              setError("Incorrect password.");
            }
          }}
        >
          Unlock
        </Button>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <WebLoginGate>
      <Routes>
        <Route path="/" element={<AppShell />}>
          <Route index element={<Navigate to="/projects" replace />} />
          <Route path="/projects" element={<Projects />} />
          <Route path="/dashboard" element={<Dashboard />} />
          <Route path="/client-share" element={<ClientShare />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/settings" element={<Settings />} />
        </Route>
      </Routes>
    </WebLoginGate>
  );
}
