import { useMemo, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, MessageSquare, SendHorizontal, Share2 } from "lucide-react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { Input } from "@/components/ui/Input";
import { Toggle } from "@/components/ui/Toggle";
import { createProjectShareLinkFromDesktop, type ProjectShareLinkResponse } from "@/lib/projectBridge";
import { useProjects } from "@/stores/projects";

type MessageSender = "team" | "client";

interface ClientMessage {
  id: string;
  sender: MessageSender;
  text: string;
  at: string;
}

const severityRank: Record<string, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

function formatDateTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "Unknown";
  }
  return parsed.toLocaleString();
}

function formatTime(value: string): string {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) {
    return "--:--";
  }
  return parsed.toLocaleTimeString();
}

export default function ClientShare() {
  const project = useProjects((state) => state.getActive());
  const navigate = useNavigate();

  const [expiresHours, setExpiresHours] = useState("24");
  const [password, setPassword] = useState("");
  const [oneTimeLink, setOneTimeLink] = useState(false);
  const [shareResult, setShareResult] = useState<ProjectShareLinkResponse | null>(null);
  const [shareError, setShareError] = useState("");
  const [shareBusy, setShareBusy] = useState(false);
  const [copied, setCopied] = useState(false);

  const [sender, setSender] = useState<MessageSender>("team");
  const [draft, setDraft] = useState("");
  const [messages, setMessages] = useState<ClientMessage[]>([
    {
      id: "intro",
      sender: "team",
      text: "Client channel ready. Share the final result and keep updates here.",
      at: new Date().toISOString(),
    },
  ]);

  const sortedFindings = useMemo(() => {
    if (!project) {
      return [];
    }
    return [...project.findings].sort((a, b) => {
      const scoreDiff = (severityRank[a.severity] ?? 99) - (severityRank[b.severity] ?? 99);
      if (scoreDiff !== 0) {
        return scoreDiff;
      }
      return new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime();
    });
  }, [project]);

  if (!project) {
    return (
      <div className="flex h-full items-center justify-center">
        <Button onClick={() => navigate("/projects")}>Select a Project</Button>
      </div>
    );
  }

  const totalFindings = project.findings.length;
  const criticalCount = project.findings.filter((item) => item.severity === "critical").length;
  const highCount = project.findings.filter((item) => item.severity === "high").length;
  const verifiedCount = project.findings.filter((item) => item.status === "verified" || item.status === "fixed").length;
  const topFindings = sortedFindings.slice(0, 5);

  async function generateShareLink() {
    if (!project) {
      return;
    }

    const expires = Number(expiresHours);
    if (!Number.isFinite(expires) || expires < 1 || expires > 168) {
      setShareError("Expiry must be between 1 and 168 hours.");
      return;
    }

    const cleanedPassword = password.trim();
    if (cleanedPassword && cleanedPassword.length < 6) {
      setShareError("Password must be at least 6 characters.");
      return;
    }

    setShareBusy(true);
    setShareError("");
    setCopied(false);
    try {
      const result = await createProjectShareLinkFromDesktop(project.id, {
        expires_hours: expires,
        password: cleanedPassword || undefined,
        one_time: oneTimeLink,
      });
      setShareResult(result);
    } catch (error) {
      setShareError(error instanceof Error ? error.message : "Failed to generate share link.");
    } finally {
      setShareBusy(false);
    }
  }

  async function copyLink() {
    if (!shareResult) {
      return;
    }
    await navigator.clipboard.writeText(shareResult.access_url);
    setCopied(true);
  }

  function sendMessage() {
    const clean = draft.trim();
    if (!clean) {
      return;
    }
    const entry: ClientMessage = {
      id: `msg-${Date.now()}`,
      sender,
      text: clean,
      at: new Date().toISOString(),
    };
    setMessages((previous) => [entry, ...previous].slice(0, 100));
    setDraft("");
  }

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-lg font-bold text-text-primary">Client Share</h1>
          <p className="text-xs text-text-muted">
            Final result package and communication hub for {project.name}
          </p>
        </div>
        <Badge variant={project.status} dot>{project.status}</Badge>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
        <Card className="space-y-3">
          <CardHeader className="mb-0">
            <CardTitle>Final Result Snapshot</CardTitle>
          </CardHeader>

          <div className="grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
            <div className="rounded-md border border-border bg-surface-0/30 p-2">
              <p className="text-[11px] text-text-muted">Total Findings</p>
              <p className="mt-0.5 text-lg font-semibold text-text-primary">{totalFindings}</p>
            </div>
            <div className="rounded-md border border-border bg-surface-0/30 p-2">
              <p className="text-[11px] text-text-muted">Critical</p>
              <p className="mt-0.5 text-lg font-semibold text-red-300">{criticalCount}</p>
            </div>
            <div className="rounded-md border border-border bg-surface-0/30 p-2">
              <p className="text-[11px] text-text-muted">High</p>
              <p className="mt-0.5 text-lg font-semibold text-orange-300">{highCount}</p>
            </div>
            <div className="rounded-md border border-border bg-surface-0/30 p-2">
              <p className="text-[11px] text-text-muted">Verified</p>
              <p className="mt-0.5 text-lg font-semibold text-emerald-300">{verifiedCount}</p>
            </div>
          </div>

          <div className="space-y-1">
            <div className="flex items-center justify-between text-[11px] text-text-muted">
              <span>Scan Completion</span>
              <span className="font-mono">{project.scanProgress}%</span>
            </div>
            <div className="h-1.5 overflow-hidden rounded-full bg-surface-2">
              <div className="h-full rounded-full bg-pf-600 transition-all duration-500" style={{ width: `${project.scanProgress}%` }} />
            </div>
          </div>

          <div className="rounded-md border border-border bg-surface-0/30 p-2">
            <p className="mb-2 text-xs font-medium text-text-secondary">Top Findings For Client</p>
            {topFindings.length === 0 ? (
              <p className="text-xs text-text-muted">No findings yet. Run a scan to build the final result.</p>
            ) : (
              <div className="space-y-1.5">
                {topFindings.map((finding) => (
                  <div key={finding.id} className="flex items-center justify-between gap-2 rounded-md bg-surface-1/40 px-2 py-1.5">
                    <p className="truncate text-xs text-text-primary">{finding.title}</p>
                    <Badge variant={finding.severity}>{finding.severity}</Badge>
                  </div>
                ))}
              </div>
            )}
          </div>
        </Card>

        <Card className="space-y-3">
          <CardHeader className="mb-0">
            <CardTitle>Share Access</CardTitle>
            <Share2 size={14} className="text-pf-400" />
          </CardHeader>

          <Input
            label="Expiry (hours)"
            value={expiresHours}
            onChange={(event) => setExpiresHours(event.target.value)}
            type="number"
            min={1}
            max={168}
          />
          <Input
            label="Password (optional)"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            placeholder="Minimum 6 chars if set"
          />
          <Toggle checked={oneTimeLink} onChange={setOneTimeLink} label="One-time link" />

          <Button onClick={generateShareLink} loading={shareBusy} size="sm">
            Generate Share Link
          </Button>

          {shareError && (
            <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs text-red-300">
              {shareError}
            </p>
          )}

          {shareResult && (
            <div className="space-y-2 rounded-md border border-border bg-surface-0/35 p-2">
              <p className="text-[11px] text-text-muted">
                Expires: {formatDateTime(shareResult.expires_at)}
              </p>
              <div className="rounded-md border border-border bg-surface-1/40 px-2 py-1.5 text-xs text-text-primary">
                {shareResult.access_url}
              </div>
              <Button variant="secondary" size="sm" onClick={copyLink}>
                <Copy size={12} />
                {copied ? "Copied" : "Copy Link"}
              </Button>
            </div>
          )}
        </Card>
      </div>

      <Card className="flex h-[380px] flex-col space-y-3">
        <CardHeader className="mb-0">
          <CardTitle>Client Communication</CardTitle>
          <MessageSquare size={14} className="text-pf-400" />
        </CardHeader>

        <div className="min-h-0 flex-1 space-y-2 overflow-y-auto rounded-md border border-border bg-surface-0/35 p-2">
          {messages.map((message) => (
            <div
              key={message.id}
              className={
                message.sender === "team"
                  ? "rounded-md border border-pf-500/20 bg-pf-500/10 p-2"
                  : "rounded-md border border-border bg-surface-1/50 p-2"
              }
            >
              <div className="mb-1 flex items-center justify-between text-[10px] uppercase tracking-wide text-text-muted">
                <span>{message.sender === "team" ? "Team" : "Client"}</span>
                <span>{formatTime(message.at)}</span>
              </div>
              <p className="text-xs text-text-primary">{message.text}</p>
            </div>
          ))}
        </div>

        <div className="flex flex-wrap items-center gap-2">
          <Button
            size="xs"
            variant={sender === "team" ? "secondary" : "ghost"}
            onClick={() => setSender("team")}
          >
            Team
          </Button>
          <Button
            size="xs"
            variant={sender === "client" ? "secondary" : "ghost"}
            onClick={() => setSender("client")}
          >
            Client
          </Button>
          <span className="text-[11px] text-text-muted">
            Sending as {sender === "team" ? "Team" : "Client"}
          </span>
        </div>

        <div className="flex items-end gap-2">
          <textarea
            value={draft}
            onChange={(event) => setDraft(event.target.value)}
            placeholder="Write update or response..."
            className="focus-ring min-h-[56px] flex-1 resize-none rounded-md border border-border bg-surface-0 px-3 py-2 text-sm text-text-primary placeholder:text-text-muted"
            rows={2}
          />
          <Button size="sm" onClick={sendMessage} disabled={!draft.trim()}>
            <SendHorizontal size={14} />
            Send
          </Button>
        </div>
      </Card>
    </div>
  );
}
