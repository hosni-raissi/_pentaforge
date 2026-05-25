import { useEffect, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Copy, MessageSquare, SendHorizontal, Share2, Download, FileCode2, Globe } from "lucide-react";

import { Badge } from "@/components/ui/Badge";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader, CardTitle } from "@/components/ui/Card";
import { 
  createProjectShareLinkFromDesktop, 
  getPentesterMessagesFromDesktop, 
  sendPentesterMessageFromDesktop,
  getReportStatusFromDesktop,
  getReportContentFromDesktop,
  generateReportFromDesktop,
  getActiveProjectRunsFromDesktop,
  setPentesterTypingFromDesktop,
  downloadReportBlobFromDesktop,
  getActiveShareLinkFromDesktop,
  stopTunnelFromDesktop,
  revokeShareLinksFromDesktop,
  type ProjectShareLinkResponse,
  type ClientMessage
} from "@/lib/projectBridge";
import { useProjects } from "@/stores/projects";

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

  const [shareResult, setShareResult] = useState<ProjectShareLinkResponse | null>(null);
  const [shareError, setShareError] = useState("");
  const [shareBusy, setShareBusy] = useState(false);
  const [copied, setCopied] = useState(false);
  const [stoppingTunnel, setStoppingTunnel] = useState(false);
  const [tunnelStatus, setTunnelStatus] = useState<"loading" | "alive" | "dead" | null>(null);

  const [draft, setDraft] = useState("");
  const [messages, setMessages] = useState<ClientMessage[]>([]);
  const [clientTyping, setClientTyping] = useState(false);
  const messagesEndRef = useRef<HTMLDivElement>(null);
  const typingTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const [reportHtml, setReportHtml] = useState<string | null>(null);
  const [reportMarkdown, setReportMarkdown] = useState<string | null>(null);
  const [reportLoading, setReportLoading] = useState(true);
  const [generatingReport, setGeneratingReport] = useState(false);
  const [viewFormat, setViewFormat] = useState<"html" | "markdown">("html");
  const [downloading, setDownloading] = useState(false);

  const requestExportPassword = (format: "html" | "markdown") => {
    const password = window.prompt(
      `Enter a password for the protected ${format.toUpperCase()} report download.\nThe exported file will be saved as a password-protected ZIP package.`,
    );
    const clean = password?.trim() || "";
    return clean || null;
  };

  const fetchMessages = async () => {
    if (!project) return;
    try {
      const res = await getPentesterMessagesFromDesktop(project.id);
      if (Array.isArray(res)) {
        setMessages(res);
        setClientTyping(false);
      } else {
        setMessages(res?.messages || []);
        setClientTyping(res?.client_typing || false);
      }
    } catch (err) {
      console.error("Failed to fetch messages", err);
    }
  };

  const [isSecure, setIsSecure] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState("");

  const fetchActiveShareLink = async () => {
    if (!project) return;
    try {
      const res = await getActiveShareLinkFromDesktop(project.id);
      if (res && res.token) {
        setShareResult(res);
        if (res.password_protected) {
          setIsSecure(true);
        }
        const targetUrl = res.tunnel_url || res.access_url;
        if (targetUrl) {
          checkTunnelStatus(targetUrl);
        }
      }
    } catch (err) {
      // No active link
    }
  };

  const checkTunnelStatus = async (url: string, retries = 10) => {
    if (!url) return;
    setTunnelStatus("loading");
    
    for (let i = 0; i < retries; i++) {
      try {
        const controller = new AbortController();
        const timeoutId = setTimeout(() => controller.abort(), 10000);
        
        // Ping the URL
        await fetch(url, { mode: 'no-cors', signal: controller.signal });
        clearTimeout(timeoutId);
        setTunnelStatus("alive");
        return; // Success, exit retry loop
      } catch (err) {
        // If it failed and we have retries left, wait and try again
        if (i < retries - 1) {
          await new Promise(resolve => setTimeout(resolve, 5000)); // Wait 5 seconds
        }
      }
    }
    setTunnelStatus("dead");
  };

  useEffect(() => {
    fetchMessages();
    const interval = setInterval(fetchMessages, 5000);
    return () => clearInterval(interval);
  }, [project?.id]);

  useEffect(() => {
    fetchActiveShareLink();
    const interval = setInterval(fetchActiveShareLink, 180000);
    return () => clearInterval(interval);
  }, [project?.id]);

  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [messages]);

  const loadReport = async () => {
    if (!project) return;
    setReportLoading(true);
    try {
      const status = await getReportStatusFromDesktop(project.id);
      if (status.html) {
        const content = await getReportContentFromDesktop(project.id, "html");
        setReportHtml(content.content);
      } else {
        setReportHtml(null);
      }
      if (status.markdown) {
        const content = await getReportContentFromDesktop(project.id, "markdown");
        setReportMarkdown(content.content);
      } else {
        setReportMarkdown(null);
      }
    } catch (err) {
      console.error("Failed to load report", err);
    } finally {
      setReportLoading(false);
    }
  };

  useEffect(() => {
    loadReport();
  }, [project?.id]);

  useEffect(() => {
    if (!project || !generatingReport) {
      return;
    }
    const interval = setInterval(() => {
      void (async () => {
        try {
          const [status, activeRuns] = await Promise.all([
            getReportStatusFromDesktop(project.id),
            getActiveProjectRunsFromDesktop(project.id),
          ]);
          const activeReportRun = activeRuns.runs.find((run) => run.task_type === "report");
          if (!activeReportRun) {
            setGeneratingReport(false);
            if (status.html || status.markdown) {
              await loadReport();
            }
          }
        } catch {
          // Keep polling until the next successful read.
        }
      })();
    }, 3000);
    return () => clearInterval(interval);
  }, [generatingReport, project?.id]);

  const handleGenerateReport = async () => {
    if (!project) return;
    setGeneratingReport(true);
    try {
      await generateReportFromDesktop(project.id);
    } catch (err) {
      console.error("Failed to generate report", err);
      setGeneratingReport(false);
    } finally {
      // Polling effect will clear the loading state once the backend run finishes.
    }
  };

  const handleDownloadReport = async () => {
    if (!project) return;
    const password = requestExportPassword(viewFormat);
    if (!password) {
      return;
    }
    setDownloading(true);
    try {
      const result = await downloadReportBlobFromDesktop(project.id, viewFormat, password);
      const url = URL.createObjectURL(result.blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = result.filename;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.setTimeout(() => URL.revokeObjectURL(url), 15000);
    } catch (err) {
      console.error("Failed to download report", err);
    } finally {
      setDownloading(false);
    }
  };

  async function generateShareLink() {
    if (!project) return;
    setShareBusy(true);
    setShareError("");
    setCopied(false);
    
    let password = null;
    if (isSecure) {
      // Generate a simple random password
      password = "PF-" + Math.random().toString(36).substring(2, 7).toUpperCase();
      setGeneratedPassword(password);
    } else {
      setGeneratedPassword("");
    }

    try {
      const result = await createProjectShareLinkFromDesktop(project.id, {
        expires_hours: 9999,
        one_time: false,
        password: password,
      });
      setShareResult(result);
      const targetUrl = result.tunnel_url || result.access_url;
      if (targetUrl) {
        checkTunnelStatus(targetUrl);
      }
    } catch (error) {
      setShareError(error instanceof Error ? error.message : "Failed to generate share link.");
    } finally {
      setShareBusy(false);
    }
  }

  async function handleStopTunnel() {
    if (!project) return;
    setStoppingTunnel(true);
    try {
      await stopTunnelFromDesktop();
      if (project) {
        await revokeShareLinksFromDesktop(project.id);
      }
      setShareResult(null);
      setTunnelStatus(null);
      setGeneratedPassword("");
      setIsSecure(false);
    } catch (err) {
      console.error("Failed to stop tunnel", err);
    } finally {
      setStoppingTunnel(false);
    }
  }

  async function copyLink() {
    if (!shareResult) return;
    await navigator.clipboard.writeText(shareResult.tunnel_url || shareResult.access_url);
    setCopied(true);
  }

  async function sendMessage() {
    const clean = draft.trim();
    if (!clean  || !project) return;
    setDraft("");
    try {
      await sendPentesterMessageFromDesktop(project.id, clean, "pentester");
      await fetchMessages();
    } catch (err) {
      console.error("Failed to send message", err);
    }
  }

  function handleDraftChange(event: React.ChangeEvent<HTMLTextAreaElement>) {
    setDraft(event.target.value);
    if (!project) return;
    if (!typingTimeoutRef.current) {
      setPentesterTypingFromDesktop(project.id).catch(console.error);
    } else {
      clearTimeout(typingTimeoutRef.current);
    }
  }

  return (
    <div className="h-screen overflow-hidden p-4">
      <div className="flex h-full flex-col gap-4">
      <div className="flex shrink-0 flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold text-text-primary">Client Share</h1>
          <p className="text-sm text-text-muted">
            Final result package and communication hub for {project?.name}
          </p>
        </div>
        <Badge variant={project?.status} dot>{project?.status}</Badge>
      </div>

      <div className="grid min-h-0 flex-1 grid-cols-1 gap-4 lg:grid-cols-[650px_1fr]">
        
        {/* Left Column */}
        <div className="flex flex-col gap-4 overflow-hidden pr-2 h-full">
          <Card className="shrink-0 space-y-3 p-4">
            <CardHeader className="mb-0 p-0">
              <CardTitle className="flex items-center gap-2 text-xl">
                <Share2 size={18} className="text-pf-400" />
                Share Access
              </CardTitle>
            </CardHeader>

            <div className="flex items-center gap-3 py-1">
              <input 
                type="checkbox" 
                id="secure-toggle" 
                className="h-4 w-4 rounded border-border bg-surface-1 text-pf-500 focus:ring-pf-500/20"
                checked={isSecure}
                onChange={(e) => setIsSecure(e.target.checked)}
              />
              <label htmlFor="secure-toggle" className="text-sm font-medium text-text-muted cursor-pointer select-none">
                Secure with Password (generated)
              </label>
            </div>

            <Button onClick={generateShareLink} loading={shareBusy} size="sm" className="w-full">
              {shareResult ? "Regenerate Share Link" : "Generate Share Link"}
            </Button>

            {shareError && (
              <p className="rounded-md border border-red-500/30 bg-red-500/10 px-2 py-1 text-xs text-red-300">
                {shareError}
              </p>
            )}

            {isSecure && generatedPassword && (
              <div className="flex items-center justify-between rounded-md border border-pf-500/30 bg-pf-500/10 px-3 py-2 text-xs">
                <div className="flex flex-col gap-0.5">
                  <span className="font-bold uppercase tracking-widest text-pf-400">Active Password</span>
                  <span className="font-mono text-pf-200 font-bold tracking-wider">{generatedPassword}</span>
                </div>
                <Button 
                  variant="ghost" 
                  size="xs" 
                  onClick={() => navigator.clipboard.writeText(generatedPassword)}
                  className="h-7 text-pf-400 hover:bg-pf-500/20"
                >
                  Copy
                </Button>
              </div>
            )}

            {shareResult && (
              <div className="space-y-2 rounded-md border border-border bg-surface-0/35 p-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs font-bold uppercase tracking-widest text-text-muted">Tunnel Health</span>
                  <div className="flex items-center gap-2">
                    {tunnelStatus === "alive" && (
                      <div className="flex items-center gap-1.5 rounded-full bg-emerald-500/10 px-2 py-0.5 border border-emerald-500/20">
                        <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-emerald-500" />
                        <span className="text-[10px] font-bold uppercase text-emerald-400">Alive</span>
                      </div>
                    )}
                    {tunnelStatus === "dead" && (
                      <div className="flex items-center gap-2">
                        <div className="flex items-center gap-1.5 rounded-full bg-red-500/10 px-2 py-0.5 border border-red-500/20">
                          <span className="h-1.5 w-1.5 rounded-full bg-red-500" />
                          <span className="text-[10px] font-bold uppercase text-red-400">Dead</span>
                        </div>
                        <Button
                          variant="ghost"
                          size="xs"
                          className="h-6 px-2 text-[10px] text-pf-400 hover:text-pf-300"
                          onClick={() => shareResult && checkTunnelStatus(shareResult.tunnel_url || shareResult.access_url)}
                        >
                          Retry Check
                        </Button>
                      </div>
                    )}
                    {tunnelStatus === "loading" && (
                      <div className="flex items-center gap-1.5 px-2 py-0.5">
                        <span className="h-1.5 w-1.5 animate-spin rounded-full border border-pf-400 border-t-transparent" />
                        <span className="text-[10px] italic text-text-muted">Checking...</span>
                      </div>
                    )}
                    {!tunnelStatus && !shareResult.tunnel_url && (
                      <div className="flex items-center gap-1.5 rounded-full bg-pf-500/10 px-2 py-0.5 border border-pf-500/20">
                        <span className="text-[10px] font-bold uppercase text-pf-400">Local Access</span>
                      </div>
                    )}
                  </div>
                </div>
                <div className="select-all break-all rounded-md border border-border bg-surface-1/40 px-2 py-1.5 font-mono text-xs text-pf-300">
                  {shareResult.tunnel_url || shareResult.access_url}
                </div>
                <div className="flex items-center gap-2">
                  <Button variant="secondary" size="sm" onClick={copyLink} className="flex-1 text-sm h-9">
                    <Copy size={14} className="mr-2" />
                    {copied ? "Copied" : "Copy Link"}
                  </Button>
                  <Button variant="ghost" size="sm" onClick={handleStopTunnel} loading={stoppingTunnel} className="text-red-400 hover:text-red-300 text-sm h-9">
                    Close Tunnel
                  </Button>
                </div>
              </div>
            )}
          </Card>

          <Card className="flex flex-1 flex-col space-y-3 p-4 min-h-0">
            <CardHeader className="mb-0 p-0 shrink-0">
              <CardTitle className="flex items-center gap-2 text-2xl py-1">
                <MessageSquare size={22} className="text-pf-400" />
                Client Discussion
                {clientTyping && (
                  <span className="text-xs font-normal italic text-pf-400/80 animate-pulse">
                    client is typing...
                  </span>
                )}
              </CardTitle>
            </CardHeader>

            <div className="min-h-0 flex-1 space-y-4 overflow-y-auto rounded-md border border-border bg-surface-0/20 p-4 custom-scrollbar">
              {messages.length === 0 && (
                <div className="flex h-full flex-col items-center justify-center text-center">
                  <div className="mb-2 rounded-full bg-surface-1 p-3">
                    <MessageSquare size={24} className="text-pf-500/50" />
                  </div>
                  <p className="text-sm text-text-muted italic">No communication history yet.</p>
                  <p className="text-[10px] text-text-muted/60 mt-1 uppercase tracking-widest font-bold">Secure Channel Active</p>
                </div>
              )}
              {messages.map((message) => {
                const isPentester = message.sender === "pentester";
                return (
                  <div
                    key={message.id}
                    className={`flex flex-col ${isPentester ? "items-end" : "items-start"}`}
                  >
                    <div className="mb-1 flex items-center gap-2 px-1 text-[10px] font-bold uppercase tracking-widest text-text-muted">
                      {!isPentester && <span className="text-pf-400">Client</span>}
                      <span>{formatTime(message.created_at)}</span>
                      {isPentester && <span className="text-emerald-400">You</span>}
                    </div>
                    <div
                      className={`max-w-[85%] rounded-2xl px-5 py-3.5 text-base shadow-lg ring-1 transition-all hover:ring-2 ${
                        isPentester
                          ? "rounded-tr-none bg-pf-600 text-white ring-pf-400/30"
                          : "rounded-tl-none bg-surface-2 text-text-primary ring-border"
                      }`}
                    >
                      <p className="leading-relaxed whitespace-pre-wrap break-words text-base">{message.content}</p>
                    </div>
                  </div>
                );
              })}
              <div ref={messagesEndRef} />
            </div>

            <div className="flex items-end gap-3 pt-3 shrink-0">
              <textarea
                value={draft}
                onChange={handleDraftChange}
                placeholder="Write update or response..."
                className="focus-ring min-h-[100px] flex-1 resize-none rounded-lg border border-border bg-surface-0 px-4 py-3 text-lg text-text-primary placeholder:text-text-muted"
                rows={3}
              />
              <Button size="sm" onClick={sendMessage} disabled={!draft.trim()} className="h-[100px] px-6">
                <SendHorizontal size={24} />
              </Button>
            </div>
          </Card>
        </div>

        {/* Right Column: Report */}
        <Card className="flex flex-col overflow-hidden border-border bg-surface-1">
          <CardHeader className="shrink-0 border-b border-border bg-surface-2/50 py-3 px-4 flex flex-row items-center justify-between">
            <CardTitle className="text-xl flex items-center gap-2">
              <Globe size={18} className="text-pf-400" />
              Project Report Preview
            </CardTitle>
            <div className="flex items-center gap-3">
              <div className="flex bg-surface-0 rounded-md border border-border p-1">
                <button
                  onClick={() => setViewFormat("html")}
                  className={`px-3 py-1.5 text-sm font-medium rounded-[4px] transition-colors ${viewFormat === "html" ? "bg-pf-600 text-white" : "text-text-muted hover:text-text-primary"}`}
                >
                  HTML
                </button>
                <button
                  onClick={() => setViewFormat("markdown")}
                  className={`px-3 py-1.5 text-sm font-medium rounded-[4px] transition-colors ${viewFormat === "markdown" ? "bg-pf-600 text-white" : "text-text-muted hover:text-text-primary"}`}
                >
                  Markdown
                </button>
              </div>
              <Button size="sm" variant="outline" onClick={handleDownloadReport} loading={downloading} disabled={downloading || (!reportHtml && !reportMarkdown)} className="h-10 px-4 text-sm font-medium">
                <Download size={16} className="mr-2" /> Download
              </Button>
            </div>
          </CardHeader>
          <div className="flex-1 overflow-hidden bg-white">
            {reportLoading ? (
              <div className="flex h-full items-center justify-center text-sm text-text-muted">
                Loading report...
              </div>
            ) : viewFormat === "html" ? (
              reportHtml ? (
                <iframe
                  title="Report Preview"
                  srcDoc={reportHtml}
                  className="h-full w-full border-0"
                />
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-4 text-sm text-text-muted">
                  <p>No HTML report available.</p>
                  <Button onClick={handleGenerateReport} loading={generatingReport} size="sm">
                    Generate Report
                  </Button>
                </div>
              )
            ) : (
              reportMarkdown ? (
                <pre className="h-full w-full p-6 overflow-auto text-sm text-pf-950 font-mono whitespace-pre-wrap selection:bg-pf-200">
                  {reportMarkdown}
                </pre>
              ) : (
                <div className="flex h-full flex-col items-center justify-center gap-4 text-sm text-text-muted">
                  <p>No Markdown report available.</p>
                  <Button onClick={handleGenerateReport} loading={generatingReport} size="sm">
                    Generate Report
                  </Button>
                </div>
              )
            )}
          </div>
        </Card>

      </div>
      </div>
    </div>
  );
}
