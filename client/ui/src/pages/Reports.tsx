// src/pages/Reports.tsx
import { useCallback, useEffect, useRef, useState } from "react";
import { useProjects } from "../stores/projects";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { clsx } from "clsx";
import {
  FileText,
  Download,
  Eye,
  CheckCircle2,
  Loader2,
  RefreshCw,
  FileCode2,
  Globe,
  Copy,
  Share2,
  X,
  SendHorizontal,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  getActiveProjectRunsFromDesktop,
  createProjectShareLinkFromDesktop,
  getActiveShareLinkFromDesktop,
  generateReportFromDesktop,
  getReportStatusFromDesktop,
  getReportContentFromDesktop,
  downloadReportBlobFromDesktop,
  revokeShareLinksFromDesktop,
  getPentesterMessagesFromDesktop,
  sendPentesterMessageFromDesktop,
  requestClientRefreshFromDesktop,
  type ClientMessage,
  type ProjectShareLinkResponse,
  type ReportStatus,
  type TaskRunStatus,
} from "../lib/projectBridge";

type ReportFormat = "markdown" | "html";

interface FormatCardConfig {
  format: ReportFormat;
  label: string;
  icon: typeof FileText;
  description: string;
  color: string;
  gradient: string;
}

const FORMAT_CARDS: FormatCardConfig[] = [
  {
    format: "html",
    label: "HTML Report",
    icon: Globe,
    description: "Styled web report with professional formatting",
    color: "text-orange-400",
    gradient: "from-orange-500/10 to-orange-600/5",
  },
  {
    format: "markdown",
    label: "Markdown Report",
    icon: FileCode2,
    description: "Raw structured report in Markdown format",
    color: "text-blue-400",
    gradient: "from-blue-500/10 to-blue-600/5",
  },
];

function triggerFileDownload(content: string, filename: string, mimeType: string) {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

const generateRandomPassword = () => `PF-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

export default function Reports() {
  const project = useProjects((s) => s.getActive());
  const navigate = useNavigate();

  const [status, setStatus] = useState<ReportStatus | null>(null);
  const [generating, setGenerating] = useState(false);
  const [activeRunId, setActiveRunId] = useState<string | null>(null);
  const [activeRunStatus, setActiveRunStatus] = useState<TaskRunStatus | null>(null);
  const [error, setError] = useState("");
  const [viewFormat, setViewFormat] = useState<ReportFormat | null>(null);
  const [viewContent, setViewContent] = useState("");
  const [viewLoading, setViewLoading] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState<ReportFormat | null>(null);
  const [shareResult, setShareResult] = useState<ProjectShareLinkResponse | null>(null);
  const [shareBusy, setShareBusy] = useState(false);
  const [shareRevoking, setShareRevoking] = useState(false);
  const [shareError, setShareError] = useState("");
  const [shareCopied, setShareCopied] = useState(false);
  const [passwordCopied, setPasswordCopied] = useState(false);
  const [secureShare, setSecureShare] = useState(false);
  const [generatedPassword, setGeneratedPassword] = useState("");
  const [messages, setMessages] = useState<ClientMessage[]>([]);
  const [messageInput, setMessageInput] = useState("");
  const [messagesLoading, setMessagesLoading] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState<ReportFormat | null>(null);
  const statusPolling = useRef<ReturnType<typeof setInterval> | null>(null);
  const messagesPolling = useRef<ReturnType<typeof setInterval> | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const hasAutoSelected = useRef<string | null>(null);



  const fetchShareState = useCallback(async () => {
    if (!project) return;
    try {
      const activeShare = await getActiveShareLinkFromDesktop(project.id);
      if (activeShare && activeShare.ok) {
        setShareResult(activeShare);
        // Recover password from local storage if possible
        const savedPwd = localStorage.getItem(`pf_share_pwd_${project.id}`);
        if (savedPwd) {
          setGeneratedPassword(savedPwd);
          setSecureShare(true);
        }
      } else {
        setShareResult(null);
      }
    } catch {
      setShareResult(null);
    }
  }, [project?.id]);

  // Persist generated password locally since backend only stores hashes
  useEffect(() => {
    if (project?.id && generatedPassword) {
      localStorage.setItem(`pf_share_pwd_${project.id}`, generatedPassword);
    } else if (project?.id && !shareResult?.ok) {
      localStorage.removeItem(`pf_share_pwd_${project.id}`);
    }
  }, [generatedPassword, project?.id, shareResult?.ok]);

  const stopStatusPolling = useCallback(() => {
    if (statusPolling.current) {
      clearInterval(statusPolling.current);
      statusPolling.current = null;
    }
  }, []);

  const beginStatusPolling = useCallback(() => {
    if (!project) {
      return;
    }
    stopStatusPolling();
    statusPolling.current = setInterval(() => {
      void fetchStatus();
    }, 3000);
  }, [project, stopStatusPolling]);

  const fetchStatus = useCallback(async () => {
    if (!project) return;
    try {
      const [s, activeRuns] = await Promise.all([
        getReportStatusFromDesktop(project.id),
        getActiveProjectRunsFromDesktop(project.id),
      ]);
      const reportRun = activeRuns.runs.find((run) => run.task_type === "report") ?? null;
      setStatus(s);
      setActiveRunId(reportRun?.run_id ?? null);
      setActiveRunStatus(reportRun?.status ?? s.run_status ?? null);
      const reportExists = Boolean(s.markdown || s.html || s.pdf);
      const stillActive = reportRun?.status === "pending" || reportRun?.status === "running" || reportRun?.status === "stopped";
      setGenerating(Boolean(stillActive));
      if (!stillActive && s.run_status === "failed") {
        setError("Report generation failed. Try regenerating the report.");
      }
      if (!stillActive && reportExists) {
        setGenerating(false);
        stopStatusPolling();
        
        // Auto-select based on preference or default to HTML
        const savedPref = localStorage.getItem(`pf_report_view_${project.id}`) as ReportFormat | null;
        if (hasAutoSelected.current !== project.id) {
          hasAutoSelected.current = project.id;
          if (savedPref && s[savedPref]) {
            handleView(savedPref);
          } else if (s.html) {
            handleView("html");
          }
        }
      } else if (!stillActive && !reportExists) {
        stopStatusPolling();
      }
    } catch {
      // Silently ignore status fetch failures.
    }
  }, [project?.id, stopStatusPolling]);

  useEffect(() => {
    if (!project) {
      setGenerating(false);
      setActiveRunId(null);
      setActiveRunStatus(null);
      stopStatusPolling();
      return;
    }
    void fetchStatus();
  }, [project?.id, beginStatusPolling, stopStatusPolling]);

  useEffect(() => {
    void fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    if (project?.id) {
      fetchShareState();
    }
    
    return () => {
      // Auto-revoke on project switch/unmount as requested for clean delivery lifecycle
      if (project?.id) {
        revokeShareLinksFromDesktop(project.id).catch(() => {});
        localStorage.removeItem(`pf_share_pwd_${project.id}`);
      }
    };
  }, [project?.id, fetchShareState]);

  useEffect(() => {
    if (generating) {
      beginStatusPolling();
    } else {
      stopStatusPolling();
    }
  }, [generating, beginStatusPolling, stopStatusPolling]);

  const fetchMessages = useCallback(async () => {
    if (!project) return;
    try {
      const resp = await getPentesterMessagesFromDesktop(project.id);
      setMessages(resp.messages);
    } catch {
      // Ignore
    }
  }, [project?.id]);

  const handleSendMessage = async () => {
    if (!project || !messageInput.trim()) return;
    const content = messageInput.trim();
    setMessageInput("");
    try {
      await sendPentesterMessageFromDesktop(project.id, content);
      await fetchMessages();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to send message");
    }
  };

  useEffect(() => {
    if (project) {
      void fetchMessages();
      messagesPolling.current = setInterval(() => {
        void fetchMessages();
      }, 5000);
    }
    return () => {
      if (messagesPolling.current) clearInterval(messagesPolling.current);
    };
  }, [project?.id, fetchMessages]);

  // Clean up polling on unmount.
  useEffect(() => {
    return () => {
      stopStatusPolling();
      if (messagesPolling.current) clearInterval(messagesPolling.current);
    };
  }, [stopStatusPolling]);

  // Sync iframe theme with dashboard mode
  useEffect(() => {
    if (!iframeRef.current || !viewContent || viewFormat !== 'html') return;
    
    const updateTheme = () => {
      const isDark = document.documentElement.classList.contains('dark');
      const doc = iframeRef.current?.contentWindow?.document;
      if (doc?.documentElement) {
        doc.documentElement.setAttribute('data-theme', isDark ? 'dark' : 'light');
      }
    };

    updateTheme();

    const observer = new MutationObserver(updateTheme);
    observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] });
    
    return () => observer.disconnect();
  }, [viewContent, viewFormat]);

  if (!project) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4">
        <div className="w-16 h-16 rounded-full bg-surface-2 flex items-center justify-center">
          <FileText size={28} className="text-text-muted" />
        </div>
        <p className="text-sm text-text-muted">Select a project to view reports</p>
        <Button onClick={() => navigate("/projects")} variant="outline">
          Go to Projects
        </Button>
      </div>
    );
  }

  const hasAnyReport = status?.markdown || status?.html;
  const shareUrl = shareResult ? (shareResult.tunnel_url || shareResult.access_url) : "";

  const handleGenerate = async () => {
    setGenerating(true);
    setActiveRunStatus("pending");
    setError("");
    setStatus((prev) => (
      prev
        ? { ...prev, markdown: false, html: false, pdf: false, generated_at: null }
        : null
    ));
    setViewFormat(null);
    setViewContent("");
    setViewLoading(false);
    try {
      const result = await generateReportFromDesktop(project.id);
      setActiveRunId(result.run_id || null);
      setActiveRunStatus(result.status ?? "pending");
      await fetchStatus();
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Report generation failed",
      );
      setGenerating(false);
      setActiveRunId(null);
      setActiveRunStatus(null);
    }
  };

  const handleView = async (format: ReportFormat) => {
    if (!project) return;
    localStorage.setItem(`pf_report_view_${project.id}`, format);
    setViewFormat(format);
    setViewLoading(true);
    setViewContent("");
    try {
      const report = await getReportContentFromDesktop(project.id, format);
      setViewContent(report.content);
    } catch (err) {
      setViewContent(
        `Failed to load report: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    } finally {
      setViewLoading(false);
    }
  };

  const handleDownload = async (format: ReportFormat) => {
    setDownloadingFormat(format);
    setDownloadSuccess(null);
    try {
      // Minimum 1 second artificial delay for UX feel as requested
      const [result] = await Promise.all([
        downloadReportBlobFromDesktop(project.id, format),
        new Promise(r => setTimeout(r, 1000))
      ]);
      
      triggerFileDownload(result.content, result.filename, result.mimeType);
      
      setDownloadSuccess(format);
      setTimeout(() => setDownloadSuccess(null), 2000);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Download failed",
      );
    } finally {
      setDownloadingFormat(null);
    }
  };

  const handleGenerateShare = async () => {
    setShareBusy(true);
    setShareError("");
    try {
      // Auto-revoke previous link if we are regenerating
      if (shareResult?.ok) {
        await revokeShareLinksFromDesktop(project.id);
      }

      const newPassword = (secureShare || !!generatedPassword) ? generateRandomPassword() : undefined;
      const result = await createProjectShareLinkFromDesktop(project.id, {
        expires_hours: 9999,
        password: newPassword,
        one_time: false,
      });

      setShareResult(result);
      if (newPassword) {
        setGeneratedPassword(newPassword);
        localStorage.setItem(`pf_share_pwd_${project.id}`, newPassword);
        setSecureShare(true);
      } else {
        setGeneratedPassword("");
        localStorage.removeItem(`pf_share_pwd_${project.id}`);
      }
    } catch (err) {
      setShareError(
        err instanceof Error ? err.message : "Share link generation failed",
      );
    } finally {
      setShareBusy(false);
    }
  };

  const handleRevokeShare = async () => {
    setShareRevoking(true);
    setShareError("");
    try {
      await revokeShareLinksFromDesktop(project.id);
      setShareResult(null);
      setShareCopied(false);
      setGeneratedPassword("");
      setSecureShare(false);
    } catch (err) {
      setShareError(
        err instanceof Error ? err.message : "Failed to revoke share access",
      );
    } finally {
      setShareRevoking(false);
    }
  };

  const handleCopyShare = async () => {
    if (!shareResult) return;
    const url = shareResult.tunnel_url || shareResult.access_url;
    await navigator.clipboard.writeText(url);
    setShareCopied(true);
    setTimeout(() => setShareCopied(false), 2000);
  };

  const handleCopyPassword = async () => {
    if (!generatedPassword) return;
    await navigator.clipboard.writeText(generatedPassword);
    setPasswordCopied(true);
    setTimeout(() => setPasswordCopied(false), 2000);
  };

  const handleCloseView = () => {
    setViewFormat(null);
    setViewContent("");
    setViewLoading(false);
  };

  return (
    <div className="flex flex-col h-full overflow-hidden bg-background">
      {/* Header */}
      <div className="flex items-center justify-between px-6 py-4 border-b border-border bg-surface-1 shrink-0">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2 leading-none">
            <FileText size={20} className="text-pf-400" />
            Reporting & Delivery
          </h1>
          <p className="text-[11px] text-text-muted mt-1.5 uppercase tracking-wider font-medium">
            {project.name} • {project.target}
          </p>
        </div>

        <div className="flex items-center gap-3">
          {status?.generated_at && (
            <div className="text-right mr-2">
              <p className="text-[10px] text-text-muted leading-tight uppercase tracking-tight">Last Generation</p>
              <p className="text-[11px] text-text-secondary font-medium">{new Date(status.generated_at).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' })}</p>
            </div>
          )}
          <Button
            size="sm"
            variant="ghost"
            onClick={handleGenerate}
            loading={generating}
            disabled={generating}
            className="border border-border/50 hover:border-pf-500/30"
          >
            {!generating && <RefreshCw size={13} />}
            Regenerate Report
          </Button>
        </div>
      </div>

      {/* Main Content Split */}
      <div className="flex-1 grid grid-cols-2 overflow-hidden">
        
        {/* Left Column: Share & Discussion (50%) */}
        <div className="border-r border-border bg-surface-1/30 flex flex-col overflow-hidden h-full">
          <div className="flex-1 flex flex-col p-5 space-y-5 overflow-hidden">
            
            {/* Share Card */}
            <Card className="relative space-y-4 border-pf-500/20 bg-gradient-to-br from-pf-600/5 to-surface-1 overflow-hidden">
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Share2 size={16} className="text-pf-400" />
                    <h2 className="text-sm font-semibold text-text-primary uppercase tracking-wide">Client Access</h2>
                  </div>
                  <p className="mt-1 text-[11px] text-text-muted leading-snug">
                    AI-powered secure delivery link and collaborative loop.
                  </p>
                </div>
                <div className="flex items-center gap-2">
                  <button 
                    onClick={async () => {
                      if (!project) return;
                      setShareBusy(true);
                      try {
                        await requestClientRefreshFromDesktop(project.id);
                      } finally {
                        setShareBusy(false);
                      }
                    }}
                    className="p-1 rounded-md text-text-muted hover:text-pf-400 hover:bg-pf-500/10 transition-all"
                    title="Refresh Client Page Content"
                  >
                    <RefreshCw size={13} className={shareBusy ? "animate-spin" : ""} />
                  </button>
                  {shareResult?.ok && (
                    <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-surface-2 border border-border">
                      <div className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse" />
                      <span className="text-[10px] font-bold text-emerald-500 uppercase tracking-tighter">Live</span>
                    </div>
                  )}
                  {!shareResult?.ok && (
                    <div className="flex items-center gap-1.5 px-2 py-1 rounded-full bg-surface-2 border border-border">
                      <div className="w-1.5 h-1.5 rounded-full bg-text-muted" />
                      <span className="text-[10px] font-bold text-text-muted uppercase tracking-tighter">Inactive</span>
                    </div>
                  )}
                </div>
              </div>

              {shareResult?.ok ? (
                <div className="space-y-4">
                  {/* URL Field with Integrated Copy */}
                  <div className="group relative">
                    <p className="text-[10px] font-bold uppercase tracking-wider text-text-muted mb-1.5 ml-1">Active URL</p>
                    <div className="relative flex items-center">
                      <div className="w-full rounded-lg border border-pf-500/20 bg-surface-1/50 p-2.5 pr-12 shadow-inner font-mono text-[11px] text-pf-400 truncate select-all h-9 flex items-center">
                        {shareUrl}
                      </div>
                      <button 
                        onClick={handleCopyShare}
                        className="absolute right-1 p-1.5 rounded-md text-text-muted hover:text-pf-400 hover:bg-pf-500/10 transition-all"
                        title="Copy Link"
                      >
                        {shareCopied ? <CheckCircle2 size={14} className="text-emerald-400" /> : <Copy size={14} />}
                      </button>
                    </div>
                  </div>

                  {/* Password Field if active */}
                  {generatedPassword && (
                    <div className="group relative">
                      <p className="text-[10px] font-bold uppercase tracking-wider text-text-muted mb-1.5 ml-1">Access Password</p>
                      <div className="relative flex items-center">
                        <div className="w-full rounded-lg border border-pf-500/30 bg-pf-500/5 p-2.5 pr-12 shadow-inner font-mono text-xs font-bold text-text-primary h-9 flex items-center">
                          {generatedPassword}
                        </div>
                        <button 
                          onClick={handleCopyPassword}
                          className="absolute right-1 p-1.5 rounded-md text-text-muted hover:text-pf-400 hover:bg-pf-500/10 transition-all"
                          title="Copy Password"
                        >
                          {passwordCopied ? <CheckCircle2 size={14} className="text-emerald-400" /> : <Copy size={14} />}
                        </button>
                      </div>
                    </div>
                  )}

                  <div className="flex gap-2">
                    <Button 
                      size="xs" 
                      variant="ghost" 
                      onClick={handleGenerateShare} 
                      loading={shareBusy} 
                      className="flex-1 h-8 border border-border hover:border-pf-500/30 hover:bg-pf-500/5"
                    >
                      <RefreshCw size={12} className={shareBusy ? "animate-spin" : ""} />
                      Regenerate
                    </Button>
                    <Button 
                      size="xs" 
                      variant="secondary" 
                      onClick={handleRevokeShare} 
                      loading={shareRevoking} 
                      className="flex-1 h-8 bg-red-500/10 hover:bg-red-500/20 text-red-400 border-red-500/20 hover:border-red-500/40"
                    >
                      <X size={12} />
                      Revoke
                    </Button>
                  </div>
                </div>
              ) : (
                <div className="space-y-3 pt-2">
                   <div className="rounded-lg border border-dashed border-pf-500/20 bg-surface-1/40 p-5 text-center">
                    <p className="text-xs text-text-muted italic">No active delivery channel</p>
                  </div>
                  <div className="flex items-center justify-between px-1">
                    <label className="flex items-center gap-3 cursor-pointer select-none">
                      <input
                        type="checkbox"
                        checked={secureShare}
                        onChange={(e) => setSecureShare(e.target.checked)}
                        className="h-3.5 w-3.5 rounded border-border bg-surface-1 text-pf-500 focus:ring-0"
                      />
                      <span className="text-[11px] text-text-secondary font-medium">Protect with password</span>
                    </label>
                  </div>
                  <Button
                    onClick={handleGenerateShare}
                    loading={shareBusy}
                    disabled={shareBusy || !hasAnyReport}
                    className="w-full h-9 shadow-lg shadow-pf-500/10"
                    size="sm"
                  >
                    <Share2 size={14} />
                    Open Delivery Channel
                  </Button>
                </div>
              )}

              {shareError && (
                <p className="text-[10px] text-red-400 bg-red-500/10 p-2 rounded border border-red-500/20 font-medium">{shareError}</p>
              )}
            </Card>

            {/* Discussion Card */}
            <Card className="flex flex-1 flex-col border-border bg-surface-1 overflow-hidden shadow-sm min-h-0">
              <div className="px-4 py-1 border-b border-border bg-surface-2/30 flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Globe size={15} className="text-pf-400" />
                  <h2 className="text-xs font-bold text-text-primary uppercase tracking-wide">Client Discussion</h2>
                </div>
                {messages.length > 0 && (
                  <span className="animate-pulse w-2 h-2 rounded-full bg-emerald-400 shadow-[0_0_8px_rgba(52,211,153,0.5)]" />
                )}
              </div>

              <div className="flex-1 overflow-y-auto p-4 space-y-4 bg-surface-0/10">
                {messages.length === 0 ? (
                  <div className="h-full flex flex-col items-center justify-center text-center px-4">
                    <div className="w-10 h-10 rounded-full bg-surface-2 flex items-center justify-center mb-3 opacity-50">
                      <Globe size={18} className="text-text-muted" />
                    </div>
                    <p className="text-[11px] text-text-muted italic leading-relaxed">
                      Collaborative feedback will appear here once the client engages with the shared report.
                    </p>
                  </div>
                ) : (
                  messages.map((msg) => (
                    <div
                      key={msg.id}
                      className={clsx(
                        "flex flex-col max-w-[90%]",
                        msg.sender === "pentester" ? "ml-auto items-end" : "mr-auto items-start"
                      )}
                    >
                      <div
                        className={clsx(
                          "rounded-xl px-4 py-2.5 text-sm shadow-sm",
                          msg.sender === "pentester"
                            ? "bg-pf-600 text-white rounded-tr-none"
                            : "bg-surface-2 text-text-primary border border-border/50 rounded-tl-none"
                        )}
                      >
                        {msg.content}
                      </div>
                      <span className="text-[9px] text-text-muted mt-1 font-medium px-1">
                        {msg.sender === "pentester" ? "You" : "Client"} • {new Date(msg.created_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                      </span>
                    </div>
                  ))
                )}
              </div>

              <div className="px-4 pb-0 pt-3 border-t border-border bg-surface-2/20">
                <div className={clsx(
                  "flex flex-col gap-2 p-2 rounded-xl border transition-all duration-300",
                  shareResult 
                    ? "bg-surface-0 border-border focus-within:border-pf-500 focus-within:ring-2 focus-within:ring-pf-500/10 shadow-sm" 
                    : "bg-surface-1 border-border opacity-50"
                )}>
                  <textarea
                    value={messageInput}
                    onChange={(e) => setMessageInput(e.target.value)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" && !e.shiftKey) {
                        e.preventDefault();
                        handleSendMessage();
                      }
                    }}
                    placeholder={shareResult ? "Write message to client..." : "Link inactive"}
                    disabled={!shareResult}
                    rows={2}
                    className="w-full bg-transparent border-none focus:ring-0 text-sm text-text-primary placeholder:text-text-muted resize-none min-h-[60px] p-2 outline-none"
                  />
                  <div className="flex items-center justify-end px-1 pb-1">
                    <Button
                      variant="primary"
                      size="sm"
                      onClick={handleSendMessage}
                      disabled={!shareResult || !messageInput.trim()}
                      className="h-8 w-8 p-0 rounded-md shadow-sm hover:shadow-pf-500/20 transition-all flex items-center justify-center"
                      title="Send Message"
                    >
                      <SendHorizontal size={16} />
                    </Button>
                  </div>
                </div>
              </div>
            </Card>
          </div>
        </div>

        {/* Right Column: Generation & Viewer (1.5fr) */}
        <div className="flex-1 flex flex-col overflow-hidden bg-surface-0/20">
          
          {/* Top: Generation Controls */}
          <div className="p-5 border-b border-border bg-surface-1/40">
            {generating ? (
              <div className="flex flex-col items-center justify-center py-6 gap-3">
                <Loader2 size={24} className="text-pf-400 animate-spin" />
                <div className="text-center">
                  <p className="text-sm font-semibold text-text-primary">Generating AI Report</p>
                  <p className="text-[11px] text-text-muted mt-1 uppercase tracking-tight">Synthesizing findings and evidence...</p>
                </div>
              </div>
            ) : !hasAnyReport ? (
              <div className="flex flex-col items-center justify-center py-8 gap-4">
                <div className="text-center max-w-md">
                  <h3 className="text-base font-bold text-text-primary">No Report Generated</h3>
                  <p className="text-xs text-text-muted mt-1.5">Start the generation process to produce a professional assessment document covering all findings.</p>
                </div>
                <Button onClick={handleGenerate} size="sm">
                  <FileText size={14} />
                  Generate Initial Report
                </Button>
              </div>
            ) : (
              <div className="grid grid-cols-2 gap-4">
                {FORMAT_CARDS.map((card) => {
                  const exists = status?.[card.format] ?? false;
                  const isDownloading = downloadingFormat === card.format;
                  const isActive = viewFormat === card.format;
                  const Icon = card.icon;

                  return (
                    <Card
                      key={card.format}
                      className={clsx(
                        "relative p-4 flex flex-col gap-3 transition-all duration-200 cursor-pointer group",
                        isActive ? "ring-2 ring-pf-500/50 border-pf-500/50 bg-pf-500/5" : "hover:border-border-strong bg-surface-1"
                      )}
                      onClick={() => handleView(card.format)}
                    >
                      <div className="flex items-start justify-between">
                        <div className={clsx("p-2 rounded-lg bg-surface-2 group-hover:scale-110 transition-transform", card.color)}>
                          <Icon size={18} />
                        </div>
                        {exists && <CheckCircle2 size={16} className="text-emerald-400" />}
                      </div>
                      <div>
                        <h3 className="text-sm font-bold text-text-primary leading-none">{card.label}</h3>
                        <p className="text-[10px] text-text-muted mt-1.5 font-medium uppercase tracking-tight">{card.description}</p>
                      </div>
                      <div className="flex gap-2 mt-2">
                        <Button
                          size="xs"
                          variant={isActive ? "primary" : "outline"}
                          className="flex-1 h-7 text-[10px] uppercase font-bold tracking-wider"
                          onClick={(e) => { e.stopPropagation(); handleView(card.format); }}
                        >
                          <Eye size={12} />
                          Preview
                        </Button>
                        <Button
                          size="xs"
                          variant={downloadSuccess === card.format ? "primary" : "secondary"}
                          className={clsx(
                            "flex-1 h-7 text-[10px] uppercase font-bold tracking-wider transition-all duration-300",
                            downloadSuccess === card.format && "bg-emerald-500 hover:bg-emerald-600 border-emerald-500 text-white"
                          )}
                          onClick={(e) => { e.stopPropagation(); handleDownload(card.format); }}
                          loading={isDownloading}
                        >
                          {downloadSuccess === card.format ? (
                            <>
                              <CheckCircle2 size={12} />
                              Saved
                            </>
                          ) : (
                            <>
                              <Download size={12} />
                              Save
                            </>
                          )}
                        </Button>
                      </div>
                    </Card>
                  );
                })}
              </div>
            )}
          </div>

          {/* Bottom: Report Viewer */}
          <div className="flex-1 flex flex-col overflow-hidden">
            {!viewFormat ? (
              <div className="flex-1 flex flex-col items-center justify-center text-text-muted/40">
                <FileText size={64} strokeWidth={1} className="opacity-20" />
                <p className="mt-4 text-sm font-medium italic tracking-wide">Select a format above to review content</p>
              </div>
            ) : (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="px-5 py-2.5 border-b border-border bg-surface-1 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={clsx("w-2 h-2 rounded-full", viewFormat === 'html' ? "bg-orange-400" : "bg-blue-400")} />
                    <span className="text-xs font-bold text-text-primary uppercase tracking-[0.15em]">Previewing: {viewFormat}</span>
                  </div>
                  <Button 
                    size="xs" 
                    variant="ghost" 
                    onClick={() => handleDownload(viewFormat)} 
                    className={clsx(
                      "transition-all duration-300",
                      downloadSuccess === viewFormat ? "text-emerald-500" : "text-text-muted hover:text-pf-400"
                    )}
                    loading={downloadingFormat === viewFormat}
                  >
                    {downloadSuccess === viewFormat ? (
                      <>
                        <CheckCircle2 size={12} />
                        Saved
                      </>
                    ) : (
                      <>
                        <Download size={12} />
                        Download {viewFormat.toUpperCase()}
                      </>
                    )}
                  </Button>
                </div>
                
                <div className="flex-1 overflow-auto bg-surface-0/40 p-6 custom-scrollbar">
                  {viewLoading ? (
                    <div className="h-full flex flex-col items-center justify-center gap-3">
                      <Loader2 size={32} className="text-pf-400 animate-spin opacity-50" />
                      <p className="text-xs text-text-muted uppercase tracking-widest font-bold">Loading Context</p>
                    </div>
                  ) : viewFormat === "html" ? (
                    <div className="w-full h-full rounded-xl overflow-hidden border border-border shadow-2xl bg-surface-0 ring-4 ring-surface-2/30">
                      <iframe
                        ref={iframeRef}
                        srcDoc={viewContent}
                        title="Report Preview"
                        className="w-full h-full border-0"
                        sandbox="allow-same-origin"
                      />
                    </div>
                  ) : (
                    <div className="max-w-3xl mx-auto">
                      <pre className="text-[13px] text-text-secondary whitespace-pre-wrap font-mono leading-relaxed bg-surface-1/50 p-8 rounded-xl border border-border shadow-inner">
                        {viewContent}
                      </pre>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>

        </div>
      </div>
    </div>
  );
}
