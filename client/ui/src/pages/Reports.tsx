// src/pages/Reports.tsx
import { useCallback, useEffect, useRef, useState } from "react";
import { useProjects } from "../stores/projects";
import { useConfig } from "../stores/config";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import { Dialog } from "../components/ui/Dialog";
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
  Pencil,
  Bot,
  Expand,
  Shrink,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  getActiveProjectRunsFromDesktop,
  createProjectShareLinkFromDesktop,
  getActiveShareLinkFromDesktop,
  generateReportFromDesktop,
  getReportStatusFromDesktop,
  getReportContentFromDesktop,
  updateReportContentFromDesktop,
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
type DownloadFormat = "markdown" | "html" | "pdf";

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
    label: "Professional Report",
    icon: Globe,
    description: "Styled report in HTML or PDF formats",
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

function triggerFileDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  window.setTimeout(() => URL.revokeObjectURL(url), 15000);
}

const generateRandomPassword = () => `PF-${Math.random().toString(36).substring(2, 7).toUpperCase()}`;

function requestExportPassword(format: DownloadFormat): string | null {
  const destination =
    format === "pdf"
      ? "The exported file will be saved as a password-protected PDF."
      : "The exported file will be saved as a password-protected ZIP package.";
  const password = window.prompt(
    `Enter a password for the protected ${format.toUpperCase()} report download.\n${destination}`,
  );
  const clean = password?.trim() || "";
  return clean || null;
}

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
  const [downloadingFormat, setDownloadingFormat] = useState<DownloadFormat | null>(null);
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
  const [downloadSuccess, setDownloadSuccess] = useState<DownloadFormat | null>(null);
  const [exportDialogOpen, setExportDialogOpen] = useState(false);
  const [isEditing, setIsEditing] = useState(false);
  const [isSavingEdit, setIsSavingEdit] = useState(false);
  const [isFullscreen, setIsFullscreen] = useState(false);
  const statusPolling = useRef<ReturnType<typeof setInterval> | null>(null);
  const messagesPolling = useRef<ReturnType<typeof setInterval> | null>(null);
  const iframeRef = useRef<HTMLIFrameElement>(null);
  const viewerRef = useRef<HTMLDivElement>(null);
  const hasAutoSelected = useRef<string | null>(null);

  const [echoTooltip, setEchoTooltip] = useState<{ visible: boolean; x: number; y: number; text: string }>({ visible: false, x: 0, y: 0, text: '' });
  const updateConfig = useConfig((s) => s.updateConfig);

  const handleSelection = useCallback(() => {
    if (isEditing) {
      setEchoTooltip(prev => prev.visible ? { ...prev, visible: false } : prev);
      return;
    }

    let selection = window.getSelection();
    let text = selection?.toString().trim() || "";
    let rect: DOMRect | null = null;
    let offsetX = 0;
    let offsetY = 0;

    if (selection && !selection.isCollapsed && text.length > 0) {
      const range = selection.getRangeAt(0);
      const commonAncestor = range.commonAncestorContainer;
      if (viewerRef.current && viewerRef.current.contains(commonAncestor)) {
        rect = range.getBoundingClientRect();
      }
    }

    if (!rect && iframeRef.current?.contentWindow) {
      const iframeWin = iframeRef.current.contentWindow;
      selection = iframeWin.getSelection();
      text = selection?.toString().trim() || "";
      if (selection && !selection.isCollapsed && text.length > 0) {
        rect = selection.getRangeAt(0).getBoundingClientRect();
        const iframeRect = iframeRef.current.getBoundingClientRect();
        offsetX = iframeRect.left;
        offsetY = iframeRect.top;
      }
    }

    if (rect && text.length > 0) {
      setEchoTooltip({
        visible: true,
        x: rect.left + rect.width / 2 + offsetX,
        y: rect.top + offsetY - 30, // Show slightly above
        text,
      });
    } else {
      setEchoTooltip(prev => prev.visible ? { ...prev, visible: false } : prev);
    }
  }, [isEditing]);

  useEffect(() => {
    document.addEventListener('mouseup', handleSelection);
    document.addEventListener('keyup', handleSelection);
    document.addEventListener('selectionchange', handleSelection);

    const handleMessage = (event: MessageEvent) => {
      if (event.data?.type === 'IFRAME_SELECTION_CHANGE') {
        handleSelection();
      }
    };
    window.addEventListener('message', handleMessage);

    return () => {
      document.removeEventListener('mouseup', handleSelection);
      document.removeEventListener('keyup', handleSelection);
      document.removeEventListener('selectionchange', handleSelection);
      window.removeEventListener('message', handleMessage);
    };
  }, [handleSelection]);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape" && isFullscreen) {
        setIsFullscreen(false);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [isFullscreen]);

  useEffect(() => {
    const handleMouseDown = () => {
      // If user clicks outside the iframe, clear the iframe's internal selection so it doesn't linger
      if (iframeRef.current?.contentWindow) {
        iframeRef.current.contentWindow.getSelection()?.removeAllRanges();
      }
      setEchoTooltip(prev => prev.visible ? { ...prev, visible: false } : prev);
    };
    document.addEventListener('mousedown', handleMouseDown);
    return () => document.removeEventListener('mousedown', handleMouseDown);
  }, []);

  useEffect(() => {
    setEchoTooltip({ visible: false, x: 0, y: 0, text: '' });
  }, [viewFormat]);





  const fetchShareState = useCallback(async () => {
    if (!project) return;
    try {
      const activeShare = await getActiveShareLinkFromDesktop(project.id);
      if (activeShare && activeShare.ok) {
        setShareResult(activeShare);
        // Recover password from local storage if the link is protected
        if (activeShare.password_protected) {
          const savedPwd = localStorage.getItem(`pf_share_pwd_${project.id}`);
          if (savedPwd) {
            setGeneratedPassword(savedPwd);
            setSecureShare(true);
          } else {
            setSecureShare(true);
          }
        } else {
          setSecureShare(false);
          setGeneratedPassword("");
        }
      } else {
        setShareResult(null);
      }
    } catch {
      setShareResult(null);
    }
  }, [project?.id]);

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

        // Auto-select based on preference or default to HTML for each new report generation.
        const savedPref = localStorage.getItem(`pf_report_view_${project.id}`) as ReportFormat | null;
        const selectionKey = `${project.id}:${s.generated_at ?? "ready"}`;
        if (!viewFormat && hasAutoSelected.current !== selectionKey) {
          hasAutoSelected.current = selectionKey;
          if (savedPref && s[savedPref]) {
            handleView(savedPref);
          } else if (s.html) {
            handleView("html");
          } else if (s.markdown) {
            handleView("markdown");
          }
        }
      } else if (!stillActive && !reportExists) {
        stopStatusPolling();
      }
    } catch {
      // Silently ignore status fetch failures.
    }
  }, [project?.id, stopStatusPolling, viewFormat]);

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
    hasAutoSelected.current = null;
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
    setIsEditing(false);
    try {
      const report = await getReportContentFromDesktop(project.id, format);
      let content = report.content;
      if (format === "markdown") {
        content = content.replace(/^```markdown\n?/i, '').replace(/\n?```$/i, '').trim();
      }
      setViewContent(content);
    } catch (err) {
      setViewContent(
        `Failed to load report: ${err instanceof Error ? err.message : "Unknown error"}`,
      );
    } finally {
      setViewLoading(false);
    }
  };

  const handleDownload = async (format: DownloadFormat) => {
    const password = requestExportPassword(format);
    if (!password) {
      return;
    }
    setDownloadingFormat(format);
    setDownloadSuccess(null);
    try {
      // Minimum 1 second artificial delay for UX feel as requested
      const [result] = await Promise.all([
        downloadReportBlobFromDesktop(project.id, format, password),
        new Promise(r => setTimeout(r, 1000))
      ]);

      triggerFileDownload(result.blob, result.filename);

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
        try {
          await requestClientRefreshFromDesktop(project.id);
          // Wait a moment for the refresh signal to hit the client's poller
          await new Promise(r => setTimeout(r, 1500));
        } catch {
          // Ignore refresh errors
        }
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
      try {
        await requestClientRefreshFromDesktop(project.id);
        // Wait a moment for the refresh signal to hit the client's poller
        await new Promise(r => setTimeout(r, 1500));
      } catch {
        // Ignore refresh errors
      }

      await revokeShareLinksFromDesktop(project.id);
      setShareResult(null);
      setShareCopied(false);
      setGeneratedPassword("");
      setSecureShare(false);
      localStorage.removeItem(`pf_share_pwd_${project.id}`);
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
                          "rounded-xl px-4 py-2.5 text-sm shadow-sm whitespace-pre-wrap break-words break-all min-w-0",
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
                          onClick={(e) => {
                            e.stopPropagation();
                            if (card.format === "html") {
                              setExportDialogOpen(true);
                            } else {
                              handleDownload(card.format);
                            }
                          }}
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
              <div className={clsx("flex flex-col overflow-hidden", isFullscreen ? "fixed inset-0 z-[100] bg-surface-0 shadow-2xl" : "flex-1")}>
                <div className="px-5 py-2.5 border-b border-border bg-surface-1 flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <div className={clsx("w-2 h-2 rounded-full", viewFormat === 'html' ? "bg-orange-400" : "bg-blue-400")} />
                    <span className="text-xs font-bold text-text-primary uppercase tracking-[0.15em]">Previewing: {viewFormat}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <Button
                      size="xs"
                      variant="ghost"
                      onClick={() => setIsFullscreen(!isFullscreen)}
                      className="text-text-muted hover:text-pf-400"
                    >
                      {isFullscreen ? <Shrink size={12} /> : <Expand size={12} />}
                      <span className="ml-1 hidden sm:inline">{isFullscreen ? "Shrink" : "Expand"}</span>
                    </Button>
                    <Button
                      size="xs"
                      variant={isEditing ? "primary" : "ghost"}
                      onClick={async () => {
                        if (isEditing) {
                          setIsSavingEdit(true);
                          try {
                            await updateReportContentFromDesktop(project!.id, "markdown", viewContent);
                            setIsEditing(false);
                          } catch (err) {
                            alert(`Failed to save edits: ${err instanceof Error ? err.message : "Unknown error"}`);
                          } finally {
                            setIsSavingEdit(false);
                          }
                        } else {
                          if (viewFormat === "html") {
                            handleView("markdown").then(() => setIsEditing(true));
                          } else {
                            setIsEditing(true);
                          }
                        }
                      }}
                      loading={isSavingEdit}
                      className={clsx(
                        "transition-all duration-300",
                        isEditing ? "text-white" : "text-text-muted hover:text-pf-400"
                      )}
                    >
                      {!isSavingEdit && (isEditing ? <CheckCircle2 size={12} /> : <Pencil size={12} />)}
                      {isEditing ? "Done Editing" : "Edit"}
                    </Button>
                  </div>
                </div>

                <div ref={viewerRef} className="flex-1 overflow-auto bg-surface-0/40 p-6 custom-scrollbar">
                  {viewLoading ? (
                    <div className="h-full flex flex-col items-center justify-center gap-3">
                      <Loader2 size={32} className="text-pf-400 animate-spin opacity-50" />
                      <p className="text-xs text-text-muted uppercase tracking-widest font-bold">Loading Context</p>
                    </div>
                  ) : isEditing ? (
                    <div className="w-full h-full rounded-xl overflow-hidden shadow-2xl bg-surface-0 ring-4 ring-pf-500/30">
                      <textarea
                        className={clsx(
                          "w-full h-full text-text-primary whitespace-pre-wrap font-mono leading-relaxed bg-surface-1/50 p-6 border-0 focus:outline-none resize-none custom-scrollbar transition-all duration-300",
                          isFullscreen ? "text-[15px]" : "text-[13px]"
                        )}
                        value={viewContent}
                        onChange={(e) => setViewContent(e.target.value)}
                        placeholder="Edit markdown here..."
                        spellCheck={false}
                      />
                    </div>
                  ) : viewFormat === "html" ? (
                    <div className="w-full h-full rounded-xl overflow-hidden border border-border shadow-2xl bg-surface-0 ring-4 ring-surface-2/30">
                      <iframe
                        ref={iframeRef}
                        srcDoc={viewContent + `
                          <script>
                            const notifyParent = () => window.parent.postMessage({ type: 'IFRAME_SELECTION_CHANGE' }, '*');
                            document.addEventListener('selectionchange', notifyParent);
                            document.addEventListener('mouseup', notifyParent);
                            document.addEventListener('keyup', notifyParent);
                          </script>
                        `}
                        title="Report Preview"
                        className="w-full h-full border-0"
                        sandbox="allow-same-origin allow-scripts"
                      />
                    </div>
                  ) : (
                    <div className={clsx("mx-auto transition-all duration-300", isFullscreen ? "max-w-6xl" : "max-w-3xl")}>
                      <pre className={clsx(
                        "text-text-secondary whitespace-pre-wrap font-mono leading-relaxed bg-surface-1/50 p-8 rounded-xl border border-border shadow-inner transition-all duration-300",
                        isFullscreen ? "text-[15px]" : "text-[13px]"
                      )}>
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

      <Dialog
        open={exportDialogOpen}
        onClose={() => setExportDialogOpen(false)}
        title="Export Professional Report"
        description="Choose a protected export format. You will be asked for a password before download."
        width="max-w-md"
      >
        <div className="grid grid-cols-2 gap-4 mt-2">
          {/* HTML Option */}
          <button
            onClick={() => {
              handleDownload("html");
              setExportDialogOpen(false);
            }}
            className="flex flex-col items-center gap-3 p-5 rounded-xl border border-border bg-surface-1 hover:border-orange-500/50 hover:bg-orange-500/5 transition-all text-left group"
          >
            <div className="w-12 h-12 rounded-full bg-orange-500/10 flex items-center justify-center text-orange-500 group-hover:scale-110 transition-transform">
              <Globe size={24} />
            </div>
            <div className="text-center">
              <h3 className="text-sm font-bold text-text-primary">HTML Package</h3>
              <p className="text-[11px] text-text-muted mt-1 leading-snug">Password-protected ZIP with the styled HTML report</p>
            </div>
          </button>

          {/* PDF Option */}
          <button
            onClick={async () => {
              setExportDialogOpen(false);
              await handleDownload("pdf");
            }}
            className="flex flex-col items-center gap-3 p-5 rounded-xl border border-border bg-surface-1 hover:border-rose-500/50 hover:bg-rose-500/5 transition-all text-left group"
          >
            <div className="w-12 h-12 rounded-full bg-rose-500/10 flex items-center justify-center text-rose-500 group-hover:scale-110 transition-transform">
              <FileText size={24} />
            </div>
            <div className="text-center">
              <h3 className="text-sm font-bold text-text-primary">Protected PDF</h3>
              <p className="text-[11px] text-text-muted mt-1 leading-snug">Encrypted PDF generated from the report content</p>
            </div>
          </button>
        </div>
      </Dialog>

      {echoTooltip.visible && (
        <button
          className="fixed z-50 flex items-center gap-2 px-3 py-1.5 rounded-full bg-pf-500 hover:bg-pf-400 text-white shadow-xl transform -translate-x-1/2 -translate-y-full transition-all border border-pf-400/30"
          style={{ top: echoTooltip.y, left: echoTooltip.x }}
          onMouseDown={(e) => {
            e.preventDefault(); // Prevent focus loss that clears selection
            updateConfig({ isAssistantOpen: true, assistantDraftPrompt: echoTooltip.text });
            navigate('/dashboard?tab=assistant');
          }}
        >
          <Bot size={14} className="text-white" />
          <span className="text-[11px] font-semibold whitespace-nowrap">Ask Echo</span>
        </button>
      )}
    </div>
  );
}
