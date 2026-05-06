// src/pages/Reports.tsx
import { useCallback, useEffect, useRef, useState } from "react";
import { useProjects } from "../stores/projects";
import { Card } from "../components/ui/Card";
import { Button } from "../components/ui/Button";
import {
  FileText,
  Download,
  Eye,
  CheckCircle2,
  Loader2,
  RefreshCw,
  FileCode2,
  Globe,
  X,
} from "lucide-react";
import { useNavigate } from "react-router-dom";
import {
  generateReportFromDesktop,
  getReportStatusFromDesktop,
  getReportContentFromDesktop,
  downloadReportBlobFromDesktop,
  type ReportStatus,
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

const REPORT_GENERATING_STORAGE_PREFIX = "pf-report-generating";

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

function reportGeneratingStorageKey(projectId: string): string {
  return `${REPORT_GENERATING_STORAGE_PREFIX}:${projectId}`;
}

function readPersistedGenerating(projectId: string): boolean {
  if (typeof window === "undefined") {
    return false;
  }
  try {
    return window.sessionStorage.getItem(reportGeneratingStorageKey(projectId)) === "1";
  } catch {
    return false;
  }
}

function writePersistedGenerating(projectId: string, generating: boolean): void {
  if (typeof window === "undefined") {
    return;
  }
  try {
    const key = reportGeneratingStorageKey(projectId);
    if (generating) {
      window.sessionStorage.setItem(key, "1");
    } else {
      window.sessionStorage.removeItem(key);
    }
  } catch {
    // Ignore storage failures.
  }
}

export default function Reports() {
  const project = useProjects((s) => s.getActive());
  const navigate = useNavigate();

  const [status, setStatus] = useState<ReportStatus | null>(null);
  const [generating, setGenerating] = useState(() => (
    project ? readPersistedGenerating(project.id) : false
  ));
  const [error, setError] = useState("");
  const [viewFormat, setViewFormat] = useState<ReportFormat | null>(null);
  const [viewContent, setViewContent] = useState("");
  const [viewLoading, setViewLoading] = useState(false);
  const [downloadingFormat, setDownloadingFormat] = useState<ReportFormat | null>(null);
  const statusPolling = useRef<ReturnType<typeof setInterval> | null>(null);

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
      const s = await getReportStatusFromDesktop(project.id);
      setStatus(s);
      const reportExists = Boolean(s.markdown || s.html || s.pdf);
      if (reportExists) {
        setGenerating(false);
        writePersistedGenerating(project.id, false);
        stopStatusPolling();
      }
    } catch {
      // Silently ignore status fetch failures.
    }
  }, [project?.id, stopStatusPolling]);

  useEffect(() => {
    if (!project) {
      setGenerating(false);
      stopStatusPolling();
      return;
    }
    const persisted = readPersistedGenerating(project.id);
    setGenerating(persisted);
    if (persisted) {
      beginStatusPolling();
    } else {
      stopStatusPolling();
    }
  }, [project?.id, beginStatusPolling, stopStatusPolling]);

  useEffect(() => {
    void fetchStatus();
  }, [fetchStatus]);

  useEffect(() => {
    if (!project) {
      return;
    }
    writePersistedGenerating(project.id, generating);
    if (generating) {
      beginStatusPolling();
    } else {
      stopStatusPolling();
    }
  }, [project?.id, generating, beginStatusPolling, stopStatusPolling]);

  // Clean up polling on unmount.
  useEffect(() => {
    return () => {
      stopStatusPolling();
    };
  }, [stopStatusPolling]);

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

  const handleGenerate = async () => {
    setGenerating(true);
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
      await generateReportFromDesktop(project.id);
      await fetchStatus();
      setGenerating(false);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Report generation failed",
      );
      setGenerating(false);
    }
  };

  const handleView = async (format: ReportFormat) => {
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
    try {
      const result = await downloadReportBlobFromDesktop(project.id, format);
      triggerFileDownload(result.content, result.filename, result.mimeType);
    } catch (err) {
      setError(
        err instanceof Error ? err.message : "Download failed",
      );
    } finally {
      setDownloadingFormat(null);
    }
  };



  const handleCloseView = () => {
    setViewFormat(null);
    setViewContent("");
    setViewLoading(false);
  };

  return (
    <div className="h-full overflow-auto p-4">
      <div className="max-w-4xl mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <FileText size={20} className="text-pf-400" />
            Reports
          </h1>
          <p className="text-xs text-text-muted mt-1">
            {project.name} — {project.target}
          </p>
        </div>

        {hasAnyReport && (
          <div className="flex items-center gap-2">
            {status?.generated_at && (
              <span className="text-[10px] text-text-muted">
                Generated {new Date(status.generated_at).toLocaleString()}
              </span>
            )}
            <Button
              size="sm"
              variant="ghost"
              onClick={handleGenerate}
              loading={generating}
              disabled={generating}
              title="Regenerate report"
            >
              <RefreshCw size={13} />
              Regenerate
            </Button>
          </div>
        )}
      </div>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/5 px-4 py-3 text-sm text-red-400 flex items-start gap-2">
          <span className="shrink-0 mt-0.5">⚠️</span>
          <span>{error}</span>
        </div>
      )}

      {/* Generate CTA — only when no reports exist */}
      {!hasAnyReport && !generating && (
        <Card className="flex flex-col items-center py-10 gap-4 bg-gradient-to-br from-pf-600/5 to-pf-500/5 border-pf-500/20">
          <div className="w-16 h-16 rounded-full bg-pf-600/10 flex items-center justify-center animate-pulse">
            <FileText size={28} className="text-pf-400" />
          </div>
          <div className="text-center">
            <h2 className="text-base font-semibold text-text-primary">
              No Report Generated Yet
            </h2>
            <p className="text-xs text-text-muted mt-1 max-w-md">
              Generate a comprehensive pentest report using AI. The assistant
              will analyze all findings, evidence, and testing coverage to
              produce a professional document.
            </p>
          </div>
          <Button
            onClick={handleGenerate}
            loading={generating}
            disabled={generating}
            className="mt-2"
          >
            <FileText size={14} />
            Generate Report
          </Button>
        </Card>
      )}

      {/* Generating spinner */}
      {generating && (
        <Card className="flex flex-col items-center py-10 gap-4 border-pf-500/20">
          <Loader2 size={32} className="text-pf-400 animate-spin" />
          <div className="text-center">
            <h2 className="text-base font-semibold text-text-primary">
              Generating Report...
            </h2>
            <p className="text-xs text-text-muted mt-1">
              The AI is analyzing findings and evidence. This may take 15–30 seconds.
            </p>
          </div>
        </Card>
      )}

      {/* Format cards — shown once reports exist */}
      {hasAnyReport && !generating && (
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          {FORMAT_CARDS.map((card) => {
            const exists = status?.[card.format] ?? false;
            const isDownloading = downloadingFormat === card.format;
            const Icon = card.icon;

            return (
              <Card
                key={card.format}
                className={`relative flex flex-col p-5 gap-4 bg-gradient-to-br ${card.gradient} transition-all duration-200 hover:border-pf-500/30`}
              >
                {/* Status indicator */}
                {exists && (
                  <div className="absolute top-3 right-3">
                    <CheckCircle2
                      size={18}
                      className="text-emerald-400 drop-shadow-sm"
                    />
                  </div>
                )}

                {/* Icon & Label */}
                <div className="flex items-center gap-3">
                  <div
                    className={`w-10 h-10 rounded-lg bg-surface-2/80 flex items-center justify-center`}
                  >
                    <Icon size={20} className={card.color} />
                  </div>
                  <div>
                    <h3 className="text-sm font-semibold text-text-primary">
                      {card.label}
                    </h3>
                    <p className="text-[11px] text-text-muted leading-tight">
                      {card.description}
                    </p>
                  </div>
                </div>

                {/* Actions */}
                {exists ? (
                  <div className="flex items-center gap-2 mt-auto">
                    <Button
                      size="sm"
                      variant="outline"
                      className="flex-1"
                      onClick={() => handleView(card.format)}
                    >
                      <Eye size={13} />
                      View
                    </Button>
                    <Button
                      size="sm"
                      variant="secondary"
                      className="flex-1"
                      onClick={() => handleDownload(card.format)}
                      loading={isDownloading}
                      disabled={isDownloading}
                    >
                      <Download size={13} />
                      Download
                    </Button>
                  </div>
                ) : (
                  <div className="flex items-center mt-auto">
                    <span className="text-[11px] text-text-muted italic">
                      Not generated yet — click Generate above
                    </span>
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}



      {/* View modal/overlay */}
      {viewFormat && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
          <div className="relative w-full max-w-4xl max-h-[85vh] bg-surface-1 border border-border rounded-xl shadow-2xl flex flex-col overflow-hidden">
            {/* Modal header */}
            <div className="flex items-center justify-between px-5 py-3 border-b border-border bg-surface-2/50">
              <div className="flex items-center gap-2">
                <FileText size={16} className="text-pf-400" />
                <span className="text-sm font-semibold text-text-primary">
                  {viewFormat === "html" ? "HTML Report" : "Markdown Report"}
                </span>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  size="xs"
                  variant="ghost"
                  onClick={() => handleDownload(viewFormat)}
                  disabled={downloadingFormat === viewFormat}
                >
                  <Download size={12} />
                  Download
                </Button>
                <Button
                  size="icon"
                  variant="ghost"
                  onClick={handleCloseView}
                >
                  <X size={16} />
                </Button>
              </div>
            </div>

            {/* Modal body */}
            <div className="flex-1 overflow-auto p-6">
              {viewLoading ? (
                <div className="flex items-center justify-center py-16">
                  <Loader2 size={24} className="text-pf-400 animate-spin" />
                </div>
              ) : viewFormat === "html" ? (
                <iframe
                  srcDoc={viewContent}
                  title="Report Preview"
                  className="w-full min-h-[70vh] border-0 rounded-lg bg-white"
                  sandbox="allow-same-origin"
                />
              ) : (
                <pre className="text-xs text-text-secondary whitespace-pre-wrap font-mono leading-relaxed">
                  {viewContent}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
      </div>
    </div>
  );
}
