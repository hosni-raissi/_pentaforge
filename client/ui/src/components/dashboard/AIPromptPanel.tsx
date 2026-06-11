import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { Bot, SendHorizontal, Sparkles, Trash2, Copy, Check, X, Clock3, Square, FileText, ChevronDown } from 'lucide-react';
import { useNavigate } from 'react-router-dom';

import {
  askAIAssistStreamFromDesktop,
  cancelAIAssistRunFromDesktop,
  clearAIAssistConversationFromDesktop,
  getActiveProjectRunsFromDesktop,
  getAIAssistContextMetricsFromDesktop,
  updateProjectSavedContextFromDesktop,
  sendAIAssistInputFromDesktop,
  compressAIAssistHistory,
  compressAIAssistWorkingContext,
} from '@/lib/projectBridge';
import type { AIAssistContextMetrics } from '@/lib/projectBridge';
import type { CopilotMessage } from '@/types';
import type { AgentInfo, Finding } from '../../types';
import { useProjects } from '../../stores/projects';
import { useConfig } from '../../stores/config';
import { Button } from '../ui/Button';
import { Card, CardHeader, CardTitle } from '../ui/Card';

interface AIPromptPanelProps {
  projectId: string;
  projectName: string;
  target: string;
  targetType: string;
  projectStatus?: string;
  savedContext?: string;
  hasScanState?: boolean;
  agents: AgentInfo[];
  history?: CopilotMessage[];
  injectedPrompt?: {
    token: string;
    text: string;
  } | null;
  onClose?: () => void;
}

const CHAT_STORAGE_PREFIX = 'pf-assistant-chat';
const MAX_CHAT_MESSAGES = 80;
const HISTORY_TOKEN_LIMIT = 8000;
const MAX_PROMPT_CHARS = 4000;

function estimateTokens(text: string): number {
  return Math.ceil((text || '').length / 4);
}

function estimateMessagesTokens(messages: CopilotMessage[]): number {
  return messages.reduce((acc, m) => acc + estimateTokens(m.text || ''), 0);
}

function estimateSavedContextTokens(savedContext?: string): number {
  const raw = String(savedContext || '').trim();
  if (!raw) {
    return 0;
  }
  return estimateTokens(raw);
}

type PanelMessage = CopilotMessage & {
  localState?: 'pending' | 'error' | 'cancelled';
  requestId?: string;
  isCompressionSeparator?: boolean;
};

const TokenUsageCircle = ({
  currentTokens,
  limitTokens,
}: {
  currentTokens: number;
  limitTokens: number;
}) => {
  const safeLimit = Math.max(1, limitTokens);
  const percentage = Math.min(100, (currentTokens / safeLimit) * 100);
  const radius = 6.5;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (percentage / 100) * circumference;

  return (
    <div className="group relative flex items-center justify-center h-5 w-5" title={`Working memory usage: ${Math.round(percentage)}% (${currentTokens}/${safeLimit} tokens)`}>
      <svg className="h-4 w-4 -rotate-90 transform">
        <circle
          cx="8"
          cy="8"
          r={radius}
          fill="transparent"
          stroke="currentColor"
          strokeWidth="1.5"
          className="text-border/40"
        />
        <circle
          cx="8"
          cy="8"
          r={radius}
          fill="transparent"
          stroke="currentColor"
          strokeWidth="1.5"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className={`transition-all duration-500 ${percentage > 90 ? 'text-red-500' : percentage > 70 ? 'text-orange-500' : 'text-pf-500'}`}
        />
      </svg>
    </div>
  );
};

function buildStorageKey(projectId: string, target: string, targetType: string): string {
  return `${CHAT_STORAGE_PREFIX}:${projectId}:${target}:${targetType}`;
}

function readStoredMessages(storageKey: string): PanelMessage[] {
  if (typeof window === 'undefined') return [];
  try {
    const raw = window.sessionStorage.getItem(storageKey);
    if (!raw) return [];
    const parsed = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter((item): item is PanelMessage => (
      typeof item === 'object'
      && item !== null
      && (item.role === 'user' || item.role === 'assistant')
      && typeof item.text === 'string'
      && typeof item.id === 'string'
    ));
  } catch {
    return [];
  }
}

function writeStoredMessages(storageKey: string, messages: PanelMessage[]): void {
  if (typeof window === 'undefined') return;
  try {
    window.sessionStorage.setItem(storageKey, JSON.stringify(messages.slice(-MAX_CHAT_MESSAGES)));
  } catch {
    // Ignore storage failures; in-memory timeline remains source of truth.
  }
}

function messageSignature(message: Pick<CopilotMessage, 'role' | 'text' | 'route' | 'blocked'>): string {
  // Only use role + text for dedup — route/blocked metadata may differ
  // between the locally-streamed version and the backend-saved history.
  return [
    message.role,
    message.text.trim().slice(0, 300),
  ].join('|');
}

function comparePanelMessages(a: PanelMessage, b: PanelMessage): number {
  if (a.id === 'intro') return -1;
  if (b.id === 'intro') return 1;
  const timeA = a.timestamp ? new Date(a.timestamp).getTime() : 0;
  const timeB = b.timestamp ? new Date(b.timestamp).getTime() : 0;
  if (timeA !== timeB) {
    return timeA - timeB;
  }
  if (a.role !== b.role) {
    if (a.role === 'user') return -1;
    if (b.role === 'user') return 1;
  }
  return String(a.id || '').localeCompare(String(b.id || ''));
}

function mergeMessages(
  baseHistory: CopilotMessage[] | undefined,
  localMessages: PanelMessage[],
  introMessage: CopilotMessage,
): PanelMessage[] {
  const merged: PanelMessage[] = [];
  const historyDupes = new Map<string, number>();
  const historyIds = new Set<string>();

  if (baseHistory) {
    for (const item of baseHistory) {
      const row = { ...item };
      merged.push(row);
      if (typeof row.id === 'string' && row.id.trim()) {
        historyIds.add(row.id);
      }
      const key = messageSignature(row);
      historyDupes.set(key, (historyDupes.get(key) ?? 0) + 1);
    }
  }

  for (const item of localMessages) {
    if (item.id === 'intro') {
      continue;
    }
    if (historyIds.has(item.id)) {
      continue;
    }
    const key = messageSignature(item);
    const remaining = historyDupes.get(key) ?? 0;
    if (remaining > 0) {
      historyDupes.set(key, remaining - 1);
      continue;
    }
    merged.push({ ...item });
  }

  // Sort chronologically by timestamp, but always keep intro at top
  merged.sort(comparePanelMessages);

  return [{ ...introMessage }, ...merged].slice(-MAX_CHAT_MESSAGES);
}

function CodeCopyButton({ text, isWhiteBg }: { text: string; isWhiteBg: boolean }) {
  const [copied, setCopied] = useState(false);
  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch { /* ignore */ }
  };
  return (
    <button
      type="button"
      onClick={handleCopy}
      className={`flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] transition-all ${isWhiteBg
        ? 'text-zinc-500 hover:bg-zinc-200 hover:text-zinc-700'
        : 'text-zinc-400 hover:bg-white/10 hover:text-white'
        }`}
    >
      {copied ? (
        <>
          <Check size={10} className="text-green-500" />
          <span className="text-green-500 font-bold">Copied</span>
        </>
      ) : (
        <>
          <Copy size={10} />
          <span>Copy</span>
        </>
      )}
    </button>
  );
}

function renderMarkdownMessage(text: string) {
  if (!text) return null;
  const parts = text.split(/(```[\s\S]*?```)/g);
  return parts.map((part, i) => {
    if (part.startsWith('```') && part.endsWith('```')) {
      const match = part.match(/```(\w+)?\n?([\s\S]*?)```/);
      if (match) {
        const lang = (match[1] || '').toLowerCase();
        const code = match[2];
        const isWhiteBg = lang === 'xml' || lang === 'html' || lang === 'soap';
        const displayLang = lang || 'code';

        return (
          <div key={i} className={`my-2 max-w-full rounded-md border overflow-hidden shadow-lg ${isWhiteBg ? 'bg-white border-zinc-200' : 'bg-zinc-900 border-white/10'}`}>
            <div className={`px-3 py-1 flex items-center justify-between text-[10px] uppercase font-bold border-b ${isWhiteBg ? 'bg-zinc-50 text-zinc-500 border-zinc-200' : 'bg-zinc-800 text-zinc-400 border-white/5'}`}>
              <span>{displayLang}</span>
              <CodeCopyButton text={code.replace(/\n$/, '')} isWhiteBg={isWhiteBg} />
            </div>
            <pre className={`p-3 text-[11px] overflow-x-auto font-mono scrollbar-pf ${isWhiteBg ? 'bg-white text-zinc-900' : 'bg-zinc-900 text-white'}`}>
              <code>{code.replace(/\n$/, '')}</code>
            </pre>
          </div>
        );
      }
    }

    // Handle headings, bold, italics, and TABLES
    const lines = part.split('\n');
    const renderedLines: React.ReactNode[] = [];
    let currentTable: string[] = [];

    const flushTable = (key: string) => {
      if (currentTable.length === 0) return;
      const tableRows = currentTable;
      currentTable = [];

      // Basic table parser
      const parseRow = (row: string) => row.split('|').filter((_, idx, arr) => idx > 0 && idx < arr.length - 1).map(c => c.trim());
      const headerRow = tableRows[0];
      const separatorRow = tableRows[1];
      const dataRows = tableRows.slice(2);

      const headers = parseRow(headerRow);
      const isHeaderOnly = !separatorRow || !separatorRow.includes('---');

      if (isHeaderOnly) {
        // Not a valid table, just render as lines
        tableRows.forEach((r, ridx) => {
          renderedLines.push(<div key={`${key}-r-${ridx}`} className="leading-relaxed">{renderLineContent(r)}</div>);
        });
        return;
      }

      renderedLines.push(
        <div key={`${key}-table`} className="my-4 overflow-x-auto rounded-md border border-pf-500/20 bg-surface-1/50 shadow-sm scrollbar-pf">
          <table className="w-full border-collapse text-[12px]">
            <thead>
              <tr className="border-b border-pf-500/30 bg-pf-500/10">
                {headers.map((h, hidx) => (
                  <th key={hidx} className="px-3 py-2 text-left font-bold text-pf-300 uppercase tracking-wider border-r border-pf-500/10 last:border-r-0">
                    {renderLineContent(h)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {dataRows.map((row, ridx) => {
                const cells = parseRow(row);
                return (
                  <tr key={ridx} className="border-b border-pf-500/10 last:border-b-0 hover:bg-pf-500/5 transition-colors">
                    {cells.map((c, cidx) => (
                      <td key={cidx} className="px-3 py-2 text-text-secondary border-r border-pf-500/10 last:border-r-0 font-mono text-[11px]">
                        {renderLineContent(c)}
                      </td>
                    ))}
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      );
    };

    const renderLineContent = (line: string) => {
      // Handle Bold (**), Italics (*), and Inline Code (`)
      const boldParts = line.split(/(\*\*.*?\*\*)/g);
      return boldParts.map((bp, bpIdx) => {
        if (bp.startsWith('**') && bp.endsWith('**')) {
          return <strong key={bpIdx} className="font-bold text-text-primary">{bp.slice(2, -2)}</strong>;
        }

        // Sub-split for inline code (`)
        const codeParts = bp.split(/(`.*?`)/g);
        return codeParts.map((cp, cpIdx) => {
          if (cp.startsWith('`') && cp.endsWith('`')) {
            return (
              <code key={cpIdx} className="px-1.5 py-0.5 rounded bg-zinc-800 text-pf-200 font-mono text-[10.5px] border border-white/5 mx-0.5 leading-none inline-block align-baseline shadow-sm">
                {cp.slice(1, -1)}
              </code>
            );
          }

          // Sub-split for italics (*)
          const italicParts = cp.split(/(\*.*?\*)/g);
          return italicParts.map((ip, ipIdx) => {
            if (ip.startsWith('*') && ip.endsWith('*')) {
              return <em key={ipIdx} className="italic opacity-85 text-text-secondary">{ip.slice(1, -1)}</em>;
            }
            return ip;
          });
        });
      });
    };

    lines.forEach((line, lineIdx) => {
      const trimmed = line.trim();

      // Table detection
      if (trimmed.startsWith('|') && trimmed.endsWith('|')) {
        currentTable.push(trimmed);
        return;
      } else if (currentTable.length > 0) {
        flushTable(`l-${lineIdx}`);
      }

      if (!trimmed) {
        renderedLines.push(<div key={lineIdx} className="h-2" />);
        return;
      }

      // Handle Horizontal Rules (---)
      if (trimmed === '---') {
        renderedLines.push(<div key={lineIdx} className="my-3 border-t border-pf-500/20" />);
        return;
      }

      // Handle Headings (#, ##, ###)
      const headingMatch = line.match(/^(#{1,4})\s+(.+)$/);
      if (headingMatch) {
        const level = headingMatch[1].length;
        const content = headingMatch[2];
        if (level === 1) {
          renderedLines.push(
            <h1 key={lineIdx} className="mt-4 mb-2 text-[16px] font-extrabold text-pf-300 border-b-2 border-pf-500/20 pb-1">
              {renderLineContent(content)}
            </h1>
          );
        } else if (level === 2) {
          renderedLines.push(
            <h2 key={lineIdx} className="mt-3.5 mb-1.5 text-[14px] font-bold text-pf-400 border-b border-pf-500/15 pb-0.5">
              {renderLineContent(content)}
            </h2>
          );
        } else if (level === 3) {
          renderedLines.push(
            <h3 key={lineIdx} className="mt-3 mb-1 text-[13px] font-semibold text-pf-400/90 border-b border-pf-500/10 pb-0.5">
              {renderLineContent(content)}
            </h3>
          );
        } else {
          renderedLines.push(
            <h4 key={lineIdx} className="mt-2.5 mb-1 text-[12px] font-bold text-pf-500 uppercase tracking-tight">
              {renderLineContent(content)}
            </h4>
          );
        }
        return;
      }

      renderedLines.push(
        <div key={lineIdx} className="leading-relaxed">
          {renderLineContent(line)}
        </div>
      );
    });

    if (currentTable.length > 0) {
      flushTable('end');
    }

    return (
      <div key={i} className="flex flex-col gap-y-0.5">
        {renderedLines}
      </div>
    );
  });
}

function mergeActiveAssistantRun(
  messages: PanelMessage[],
  run: {
    run_id: string;
    status: string;
    created_at: string;
    updated_at: string;
    payload: Record<string, unknown>;
  },
): PanelMessage[] {
  const prompt = typeof run.payload.prompt === 'string' ? run.payload.prompt.trim() : '';
  const reply = typeof run.payload.reply === 'string' ? run.payload.reply : '';
  const route = (
    run.payload.route === 'assistant'
    || run.payload.route === 'planner'
    || run.payload.route === 'reporting'
    || run.payload.route === 'blocked'
  ) ? run.payload.route : undefined;
  const blocked = typeof run.payload.blocked === 'boolean' ? run.payload.blocked : undefined;
  const toolLogs = Array.isArray(run.payload.toolLogs) ? run.payload.toolLogs as PanelMessage['toolLogs'] : [];
  const passwordRequests = Array.isArray(run.payload.password_requests)
    ? run.payload.password_requests as PanelMessage['passwordRequests']
    : [];
  const isResumable = isAssistantRunResumable({
    status: run.status,
    reply,
    toolLogs,
    passwordRequests,
  });
  const existingUser = messages.find(
    (message) => message.id === `u-${run.run_id}` || (message.role === 'user' && message.text === prompt)
  );
  const existingAssistant = messages.find((message) => message.id === `a-${run.run_id}`);

  let next = [...messages];
  if (prompt && !existingUser) {
    next.push({
      id: `u-${run.run_id}`,
      role: 'user',
      text: prompt,
      timestamp: run.created_at,
    });
  }

  const assistantMessage: PanelMessage = {
    id: `a-${run.run_id}`,
    requestId: run.run_id,
    role: 'assistant',
    text: reply,
    route,
    blocked,
    timestamp: run.updated_at || run.created_at,
    toolLogs,
    passwordRequests,
    localState: isResumable
      ? 'pending'
      : run.status === 'cancelled'
        ? 'cancelled'
        : run.status === 'failed'
          ? 'error'
          : undefined,
  };

  if (!existingAssistant) {
    next.push(assistantMessage);
  } else {
    next = next.map((message) => (
      message.id === existingAssistant.id ? { ...message, ...assistantMessage } : message
    ));
  }

  next.sort(comparePanelMessages);
  return next.slice(-MAX_CHAT_MESSAGES);
}

function isAssistantRunResumable(run: {
  status: string;
  reply?: string;
  toolLogs?: PanelMessage['toolLogs'];
  passwordRequests?: PanelMessage['passwordRequests'];
}): boolean {
  if (run.status !== 'pending' && run.status !== 'running') {
    return false;
  }
  const toolLogs = Array.isArray(run.toolLogs) ? run.toolLogs : [];
  const passwordRequests = Array.isArray(run.passwordRequests) ? run.passwordRequests : [];
  const hasRunningTool = toolLogs.some((log) => log.status === 'running');
  const hasPendingPassword = passwordRequests.some((request) => request.status === 'pending');
  return !String(run.reply || '').trim() || hasRunningTool || hasPendingPassword;
}

function findPendingAssistantMessage(messages: PanelMessage[]): PanelMessage | null {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    const isResumable = isAssistantRunResumable({
      status: message.localState === 'pending' ? 'pending' : '',
      reply: message.text,
      toolLogs: message.toolLogs,
      passwordRequests: message.passwordRequests,
    });
    if (message.role === 'assistant' && message.localState === 'pending' && message.requestId && isResumable) {
      return message;
    }
  }
  return null;
}

function buildErrorReply(error: unknown, fallbackReply: string): string {
  if (error instanceof DOMException && error.name === 'AbortError') {
    return 'Echo timed out waiting for the backend. The request may still complete — try reopening the chat in a moment.';
  }
  if (error instanceof Error) {
    const text = error.message.trim();
    if (text) return `Echo couldn't complete that request.\n${text}`;
  }
  return `${fallbackReply}\n(backend AI assist unavailable — fallback mode)`;
}

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function isSuccessfulReportReply(message: PanelMessage): boolean {
  if (message.role !== 'assistant' || !!message.localState) {
    return false;
  }
  const text = message.text.trim().toLowerCase();
  if (!text) {
    return false;
  }
  return (
    text.includes("generated a comprehensive penetration testing report")
    || (
      text.includes("report is now available")
      && text.includes("reports page")
    )
  );
}

function normalizeFindingReference(value: string): string {
  return value.trim().toLowerCase().replace(/[_-]+/g, ' ').replace(/\s+/g, ' ');
}

function findingMatchesFalsePositiveResult(
  finding: Finding,
  matchedId: string,
  matchedTitle: string,
  requestedReference: string,
): boolean {
  if (matchedId && finding.id === matchedId) {
    return true;
  }

  const findingTitle = normalizeFindingReference(finding.title || '');
  const expectedTitle = normalizeFindingReference(matchedTitle);
  if (expectedTitle && findingTitle === expectedTitle) {
    return true;
  }

  const requested = normalizeFindingReference(requestedReference);
  if (!requested) {
    return false;
  }

  const description = normalizeFindingReference(finding.description || '');
  return (
    (findingTitle.length >= 12 && requested.includes(findingTitle))
    || (description.length >= 20 && requested.includes(description))
    || (requested.length >= 20 && description.includes(requested))
  );
}

// ── Copy button with transient "Copied" feedback ──────────────────────────────
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard unavailable — silently ignore
    }
  };

  return (
    <button
      type="button"
      onClick={handleCopy}
      className="mt-1 flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] text-text-muted transition-colors hover:text-text-secondary"
      title="Copy message"
    >
      {copied ? (
        <>
          <Check size={10} className="text-green-500" />
          <span className="text-green-500">Copied</span>
        </>
      ) : (
        <>
          <Copy size={10} />
          Copy
        </>
      )}
    </button>
  );
}

// ── Clear chat confirmation popover ──────────────────────────────────────────
function ClearButton({ onConfirm, disabled = false }: { onConfirm: () => void; disabled?: boolean }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, [open]);

  return (
    <div ref={ref} className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        disabled={disabled}
        className="flex items-center gap-1 rounded border border-border px-2 py-1 text-xs text-text-muted transition-colors hover:border-red-400 hover:text-red-500"
        title="Clear conversation"
      >
        <Trash2 size={11} />
        Clear
      </button>

      {open && (
        <div className="absolute right-0 top-8 z-20 w-44 rounded-md border border-border bg-surface-0 p-3 shadow-md">
          <p className="mb-2 text-xs text-text-secondary">Clear all messages?</p>
          <div className="flex gap-2">
            <Button
              size="xs"
              variant="danger"
              onClick={() => { setOpen(false); onConfirm(); }}
            >
              Clear
            </Button>
            <Button size="xs" variant="secondary" onClick={() => setOpen(false)}>
              Cancel
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}

// ── Auto-growing textarea ─────────────────────────────────────────────────────
function AutoTextarea({
  value,
  onChange,
  onKeyDown,
  placeholder,
  disabled,
  className,
  maxLength,
}: {
  value: string;
  onChange: (v: string) => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void;
  placeholder: string;
  disabled: boolean;
  className?: string;
  maxLength?: number;
}) {
  const ref = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${Math.min(el.scrollHeight, 120)}px`;
  }, [value]);

  return (
    <textarea
      ref={ref}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      onKeyDown={onKeyDown}
      placeholder={placeholder}
      disabled={disabled}
      maxLength={maxLength}
      rows={1}
      className={`focus-ring w-full resize-none bg-transparent px-3 py-2 text-sm text-text-primary placeholder:text-text-muted disabled:opacity-50 ${className || ''}`}
      style={{ minHeight: 40, maxHeight: 120, overflowY: 'auto' }}
    />
  );
}

// ── Main component ────────────────────────────────────────────────────────────
function PasswordRequestBlock({
  requestId,
  request,
  onResponse,
}: {
  requestId: string;
  request: {
    call_id: string;
    prompt: string;
    reason: string;
    status: 'pending' | 'submitted' | 'denied';
  };
  onResponse: (callId: string, value: string, denied: boolean) => void;
}) {
  const [value, setValue] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const handleSubmit = async (denied: boolean) => {
    setSubmitting(true);
    try {
      await sendAIAssistInputFromDesktop(requestId, {
        callId: request.call_id,
        value: denied ? '' : value,
        denied,
      });
      onResponse(request.call_id, value, denied);
    } catch (err) {
      console.error('Failed to submit password:', err);
    } finally {
      setSubmitting(false);
    }
  };

  if (request.status === 'submitted') {
    return (
      <div className="flex items-center gap-2 rounded-md bg-green-500/10 border border-green-500/20 px-3 py-2 text-[11px] text-green-700 dark:text-green-300 italic">
        <Check size={12} />
        <span>Password provided.</span>
      </div>
    );
  }

  if (request.status === 'denied') {
    return (
      <div className="flex items-center gap-2 rounded-md bg-surface-2 border border-border px-3 py-2 text-[11px] text-text-muted italic">
        <X size={12} />
        <span>Password request declined.</span>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-2 rounded-md border border-pf-500/30 bg-pf-500/5 p-3 shadow-sm">
      <div className="flex items-center gap-2 text-xs font-semibold text-pf-400">
        <Sparkles size={13} />
        <span>Interactive Input Required</span>
      </div>
      <p className="text-[11px] text-text-muted leading-tight">
        {request.reason || 'The tool requires a password to proceed.'}
      </p>
      <div className="flex flex-col gap-1.5">
        <label className="text-[10px] uppercase tracking-wider text-text-muted/70 font-bold px-1">
          {request.prompt || 'Password'}
        </label>
        <div className="flex gap-2">
          <input
            type="password"
            autoFocus
            value={value}
            onChange={(e) => setValue(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && value.trim()) {
                void handleSubmit(false);
              }
            }}
            placeholder="••••••••"
            disabled={submitting}
            className="flex-1 rounded border border-border bg-surface-2 px-2 py-1.5 text-sm focus:border-pf-500/50 focus:outline-none"
          />
          <Button
            size="sm"
            className="h-8"
            disabled={!value.trim() || submitting}
            onClick={() => { void handleSubmit(false); }}
          >
            {submitting ? 'Sending...' : 'Submit'}
          </Button>
          <Button
            size="sm"
            variant="ghost"
            className="h-8 text-text-muted hover:text-red-500"
            disabled={submitting}
            onClick={() => { void handleSubmit(true); }}
          >
            Skip
          </Button>
        </div>
      </div>
    </div>
  );
}


export function AIPromptPanel({
  projectId,
  projectName,
  target,
  targetType,
  projectStatus,
  savedContext,
  hasScanState = false,
  agents,
  history,
  injectedPrompt,
  onClose,
}: AIPromptPanelProps) {
  const introMessage: CopilotMessage = useMemo(
    () => ({
      id: 'intro',
      role: 'assistant',
      text: `Echo online for ${projectName}. Ask anything about ${target}.`,
      timestamp: new Date().setHours(0, 0, 0, 0).toString(), // Stable for the day
    }),
    [projectName, target],
  );
  const navigate = useNavigate();
  const assistantDraftPrompt = useConfig((s) => s.assistantDraftPrompt);
  const updateConfig = useConfig((s) => s.updateConfig);
  const projects = useProjects((s) => s.projects);
  const updateProject = useProjects((s) => s.updateProject);
  const project = useMemo(() => projects.find((p) => p.id === projectId), [projects, projectId]);

  const [prompt, setPrompt] = useState('');
  const [sending, setSending] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [historySuppressed, setHistorySuppressed] = useState(false);
  const [loadingStep, setLoadingStep] = useState<'thinking' | 'working'>('thinking');
  const [contextMetrics, setContextMetrics] = useState<AIAssistContextMetrics>({
    display_tokens: 0,
    effective_tokens: 0,
    limit_tokens: HISTORY_TOKEN_LIMIT,
    threshold_tokens: Math.floor(HISTORY_TOKEN_LIMIT * 0.95),
    should_compress_before_send: false,
    operator_mode: 'Ask',
    execution_lane: 'lightweight',
    response_style: 'natural',
    has_working_memory: false,
    uses_recent_history_fallback: false,
  });

  useEffect(() => {
    let timer: any;
    if (sending) {
      setLoadingStep('thinking');
      timer = setTimeout(() => {
        setLoadingStep('working');
      }, 3000);
    }
    return () => clearTimeout(timer);
  }, [sending]);

  const storageKey = useMemo(
    () => buildStorageKey(projectId, target, targetType),
    [projectId, target, targetType],
  );

  const [messages, setMessages] = useState<PanelMessage[]>(() =>
    mergeMessages(history, readStoredMessages(storageKey), introMessage),
  );
  const activeAbortControllerRef = useRef<AbortController | null>(null);
  const activeRequestIdRef = useRef<string | null>(null);
  const cancelledRequestIdsRef = useRef<Set<string>>(new Set());
  const previousProjectStatusRef = useRef<string | undefined>(projectStatus);
  const previousHasScanStateRef = useRef<boolean>(hasScanState);
  const agentsRef = useRef<AgentInfo[]>(agents);

  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);
  const [showScrollButton, setShowScrollButton] = useState(false);
  const userIsAtBottomRef = useRef(true);

  useEffect(() => {
    agentsRef.current = agents;
  }, [agents]);

  const handleScroll = useCallback(() => {
    if (!scrollContainerRef.current) return;
    const { scrollTop, scrollHeight, clientHeight } = scrollContainerRef.current;
    const distFromBottom = scrollHeight - scrollTop - clientHeight;

    // User is "at bottom" if they are within 50px of the end
    userIsAtBottomRef.current = distFromBottom < 50;

    // Show button if more than 200px away from bottom AND we are actually scrollable
    setShowScrollButton(scrollHeight > clientHeight && distFromBottom > 200);
  }, []);

  useEffect(() => {
    const el = scrollContainerRef.current;
    if (!el) return;
    el.addEventListener('scroll', handleScroll, { passive: true });
    return () => el.removeEventListener('scroll', handleScroll);
  }, [handleScroll]);
  const handleOpenReportsShare = useCallback(() => {
    navigate('/reports');
  }, [navigate]);

  const buildLiveContext = useCallback(() => {
    const state = useProjects.getState();
    const currentProject = state.projects.find((entry) => entry.id === projectId) ?? null;
    const findingsSummary = (currentProject?.findings || [])
      .filter((finding) => finding.status !== 'false_positive')
      .slice(0, 10)
      .map((finding) => `[${finding.severity}] ${finding.title}`)
      .join('; ');

    const contextRaw = [
      ...agentsRef.current.map((agent) => `${agent.name}:${agent.state}:${agent.currentTask ?? ''}`),
      findingsSummary ? `Findings: ${findingsSummary}` : 'No confirmed findings yet.',
    ].join(' | ');

    return contextRaw.length > 11500
      ? contextRaw.slice(0, 11500) + '... [truncated for length]'
      : contextRaw;
  }, [projectId]);

  const fetchContextMetrics = useCallback(async (
    promptText = '',
    options?: { updateState?: boolean; savedContextOverride?: string },
  ): Promise<AIAssistContextMetrics> => {
    const updateState = options?.updateState !== false;
    const latestProject = useProjects.getState().projects.find((entry) => entry.id === projectId) ?? null;
    const fallbackSavedContext = options?.savedContextOverride || latestProject?.copilotContext;
    const fallbackDisplayTokens = estimateSavedContextTokens(fallbackSavedContext);
    const fallbackTokens = fallbackDisplayTokens + estimateTokens(promptText);
    const fallback: AIAssistContextMetrics = {
      display_tokens: fallbackDisplayTokens,
      effective_tokens: fallbackTokens,
      limit_tokens: HISTORY_TOKEN_LIMIT,
      threshold_tokens: Math.floor(HISTORY_TOKEN_LIMIT * 0.95),
      should_compress_before_send: fallbackTokens > Math.floor(HISTORY_TOKEN_LIMIT * 0.95),
      operator_mode: 'Ask',
      execution_lane: 'lightweight',
      response_style: 'natural',
      has_working_memory: Boolean(String(fallbackSavedContext || '').trim()),
      uses_recent_history_fallback: false,
    };

    try {
      const metrics = await getAIAssistContextMetricsFromDesktop({
        projectId,
        target,
        targetType,
        context: buildLiveContext(),
        prompt: promptText,
        savedContextOverride: options?.savedContextOverride,
      });
      if (updateState) {
        setContextMetrics(metrics);
      }
      return metrics;
    } catch {
      if (updateState) {
        setContextMetrics(fallback);
      }
      return fallback;
    }
  }, [buildLiveContext, projectId, target, targetType]);

  const scrollToBottom = useCallback((instant = false) => {
    setShowScrollButton(false);
    if (messagesEndRef.current) {
      messagesEndRef.current.scrollIntoView({
        behavior: instant ? 'auto' : 'smooth',
        block: 'end',
      });
    } else if (scrollContainerRef.current) {
      // Fallback
      scrollContainerRef.current.scrollTop = scrollContainerRef.current.scrollHeight;
    }
  }, []);

  // Sync state when project/target changes (reset or load new history)
  useEffect(() => {
    setHistorySuppressed(false);
    activeAbortControllerRef.current?.abort();
    activeAbortControllerRef.current = null;
    activeRequestIdRef.current = null;
    setSending(false);
    // Use a fresh read of storage and a fresh merge of the history prop
    setMessages(mergeMessages(history, readStoredMessages(storageKey), introMessage));
    setPrompt('');
  }, [projectId, target, targetType, storageKey]); // Removed 'history' from deps to prevent re-sync on every turn

  useEffect(() => {
    let cancelled = false;
    void (async () => {
      try {
        const activeRuns = await getActiveProjectRunsFromDesktop(projectId);
        if (cancelled) {
          return;
        }
        const matchingRun = activeRuns.runs.find((run) => {
          if (run.task_type !== 'assistant') {
            return false;
          }
          if (run.status !== 'pending' && run.status !== 'running') {
            return false;
          }
          const payloadTarget = typeof run.payload.target === 'string' ? run.payload.target : '';
          const payloadTargetType = typeof run.payload.target_type === 'string' ? run.payload.target_type : '';
          return payloadTarget === target && payloadTargetType === targetType;
        });
        if (!matchingRun) {
          return;
        }
        const toolLogs = Array.isArray(matchingRun.payload.toolLogs)
          ? matchingRun.payload.toolLogs as PanelMessage['toolLogs']
          : [];
        const passwordRequests = Array.isArray((matchingRun.payload as { password_requests?: unknown }).password_requests)
          ? (matchingRun.payload as { password_requests: PanelMessage['passwordRequests'] }).password_requests
          : [];
        if (!isAssistantRunResumable({
          status: matchingRun.status,
          reply: typeof matchingRun.payload.reply === 'string' ? matchingRun.payload.reply : '',
          toolLogs,
          passwordRequests,
        })) {
          return;
        }
        setLoadingStep(
          (toolLogs ?? []).some((log) => log.status === 'running')
            ? 'working'
            : 'thinking',
        );
        setSending(true);
        setMessages((prev) => mergeActiveAssistantRun(prev, matchingRun));
      } catch {
        // Ignore resume lookup failures; local state/history still works.
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [projectId, target, targetType]);

  useEffect(() => {
    if (historySuppressed) {
      return;
    }
    setMessages((prev) => mergeMessages(history, prev, introMessage));
  }, [history, historySuppressed, introMessage]);

  useEffect(() => {
    const previousStatus = previousProjectStatusRef.current;
    const previousHadScanState = previousHasScanStateRef.current;
    previousProjectStatusRef.current = projectStatus;
    previousHasScanStateRef.current = hasScanState;

    const resetDetected = (
      (previousStatus && previousStatus !== 'idle' && projectStatus === 'idle')
      || (previousHadScanState && !hasScanState)
    );
    if (!resetDetected) {
      return;
    }
    if ((history?.length ?? 0) > 0) {
      return;
    }
    if (String(savedContext || '').trim()) {
      return;
    }

    activeAbortControllerRef.current?.abort();
    activeAbortControllerRef.current = null;
    activeRequestIdRef.current = null;
    cancelledRequestIdsRef.current.clear();
    setSending(false);
    setHistorySuppressed(true);
    setShowScrollButton(false);
    writeStoredMessages(storageKey, []);
    setMessages([{ ...introMessage }]);
    setPrompt('');
  }, [hasScanState, history, introMessage, projectStatus, savedContext, storageKey]);

  useEffect(() => {
    return () => {
      activeAbortControllerRef.current?.abort();
      activeAbortControllerRef.current = null;
      activeRequestIdRef.current = null;
    };
  }, []);

  // Handle history suppression (clearing)
  useEffect(() => {
    if (historySuppressed) {
      setMessages([{ ...introMessage }]);
    }
  }, [historySuppressed, introMessage]);

  useEffect(() => {
    if (!injectedPrompt?.token || !injectedPrompt.text.trim()) {
      return;
    }
    setPrompt(injectedPrompt.text);
  }, [injectedPrompt]);

  useEffect(() => {
    if (assistantDraftPrompt) {
      setPrompt(assistantDraftPrompt);
      updateConfig({ assistantDraftPrompt: undefined });
    }
  }, [assistantDraftPrompt, updateConfig]);

  useEffect(() => {
    void fetchContextMetrics();
  }, [fetchContextMetrics, projectId, target, targetType]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      void fetchContextMetrics();
    }, 60_000);
    return () => {
      window.clearInterval(intervalId);
    };
  }, [fetchContextMetrics, projectId, target, targetType]);

  // Persist to sessionStorage
  useEffect(() => {
    writeStoredMessages(storageKey, messages);
  }, [messages, storageKey]);

  // Auto-scroll to bottom on messages change
  useEffect(() => {
    const lastMessage = messages[messages.length - 1];
    const isUserMessage = lastMessage?.role === 'user';

    // Only auto-scroll if it's a user message OR if we're already at the bottom
    if (isUserMessage || userIsAtBottomRef.current) {
      const timer = setTimeout(() => {
        scrollToBottom();
      }, 100);
      return () => clearTimeout(timer);
    } else {
      // Manually trigger scroll check to update button visibility
      handleScroll();
    }
  }, [messages, scrollToBottom, handleScroll]);

  // Initial scroll on mount
  useEffect(() => {
    const timer = setTimeout(() => {
      scrollToBottom(true);
    }, 300);
    return () => clearTimeout(timer);
  }, [scrollToBottom]);

  const hasConversationStarted = messages.some((m) => m.role === 'user');

  const runningAgent = useMemo(
    () => agents.find((a) => a.state === 'running'),
    [agents],
  );

  const buildFallbackReply = useCallback(() => {
    if (runningAgent) {
      return `Active agent: ${runningAgent.name}. Task: ${runningAgent.currentTask ?? 'in progress'}.`;
    }
    return 'No agent is actively running. You can start a scan from the dashboard header.';
  }, [runningAgent]);

  const attachToRequest = useCallback(async (requestId: string, promptText: string) => {
    if (!requestId) {
      return;
    }

    if (activeRequestIdRef.current === requestId) {
      return;
    }

    setSending(true);
    activeRequestIdRef.current = requestId;
    cancelledRequestIdsRef.current.delete(requestId);
    const abortController = new AbortController();
    activeAbortControllerRef.current = abortController;

    try {
      const context = buildLiveContext();

      await askAIAssistStreamFromDesktop(
        {
          prompt: promptText,
          projectId,
          target,
          targetType,
          context,
          requestId,
        },
        (event) => {
          if (cancelledRequestIdsRef.current.has(requestId)) {
            return;
          }

          if (event.type === 'history_compressed') {
            // We no longer truncate UI history when the backend compresses.
            // The background summary is handled by the 'context' event.
            return;
          }
          setMessages((prev) =>
            prev.map((m) => {
              if (m.requestId !== requestId || m.role !== 'assistant') return m;

              if (event.type === 'run' || event.type === 'keepalive') {
                return m;
              }

              if (event.type === 'tool_start') {
                const existingLogs = Array.isArray(m.toolLogs) ? m.toolLogs : [];
                const alreadyExists = existingLogs.some((log) => log.id === event.data.call_id);
                if (alreadyExists) {
                  return m;
                }
                return {
                  ...m,
                  toolLogs: [
                    ...existingLogs,
                    {
                      id: event.data.call_id,
                      tool: event.data.tool,
                      input: event.data.input,
                      status: 'running',
                    },
                  ],
                };
              }

              if (event.type === 'tool_output') {
                if (event.data.tool === 'mark_false_positive' && event.data.output?.success) {
                  const matchedId = typeof event.data.output.matched_finding_id === 'string'
                    ? event.data.output.matched_finding_id
                    : '';
                  const matchedTitle = typeof event.data.output.matched_finding_title === 'string'
                    ? event.data.output.matched_finding_title
                    : '';
                  const requestedReference = typeof event.data.output.finding_id === 'string'
                    ? event.data.output.finding_id
                    : '';
                  const projectState = useProjects.getState();
                  const activeProject = projectState.projects.find((project) => project.id === projectId);
                  if (activeProject && Array.isArray(activeProject.findings)) {
                    let changed = false;
                    const nextFindings: Finding[] = activeProject.findings.map((finding) => {
                      if (!findingMatchesFalsePositiveResult(
                        finding,
                        matchedId,
                        matchedTitle,
                        requestedReference,
                      )) {
                        return finding;
                      }
                      changed = true;
                      return {
                        ...finding,
                        status: 'false_positive' as const,
                      };
                    });
                    if (changed) {
                      projectState.updateProject(projectId, { findings: nextFindings }, { persist: false });
                    }
                  }
                }

                const existingLogs = Array.isArray(m.toolLogs) ? m.toolLogs : [];
                const hasExisting = existingLogs.some((log) => log.id === event.data.call_id);
                return {
                  ...m,
                  toolLogs: hasExisting
                    ? existingLogs.map((log) =>
                      log.id === event.data.call_id
                        ? { ...log, output: event.data.output, status: 'done' }
                        : log,
                    )
                    : [
                      ...existingLogs,
                      {
                        id: event.data.call_id,
                        tool: event.data.tool,
                        input: '',
                        output: event.data.output,
                        status: 'done',
                      },
                    ],
                };
              }

              if (event.type === 'context') {
                updateProject(projectId, { copilotContext: event.data.next_context }, { persist: false });
                void (async () => {
                  await updateProjectSavedContextFromDesktop(projectId, event.data.next_context);
                  await fetchContextMetrics('', { savedContextOverride: event.data.next_context });
                })();
                return m;
              }

              if (event.type === 'ping') {
                const step = event.data.step;
                if (step === 'generating_final_reply') {
                  setLoadingStep('working');
                } else if (step === 'compressing_history' || step === 'optimizing_context') {
                  // Inject a transient notification for history compression
                  setMessages((prev) => {
                    const now = Date.now();
                    const alreadyNotified = prev.some(m => {
                      if (!m.isCompressionSeparator || !m.timestamp) return false;
                      const ts = new Date(m.timestamp).getTime();
                      return !isNaN(ts) && (now - ts < 10000);
                    });
                    if (alreadyNotified) return prev;
                    const separator: PanelMessage = {
                      id: `opt-${now}`,
                      role: 'assistant',
                      text: 'Automatically compacting context',
                      isCompressionSeparator: true,
                      timestamp: new Date().toISOString(),
                    };
                    return [...prev, separator].slice(-MAX_CHAT_MESSAGES);
                  });
                }
                return m;
              }

              if (event.type === 'reply') {
                setSending(false);
                return {
                  ...m,
                  text: event.data.text,
                  route: event.data.route || 'assistant',
                  blocked: event.data.blocked ?? false,
                  localState: undefined,
                };
              }

              if (event.type === 'error') {
                if (String(event.data.detail || '').toLowerCase().includes('cancelled')) {
                  return {
                    ...m,
                    text: m.text.trim() || 'Echo response stopped.',
                    localState: 'cancelled',
                  };
                }
                setSending(false);
                return {
                  ...m,
                  text: buildErrorReply(new Error(event.data.detail), buildFallbackReply()),
                  localState: 'error',
                };
              }

              if (event.type === 'password_request') {
                const existing = Array.isArray(m.passwordRequests) ? m.passwordRequests : [];
                return {
                  ...m,
                  passwordRequests: [
                    ...existing,
                    {
                      call_id: event.data.call_id,
                      prompt: event.data.prompt,
                      reason: event.data.reason,
                      status: 'pending' as const,
                    },
                  ],
                };
              }

              return m;
            }),
          );
        },
        { signal: abortController.signal },
      );
    } catch (error) {
      if (cancelledRequestIdsRef.current.has(requestId)) {
        return;
      }
      if (abortController.signal.aborted) {
        return;
      }
      const aiMessage: PanelMessage = {
        id: `a-${requestId}`,
        requestId,
        role: 'assistant',
        text: buildErrorReply(error, buildFallbackReply()),
        localState: 'error',
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) =>
        prev.map((m) =>
          m.requestId === requestId && m.role === 'assistant' ? aiMessage : m,
        ),
      );
    } finally {
      if (activeRequestIdRef.current === requestId) {
        activeRequestIdRef.current = null;
      }
      if (activeAbortControllerRef.current === abortController) {
        activeAbortControllerRef.current = null;
      }
      if (abortController.signal.aborted && !cancelledRequestIdsRef.current.has(requestId)) {
        return;
      }
      setSending(false);
      setMessages((prev) =>
        prev.map((m) => {
          if (m.requestId === requestId && m.role === 'assistant' && m.localState === 'pending') {
            if (cancelledRequestIdsRef.current.has(requestId)) {
              return {
                ...m,
                localState: 'cancelled',
                text: m.text.trim() || 'Echo response stopped.',
              };
            }
            return {
              ...m,
              localState: 'error',
              text: 'Echo disconnected before finishing. Try sending your prompt again.',
            };
          }
          return m;
        }),
      );
      cancelledRequestIdsRef.current.delete(requestId);
    }
  }, [buildFallbackReply, buildLiveContext, fetchContextMetrics, projectId, target, targetType, updateProject]);

  const handleClear = useCallback(async () => {
    activeAbortControllerRef.current?.abort();
    activeAbortControllerRef.current = null;
    activeRequestIdRef.current = null;
    setClearing(true);
    try {
      await clearAIAssistConversationFromDesktop({
        projectId,
        target,
        targetType,
      });
    } catch {
      // Keep local reset behavior even if backend cleanup fails.
    } finally {
      setHistorySuppressed(true);
      setShowScrollButton(false);
      updateProject(projectId, { copilotContext: '' }, { persist: false });
      setContextMetrics({
        display_tokens: 0,
        effective_tokens: 0,
        limit_tokens: HISTORY_TOKEN_LIMIT,
        threshold_tokens: Math.floor(HISTORY_TOKEN_LIMIT * 0.95),
        should_compress_before_send: false,
        operator_mode: 'Ask',
        execution_lane: 'lightweight',
        response_style: 'natural',
        has_working_memory: false,
        uses_recent_history_fallback: false,
      });
      writeStoredMessages(storageKey, []);
      setMessages([{ ...introMessage }]);
      setPrompt('');
      setClearing(false);
    }
  }, [introMessage, projectId, storageKey, target, targetType, updateProject]);

  const handleCancelSend = useCallback(() => {
    const requestId = activeRequestIdRef.current;
    if (!requestId) {
      return;
    }

    cancelledRequestIdsRef.current.add(requestId);
    activeAbortControllerRef.current?.abort();
    activeAbortControllerRef.current = null;
    activeRequestIdRef.current = null;
    setSending(false);
    void cancelAIAssistRunFromDesktop(requestId).catch(() => {
      // Best effort; local cancellation UX still applies.
    });

    setMessages((prev) =>
      prev.map((message) => {
        if (message.requestId !== requestId || message.role !== 'assistant') {
          return message;
        }
        return {
          ...message,
          text: message.text.trim() || 'Echo response stopped.',
          localState: 'cancelled',
        };
      }),
    );
  }, []);

  const sendPrompt = useCallback(async (text: string) => {
    const clean = text.trim();
    if (!clean || sending || clearing) return;

    const workingContext = String(project?.copilotContext || '').trim();
    const metrics = await fetchContextMetrics(clean, { updateState: false });
    const needsBootstrapCompression = (
      !workingContext
      && estimateMessagesTokens(messages) > (metrics.threshold_tokens || (HISTORY_TOKEN_LIMIT * 0.95))
    );

    // Keep the backend working memory under budget before the next agent turn starts.
    if (metrics.should_compress_before_send || needsBootstrapCompression) {
      setSending(true);
      const optimizationId = `opt-${Date.now()}`;

      // Inject optimization notification (transient, won't be truncated).
      setMessages(prev => [...prev, {
        id: optimizationId,
        role: 'assistant',
        text: 'Automatically compacting context',
        isCompressionSeparator: true,
        timestamp: new Date().toISOString()
      }]);

      try {
        let nextContext = workingContext;
        if (workingContext) {
          nextContext = await compressAIAssistWorkingContext(workingContext);
        } else {
          const summary = await compressAIAssistHistory(messages);
          nextContext = JSON.stringify({ rolling_summary: summary });
        }

        updateProject(projectId, { copilotContext: nextContext }, { persist: false });
        await updateProjectSavedContextFromDesktop(projectId, nextContext);
        await fetchContextMetrics('', { savedContextOverride: nextContext });
      } catch (err) {
        console.error('History optimization failed:', err);
      }
    }

    const requestId = `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;

    const userMessage: PanelMessage = {
      id: `u-${requestId}`,
      role: 'user',
      text: clean,
      timestamp: new Date().toISOString(),
    };

    const assistantMessage: PanelMessage = {
      id: `a-${requestId}`,
      requestId,
      role: 'assistant',
      text: '',
      localState: 'pending',
      timestamp: new Date().toISOString(),
      toolLogs: [],
    };

    setMessages((prev) => [...prev, userMessage, assistantMessage].slice(-MAX_CHAT_MESSAGES));
    setPrompt('');
    void attachToRequest(requestId, clean);
  }, [attachToRequest, clearing, sending, fetchContextMetrics, messages, project?.copilotContext, projectId, updateProject]);

  useEffect(() => {
    const pendingMessage = findPendingAssistantMessage(messages);
    if (!pendingMessage?.requestId) {
      return;
    }
    if (activeRequestIdRef.current === pendingMessage.requestId) {
      return;
    }
    const promptText = messages.find((message) => message.id === `u-${pendingMessage.requestId}`)?.text ?? '';

    if (!promptText) {
      // If the user message was dropped during history merge, orphan this pending message
      setMessages((prev) => prev.map(m => m.id === pendingMessage.id ? { ...m, localState: 'error', text: 'Echo disconnected and request context was lost.' } : m));
      return;
    }

    setLoadingStep(
      Array.isArray(pendingMessage.toolLogs) && pendingMessage.toolLogs.some((log) => log.status === 'running')
        ? 'working'
        : 'thinking',
    );
    void attachToRequest(pendingMessage.requestId, promptText);
  }, [attachToRequest, messages]);

  const displayedContextTokens = Math.min(
    contextMetrics.limit_tokens || HISTORY_TOKEN_LIMIT,
    contextMetrics.display_tokens,
  );

  return (
    <Card className="relative flex h-full border-0 rounded-none shadow-none flex-col">
      {/* ── Header ── */}
      <CardHeader className="mb-2 flex-row items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full bg-green-500" title="Echo online" />
          <div>
            <CardTitle>Echo</CardTitle>
            <p className="text-[11px] text-text-muted">AI assistant · {target}</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Sparkles size={13} className="text-pf-400" />
          <ClearButton onConfirm={() => { void handleClear(); }} disabled={sending || clearing} />
          {onClose && (
            <Button
              size="icon"
              variant="ghost"
              onClick={onClose}
              title="Close panel"
              className="h-8 w-8 text-text-muted hover:text-text-primary"
            >
              <X size={16} />
            </Button>
          )}
        </div>
      </CardHeader>

      {/* ── Message list ── */}
      <div
        ref={scrollContainerRef}
        className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto overflow-x-hidden p-4 scrollbar-pf"
      >
        {messages.length >= MAX_CHAT_MESSAGES && (
          <div className="flex items-center justify-center py-2">
            <div className="flex items-center gap-2 rounded-full border border-border bg-surface-1/50 px-3 py-1 text-[10px] text-text-muted">
              <Clock3 size={10} />
              <span>Conversation history compressed (max context reached)</span>
            </div>
          </div>
        )}

        {messages.map((message) => {
          if (message.isCompressionSummary) return null;
          if (message.isCompressionSeparator) {
            return (
              <div key={message.id} className="my-6 flex items-center justify-center px-4">
                <div className="flex w-full max-w-[92%] items-center gap-4">
                  <div className="h-px flex-1 bg-border/40" />
                  <span className="text-[11px] font-medium text-text-muted/65">
                    {message.text || 'Automatically compacting context'}
                  </span>
                  <div className="h-px flex-1 bg-border/40" />
                </div>
              </div>
            );
          }
          return (
            <div key={message.id} className={message.role === 'user' ? 'flex justify-end' : ''}>
              <div
                className={
                  message.role === 'assistant'
                    ? `max-w-[92%] rounded-md border p-2 text-sm ${message.localState === 'error'
                      ? 'border-orange-500/30 bg-orange-500/10 text-orange-900 dark:text-orange-200'
                      : message.localState === 'cancelled'
                        ? 'border-border bg-surface-1/70 text-text-secondary'
                        : 'border-pf-500/20 bg-pf-500/10 text-text-primary'
                    }`
                    : 'max-w-[92%] rounded-md border border-border bg-surface-2 p-2 text-sm text-text-primary'
                }
              >
                {/* Assistant label */}
                {message.role === 'assistant' && (
                  <div className="mb-1 flex items-center gap-1 text-xs font-semibold text-pf-400">
                    <Bot size={11} />
                    Echo
                  </div>
                )}

                {/* Content */}
                <div className="flex flex-col gap-2">
                  {/* Tool Logs */}
                  {message.toolLogs && message.toolLogs.length > 0 && (
                    <div className="flex flex-col gap-1.5 border-l-2 border-pf-500/30 pl-2 my-1">
                      {message.toolLogs.map((log, idx) => (
                        <div key={idx} className="text-[11px] leading-tight">
                          <div className="flex items-center gap-1.5 text-text-muted">
                            <span className={`h-1.5 w-1.5 rounded-full ${log.status === 'running' ? 'bg-orange-500 animate-pulse' : 'bg-green-500/50'}`} />
                            {(() => {
                              const t = (log.tool || '').toLowerCase().trim();
                              if (t === 'search_project_vectors') return <span className="opacity-80">Searching findings</span>;
                              if (t === 'get_page') return <span className="opacity-80">Fetching page</span>;
                              if (t === 'mark_false_positive') return <span className="opacity-80">Marking false positive</span>;
                              if (t === 'memory' || t === 'context') return <span className="opacity-80">Updating memory</span>;
                              if (t === 'run_custom' || !t) return null;
                              return <span className="font-mono opacity-80">[{log.tool}]</span>;
                            })()}
                            <div className={`break-all min-w-0 flex-1 ${log.tool === 'run_custom' ? 'font-mono text-[11px] text-zinc-600 font-medium' : 'text-[10px] italic opacity-80'}`}>
                              {log.tool === 'run_custom' ? log.input : `"${log.input}"`}
                            </div>
                          </div>
                          {log.output && log.output.error && (
                            <div className="mt-0.5 text-red-500 opacity-90 pl-3">
                              Error: {log.output.error}
                            </div>
                          )}
                          {log.output && log.output.success && log.tool === 'run_custom' && (
                            <div className="mt-0.5 text-[10px] text-text-muted/80 pl-3 line-clamp-2 font-mono">
                              {log.output.stdout || 'Command completed.'}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Password Requests */}
                  {message.passwordRequests && message.passwordRequests.length > 0 && (
                    <div className="flex flex-col gap-3 my-2">
                      {message.passwordRequests.map((req) => (
                        <PasswordRequestBlock
                          key={req.call_id}
                          requestId={message.requestId || ''}
                          request={req}
                          onResponse={(callId, val, denied) => {
                            setMessages((prev) =>
                              prev.map((m) => {
                                if (m.requestId === message.requestId && m.passwordRequests) {
                                  return {
                                    ...m,
                                    passwordRequests: m.passwordRequests.map((r) =>
                                      r.call_id === callId
                                        ? { ...r, status: denied ? ('denied' as const) : ('submitted' as const) }
                                        : r
                                    ),
                                  };
                                }
                                return m;
                              })
                            );
                          }}
                        />
                      ))}
                    </div>
                  )}

                  {message.localState === 'pending' ? (
                    <div className="flex items-center gap-2 py-1">
                      <div className="flex items-center gap-1.5">
                        <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-pf-400 [animation-delay:-0.2s]" />
                        <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-pf-400 [animation-delay:-0.1s]" />
                        <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-pf-400" />
                      </div>
                      <span className="text-[11px] font-medium text-text-muted italic animate-pulse">
                        {message.toolLogs?.some(l => l.status === 'running')
                          ? `Echo is running ${message.toolLogs.find(l => l.status === 'running')?.tool === 'run_custom' ? 'command' : 'tool'}...`
                          : (loadingStep === 'thinking' ? 'Echo is thinking...' : 'Echo is working...')}
                      </span>
                    </div>
                  ) : (
                    <div className="space-y-1">
                      <div className="whitespace-pre-wrap break-words text-sm leading-relaxed">
                        {renderMarkdownMessage(message.text)}
                      </div>
                      {isSuccessfulReportReply(message) && (
                        <div className="pt-1">
                          <Button
                            size="xs"
                            variant="outline"
                            onClick={handleOpenReportsShare}
                            className="font-semibold"
                          >
                            <FileText size={12} />
                            Open Reports & Share
                          </Button>
                        </div>
                      )}
                      {message.localState === 'cancelled' && (
                        <p className="text-[10px] uppercase tracking-wide text-text-muted">
                          Stopped
                        </p>
                      )}
                    </div>
                  )}
                </div>

                {/* Footer: timestamp + copy */}
                <div className="mt-1 flex items-center justify-between">
                  {message.timestamp && (
                    <span className="text-[10px] text-text-muted">
                      {formatTime(message.timestamp)}
                    </span>
                  )}
                  {message.role === 'assistant' && !message.localState && message.text && (
                    <CopyButton text={message.text} />
                  )}
                </div>
              </div>
            </div>
          )
        })}
        <div ref={messagesEndRef} className="h-0" />
      </div>

      {/* Floating Scroll to Bottom Button */}
      {showScrollButton && (
        <button
          onClick={() => scrollToBottom()}
          className="absolute bottom-24 right-8 z-50 flex h-10 w-10 items-center justify-center rounded-full border border-pf-500/30 bg-surface-2 text-pf-500 shadow-2xl transition-all hover:bg-surface-3 hover:scale-110 active:scale-95 animate-in fade-in slide-in-from-bottom-2 duration-300"
          title="Scroll to bottom"
        >
          <ChevronDown size={22} />
        </button>
      )}
      {/* ── Input row ── */}
      <div className="mt-auto p-4">
        <div className="relative flex flex-col gap-2 rounded-xl border border-border bg-surface-1/80 p-2 shadow-sm transition-all focus-within:border-pf-500/50 focus-within:ring-1 focus-within:ring-pf-500/20">
          <AutoTextarea
            value={prompt}
            onChange={setPrompt}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                if (prompt.trim() && prompt.length <= MAX_PROMPT_CHARS) {
                  void sendPrompt(prompt);
                }
              }
            }}
            placeholder="Ask Echo for strategy, scope checks, or next step…"
            disabled={sending || clearing}
            className="!ring-0 border-0"
            maxLength={MAX_PROMPT_CHARS}
          />


          <div className="flex items-center justify-between px-2 pb-1 relative">
            <div className="flex items-center gap-3 ">
              <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                <Sparkles size={12} className="text-pf-400" />
                <span>Echo 3.5</span>
                <TokenUsageCircle
                  currentTokens={displayedContextTokens}
                  limitTokens={contextMetrics.limit_tokens || HISTORY_TOKEN_LIMIT}
                />
              </div>
              <div className=" absolute top-4 right-14  pointer-events-none">
                <span className={`text-[9px] font-mono ${prompt.length >= MAX_PROMPT_CHARS ? 'text-red-500 font-bold' : 'text-text-muted/30'}`}>
                  {prompt.length}/{MAX_PROMPT_CHARS}
                </span>
              </div>
            </div>

            <Button
              type="button"
              onClick={() => {
                if (sending) {
                  handleCancelSend();
                  return;
                }
                void sendPrompt(prompt);
              }}
              disabled={clearing || (!sending && !prompt.trim())}
              size="icon"
              variant={sending ? 'danger' : 'primary'}
              className="h-8 w-8 rounded-full shadow-md"
              title={sending ? 'Stop response' : 'Send message'}
            >
              {sending ? <Square size={12} /> : <SendHorizontal size={14} />}
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}
