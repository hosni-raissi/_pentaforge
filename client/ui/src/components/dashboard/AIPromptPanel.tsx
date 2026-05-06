import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { Bot, SendHorizontal, Sparkles, Trash2, Copy, Check, X, Clock3, Square } from 'lucide-react';

import {
  askAIAssistStreamFromDesktop,
  cancelAIAssistRunFromDesktop,
  clearAIAssistConversationFromDesktop,
  updateProjectSavedContextFromDesktop,
  sendAIAssistInputFromDesktop,
} from '@/lib/projectBridge';
import type { CopilotMessage } from '@/types';
import type { AgentInfo, Finding } from '../../types';
import { useProjects } from '../../stores/projects';
import { Button } from '../ui/Button';
import { Card, CardHeader, CardTitle } from '../ui/Card';

interface AIPromptPanelProps {
  projectId: string;
  projectName: string;
  target: string;
  targetType: string;
  agents: AgentInfo[];
  history?: CopilotMessage[];
  onClose?: () => void;
}

const CHAT_STORAGE_PREFIX = 'pf-assistant-chat';
const MAX_CHAT_MESSAGES = 80;

type PanelMessage = CopilotMessage & {
  localState?: 'pending' | 'error' | 'cancelled';
  requestId?: string;
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
  return [
    message.role,
    message.text.trim(),
    message.route ?? '',
    message.blocked ? '1' : '0',
  ].join('|');
}

function mergeMessages(
  baseHistory: CopilotMessage[] | undefined,
  localMessages: PanelMessage[],
  introMessage: CopilotMessage,
): PanelMessage[] {
  const merged: PanelMessage[] = [{ ...introMessage }];
  const historyDupes = new Map<string, number>();

  if (baseHistory) {
    for (const item of baseHistory) {
      const row = { ...item };
      merged.push(row);
      const key = messageSignature(row);
      historyDupes.set(key, (historyDupes.get(key) ?? 0) + 1);
    }
  }

  for (const item of localMessages) {
    if (item.id === 'intro') {
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

  return merged.slice(-MAX_CHAT_MESSAGES);
}

function findPendingAssistantMessage(messages: PanelMessage[]): PanelMessage | null {
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    const message = messages[index];
    if (message.role === 'assistant' && message.localState === 'pending' && message.requestId) {
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
}: {
  value: string;
  onChange: (v: string) => void;
  onKeyDown: (e: React.KeyboardEvent<HTMLTextAreaElement>) => void;
  placeholder: string;
  disabled: boolean;
  className?: string;
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
  agents,
  history,
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

  const [prompt, setPrompt] = useState('');
  const [sending, setSending] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [historySuppressed, setHistorySuppressed] = useState(false);
  const [loadingStep, setLoadingStep] = useState<'thinking' | 'working'>('thinking');

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

  const scrollContainerRef = useRef<HTMLDivElement | null>(null);
  const messagesEndRef = useRef<HTMLDivElement | null>(null);

  const scrollToBottom = useCallback((instant = false) => {
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
    if (historySuppressed) {
      return;
    }
    setMessages((prev) => mergeMessages(history, prev, introMessage));
  }, [history, historySuppressed, introMessage]);

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

  // Persist to sessionStorage
  useEffect(() => {
    writeStoredMessages(storageKey, messages);
  }, [messages, storageKey]);

  // Auto-scroll to bottom on messages change
  useEffect(() => {
    // Small delay to ensure DOM is updated and images/content are rendered
    const timer = setTimeout(() => {
      scrollToBottom();
    }, 100);
    return () => clearTimeout(timer);
  }, [messages, scrollToBottom]);

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
      const state = useProjects.getState();
      const currentProject = state.projects.find((p) => p.id === projectId);
      const findingsSummary = (currentProject?.findings || [])
        .filter((f) => f.status !== 'false_positive')
        .slice(0, 10)
        .map((f) => `[${f.severity}] ${f.title}`)
        .join('; ');

      const context = [
        ...agents.map((a) => `${a.name}:${a.state}:${a.currentTask ?? ''}`),
        findingsSummary ? `Findings: ${findingsSummary}` : 'No confirmed findings yet.',
      ].join(' | ');

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
                void updateProjectSavedContextFromDesktop(projectId, event.data.next_context);
                return m;
              }

              if (event.type === 'ping') {
                const step = event.data.step;
                if (step === 'generating_final_reply') {
                  setLoadingStep('working');
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
  }, [agents, buildFallbackReply, projectId, target, targetType]);

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
      writeStoredMessages(storageKey, []);
      setMessages([{ ...introMessage }]);
      setPrompt('');
      setClearing(false);
    }
  }, [introMessage, projectId, storageKey, target, targetType]);

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
  }, [attachToRequest, clearing, sending]);

  useEffect(() => {
    const pendingMessage = findPendingAssistantMessage(messages);
    if (!pendingMessage?.requestId) {
      return;
    }
    if (activeRequestIdRef.current === pendingMessage.requestId) {
      return;
    }
    const promptText = messages.find((message) => message.id === `u-${pendingMessage.requestId}`)?.text ?? '';
    setLoadingStep(
      Array.isArray(pendingMessage.toolLogs) && pendingMessage.toolLogs.some((log) => log.status === 'running')
        ? 'working'
        : 'thinking',
    );
    void attachToRequest(pendingMessage.requestId, promptText);
  }, [attachToRequest, messages]);

  return (
    <Card className="flex h-full border-0 rounded-none shadow-none flex-col">
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
        className="flex min-h-0 flex-1 flex-col gap-4 overflow-y-auto p-4 scrollbar-pf"
      >
        {messages.length >= MAX_CHAT_MESSAGES && (
          <div className="flex items-center justify-center py-2">
            <div className="flex items-center gap-2 rounded-full border border-border bg-surface-1/50 px-3 py-1 text-[10px] text-text-muted">
              <Clock3 size={10} />
              <span>Conversation history compressed (max context reached)</span>
            </div>
          </div>
        )}

        {messages.map((message) => (
          <div key={message.id} className={message.role === 'user' ? 'flex justify-end' : ''}>
            <div
              className={
                message.role === 'assistant'
                  ? `max-w-[92%] rounded-md border p-2 text-sm ${
                      message.localState === 'error'
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
                          <span className={`truncate max-w-[320px] ${log.tool === 'run_custom' ? 'font-mono text-[10px] bg-surface-2 px-1 rounded border border-border/50' : 'text-[10px] italic opacity-80'}`}>
                            {log.tool === 'run_custom' ? log.input : `"${log.input}"`}
                          </span>
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
                    <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
                      {message.text}
                    </p>
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
        ))}
        <div ref={messagesEndRef} className="h-0" />
      </div>


      {/* ── Input row ── */}
      <div className="mt-auto p-4">
        <div className="relative flex flex-col gap-2 rounded-xl border border-border bg-surface-1/80 p-2 shadow-sm transition-all focus-within:border-pf-500/50 focus-within:ring-1 focus-within:ring-pf-500/20">
          <AutoTextarea
            value={prompt}
            onChange={setPrompt}
            onKeyDown={(e) => {
              if (e.key === 'Enter' && !e.shiftKey) {
                e.preventDefault();
                void sendPrompt(prompt);
              }
            }}
            placeholder="Ask Echo for strategy, scope checks, or next step…"
            disabled={sending || clearing}
            className="!ring-0 border-0"
          />
          
          <div className="flex items-center justify-between px-2 pb-1">
            <div className="flex items-center gap-3">
               <div className="flex items-center gap-1.5 text-[11px] text-text-muted">
                 <Sparkles size={12} className="text-pf-400" />
                 <span>Echo 3.5</span>
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
