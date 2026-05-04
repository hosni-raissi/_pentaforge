import { useEffect, useMemo, useRef, useState, useCallback } from 'react';
import { Bot, SendHorizontal, Sparkles, Trash2, Copy, Check, X, Clock3 } from 'lucide-react';

import {
  askAIAssistFromDesktop,
  clearAIAssistConversationFromDesktop,
} from '@/lib/projectBridge';
import type { CopilotMessage } from '@/types';
import type { AgentInfo } from '../../types';
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
  localState?: 'pending' | 'error';
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

function messageSignature(message: CopilotMessage): string {
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
  const seed: PanelMessage[] = (
    baseHistory && baseHistory.length > 0
      ? baseHistory.map((m) => ({ ...m }))
      : [{ ...introMessage }]
  );
  const seen = new Set(seed.map(messageSignature));
  const merged = [...seed];

  for (const message of localMessages) {
    if (!message.text.trim() && message.localState !== 'pending') continue;
    if (message.localState === 'pending') {
      merged.push({ ...message });
      continue;
    }
    const sig = messageSignature(message);
    if (seen.has(sig)) continue;
    seen.add(sig);
    merged.push({ ...message });
  }

  return merged.slice(-MAX_CHAT_MESSAGES);
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
      timestamp: new Date().toISOString(),
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

  const scrollContainerRef = useRef<HTMLDivElement | null>(null);

  // Reset suppression when the chat scope changes.
  useEffect(() => {
    setHistorySuppressed(false);
    setMessages(mergeMessages(history, readStoredMessages(storageKey), introMessage));
  }, [introMessage, storageKey]);

  useEffect(() => {
    if (historySuppressed) {
      setMessages((prev) => mergeMessages(undefined, prev, introMessage));
      return;
    }
    setMessages((prev) => mergeMessages(history, prev, introMessage));
  }, [history, historySuppressed, introMessage]);

  // Persist to sessionStorage
  useEffect(() => {
    writeStoredMessages(storageKey, messages);
  }, [messages, storageKey]);

  // Auto-scroll to bottom
  useEffect(() => {
    const el = scrollContainerRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [messages]);

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

  const handleClear = useCallback(async () => {
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

    const thinkingMessage: PanelMessage = {
      id: `a-${requestId}`,
      requestId,
      role: 'assistant',
      text: '',
      localState: 'pending',
      timestamp: new Date().toISOString(),
    };

    setMessages((prev) => [...prev, userMessage, thinkingMessage].slice(-MAX_CHAT_MESSAGES));
    setPrompt('');
    setSending(true);

    try {
      const context = agents
        .map((a) => `${a.name}:${a.state}:${a.currentTask ?? ''}`)
        .join(' | ');

      const response = await askAIAssistFromDesktop({
        prompt: clean,
        projectId,
        target,
        targetType,
        context,
      });

      const aiMessage: PanelMessage = {
        id: `a-${requestId}`,
        requestId,
        role: 'assistant',
        text: response.reply.trim() || 'Echo returned an empty reply.',
        route: response.route,
        blocked: response.blocked,
        timestamp: new Date().toISOString(),
      };

      setMessages((prev) =>
        prev.map((m) =>
          m.requestId === requestId && m.role === 'assistant' ? aiMessage : m,
        ),
      );
    } catch (error) {
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
      setSending(false);
    }
  }, [sending, clearing, agents, projectId, target, targetType, buildFallbackReply]);

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
                        ? 'border-amber-500/30 bg-amber-500/10 text-amber-900 dark:text-amber-200'
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
              {message.localState === 'pending' ? (
                <div className="flex items-center gap-2 py-1">
                  <div className="flex items-center gap-1.5">
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-pf-400 [animation-delay:-0.2s]" />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-pf-400 [animation-delay:-0.1s]" />
                    <span className="h-1.5 w-1.5 animate-bounce rounded-full bg-pf-400" />
                  </div>
                  <span className="text-[11px] font-medium text-text-muted italic animate-pulse">
                    {loadingStep === 'thinking' ? 'Echo is thinking...' : 'Echo is working...'}
                  </span>
                </div>
              ) : (
                <p className="whitespace-pre-wrap break-words text-sm leading-relaxed">
                  {message.text}
                </p>
              )}

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
              onClick={() => void sendPrompt(prompt)}
              disabled={sending || clearing || !prompt.trim()}
              loading={sending}
              size="icon"
              variant="primary"
              className="h-8 w-8 rounded-full shadow-md"
            >
              <SendHorizontal size={14} />
            </Button>
          </div>
        </div>
      </div>
    </Card>
  );
}
