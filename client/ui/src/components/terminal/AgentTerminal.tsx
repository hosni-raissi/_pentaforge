import { useEffect, useRef, useCallback } from 'react';
import { Terminal } from 'xterm';
import { FitAddon } from 'xterm-addon-fit';
import { WebLinksAddon } from 'xterm-addon-web-links';
import { cn } from '../../lib/utils';
import 'xterm/css/xterm.css';

interface AgentTerminalProps {
  className?: string;
  onReady?: (terminal: Terminal) => void;
}

export function AgentTerminal({ className, onReady }: AgentTerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const terminalRef = useRef<Terminal | null>(null);
  const fitAddonRef = useRef<FitAddon | null>(null);

  const initTerminal = useCallback(() => {
    if (!containerRef.current || terminalRef.current) return;

    const isDark = document.documentElement.classList.contains('dark');

    const terminal = new Terminal({
      fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
      fontSize: 12,
      lineHeight: 1.4,
      cursorBlink: true,
      cursorStyle: 'bar',
      scrollback: 5000,
      allowTransparency: true,
      theme: isDark
        ? {
            background: '#0f1729',
            foreground: '#e2e8f0',
            cursor: '#3b82f6',
            selectionBackground: '#3b82f640',
            black: '#0f1729',
            red: '#ef4444',
            green: '#22c55e',
            yellow: '#eab308',
            blue: '#3b82f6',
            magenta: '#a855f7',
            cyan: '#06b6d4',
            white: '#e2e8f0',
          }
        : {
            background: '#f8fafc',
            foreground: '#0f172a',
            cursor: '#2563eb',
            selectionBackground: '#3b82f640',
            black: '#0f172a',
            red: '#dc2626',
            green: '#16a34a',
            yellow: '#ca8a04',
            blue: '#2563eb',
            magenta: '#9333ea',
            cyan: '#0891b2',
            white: '#f8fafc',
          },
    });

    const fitAddon = new FitAddon();
    const webLinksAddon = new WebLinksAddon();

    terminal.loadAddon(fitAddon);
    terminal.loadAddon(webLinksAddon);
    terminal.open(containerRef.current);
    fitAddon.fit();

    terminalRef.current = terminal;
    fitAddonRef.current = fitAddon;

    // Welcome message
    terminal.writeln('\x1b[34m╔══════════════════════════════════════╗\x1b[0m');
    terminal.writeln('\x1b[34m║\x1b[0m  \x1b[1;37mPentaForge Agent Terminal\x1b[0m          \x1b[34m║\x1b[0m');
    terminal.writeln('\x1b[34m╚══════════════════════════════════════╝\x1b[0m');
    terminal.writeln('');

    onReady?.(terminal);

    return () => {
      terminal.dispose();
      terminalRef.current = null;
    };
  }, [onReady]);

  useEffect(() => {
    const cleanup = initTerminal();
    return cleanup;
  }, [initTerminal]);

  // Handle resize
  useEffect(() => {
    const handleResize = () => fitAddonRef.current?.fit();
    const observer = new ResizeObserver(handleResize);
    if (containerRef.current) observer.observe(containerRef.current);
    return () => observer.disconnect();
  }, []);

  return (
    <div
      ref={containerRef}
      className={cn(
        'rounded-lg border border-border overflow-hidden',
        'bg-pf-900 dark:bg-pf-950',
        className
      )}
    />
  );
}

// Helper to write styled agent output
export function writeAgentLog(terminal: Terminal, agent: string, message: string, type: 'info' | 'success' | 'warn' | 'error' = 'info') {
  const colors = {
    info:    '\x1b[34m',   // blue
    success: '\x1b[32m',   // green
    warn:    '\x1b[33m',   // yellow
    error:   '\x1b[31m',   // red
  };
  const symbols = { info: '→', success: '✓', warn: '⚠', error: '✗' };
  const reset = '\x1b[0m';

  const time = new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' });
  terminal.writeln(
    `\x1b[90m${time}\x1b[0m ${colors[type]}${symbols[type]}${reset} \x1b[1m[${agent}]\x1b[0m ${message}`
  );
}