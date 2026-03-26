import { Moon, Sun, Minus, Square, X } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { getCurrentWindow } from '@tauri-apps/api/window';

import { useTheme } from '../../stores/theme';

export function Titlebar() {
  const { isDark, toggle } = useTheme();
  const location = useLocation();
  const normalizedPath = location.pathname.replace(/\/+$/, '') || '/';
  const routeLabel = `pentaforge${normalizedPath}`;
  const appWindow = getCurrentWindow();

  const handleMinimize = async () => {
    try {
      await appWindow.minimize();
    } catch {
      // no-op outside Tauri runtime
    }
  };

  const handleToggleMaximize = async () => {
    try {
      const isMaximized = await appWindow.isMaximized();
      if (isMaximized) {
        await appWindow.unmaximize();
      } else {
        await appWindow.maximize();
      }
    } catch {
      // no-op outside Tauri runtime
    }
  };

  const handleClose = async () => {
    try {
      await appWindow.close();
    } catch {
      // no-op outside Tauri runtime
    }
  };

  return (
    <div className="h-11 flex items-center justify-between px-3 bg-surface-1 border-b border-border select-none">
      {/* App name */}
      <div className="flex min-w-0 items-center gap-2 flex-1" data-tauri-drag-region>
        <div className="h-3 w-3 rounded-sm bg-pf-600" />
        <div className="min-w-0 leading-tight">
          <div className="text-xs font-semibold tracking-wide text-text-primary">PENTAFORGE</div>
          <div className="truncate font-mono text-[10px] text-text-muted">{routeLabel}</div>
        </div>
      </div>

      {/* Controls */}
      <div className="flex items-center gap-0.5">
        <button onClick={toggle} className="p-1.5 rounded hover:bg-surface-2 text-text-muted">
          {isDark ? <Sun size={13} /> : <Moon size={13} />}
        </button>
        <button onClick={handleMinimize} className="p-1.5 rounded hover:bg-surface-2 text-text-muted">
          <Minus size={13} />
        </button>
        <button onClick={handleToggleMaximize} className="p-1.5 rounded hover:bg-surface-2 text-text-muted">
          <Square size={11} />
        </button>
        <button onClick={handleClose} className="p-1.5 rounded hover:bg-red-500/20 text-text-muted hover:text-red-400">
          <X size={13} />
        </button>
      </div>
    </div>
  );
}
