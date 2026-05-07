import { Moon, Sun, Minus, Square, X } from 'lucide-react';
import { useLocation } from 'react-router-dom';
import { getCurrentWindow } from '@tauri-apps/api/window';

import { routeLabelForPath } from '../../lib/productWorkflows';
import { useTheme } from '../../stores/theme';

export function Titlebar() {
  const { isDark, toggle } = useTheme();
  const location = useLocation();
  const routeLabel = routeLabelForPath(location.pathname, location.search);
  const handleMinimize = async () => {
    try {
      await getCurrentWindow().minimize();
    } catch {
      // no-op outside Tauri runtime
    }
  };

  const handleToggleMaximize = async () => {
    try {
      const appWindow = getCurrentWindow();
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
      await getCurrentWindow().close();
    } catch {
      // no-op outside Tauri runtime
    }
  };

  return (
    <div className="h-11 flex items-center justify-between px-3 bg-surface-1 border-b border-border select-none">
      {/* App name */}
      <div className="flex min-w-0 items-center gap-2 flex-1" data-tauri-drag-region>
        <div className="h-3 w-3 rounded-sm bg-pf-600" />
        <div className="flex items-center min-w-0 gap-2">
          <div className="text-sm font-semibold tracking-wide text-text-primary">PENTAFORGE</div>
          {routeLabel && (
            <>
              <div className="text-text-muted">/</div>
              <div className="truncate font-mono text-sm text-text-muted">{routeLabel}</div>
            </>
          )}
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
