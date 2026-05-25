import { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { Titlebar } from './Titlebar';
import { Sidebar } from './Sidebar';
import { useProjects } from '../../stores/projects';

export function AppShell() {
  const hydrateFromDatabase = useProjects((state) => state.hydrateFromDatabase);

  useEffect(() => {
    void hydrateFromDatabase();

    const handleFocus = () => {
      void hydrateFromDatabase();
    };
    const handleVisibility = () => {
      if (document.visibilityState === 'visible') {
        void hydrateFromDatabase();
      }
    };

    window.addEventListener('focus', handleFocus);
    document.addEventListener('visibilitychange', handleVisibility);

    return () => {
      window.removeEventListener('focus', handleFocus);
      document.removeEventListener('visibilitychange', handleVisibility);
    };
  }, [hydrateFromDatabase]);

  return (
    <div className="h-screen flex flex-col overflow-hidden">
      <Titlebar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-hidden bg-surface-0">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
