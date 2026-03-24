import { Outlet } from 'react-router-dom';
import { Titlebar } from './Titlebar';
import { Sidebar } from './Sidebar';
import { StatusBar } from './StatusBar';

export function AppShell() {
  return (
    <div className="h-screen flex flex-col overflow-hidden">
      <Titlebar />
      <div className="flex flex-1 overflow-hidden">
        <Sidebar />
        <main className="flex-1 overflow-auto bg-surface-0 p-4">
          <Outlet />
        </main>
      </div>
      <StatusBar />
    </div>
  );
}