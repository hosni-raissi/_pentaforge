import { NavLink, useLocation } from "react-router-dom";
import { clsx } from "clsx";
import {
  LayoutDashboard,
  FolderOpen,
  Radar,
  Bug,
  FileText,
  Settings,
  Shield
} from "lucide-react";

import { useProjects } from "../../stores/projects";
import { Badge } from "../ui/Badge";

const navItems = [
  { to: "/projects", icon: FolderOpen, label: "Projects" },
  { to: "/dashboard", icon: LayoutDashboard, label: "Dashboard" },
  { to: "/scan", icon: Radar, label: "Scan" },
  { to: "/findings", icon: Bug, label: "Findings" },
  { to: "/reports", icon: FileText, label: "Reports" },
  { to: "/settings", icon: Settings, label: "Settings" }
];

export function Sidebar() {
  const location = useLocation();
  const running = useProjects((state) => state.getRunning());

  return (
    <aside className="flex h-full w-48 flex-col border-r border-border bg-surface-1">
      <div className="border-b border-border px-3 py-3">
        <div className="flex items-center gap-2">
          <Shield size={14} className="text-pf-500" />
          <span className="truncate text-[11px] font-medium text-text-secondary">
            {running?.name ?? "No active scan"}
          </span>
        </div>
        {running ? (
          <Badge variant="running" dot className="mt-1.5">
            Running
          </Badge>
        ) : null}
      </div>

      <nav className="flex-1 space-y-0.5 px-2 py-2">
        {navItems.map(({ to, icon: Icon, label }) => {
          const active = location.pathname === to;

          return (
            <NavLink
              key={to}
              to={to}
              className={clsx(
                "flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-xs font-medium transition-colors duration-100",
                active
                  ? "bg-pf-600/15 text-pf-400"
                  : "text-text-secondary hover:bg-surface-2 hover:text-text-primary"
              )}
            >
              <Icon size={15} className={active ? "text-pf-400" : ""} />
              {label}
            </NavLink>
          );
        })}
      </nav>

      <div className="border-t border-border px-3 py-2">
        <span className="text-[10px] text-text-muted">v1.0.0</span>
      </div>
    </aside>
  );
}
