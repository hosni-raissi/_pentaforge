import { NavLink, useLocation } from "react-router-dom";
import { clsx } from "clsx";
import {
  LayoutDashboard,
  FolderOpen,
  FileText,
  Settings,
  Shield,
  Search,
  type LucideIcon,
} from "lucide-react";

import { useProjects } from "../../stores/projects";
import {
  PRODUCT_LOOPS,
} from "../../lib/productWorkflows";
import { Badge } from "../ui/Badge";

const loopNavItems = [
  { to: "/dashboard", icon: LayoutDashboard, label: "Run Scan" },
  { to: "/reports", icon: FileText, label: "Reports & Share" },
];

const supportNavItems = [
  { to: "/projects", icon: FolderOpen, label: "Projects" },
  { to: "/settings", icon: Settings, label: "Settings" },
];

export function Sidebar() {
  const location = useLocation();
  const running = useProjects((state) => state.getRunning());
  const activeProject = useProjects((state) => state.getActive());
  const displayProject = activeProject || running;

  const status = displayProject?.status;
  const lastScanStatus = displayProject?.lastScan?.status;
  const needsApproval =
    status === "awaiting_tool_approval" ||
    status === "awaiting_planner_approval" ||
    status === "awaiting_information_gathering_approval" ||
    lastScanStatus === "awaiting_tool_approval" ||
    lastScanStatus === "awaiting_planner_approval" ||
    lastScanStatus === "awaiting_information_gathering_approval";

  const activeLoop = PRODUCT_LOOPS.find((loop) => {
    if (loop.route === "/dashboard?focus=findings") {
      return (
        location.pathname === "/dashboard"
        && new URLSearchParams(location.search).get("focus") === "findings"
      );
    }
    return location.pathname === loop.route;
  });

  const renderNavLink = ({
    to,
    icon: Icon,
    label,
  }: {
    to: string;
    icon: LucideIcon;
    label: string;
  }) => {
    const [pathname, search = ""] = to.split("?");
    const active =
      location.pathname === pathname
      && ((search.length === 0 && location.search.length === 0)
        || location.search === `?${search}`);

    return (
      <NavLink
        key={to}
        to={to}
        className={clsx(
          "flex items-center justify-between rounded-md px-2.5 py-1.5 text-sm font-medium transition-colors duration-100",
          active
            ? "bg-pf-600/15 text-pf-400"
            : "text-text-secondary hover:bg-surface-2 hover:text-text-primary",
        )}
      >
        <div className="flex items-center gap-2.5">
          <Icon size={15} className={active ? "text-pf-400" : ""} />
          <span>{label}</span>
        </div>
        {label === "Run Scan" && needsApproval && (
          <span className="h-2 w-2 rounded-full bg-yellow-500 animate-pulse" />
        )}
      </NavLink>
    );
  };

  return (
    <aside className="flex h-full w-48 flex-col border-r border-border bg-surface-1">
      <div className="border-b border-border px-3 py-3">
        <div className="flex items-center gap-2">
          <Shield size={14} className="text-pf-500" />
          <span className="truncate text-sm font-medium text-text-secondary">
            {displayProject?.name ?? "No Active Project"}
          </span>
        </div>
        {running ? (
          <Badge variant="running" dot className="mt-1.5">
            Running
          </Badge>
        ) : null}
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-4">
        <nav className="space-y-1">
          {loopNavItems.map(renderNavLink)}
        </nav>
        <div className="my-3 border-t border-border/50 px-3" />
        <nav className="space-y-1">
          {supportNavItems.map(renderNavLink)}
        </nav>
      </div>

      <div className="border-t border-border px-3 py-2">
        <span className="mt-1 block text-xs text-text-muted">v1.0.0</span>
      </div>
    </aside>
  );
}
