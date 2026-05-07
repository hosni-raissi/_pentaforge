export type ProductLoopId =
  | "run_scan"
  | "review_findings"
  | "generate_share_report";

export interface ProductLoopDefinition {
  id: ProductLoopId;
  label: string;
  route: string;
  description: string;
  features: string[];
}

export const PRODUCT_WORKFLOW_RULE =
  "No new feature ships unless it connects to findings, planner memory, reporting, and the audit trail.";

export const PRODUCT_LOOPS: ProductLoopDefinition[] = [
  {
    id: "run_scan",
    label: "Run Scan",
    route: "/dashboard",
    description: "Launch scans, watch phases, handle approvals, and keep the operator in control.",
    features: [
      "mission_control",
      "phase_tracking",
      "tool_approvals",
      "assistant_runtime_help",
    ],
  },
  {
    id: "review_findings",
    label: "Review Findings",
    route: "/dashboard?focus=findings",
    description: "Inspect verified impact, remove false positives, and review evidence before reporting.",
    features: [
      "verified_findings",
      "attack_graph",
      "false_positive_workflow",
      "planner_feedback",
    ],
  },
  {
    id: "generate_share_report",
    label: "Reports & Share",
    route: "/reports",
    description: "Generate deliverables, preview them, and publish the client-facing access link.",
    features: [
      "report_generation",
      "report_preview",
      "share_link_delivery",
      "download_exports",
    ],
  },
];

export const SUPPORT_SURFACES = [
  {
    label: "Projects & Scope",
    route: "/projects",
    description: "Define targets and choose which engagement the workflows operate on.",
  },
  {
    label: "Settings",
    route: "/settings",
    description: "Change platform-wide behavior only after it supports the three core loops.",
  },
] as const;

export function routeLabelForPath(pathname: string, search = ""): string {
  const normalizedPath = pathname.replace(/\/+$/, "") || "/";
  const params = new URLSearchParams(search);
  if (normalizedPath === "/dashboard" && params.get("focus") === "findings") {
    return "Review Findings";
  }
  if (normalizedPath === "/dashboard") {
    return "Run Scan";
  }
  if (normalizedPath === "/reports" || normalizedPath === "/client-share") {
    return "Reports & Share";
  }
  if (normalizedPath === "/projects") {
    return "Projects";
  }
  if (normalizedPath === "/settings") {
    return "Settings";
  }
  return `pentaforge${normalizedPath}`;
}
