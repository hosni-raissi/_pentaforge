/* ── Core types ──────────────────────────────────────────── */

export type ProjectStatus = 'idle' | 'running' | 'paused' | 'completed' | 'error';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AgentName = 'planner' | 'recon' | 'exploit' | 'verify' | 'report' | 'retest';
export type AgentState = 'idle' | 'running' | 'success' | 'error' | 'waiting';
export type PhaseName = 'Reconnaissance' | 'Enumeration' | 'Exploitation' | 'Post-Exploitation' | 'Reporting';

export interface Project {
  id: string;
  name: string;
  target: string;
  targetType: string;
  targetConfig?: Record<string, string>;
  status: ProjectStatus;
  createdAt: string;
  updatedAt: string;
  description?: string;
  findings: Finding[];
  agents: AgentInfo[];
  phases: PhaseInfo[];
  scanProgress: number;
  lastScan?: {
    scanId?: string;
    status?: string;
    startedAt?: string;
    finishedAt?: string;
    error?: string;
    result?: {
      target?: string;
      targetType?: string;
      intel?: {
        status?: string;
        summary?: string;
        stats?: Record<string, unknown>;
        checklist?: Record<string, unknown>;
      };
      planner?: {
        summary?: string;
        scenarios?: unknown[];
        needs?: unknown[];
        plan_data?: Record<string, unknown>;
      };
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
}

export interface Finding {
  id: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  target: string;
  status: 'open' | 'verified' | 'fixed' | 'false_positive';
  cvss?: number;
  cve?: string;
  description: string;
  evidence?: string;
  remediation?: string;
  timestamp: string;
}

export interface AgentInfo {
  name: AgentName;
  state: AgentState;
  currentTask?: string;
  progress?: number;
  lastUpdate?: string;
}

export interface PhaseInfo {
  name: PhaseName;
  status: 'pending' | 'active' | 'completed';
  progress: number;
  startedAt?: string;
  completedAt?: string;
}

export interface LLMConfig {
  id: string;
  name: string;
  provider: 'groq' | 'openai' | 'anthropic' | 'ollama' | 'custom';
  model: string;
  apiKey?: string;
  baseUrl?: string;
  maxTokens: number;
  temperature: number;
  isDefault: boolean;
  mode: 'public' | 'local';
}

export interface AppConfig {
  llmConfigs: LLMConfig[];
  activeLLM: string;
  serverUrl: string;
  serverPort: number;
  autoApprove: boolean;
  stealthMode: boolean;
}
