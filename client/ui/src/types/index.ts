/* ── Core types ──────────────────────────────────────────── */

export type ProjectStatus =
  | 'idle'
  | 'running'
  | 'stopped'
  | 'completed'
  | 'error'
  | 'awaiting_tool_approval'
  | 'awaiting_planner_approval'
  | 'awaiting_information_gathering_approval';
export type SeverityLevel = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type AgentName = 'planner' | 'executer' | 'analyzer';
export type AgentState = 'idle' | 'running' | 'success' | 'error' | 'waiting';
export type PhaseName = 'Reconnaissance' | 'Enumeration' | 'Exploitation' | 'Post-Exploitation' | 'Reporting';
export type FindingStatus = 'open' | 'verified' | 'fixed' | 'false_positive';
export type FindingEvidenceStatus = 'suspicion' | 'evidence_backed' | 'confirmed';
export type FindingProofQuality = 'weak' | 'moderate' | 'strong';
export type DashboardSeverity = SeverityLevel;

export interface ScanEventPayload {
  agent?: string;
  tool?: string;
  worker_id?: string;
  reason_code?: string;
  is_cached?: boolean;
}

export interface RealtimeVulnFinding {
  id: string;
  title: string;
  severity: DashboardSeverity;
  source: string;
  at: string;
  endpoint?: string;
  status: string;
  findingKey: string;
  cve?: string;
  cvss?: number | string;
  category?: string;
  description?: string;
  evidence?: FindingEvidence;
  evidenceStatus?: FindingEvidenceStatus;
  proofQuality?: FindingProofQuality;
  deterministicValidation?: boolean;
  remediation?: string;
  timestamp?: string; // Add timestamp as it's sometimes used interchangeably with 'at'
  // Structured PoC fields
  cwe_id?: string;
  cve_id?: string;
  steps_to_reproduce?: string[];
  exploit_script?: string;
  verification_commands?: string[];
  visual_evidence_paths?: string[];
  impact_assessment?: Record<string, string>;
  remediation_steps?: string[];
}

export interface CopilotMessage {
  id: string;
  role: 'user' | 'assistant';
  text: string;
  timestamp?: string;
  route?: 'assistant' | 'planner' | 'reporting' | 'blocked';
  blocked?: boolean;
  isCompressionSeparator?: boolean;
  isCompressionSummary?: boolean;
  toolLogs?: Array<{
    id: string;
    tool: string;
    input: string;
    output?: any;
    status: 'running' | 'done' | 'error';
  }>;
  passwordRequests?: Array<{
    call_id: string;
    prompt: string;
    reason: string;
    status: 'pending' | 'submitted' | 'denied';
  }>;
}

export interface Project {
  id: string;
  name: string;
  target: string;
  targetType: string;
  targetConfig?: Record<string, unknown>;
  customChecklistText?: string;
  customChecklistName?: string;
  status: ProjectStatus;
  createdAt: string;
  updatedAt: string;
  description?: string;
  copilotHistory?: CopilotMessage[];
  copilotContext?: string;
  findings: Finding[];
  agents: AgentInfo[];
  phases: PhaseInfo[];
  scanProgress: number;
  lastScan?: {
    scanId?: string;
    status?: string;
    startedAt?: string;
    finishedAt?: string;
    elapsedSeconds?: number;
    durationSeconds?: number;
    error?: string;
    mobileRuntime?: {
      mode?: string;
      executionMode?: string | null;
      runtimeAvailable?: boolean;
      prepared?: boolean;
      warning?: string;
      deviceId?: string;
    };
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
      targetInfoGathering?: {
        status?: string;
        program?: unknown[];
        blocks?: unknown[];
        paths?: Record<string, unknown>;
      };
      targetMemory?: Record<string, unknown>;
      [key: string]: unknown;
    };
    [key: string]: unknown;
  };
  payload?: Record<string, any>;
  approval_mode?: 'custom' | 'auto';
}

export interface Finding {
  id: string;
  title: string;
  severity: SeverityLevel;
  category: string;
  target: string;
  status: FindingStatus;
  cvss?: number;
  cve?: string;
  description: string;
  evidence?: FindingEvidence;
  evidenceStatus?: FindingEvidenceStatus;
  proofQuality?: FindingProofQuality;
  deterministicValidation?: boolean;
  verificationMethods?: string[];
  remediation?: string;
  timestamp: string;
  // Structured PoC fields
  cwe_id?: string;
  cve_id?: string;
  steps_to_reproduce?: string[];
  exploit_script?: string;
  verification_commands?: string[];
  visual_evidence_paths?: string[];
  impact_assessment?: Record<string, string>;
  remediation_steps?: string[];
}

export interface FindingEvidence {
  verification_summary?: string;
  verification_confidence?: number;
  evidence_status?: FindingEvidenceStatus;
  proof_quality?: FindingProofQuality;
  deterministic_validation?: boolean;
  verification_methods?: string[];
  oob_confirmed?: boolean;
  protocol?: string;
  remote_address?: string;
  callbacks?: Array<Record<string, unknown>>;
  commands?: string[];
  tools_used?: string[];
  artifact_quality?: Record<string, unknown>;
  [key: string]: unknown;
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
  privacyGate: boolean;
  isAssistantOpen: boolean;
  assistantDraftPrompt?: string;
}
