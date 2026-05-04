# PentaForge Server Architecture

This document describes how the `server/` side of PentaForge is structured today: API entrypoints, orchestration flow, agents, nodes, memory, and database integration.

## 1. High-Level Shape

The server is a FastAPI application that orchestrates multi-stage pentest runs.

At a high level, the runtime pipeline is:

1. API receives a scan request.
2. `ScanOrchestratorService` resolves project state and target configuration.
3. Intel refreshes or reuses long-lived knowledge.
4. Information Gathering builds a grouped, deterministic target profile.
5. System Memory is updated and projected into a structured `Brain`.
6. Planner generates a checklist and then a pentest plan.
7. Executer runs recon and exploit scenarios in cycles.
8. Analyzer classifies findings, verifies them, and generates PoC/retest evidence.
9. Verified findings and memory artifacts are persisted back into project storage and project-scoped RAG.

There are two different “knowledge” layers:

- Global / reusable knowledge:
  lives in the knowledge database and is refreshed by Intel.
- Per-project / per-run memory:
  lives in the runtime cache directory and is updated throughout the scan.

## 2. Entry Point And API Layer

### Startup

The main entrypoint is:

- `server/main.py`

It launches Uvicorn against:

- `server.api.app:app`

### FastAPI App

The FastAPI app is wired in:

- `server/api/app.py`

Key responsibilities:

- create the FastAPI application
- register API safety middleware
- register CORS middleware for the local UI / Tauri clients
- initialize API state on startup
- mount routers

### API Dependencies

Shared singletons are initialized in:

- `server/api/dependencies.py`

Important shared runtime objects:

- `ProjectsStore`
- `IntelStateStore`
- `RateLimiter`
- `ScanOrchestratorService`

### Main Route Groups

Important route modules include:

- `server/api/routes/projects.py`
- `server/api/routes/scans.py`
- `server/api/routes/ai.py`
- `server/api/routes/intel.py`
- `server/api/routes/target_types.py`
- `server/api/routes/share.py`
- `server/api/routes/health.py`

The most important operational route for scans is:

- `server/api/routes/scans.py`

It exposes:

- scan start / stop
- planner approval
- information gathering approval
- tool approval
- password approval
- SSE event streaming for scan progress
- current scan status
- cached event retrieval

## 3. Core Runtime Coordinator

The central runtime brain is:

- `server/app/orchestrator.py`

`ScanOrchestratorService` is the main application service. It owns:

- run lifecycle
- event emission
- scan status persistence
- agent instantiation
- cyclic execution
- analyzer / planner feedback loops
- project memory integration

It is effectively the conductor for the whole server-side scan.

### What The Orchestrator Does

For a typical scan, it:

1. loads the project and target inputs
2. creates a project run cache directory
3. initializes system memory
4. refreshes Intel/RAG if needed
5. runs grouped information gathering
6. stores checklist and target information in memory
7. creates the initial plan
8. enters the execution cycle loop
9. feeds results through Analyzer and Planner
10. persists findings, events, and memory artifacts

### Event Model

The orchestrator emits structured events the UI consumes over SSE. These are cached in the project database and also pushed live to subscribers.

Examples:

- system status changes
- planner start / approval / completion
- executer cycle start / finish
- analyzer classification / verify / retest
- tool approval waits

## 4. Runtime Flow In Detail

### Phase A: Intel

Intel is wrapped by:

- `server/nodes/intel/node.py`

`IntelNode` does two main things:

- `refresh_rag(...)`
- `synthesize_checklist(...)`

Intel uses long-lived knowledge sources and a cooldown model. It decides whether to reuse current knowledge or refresh it.

Supporting persistent state:

- `server/db/knowledge/storage/intel_state_store.py`

This SQLite store tracks the last refresh timestamp per `target_type`.

### Phase B: Information Gathering

Grouped target profiling is handled by:

- `server/nodes/information_gathering/node.py`

This node:

- loads target info profiles
- organizes work into logical blocks
- optionally lets the LLM prepare / refine those blocks
- executes approved tools in grouped batches
- feeds results into system memory

For `web_app` and `api` targets, the grouped profile now includes a deterministic
**known-vulnerability fast lane** immediately after fingerprinting.

That fast lane works like this:

1. `http_probe`, `detect_tech`, and `http_header_analysis` run first.
2. Their structured outputs are normalized into a product/version inventory.
3. Only then does `known_vuln_lookup` run.
4. It correlates corroborated fingerprints against project knowledge + runtime NVD lookups.
5. The resulting signals are written into system memory before planner starts.

Its profile definitions are stored in:

- `server/nodes/information_gathering/target_info_profiles.json`

This is the deterministic “what should we gather first for this target type?” layer.

### Phase C: System Memory

System memory is wrapped by:

- `server/nodes/system_memory/node.py`

Core helpers live in:

- `server/nodes/system_memory/core.py`
- `server/nodes/system_memory/schema.py`
- `server/nodes/system_memory/brain.py`

System memory is the runtime truth source for:

- target overview
- observed routes
- authenticated routes
- auth deltas
- blocked routes / route families
- parameter hints
- verified findings
- tool observations
- session context
- checklist state
- grouped gathering blocks
- normalized tech inventory
- known vulnerability signals
- selective nuclei / tool-routing hints

System memory now does more than store freeform summaries.

During save/normalization it deterministically derives:

- `tech_stack`
- `tech_inventory`
- `known_vulnerability_signals`
- `recommended_run_custom_tools`
- `nuclei_scan_hints`

This means product/version intelligence is computed once and reused everywhere
instead of being re-parsed by each agent loop.

#### Storage Format

Each project run gets a memory directory under:

- `server/cache/project_runs/<run-id>/system_memory/`

Important artifacts:

- `memory.json`
- `memory.md`

`memory.json` is the structured machine state.

It now includes richer known-vuln acceleration state such as:

- normalized product/version fingerprints with provenance
- source-count / corroboration confidence
- per-product knowledge-base queries
- known CVE/KEV-style signals from the fast lane
- preferred `run_custom` tools and selective nuclei hints

`memory.md` is the compressed human-readable memory summary, generated with LLM assistance and later re-indexed into project RAG.

### Phase D: Brain Projection

The bridge from raw runtime memory into agent-friendly structured context is:

- `server/nodes/system_memory/brain.py`

`BrainBuilderNode` produces projections for:

- planner
- executor
- analyzer

The `Brain` model in `schema.py` converts raw memory into structured signals like:

- `tech_stack`
- `tech_inventory`
- `known_vulnerability_signals`
- `findings`
- `tool_results`
- `parameter_hints`
- `blocked_route_prefixes`

And then exposes role-specific projections:

- `for_planner()`
- `for_executor()`
- `for_analyzer()`

This is one of the most important architectural decisions in the server: agents do not reason against raw scan history directly; they reason against curated memory projections.

An important recent extension is that the Brain now carries **confidence-scored
technology fingerprints** instead of only flattened stack strings.

For each detected product it can carry:

- canonical product name
- raw and normalized version
- source provenance
- corroboration count
- confidence label
- product-aware KB query
- recommended `run_custom` tools
- selective nuclei tags/templates

This is the key bridge that lets planner and executer make deterministic
known-vuln decisions without re-extracting versions from prose every cycle.

### Phase E: Planner

Planner code lives in:

- `server/agents/planner/agent.py`
- `server/agents/planner/prompts.py`
- `server/agents/planner/context_builder.py`
- `server/agents/planner/tools/`

Planner responsibilities:

- generate a target-specific checklist
- merge checklist state with target memory
- generate or update the pentest plan
- keep the plan bounded and machine-normalized
- decide what scenarios are available to run next

Planner now consumes the normalized `tech_inventory` and
`known_vulnerability_signals` from Brain directly.

That enables two important behaviors:

- product-aware checklist / scenario generation
- structured `search_kb(product=..., version=...)` lookups instead of only fuzzy text search

Planner has tool access for:

- checklist retrieval
- RAG search
- web search
- page fetches
- current plan state management

Important planner state tool files:

- `server/agents/planner/tools/get_checklists.py`
- `server/agents/planner/tools/pentest_plan.py`
- `server/agents/planner/tools/search_kb.py`
- `server/agents/planner/tools/search_web.py`
- `server/agents/planner/tools/get_page.py`

The planner is not a simple one-shot prompt. It is a LangGraph-based loop that can call tools before finalizing output.

`search_kb.py` now supports structured product/version inputs, so planner can
turn a fingerprint like `WordPress 6.x` or `nginx 1.29.8` into a deterministic
knowledge query instead of relying on freeform wording.

### Phase F: Executer

Executer logic is split into:

- recon agent
- exploit agent
- shared executer base

Key files:

- `server/agents/executer/base.py`
- `server/agents/executer/recon/agent.py`
- `server/agents/executer/exploit/agent.py`
- `server/agents/executer/target_tool_routing.py`
- `server/agents/executer/resource_catalog.py`
- `server/agents/executer/payload_filter.py`
- `server/agents/executer/sandbox.py`

#### Recon Agent

`ReconExecuterAgent`:

- runs scoped reconnaissance scenarios
- receives only target-compatible tools
- injects target-type-specific `run_custom` tool catalogs
- uses project-local wordlists and resource catalogs
- receives product-aware routing hints from Brain / orchestrator context

It merges Python-native tools and security-tool catalogs such as:

- web
- api
- network
- infra
- server
- container
- mobile
- repository
- cloud
- iot

#### Exploit Agent

`ExploitExecuterAgent`:

- runs evidence-backed exploit scenarios
- keeps core exploit helpers always available
- expands with target-compatible exploit tools
- also gets target-type-specific `run_custom` security tool catalogs
- consumes selective nuclei and product-tool hints from the executor projection

#### Base Executer

`BaseExecuterAgent` provides:

- LLM round loop
- tool call handling
- tool approval callbacks
- command normalization
- result truncation / compaction
- runtime sandbox setup
- discovered target-type extraction

This base is the execution runtime shared by recon and exploit, and Analyzer verify/retest runners also reuse the same base pattern.

### Phase G: Analyzer

Analyzer code lives in:

- `server/agents/analyzer/agent.py`
- `server/agents/analyzer/prompts.py`
- `server/agents/analyzer/parsers.py`
- `server/agents/analyzer/policy.py`
- `server/agents/analyzer/tools/`

Analyzer responsibilities:

1. classify executer outputs
2. decide whether a scenario result is info / vuln / false positive
3. verify candidate vulnerabilities
4. generate PoC / retest evidence for confirmed findings

Analyzer is internally split into two tool runners:

- verification runner
- PoC / retest runner

Important recent design split:

- `verify` is deterministic and minimal
- `retest` / `poc` can use screenshots and vision tools

Analyzer also consumes:

- executor command history
- scenario evidence metadata
- OOB assessment helpers

This improves continuity between execution and verification.

### Phase H: Assistant

Separate from the scan pipeline, the frontend AI panel uses:

- `server/agents/assistant/agent.py`

This is a lighter-weight tool-using assistant that can:

- search project vectors
- fetch pages
- run bounded custom commands

It is scoped to the current project / target and uses prompt injection guards.

## 5. Nodes Vs Agents

The server uses both **nodes** and **agents**, but they play different roles.

### Nodes

Nodes are deterministic or semi-deterministic runtime building blocks.

Examples:

- `IntelNode`
- `InformationGatheringNode`
- `SystemMemoryNode`
- `BrainBuilderNode`

Nodes are responsible for:

- stable contracts
- data preparation
- storage updates
- structured workflow steps

### Agents

Agents are LLM-driven decision makers or tool runners.

Examples:

- `PlannerAgent`
- `ReconExecuterAgent`
- `ExploitExecuterAgent`
- `AnalyzerAgent`
- `AssistantAgent`

Agents are responsible for:

- reasoning
- scenario choice
- tool usage
- interpretation
- verification

The architecture deliberately puts persistent structure in nodes and tactical reasoning in agents.

## 6. Storage Architecture

PentaForge uses multiple storage layers, each with a different purpose.

### A. SQLite Project Store

Primary project persistence is:

- `server/db/projects/store.py`

This SQLite store persists project JSON payloads and operational metadata.

Important tables include:

- `records`
- `share_links`
- `intel_resources`
- `intel_update_prefs`
- `intel_hidden_builtin_resources`
- `planner_static_recon_plans`
- `target_info_profiles`
- `scan_event_cache`

This is the authoritative store for project records and scan event history.

### B. Qdrant Knowledge Store

Global reusable knowledge is stored in Qdrant through:

- `server/db/knowledge/storage/qdrant_store.py`

It uses five content-type collections:

- `strategies`
- `exploits`
- `tools`
- `standards`
- `attack_types`

Domain is stored as metadata, not as separate collections.

This store backs:

- Intel refresh
- planner knowledge lookups
- project-level RAG artifacts

### C. Project-Scoped RAG Artifacts

Project-specific searchable artifacts are managed in:

- `server/db/projects/project_rag.py`

This indexes:

- verified findings
- system memory markdown

into Qdrant, and also writes artifact metadata back into the project record.

This is the bridge between one scan’s discoveries and later project-level retrieval.

### D. Redis Runtime Cache

Short-lived runtime scratch data is handled by:

- `server/db/projects/runtime_cache.py`

This is a small Redis helper used for ephemeral orchestrator state and short-lived cached artifacts.

### E. Intel Cooldown State

Intel refresh state is tracked in:

- `server/db/knowledge/storage/intel_state_store.py`

This is separate from the project store because it tracks refresh cadence by `target_type`, not by project.

### F. File-Based Runtime Cache

Per-run artifacts are also written under:

- `server/cache/project_runs/`

This includes:

- system memory JSON / Markdown
- tool outputs
- temporary project-run evidence

This file layer is important because many tools are filesystem-oriented and some outputs are too bulky or too transient for SQLite rows.

## 7. Knowledge Ingestion Architecture

Global security knowledge is ingested through:

- `server/db/knowledge/orchestrator.py`

The ingestion pipeline is:

1. extract source content
2. clean content
3. chunk content
4. embed chunks
5. store vectors in Qdrant

Supported extractor families include:

- GitHub repos
- websites
- GitBook
- NVD/CVE data

Supporting modules:

- `server/db/knowledge/sources/`
- `server/db/knowledge/processing/`
- `server/db/knowledge/storage/embedding.py`

This knowledge base is what Intel and planner knowledge tools rely on.

## 8. Tool Architecture

Tooling is layered.

### Python-Native Tools

Many recon / exploit tools are Python wrappers with extra logic such as:

- result normalization
- multi-step validation
- project-local wordlist selection
- safety rules

### Security Tool Catalogs

Each major target type also has a structured `security_tools.py` catalog.

Examples:

- `server/agents/executer/recon/tools/web/security_tools.py`
- `server/agents/executer/recon/tools/api/security_tools.py`
- `server/agents/executer/recon/tools/network/security_tools.py`

These catalogs describe external CLI tooling that can be run through `run_custom`.

### Tool Routing

Target-aware filtering is handled by:

- `server/agents/executer/target_tool_routing.py`

This ensures agents only see tools that are compatible with the current target type.

There is now a second routing layer on top of target type:

- **target-type routing**
  decides whether a tool belongs to `web_app`, `api`, `network`, etc.
- **product-aware routing hints**
  decide which tools are best once the stack is known

Examples:

- WordPress -> prefer `wpscan` + WordPress-flavored nuclei hints
- Drupal -> prefer `droopescan`
- Joomla -> prefer `joomscan`
- front-end library fingerprints -> prefer `retire_js`
- web server / framework versions -> prefer selective nuclei tags/templates over broad scans

This keeps the agent catalog broad enough for flexibility, while still giving
it deterministic shortcuts once the target is fingerprinted.

## 9. Session And OOB Support

### Session Management

Lightweight authenticated session context is stored through:

- `server/tools/session/session_manager.py`

It supports:

- cookie sets
- custom headers
- JWT auth
- multi-user session labels

This is used when scenarios need stateful or role-aware testing.

### OOB Runtime

Out-of-band support is handled by:

- `server/tools/oob/runtime.py`
- `server/tools/oob/interactsh_client.py`

OOB is engagement-scoped and uses the current execution context to derive the right client identity.

This is important for:

- blind SSRF
- blind command injection
- callback-based verification

## 10. Safety And Guard Rails

Safety is not a single module; it is layered.

### API Safety

- `server/api/middleware/safety.py`

This protects inbound API usage.

### Prompt / LLM Safety

- `server/layers/safety/`
- `server/layers/PrivacyGate/`
- `server/layers/sanitizer/`

These layers cover:

- rate limiting
- prompt guard behavior
- sanitization
- privacy-aware filtering

### Executer Safety

Important protection points include:

- sandbox preparation in `server/agents/executer/sandbox.py`
- payload filtering in `server/agents/executer/payload_filter.py`
- tool approval callbacks in `BaseExecuterAgent`
- target scope enforcement
- assistant scope restrictions

## 11. The End-To-End Scan Sequence

A normal scan looks like this:

1. `POST /api/scans/start`
2. project is loaded from `ProjectsStore`
3. orchestrator initializes per-run cache and system memory
4. Intel refreshes or reuses global knowledge
5. grouped information gathering runs deterministic fingerprinting blocks
6. the known-vulnerability fast lane enriches corroborated product/version signals
7. system memory stores grouped output, tech inventory, vuln signals, and checklist state
8. planner builds checklist using the enriched Brain projection
9. user may approve checklist / information gathering plan
10. planner builds the pentest plan
11. executer starts cyclic recon/exploit execution with product-aware tool hints
12. analyzer classifies and verifies findings
13. planner replans using updated memory
14. verified findings are saved to project storage and indexed into project RAG
15. event stream keeps the UI updated throughout

## 12. Architectural Boundaries

The current server is easiest to understand if you keep these boundaries in mind:

- **API layer**
  accepts requests and exposes scan / project operations
- **Orchestrator**
  owns runtime control flow
- **Nodes**
  own structured workflow steps and memory contracts
- **Agents**
  own LLM reasoning and tool use
- **Project store**
  owns durable project and event state
- **Knowledge store**
  owns reusable global security intelligence
- **System memory**
  owns per-run state and role-specific projections

## 13. Mental Model

The best short mental model for the server is:

- **ProjectsStore** is the durable application database.
- **Qdrant + knowledge orchestrator** are the reusable security brain.
- **System memory** is the per-run working memory.
- **Planner / Executer / Analyzer** are the operational agent loop.
- **ScanOrchestratorService** is the conductor that keeps them synchronized.

## 14. Important Files To Start Reading

If you want to understand the system quickly, start with these files in order:

1. `server/api/app.py`
2. `server/api/routes/scans.py`
3. `server/app/orchestrator.py`
4. `server/nodes/system_memory/schema.py`
5. `server/nodes/information_gathering/node.py`
6. `server/agents/planner/agent.py`
7. `server/agents/executer/base.py`
8. `server/agents/executer/recon/agent.py`
9. `server/agents/executer/exploit/agent.py`
10. `server/agents/analyzer/agent.py`
11. `server/db/projects/store.py`
12. `server/db/knowledge/storage/qdrant_store.py`

That path gives the clearest top-down view of how the server actually works today.
