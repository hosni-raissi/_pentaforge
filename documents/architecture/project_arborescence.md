# PentaForge Essential Project Arborescence

## Simplified Version for Report and Presentation

```text
PentaForge/
├── server/                       # Backend application and AI runtime
│   ├── api/                      # FastAPI routes, middleware and API entrypoint
│   ├── app/                      # Scan orchestrator and scan lifecycle services
│   ├── agents/                   # AI agents orchestrating intelligence and actions
│   │   ├── analyzer/             # Synthesizes execution results into intelligence
│   │   ├── assistant/            # General conversational support and queries
│   │   ├── executor/             # Manages tool dispatch and sandbox execution
│   │   └── planner/              # Determines action plans from gathered intel
│   ├── nodes/                    # Deterministic nodes mapping to architectural blocks
│   │   ├── architect/            # Project structure and scoping analysis
│   │   ├── information_gathering/# Collects repository metadata and static facts
│   │   ├── intel/                # State management and RAG retrieval node
│   │   ├── report/               # Final report generation and synthesis
│   │   └── system_memory/        # Context consolidation and memory building
│   ├── db/                       # Project database, runtime cache and RAG storage logic
│   ├── sandbox_service/          # Isolated command execution service
│   └── test/                     # Backend tests and workflow validation
├── client/
│   └── ui/                       # React and Tauri desktop interface
├── infra/
│   └── docker/                   # Docker Compose and service images
├── documents/                    # Report assets, diagrams and documentation snippets
└── scripts/                      # Local startup and automation scripts
```
This simplified structure highlights the main engineering blocks of the platform:
the backend runtime, the desktop interface, the Docker deployment layer, the project
documentation, and the report source. It is the most suitable version for a report
figure or a presentation slide because it avoids implementation-level noise while
still showing the real organization of the project.

```text
PentaForge/
├── server/
│   ├── api/
│   │   ├── app.py                  # FastAPI application entrypoint
│   │   ├── routes/                 # Projects, scans, reports, share, AI, settings routes
│   │   └── middleware/             # API safety middleware
│   ├── app/
│   │   ├── orchestrator.py         # Public ScanOrchestrator facade
│   │   ├── _full_orchestrator_impl.py
│   │   │                           # Main scan orchestration implementation
│   │   └── scan/                   # Scan lifecycle, events, approval, execution helpers
│   ├── agents/
│   │   ├── planner/                # Checklist generation and pentest planning agent
│   │   ├── executer/
│   │   │   ├── recon/              # Reconnaissance executer agent and tools
│   │   │   ├── exploit/            # Exploitation executer agent and tools
│   │   │   ├── sandbox_client.py   # Client used to call the sandbox service
│   │   │   ├── run_custom_guard.py # Scope and command guardrails
│   │   │   └── global_cache.py     # Tool result reuse / command de-duplication
│   │   ├── analyzer/               # Evidence analysis, verification and classification
│   │   ├── assistant/              # Project-aware assistant agent
│   │   ├── architect/              # Architecture synthesis agent
│   │   ├── report/                 # Report generator and report prompts
│   │   └── tools/                  # Shared agent tools such as run_custom and run_python
│   ├── nodes/
│   │   ├── intel/                  # Intel refresh and target-oriented knowledge preparation
│   │   ├── information_gathering/  # Target information gathering profiles and node
│   │   └── system_memory/          # System Memory, Brain Builder and memory schema
│   ├── db/
│   │   ├── projects/               # SQLite project store, scan observability and runtime cache
│   │   └── knowledge/              # RAG knowledge pipeline, Qdrant storage and Intel sources
│   ├── layers/
│   │   ├── PrivacyGate/            # Privacy and prompt safety controls
│   │   ├── safety/                 # Safety layer components
│   │   └── sanitizer/              # Data sanitization layer
│   ├── sandbox_service/
│   │   └── app.py                  # HTTP service used for isolated command execution
│   ├── sandbox/                    # Sandbox workspace, shared wordlists and runtime files
│   ├── config/                     # Agent and database configuration
│   ├── schemas/                    # API and scan request/response schemas
│   ├── test/                       # Backend regression and workflow tests
│   └── requirements.txt            # Python backend dependencies
├── client/
│   └── ui/
│       ├── src/                    # React user interface
│       ├── src-tauri/              # Tauri desktop shell and Rust configuration
│       ├── package.json            # Frontend dependencies and scripts
│       └── vite.config.ts          # Vite frontend build configuration
├── infra/
│   └── docker/
│       ├── docker-compose.yml      # Backend, frontend, Redis, Qdrant and sandbox stack
│       ├── backend.Dockerfile      # FastAPI backend image
│       ├── frontend.Dockerfile     # Frontend image
│       ├── sandbox.Dockerfile      # Tool sandbox service image
│       ├── sandbox-tools.Dockerfile
│       │                           # Base image for security tooling
│       └── install-sandbox-tools.sh
│                                   # Sandbox toolchain installation script
├── documents/
│   ├── figures/                    # Architecture diagrams and report figures
│   ├── project_arborescence.md     # Essential project tree
│   ├── technology_used_table.tex   # Technology table snippet
│   └── hardware_prerequisites_table.tex
│                                   # Hardware prerequisites table snippet
├── scripts/
│   └── run-desktop-with-docker.sh  # Main local startup script
├── report.tex                      # End-of-studies report source
├── enicar.jpg                      # ENICarthage logo used in the report
└── talan1.png                      # Talan logo used in the report
```

## Storage Mapping

```text
Storage layer
├── SQLite
│   └── server/db/projects/         # Project metadata, scan state, findings and reports
├── Qdrant
│   └── server/db/knowledge/storage/qdrant_store.py
│                               # Vector database integration for RAG
├── Redis
│   └── server/db/projects/runtime_cache.py
│                               # Runtime cache and short-lived coordination state
└── Filesystem / Docker volumes
    ├── server/cache/               # Runtime cache and project run cache
    ├── server/logs/                # Backend and execution logs
    └── server/sandbox/             # Sandbox workspace and shared resources
```
