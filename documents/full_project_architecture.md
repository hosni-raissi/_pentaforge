# PentaForge Main Architecture

```mermaid
flowchart TB
  User[User]

  subgraph UI["1. Desktop UI"]
    Tauri["Tauri Shell"]
    ReactUI["React UI
    Projects / Scan / Findings / Reports / Dashboard"]
    User --> Tauri --> ReactUI
  end

  subgraph API["2. Backend API"]
    Main["server.main"]
    FastAPI["FastAPI App"]
    ScanRoutes["Scan + Project Routes"]
    AIRoutes["AI Routes"]
    ReportRoutes["Report + Share Routes"]
    Middleware["Middleware
    CORS / safety / rate limiting"]

    Main --> FastAPI
    FastAPI --> Middleware
    Middleware --> ScanRoutes
    Middleware --> AIRoutes
    Middleware --> ReportRoutes
  end

  ReactUI <-->|HTTP + SSE| FastAPI

  subgraph ScanRuntime["3. Main Scan Runtime"]
    Orch["ScanOrchestratorService"]

    subgraph Nodes["Deterministic Nodes"]
      InfoNode["Information Gathering Node"]
      MemoryNode["System Memory Node"]
      Brain["Brain Builder"]
      IntelNode["Intel Node"]
    end

    subgraph ScanAgents["Scan Agents"]
      Planner["Planner"]
      Recon["Recon Executer"]
      Exploit["Exploit Executer"]
      Analyzer["Analyzer"]
    end

    Orch --> InfoNode
    Orch --> IntelNode
    InfoNode --> MemoryNode
    MemoryNode --> Brain
    Brain --> Planner
    Planner --> Recon
    Planner --> Exploit
    Recon --> Analyzer
    Exploit --> Analyzer
    Analyzer --> MemoryNode
    Analyzer --> Planner
    Analyzer --> Report
  end

  ScanRoutes --> Orch

  subgraph SupportAI["4. Support Backend Path"]
    SupportBackend["Support Backend Services"]

    subgraph SupportAgents["Support Services"]
      Assistant["Assistant Agent
      frontend chat"]
      Architect["Architect Agent
      architecture synthesis"]
      Report["Report Generator
      final report generation"]
      Share["Share Links
      public report access"]
    end

    SupportBackend --> Assistant
    SupportBackend --> Architect
    SupportBackend --> Report
    SupportBackend --> Share
  end

  AIRoutes --> SupportBackend
  ReportRoutes --> SupportBackend

  subgraph Execution["5. Execution Layer"]
    ToolRouting["Tool Routing / Tool Catalogs"]
    SandboxClient["Sandbox Client"]
    SandboxSvc["Sandbox Service"]
    Guards["Execution Guards
    scope / role / policy"]

    Recon --> ToolRouting
    Exploit --> ToolRouting
    Assistant --> ToolRouting
    ToolRouting --> SandboxClient --> SandboxSvc --> Guards
  end

  subgraph Storage["6. Storage Layer"]
    ProjectsDB["Projects Store"]
    Qdrant["Qdrant Vector Store"]
    Redis["Redis Cache"]
    IntelState["Intel State Store"]
    Files["Filesystem
    cache / logs / reports / artifacts"]
  end

  Orch --> ProjectsDB
  Orch --> Qdrant
  Orch --> Redis
  Orch --> IntelState
  Orch --> Files

  SupportBackend --> ProjectsDB
  SupportBackend --> Qdrant
  SupportBackend --> Files

  Execution ~~~ SupportAI
  SupportAI ~~~ Storage
```

## Reading Order

1. The user works in the **Tauri + React desktop UI**.
2. The UI calls the **FastAPI backend**.
3. Scan requests enter the **main scan runtime**:
   `Orchestrator -> Nodes -> Planner -> Recon/Exploit -> Analyzer -> Memory/Planner loop`.
4. Chat and architecture generation go through a separate **support AI path**.
5. Real tool execution happens through the **sandbox layer**.
6. State, vectors, cache, and artifacts are stored in the **storage layer**.
