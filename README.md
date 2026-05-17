# PentaForge

**Advanced Agentic Penetration Testing Platform**

PentaForge is an autonomous, multi-agent penetration testing platform designed to automate complex security assessments. It operates on a "conductor-orchestra" model where a central orchestrator synchronizes specialized LLM-driven agents to perform reconnaissance, vulnerability analysis, and exploitation in a safe, controlled manner.

---

## 🎯 Overview

Unlike traditional vulnerability scanners that rely on static signatures and emit noisy false positives, PentaForge acts like a human penetration tester. It:
1. Researches the target.
2. Builds a dynamic attack plan.
3. Safely executes tools.
4. Continuously adapts its strategy based on the results.
5. **Strictly verifies** vulnerabilities by requiring deterministic evidence (e.g., OOB callbacks, reproducible command output) before flagging a finding as confirmed.

## 🏗️ Architecture & The "Orchestra"

PentaForge is built as a **Modular Monolith**. 

### The Agents
Instead of a single AI trying to do everything, the backend is split into specialized agents:
*   **Planner**: Creates multi-step pentest plans and checklists based on initial reconnaissance.
*   **Executer**: Runs the actual tools (like scanners and scripts) in controlled sandboxes to execute the recon and exploit scenarios.
*   **Analyzer**: Evaluates the output from the Executer. Uses strict "Verification Tiers" to classify findings, verify vulnerabilities, and generate Proofs of Concept (PoCs).
*   **Assistant**: Powers the real-time AI helper in the UI to guide operators.

### The Flow
1.  **Intel Phase**: The system refreshes global knowledge (RAG/Qdrant) and builds a target-specific checklist.
2.  **Information Gathering**: Deterministic tools (nmap, tech detection) build a profile of the target, immediately checking for known CVEs based on the tech stack.
3.  **Brain Projection**: Raw findings are normalized into "System Memory" that agents use to reason.
4.  **Planning**: The Planner creates an initial attack plan.
5.  **Execution Loop**: Executer runs tools -> Analyzer evaluates outputs -> Planner updates the plan.
6.  **Verification**: Findings are verified with deterministic proof and safely stored in the project database.

---

## 🛠️ Technology Stack

*   **Frontend**: React, TypeScript, Vite, Tailwind CSS, Zustand, Server-Sent Events (SSE) for real-time monitoring.
*   **Desktop Client**: Tauri (Rust).
*   **Backend**: Python 3.11+, FastAPI, LangGraph (Agentic loops), Uvicorn.
*   **AI/LLM**: OpenAI/Anthropic/Google models via unified core.
*   **Databases**: 
    *   SQLite (Metadata & Project persistence)
    *   Qdrant (Vector/RAG for security knowledge)
    *   Redis (Ephemeral cache)

---

## 📂 Project Structure

```text
PentaForge/
├── client/          # Frontend applications
│   ├── ui/          # React web dashboard
│   ├── src-tauri/   # Rust desktop application wrapper
│   └── cli/         # CLI client (if applicable)
├── server/          # Core Backend Engine
│   ├── agents/      # Specialized LLM decision makers (Planner, Executer, Analyzer)
│   ├── api/         # FastAPI routes and middleware
│   ├── app/         # ScanOrchestratorService (The Conductor)
│   ├── db/          # SQLite, Qdrant, and Redis logic
│   ├── layers/      # Safety, privacy, and sanitization guardrails
│   ├── nodes/       # Deterministic building blocks (Intel, Info Gathering, System Memory)
│   ├── sandbox/     # Isolated execution environments for tools
│   └── tools/       # Reusable utilities (OOB, session management, etc.)
├── infra/           # Infrastructure & Deployment (Docker, Kubernetes)
└── documents/       # Project documentation (DB schemas, internal notes)
```

---

## 🚀 Getting Started (Docker)

You can run the entire PentaForge stack (Frontend, Backend, Redis, Qdrant) easily using Docker Compose.

1. Ensure you have Docker and Docker Compose installed.
2. Clone the repository and navigate to the project root:
   ```bash
   cd PentaForge
   ```
3. Boot the environment:
   ```bash
   docker compose -f infra/docker/docker-compose.yml up --build
   ```
4. Access the platform:
   * **Frontend UI**: `http://localhost:8080`
   * **Backend API**: `http://localhost:8000`

Desktop app:

- Docker does not open the Tauri desktop window by itself.
- To run the desktop shell against the Docker backend stack:
  ```bash
  bash scripts/run-desktop-with-docker.sh
  ```
- That script:
  - starts the Docker services
  - waits for the backend health check on `http://127.0.0.1:8000/api/health`
  - launches the Tauri desktop app from `client/ui`
- It reuses existing Docker images by default. Force a rebuild only when needed:
  ```bash
  bash scripts/run-desktop-with-docker.sh --build
  ```

See [infra/README.md](infra/README.md) for service details, persistence, and first-start notes.

Important behavior:

- the Docker image does not include your local vector data, knowledge cache, or model cache
- each machine creates its own runtime state inside Docker volumes on first use
- the `tool-sandbox` image now installs a broad recon/security toolchain during Docker build; rebuild it with:
  ```bash
  docker compose -f infra/docker/docker-compose.yml build tool-sandbox
  ```
- the sandbox now also ships catalog-aligned aliases and bundled wordlist paths like `/usr/share/wordlists/pentaforge` and `/usr/share/wordlists/SecLists`
- `./scripts/run-desktop-with-docker.sh` now auto-rebuilds backend/sandbox images when the Docker bootstrap files change and warms the local Nomic embedding model before the desktop window opens
- the desktop launcher now keeps the heavy sandbox image stable by default; use `--build-backend`, `--build-sandbox`, or `--build` when you want specific rebuilds
- reset all Docker-managed state with:
  ```bash
  docker compose -f infra/docker/docker-compose.yml down -v
  ```

---

## 🛡️ Core Principles

1. **Eliminate Hallucinations**: Agents are required to cite tool outputs and memory facts. Extrapolations are explicitly tagged as assumptions.
2. **Strict Verification**: No vulnerability is marked `confirmed_with_strong_proof` without deterministic validation.
3. **Safety Isolation**: High-risk execution runs in restricted sandboxes. Target scope is hardcoded and enforced at the infrastructure level, not just via LLM prompts.
4. **Human in the Loop (HitL)**: The UI acts as a mature operator console, explicitly waiting for user approval on destructive/high-risk tool executions.

---

## 📖 Additional Documentation
- [Backend Architecture Deep Dive](server/ARCHITECTURE.md)
- [Project Guide](PROJECT_GUIDE.md)
- [Databases](documents/DB.md)
