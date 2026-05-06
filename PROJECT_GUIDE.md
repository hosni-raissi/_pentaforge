# PentaForge: Advanced Agentic Penetration Testing Platform

PentaForge is a multi-agentic autonomous penetration testing platform designed to automate complex security assessments. It uses a "conductor-orchestra" model where a central service synchronizes specialized LLM-driven agents to perform reconnaissance, vulnerability analysis, and exploitation.

---

## 📂 Project Structure

The codebase is split into two main parts: a **React/TypeScript frontend** and a **Python/FastAPI backend**.

### 1. Root Directory
- `client/`: Frontend application (Vite + React + Tailwind + Lucide).
- `server/`: Backend application (FastAPI + LangGraph + Agents).
- `infra/`: Infrastructure configurations (Docker, deployments).
- `documents/`: Project-level documentation and assets.
- `scratch/`: Temporary development scripts and experimental code.
- `PROJECT_GUIDE.md`: This file (Project overview).

### 2. Backend (`server/`)
The backend is the core engine of PentaForge.
- `agents/`: LLM-driven decision makers.
    - `planner/`: Generates pentest plans and checklists.
    - `executer/`: Runs actual tools (split into `recon` and `exploit`).
    - `analyzer/`: Classifies findings, verifies vulnerabilities, and generates PoCs.
    - `assistant/`: Powers the real-time AI helper in the UI.
- `nodes/`: Semi-deterministic building blocks.
    - `intel/`: Manages global security knowledge (RAG).
    - `information_gathering/`: Deterministic target profiling.
    - `system_memory/`: The "Brain" that maintains state during a run.
- `api/`: FastAPI routes, middleware, and dependency injection.
- `app/`: Contains the `ScanOrchestratorService`, the conductor of the whole system.
- `db/`: Persistence layers (SQLite for projects, Qdrant for vectors, Redis for cache).
- `layers/`: Safety, sanitization, and privacy guardrails.
- `tools/`: Reusable utilities for OOB (Out-of-Band), session management, etc.
- `ARCHITECTURE.md`: Deep-dive into the server's internal design.

### 3. Frontend (`client/ui/src/`)
A modern React application providing a real-time dashboard for scan monitoring.
- `pages/`: Main application views (`Dashboard`, `Projects`, `Settings`).
- `components/`: Reusable UI elements (Buttons, Cards, Modals, etc.).
- `stores/`: State management (Zustand) for projects, scans, and UI state.
- `hooks/`: Custom React hooks for SSE (Server-Sent Events) and API calls.
- `types/`: TypeScript interfaces and type definitions.

---

## ⚙️ How It Works (The Scan Flow)

PentaForge operates in a cyclic, multi-phase pipeline:

1.  **Intel Phase**: The system refreshes global knowledge (RAG) and builds a target-specific checklist.
2.  **Information Gathering**: Deterministic tools (nmap, tech detection) build a profile of the target.
3.  **Brain Projection**: Raw findings are normalized into a "Brain" state that agents can reason about.
4.  **Planning**: The `PlannerAgent` creates a multi-step pentest plan based on the target profile.
5.  **Execution Loop**: 
    - **Executer** runs scenarios (Recon or Exploit) using specialized tools.
    - **Analyzer** evaluates output to find vulnerabilities or information.
    - **Planner** updates the plan based on new discoveries.
6.  **Verification & Reporting**: Analyzer verifies findings with PoCs and persists them to the project database.

---

## 🛠️ Technology Stack

- **Frontend**: React, TypeScript, Vite, Tailwind CSS, Lucide Icons, Zustand (State).
- **Backend**: Python 3.11+, FastAPI, LangGraph (Agentic loops), Uvicorn.
- **LLM/AI**: OpenAI/Anthropic/Google models via unified core, LangChain primitives.
- **Database**: SQLite (Metadata), Qdrant (Vector/RAG), Redis (Ephemeral cache).
- **Communication**: SSE (Server-Sent Events) for real-time log and status streaming.

---

## 📖 Key Documentation
- **Server Architecture**: [server/ARCHITECTURE.md](file:///home/hosnizap/projects/PentaForge/server/ARCHITECTURE.md)
- **Deployment**: `infra/README.md` (if exists)
