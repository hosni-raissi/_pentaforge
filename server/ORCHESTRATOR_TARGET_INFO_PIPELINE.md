# PentaForge Orchestrator Architecture

## Goal

Make the active scan path simple, memory-driven, and node-oriented:

1. `Intel node` refreshes or reuses RAG.
2. `Information gathering node` runs grouped static gathering by target type.
3. `System memory node` converts each finished block into durable memory.
4. `Checklist generation` uses gathered evidence plus checklist sources.
5. `Planner` builds the full plan from memory, not from scattered raw outputs.
6. `Executer -> Perceptor -> Verify -> Retest -> Planner` loops while system memory keeps the durable state.

This keeps responsibilities clean:

- nodes orchestrate stages
- agents do reasoning or execution
- system memory is the shared evidence layer
- planner chooses only the next two runnable scenarios with `priority=6`

## Active Flow

### Step 1. Intel Node

Path:

- [server/nodes/intel/node.py](/home/hosnizap/projects/PentaForge/server/nodes/intel/node.py)

Role:

- refresh or reuse RAG only
- no planning
- no checklist persistence logic

Input:

- `target_type`
- `info`
- `project_id`

Output:

- update-only Intel result
- RAG freshness / refresh stats

Current runtime use:

- [server/app/orchestrator.py](/home/hosnizap/projects/PentaForge/server/app/orchestrator.py)

### Step 2. Information Gathering Node

Paths:

- [server/nodes/information_gathering/node.py](/home/hosnizap/projects/PentaForge/server/nodes/information_gathering/node.py)
- [server/nodes/information_gathering/config.py](/home/hosnizap/projects/PentaForge/server/nodes/information_gathering/config.py)
- [server/nodes/information_gathering/prompts.py](/home/hosnizap/projects/PentaForge/server/nodes/information_gathering/prompts.py)

Role:

- accept target info + static grouped scenario profile
- ask the LLM to trim the block before execution
- remove mismatched tools
- optionally add a single scoped `run_custom` entry when clearly justified
- run tools block by block
- hand raw results to system memory for organization

Input:

- `target`
- `target_type`
- `scope`
- `info`
- `profile.blocks[]`
- `tool_map`
- deterministic tool-argument builder callback

Output:

- updated runtime memory payload
- one organized memory block per gathering block

LLM preparation contract:

- input: target + scope + info + candidate block
- output:

```json
{
  "status": "run",
  "name": "Fingerprinting",
  "goal": "Identify the live HTTP surface and stack.",
  "interaction": "active_safe",
  "tools": [
    "http_probe",
    "detect_tech",
    {
      "tool": "run_custom",
      "command": "curl",
      "args": ["-I", "http://127.0.0.1"],
      "reason": "Confirm simple HTTP header behavior."
    }
  ],
  "rationale": "Loopback target; keep local HTTP tools only.",
  "skipped_tools": ["dns_recon"]
}
```

Execution contract per tool row:

```json
{
  "tool": "http_probe",
  "status": "completed",
  "summary": "200 OK ...",
  "args": {"target": "http://127.0.0.1"}
}
```

### Step 3. System Memory Node

Paths:

- [server/nodes/system_memory/node.py](/home/hosnizap/projects/PentaForge/server/nodes/system_memory/node.py)
- [server/system_memory/core.py](/home/hosnizap/projects/PentaForge/server/system_memory/core.py)
- [server/system_memory/config.py](/home/hosnizap/projects/PentaForge/server/system_memory/config.py)
- [server/system_memory/prompts.py](/home/hosnizap/projects/PentaForge/server/system_memory/prompts.py)

Role:

- initialize runtime memory
- organize grouped block output through an LLM
- save `memory.json` and `memory.md`
- compress markdown when it grows too large
- append later perceptor / verify / retest updates
- store checklist snapshots

Runtime files:

- `server/cache/project_runs/<run>/system_memory/memory.json`
- `server/cache/project_runs/<run>/system_memory/memory.md`

Input:

- grouped block metadata
- grouped raw tool results
- later dynamic updates
- checklist payload

Output:

- durable structured memory
- human-readable markdown memory

Organized block shape:

```json
{
  "id": "surface_mapping",
  "name": "Surface Mapping",
  "goal": "Map routes, APIs, and JS-exposed paths.",
  "interaction": "active_safe",
  "planned_tools": ["web_crawler", "api_endpoint_discovery"],
  "selection_rationale": "Loopback target; keep local HTTP mapping only.",
  "skipped_tools": ["dns_recon"],
  "status": "completed",
  "summary": "Mapped the local web surface and extracted client-side API clues.",
  "key_findings": ["..."],
  "risk_signals": ["..."],
  "open_questions": ["..."],
  "artifacts": ["http://127.0.0.1", "/main.js", "/api/users"],
  "results": [
    {
      "tool": "web_crawler",
      "status": "completed",
      "summary": "...",
      "artifacts": ["http://127.0.0.1"]
    }
  ]
}
```

### Step 4. Checklist Generation

Current implementation:

- the scan path still uses the Intel synthesis step after grouped gathering
- the grouped memory is passed into the synthesis input
- the synthesized checklist is stored back into system memory

Future target design:

- planner-owned checklist generation phase using system memory + checklist sources

Checklist storage contract:

```json
{
  "target_type": "web_app",
  "available_total": 20,
  "checklist": [
    {
      "phase": 1,
      "title": "Reconnaissance",
      "items": [
        {"name": "Identify Application Entry Points", "priority": 2}
      ]
    }
  ]
}
```

### Step 5. Planner

Paths:

- [server/agents/planner/prompts.py](/home/hosnizap/projects/PentaForge/server/agents/planner/prompts.py)
- [server/agents/planner/tools/pentest_plan.py](/home/hosnizap/projects/PentaForge/server/agents/planner/tools/pentest_plan.py)

Role:

- consume target info + grouped memory + checklist
- create the full plan
- choose the next two runnable scenarios with `priority=6`
- keep every other pending scenario in `priority=1..5`
- never invent exploit targets
- use recon evidence, visible inputs, or verified findings

Runnable-now rule:

- exactly two pending scenarios across Phases 1-3 should be `priority=6`
- they are the next scenarios the executer runs now
- they may be:
  - two recon
  - two exploit
  - one recon + one exploit

Planner scenario shape:

```json
{
  "task": "Test reflected XSS in visible search input on /search",
  "agent": "exploit",
  "priority": 6,
  "details": "Visible query parameter already confirmed by memory.",
  "methods": ["Direct visible-input payload testing with evidence-backed reflection checks."],
  "done": false
}
```

### Step 6. Executer Loop

Path:

- [server/app/orchestrator.py](/home/hosnizap/projects/PentaForge/server/app/orchestrator.py)

Role:

- read current plan
- normalize runnable-now priorities
- execute up to two `priority=6` scenarios
- hand raw execution rows to Perceptor

Dispatcher behavior:

- if planner marked two exploits as `priority=6`, run two exploit scenarios
- if planner marked two recon scenarios as `priority=6`, run two recon scenarios
- if planner marked one recon and one exploit as `priority=6`, run one of each
- if planner returns too many `priority=6`, the orchestrator keeps at most two pending P6 scenarios

### Step 7. Perceptor

Role:

- classify execution results honestly and aggressively
- separate:
  - information only
  - vulnerability candidates

Routing:

- `info_only` -> planner + system memory updates
- `vulnerability` -> verify

### Step 8. Verify

Role:

- disprove weak findings first
- decide:
  - `real_vulnerability`
  - `false_positive`
  - `inconclusive`

Routing:

- `real_vulnerability` -> system memory + retest + planner
- `false_positive` -> system memory + planner
- `inconclusive` -> system memory + planner

### Step 9. Retest

Role:

- produce stronger PoC evidence and reporting material
- run only after Verify confirms a real vulnerability

Routing:

- save proof-oriented updates into system memory
- send planner fresh state for the next loop

## Memory Strategy

The memory should become the project truth layer.

It currently stores:

- target overview
- grouped information-gathering profile
- grouped information-gathering results
- checklist
- dynamic updates
- verified findings
- artifact digest
- compressed snapshot when needed

Recommended interpretation:

- `memory.json` is the structured source of truth
- `memory.md` is the compressed LLM/human handoff format

## Input / Output Summary By Stage

### Intel Node

- input: `target_type`, `info`
- output: `rag_update_result`

### Information Gathering Node

- input: `target`, `target_type`, `scope`, `info`, `profile`, `tool_map`
- output: organized grouped memory blocks

### System Memory Node

- input: raw grouped results, checklist, dynamic findings
- output: `memory.json`, `memory.md`, compressed snapshot when needed

### Planner

- input: target profile + memory + checklist + later verify/perceptor state
- output: full plan with exactly two pending `priority=6` scenarios

### Executer

- input: current plan
- output: execution rows

### Perceptor

- input: execution rows
- output: classified findings

### Verify

- input: vulnerability candidates
- output: `real_vulnerability | false_positive | inconclusive`

### Retest

- input: verified real vulnerabilities
- output: stronger proof / report-ready evidence

## What Is Already Active

Already active in code:

- Intel node wrapper for update-only RAG refresh
- Information gathering node wrapper for grouped block execution
- System memory node wrapper for durable memory writes
- planner/runtime `priority=6` contract
- grouped gathering saved into runtime system memory before planning

Still legacy / not fully moved:

- some older warmup-era helpers still exist in [orchestrator.py](/home/hosnizap/projects/PentaForge/server/app/orchestrator.py)
- checklist synthesis still uses the Intel synthesis path instead of a planner-owned checklist stage

## Recommended Next Refactor

1. Move target-info profile defaults out of `orchestrator.py` into `server/nodes/information_gathering/static_profiles/`.
2. Add an explicit planner checklist-generation mode.
3. Remove dead warmup-only helper paths once the new loop is fully stable.
4. Split reporting into a cleaner final reporting node or report agent contract that consumes system memory directly.
