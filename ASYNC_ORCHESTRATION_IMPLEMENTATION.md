# PentaForge Async Orchestration Implementation Guide

## Overview

The new orchestration system implements **async streaming architecture** with **dynamic agent triggering** based on Perceptor intelligence. The application cycles through scenarios until the Planner declares completion.

## System Lifecycle

```
START
  ↓
INTEL (once)
  ├─ Create security checklist
  └─ Return to Planner
  ↓
PLANNER (cycle 1)
  ├─ Create initial plan
  └─ Return to Executer
  ↓
EXECUTER (cycles 1-N)
  ├─ Select up to 2 scenarios: 1 recon + 1 exploit (highest priority)
  ├─ Launch both in PARALLEL (non-blocking)
  │
  ├─ RECON finishes → Results to Perceptor immediately
  │
  ├─ EXPLOIT finishes → Results to Perceptor immediately
  │
  └─ PERCEPTOR starts processing results as they arrive
      ├─ CRITICAL findings     → Call VERIFY (on-demand)
      ├─ EXPLOITED findings    → Call RETEST (on-demand)
      └─ INFO findings         → Queue to PLANNER
          ↓
          PLANNER (cycle 2+)
          ├─ Review evidence from Perceptor
          ├─ Mark executed scenarios done
          ├─ Add next scenarios
          └─ Return to Executer OR say "done"
             ↓
             If "done" → STOP APPLICATION
             If more scenarios → Loop back to EXECUTER
```

## Key Components

### 1. Orchestrator (`server/app/orchestrator.py`)

Main orchestration loop in `_run_execution_cycle()`:

```python
async def _run_execution_cycle(
    self,
    *,
    plan_data: dict[str, Any],
    recon_agent: Any,
    exploit_agent: Any,
    verify_agent: Any,
    retest_agent: Any,
    perceptor_agent: Any,
    loop_planner: Any,
    target: str,
    target_type: str,
    scope: str,
    info: str,
    intel_checklist: dict[str, Any],
) -> tuple[bool, dict[str, Any]]:
    """
    One cycle: select scenarios → run parallel → perceptor decides → verify/retest/plan.

    Returns: (should_continue, updated_plan_data)
        should_continue=False means Planner said "done"
    """
```

**Flow**:
1. Select up to 2 scenarios (1 recon, 1 exploit) from pending list
2. Run them in parallel using `asyncio.gather(...)`
3. Process each result through Perceptor
4. Perceptor makes decisions:
   - **CRITICAL** → Call `verify_agent.run()` immediately
   - **EXPLOITED** → Call `retest_agent.run()` immediately
   - **INFO** → Route to `loop_planner.run()` for plan update
5. Return updated plan and continue flag

**Cyclic Loop** in `_run_scan()`:
```python
while cycle_count < max_cycles:
    cycle_count += 1
    should_continue, updated_plan = await self._run_execution_cycle(...)
    plan_data = updated_plan

    if not should_continue:
        # Planner said "done"
        break
```

### 2. Planner Agent (`server/agents/planner/agent.py`)

**Initial Run** (`is_loop=False`):
- Creates multi-phase plan with scenarios
- Scenarios have `done: false` status
- Returns plan structure

**Loop Runs** (`is_loop=True`):
- Receives Perceptor's compact evidence summary
- Updates plan based on evidence
- Marks executed scenarios `done: true`
- Adds next scenarios or returns "Pentest complete."

**Completion Signal**:
```python
# When all critical items tested and no other scenarios pending
summary = "Pentest complete."
return {
    "status": "DONE",
    "summary": "Pentest complete.",
    ...
}
```

Application stops when `summary.lower().contains("complete")`

### 3. Perceptor Agent (`server/agents/perceptor/agent.py`)

**Decision Engine** via `assess_tool_results()`:

```python
async def assess_tool_results(
    self,
    scenario: dict[str, Any],
    tool_results: list[dict[str, Any]],
    asset_context: dict[str, Any],
) -> dict[str, Any]:
    """
    Analyze findings and return:
    {
        "overall": {
            "ssvc": "ACT" | "ATTEND" | "TRACK",
            "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO",
            "confidence": "high" | "medium" | "low",
        },
        "compact_summary": "...",  # For next agent
        "findings": [...],
    }
    """
```

**Routing Logic**:
```python
if severity == "CRITICAL":
    return "verify"  # Perceptor will call Verify agent
elif severity == "HIGH" and exploited:
    return "retest"  # Perceptor will call Retest agent
else:
    return "planner"  # Perceptor returns to Planner for update
```

**Compact Summaries** (token-efficient for next agent):
- For Planner: "Found 5 endpoints under /api/v1. Tech stack: Node.js+Express. No vulns yet. Recommend: fuzz params."
- For Verify: "SQLi in POST /api/search?q. Time-based blind with 5s delay confirmed. Test for data extraction."
- For Retest: "Auth bypass on /api/login: admin:admin123. Verify 3x for consistency."

### 4. Recon Executer (`server/agents/executer/recon/agent.py`)

**Async Execution**:
- Launched in parallel with Exploit
- Completes whenever its scans finish
- Sends results to Perceptor immediately
- **Does NOT wait** for Exploit agent

**Returns**:
```python
{
    "status": "complete",
    "findings": [...],  # Endpoints, services, tech stack, secrets
    "evidence": [...],
    "attack_surface": {...},
    "summary": "...",
}
```

### 5. Exploit Executer (`server/agents/executer/exploit/agent.py`)

**Async Execution**:
- Launched in parallel with Recon
- Completes whenever exploits finish
- Sends results to Perceptor immediately
- **Does NOT wait** for Recon agent

**Returns**:
```python
{
    "status": "complete",
    "exploitation_result": {...},
    "findings": [...],  # Successful exploits, WAF detection
    "evidence": [...],
    "summary": "...",
}
```

### 6. Verify Executer (`server/agents/executer/verify/agent.py`)

**On-Demand Triggering**:
- Called by Perceptor ONLY when CRITICAL findings exist
- NOT in the main plan
- High priority: confirm vulnerability

**Task**:
```
Input:  CRITICAL finding from Perceptor
        ├ SQLi found in POST /api/search?q
        ├ Auth bypass on /api/login with default creds
        └ RCE via template injection in /template endpoint

Process:
  1. Reproduce finding under controlled conditions
  2. Capture before/after screenshots
  3. Use vision model to confirm (false positive detection)
  4. Generate evidence chain with SHA-256 hashes

Output:
  {
      "status": "verified|false_positive|inconclusive",
      "verification_result": {...},
      "vision_analysis": {...},
      "evidence_chain": {...},
  }
```

### 7. Retest Executer (`server/agents/executer/retest/agent.py`)

**On-Demand Triggering**:
- Called by Perceptor ONLY when finding is EXPLOITED and HIGH severity
- NOT in the main plan
- Mission: Test consistency across multiple attempts

**Task**:
```
Input:  EXPLOITED finding from Perceptor
        ├ Auth bypass confirmed: admin:admin123
        ├ RCE confirmed: /bin/id executed
        └ Data extraction confirmed: 500+ records leaked

Process:
  1. Replay exploit 3 times
  2. Measure success rate (3/3, 2/3, 1/3, 0/3)
  3. Test bypass mutations if original blocked on retest
  4. Calculate consistency_score (0.0-1.0)

Output:
  {
      "status": "complete",
      "retest_result": {
          "verdict": "stable|inconsistent|bypassed",
          "consistency_score": 0.85,  # 3/3 attempts succeeded
      },
  }
```

## Execution Timeline Example

### Cycle 1 (Recon + Exploit)

```
T=0s    PLANNER creates initial plan
        Scenarios:
          - recon_web_discovery (priority 1)
          - exploit_default_creds (priority 1)

T=1s    EXECUTER selects both

T=2s    RECON starts    |    EXPLOIT starts
        (parallel, non-blocking)

T=5s    RECON finishes  |    EXPLOIT still running
        ├ Found 10 endpoints
        ├ Sends to Perceptor
        └ Perceptor receives (no blocking)

T=8s    EXPLOIT finishes
        ├ Found auth bypass
        ├ CRITICAL severity
        ├ Sends to Perceptor
        └ Perceptor receives (no blocking)

T=9s    PERCEPTOR processes RECON findings
        ├ 10 endpoints = INFO only
        ├ Route: planner

T=10s   PERCEPTOR processes EXPLOIT findings
        ├ Auth bypass = CRITICAL
        ├ Route: verify
        ├ Calls VERIFY agent on-demand

T=15s   VERIFY finishes
        ├ Confirms auth bypass is real
        ├ Returns to Perceptor

T=16s   PERCEPTOR consolidates all findings
        ├ Recon: 10 endpoints [INFO]
        ├ Exploit: auth bypass [VERIFIED]
        └ Sends to Intel + Planner

T=17s   PLANNER cycles (cycle 2)
        ├ Marks recon_web_discovery done
        ├ Marks exploit_default_creds done
        ├ Adds next scenarios based on evidence
        └ Returns to EXECUTER

T=18s   EXECUTER cycle 2...
        (Loop continues until Planner says "done")
```

## Data Flow Diagram

```
RECON (parallel)          EXPLOIT (parallel)
   ↓                         ↓
   └─────────────┬───────────┘
                 ↓
           PERCEPTOR (async decision)
                 │
        ┌────────┼────────┐
        ↓        ↓        ↓
      VERIFY   RETEST   PLANNER
        ↓        ↓        ↓
        └────────┬────────┘
                 ↓
              INTEL (consolidates)
                 ↓
             PLANNER (cycles)
```

## Context Window Management

Each agent maintains 15k token context:

| Agent     | Context Purpose |
|-----------|-----------------|
| Planner   | Plan state + evidence history |
| Perceptor | Findings assessment + decisions |
| Recon     | Scan state + observations |
| Exploit   | Test attempts + discoveries |
| Verify    | Verification attempts + evidence |
| Retest    | Replay attempts + consistency |
| Intel     | Historical consolidation |

**Auto-compression when reaching 15k tokens**:
```
[ENTRIES 1-20] (old) → SUMMARY + [ENTRIES 21-26] (recent)
```

## Stop Conditions

Application **STOPS** when:

1. Planner returns: `summary.lower().contains("complete")`
2. AND all agent closures complete successfully
3. Final scan result saved to project

**NOT triggered by**:
- Empty scenarios (continues asking Planner)
- Failed tasks (continues with next scenario)
- Executor error (bubbles up, marked as failed scan)

## Configuration

See `server/agents/config_context_windows.json` for per-agent settings:
- `max_tokens`: 15000
- `compression_strategy`: "keep_recent_50_entries"
- `consolidation_target`: "intel" or "planner"

## Implementation Checklist

- [x] Orchestrator.py updated with `_run_execution_cycle()`
- [x] Cyclic loop in `_run_scan()` with max_cycles=20
- [x] Planner prompts updated for cyclic update behavior
- [x] Perceptor prompts with decision engine logic
- [x] Recon/Exploit prompts for parallel non-blocking execution
- [x] Verify/Retest prompts for on-demand triggering
- [x] Scenario selection: 1 recon + 1 exploit max
- [x] Parallel execution: `asyncio.gather()` with no blocking
- [x] Perceptor routing: CRITICAL → verify, EXPLOITED → retest, else → planner
- [x] Completion detection: "Pentest complete." signal
- [ ] Testing: Execute full cycle with mock agents
- [ ] Token monitoring: Ensure context windows don't overflow
- [ ] Evidence preservation: Crypto signing in Verify/Retest

## Next Steps

1. **Test Orchestrator Loop**: Run with mock data to verify cycle mechanics
2. **Agent Integration**: Ensure all agents support async/streaming properly
3. **Error Handling**: Add retry logic for failed scenarios
4. **Monitoring**: Add timing telemetry for cycle performance
5. **Documentation**: User guide for reading end-to-end reports
