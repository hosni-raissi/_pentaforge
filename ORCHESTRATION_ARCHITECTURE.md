# PentaForge Agent Orchestration Architecture

## High-Level Flow

```
┌───────────────────────────────────────────────────────────────────────────────┐
│                          Application Lifecycle                                 │
└────┬────────────────────────────────────────────────────────────────────────┬──┘
     │                                                                          │
     │ START                                                            STOP when
     │                                                                  Planner says
     │                                                                  "done"
     │
     ▼
┌─────────┐
│  INTEL  │ Run ONCE at start
│         │ ├─ Create checklist from target
│         │ └─ Pass to Planner
└────┬────┘
     │
     ▼
┌────────────┐
│  PLANNER   │ Create initial plan
│ (Cycle 1)  │ ├─ Define phases
└────┬───────┘ ├─ Select methodologies
     │         └─ Return to Executer
     │
     ├──────────────────────────────────────────────┐
     │                                              │
     │ CYCLE LOOP (Repeats until no tasks left)    │
     │                                              │
     ▼                                              │
┌──────────────┐                                   │
│  EXECUTER    │ Choose 2 scenarios:                │
│ (Multi-task) │ ├─ ONE Recon (if available)       │
│              │ ├─ ONE Exploit (if available)      │
└┬────────┬────┘ └─ With priority ordering          │
 │        │                                         │
 │ ASYNC  │                                         │
 │        │                                         │
 ▼        ▼                                         │
┌─────┐  ┌──────┐                                  │
│RECON│  │EXPLOIT│ Run in PARALLEL                │
│     │  │       │ ├─ Don't wait for each other  │
│     │  │       │ ├─ Fire results as they       │
│     │  │       │ │  complete (no blocking)     │
│     │  │       │ └─ Each sends to Perceptor    │
└──┬──┘  └───┬───┘    independently               │
   │        │                                     │
   │ ASYNC  │ RESULTS STREAM TO PERCEPTOR         │
   │        │                                     │
   └────┬───┘                                     │
        │                                          │
        ▼                                          │
   ┌──────────┐                                   │
   │PERCEPTOR │ ASYNC start (no blocking)         │
   │          │ ├─ Receive Recon result          │
   │          │ ├─ Process immediately           │
   │          │ ├─ Receive Exploit result        │
   │          │ ├─ Process immediately           │
   │          │                                   │
   │ DECISION │ For each finding:                  │
   │ ENGINE   │ ├─ CRITICAL → call Verify         │
   │          │ ├─ EXPLOITED → call Retest       │
   │          │ ├─ CHAIN → call Verify + Retest  │
   │          │ └─ INFO → queue to Planner        │
   │          │                                   │
   │ DYNAMIC  │ Run Verify/Retest sequentially   │
   │ TRIGGER  │ as findings arrive (one by one)  │
   └────┬─────┘                                   │
        │                                          │
        ├─ Collect all organized results          │
        │                                          │
        ▼                                          │
   ┌──────────┐                                    │
   │   INTEL  │ Consolidate findings              │
   │ Aggregate│ ├─ All verified findings          │
   │          │ ├─ All retest confirmations       │
   │          │ ├─ Maintain historical context    │
   │          │ └─ Pass to Planner with context   │
   └────┬─────┘                                    │
        │                                          │
        ▼                                          │
   ┌─────────────┐                                │
   │  PLANNER    │ UPDATE PLAN or KEEP            │
   │ (Cycle N+1) │ ├─ Review new findings         │
   │             │ ├─ Identify next scenarios     │
   │             │ ├─ Return to Executer OR       │
   │             │ └─ Say "done" → STOP APP       │
   │             │                                │
   └─────┬───────┘                                │
         │                                        │
         └────────────────────────────────────────┘
              BACK TO EXECUTER if not done
```

## Detailed Agent Responsibilities

### 1. INTEL (Startup Only)
```python
# Run ONCE during initialization
class IntelAgent:
    async def create_checklist(self, target):
        """
        Generate the initial security checklist
        Returns: Checklist with all aspects to test
        """
        checklist = {
            "web_app": ["waf", "auth", "injection", ...],
            "api": ["endpoints", "auth", "rate_limit", ...],
            "container": ["registry", "layers", "config", ...],
            "infra": ["db", "secrets", "network", ...],
        }
        return checklist
        # Pass directly to Planner - ONLY RUNS ONCE
```

### 2. PLANNER (Cyclic)
```python
# Runs multiple times (once per cycle)
class PlannerAgent:
    async def create_plan(self, checklist, previous_findings=None):
        """
        Cycle 1: Create initial plan from checklist
        Cycle N+1: Update plan based on findings
        Returns to Executer when ready
        """
        return {
            "current_phase": "initial_recon",
            "scenarios": [
                {
                    "id": "recon_web_001",
                    "type": "recon",
                    "target_aspect": "web_app",
                    "priority": 1,
                    "status": "pending"
                },
                {
                    "id": "exploit_auth_001",
                    "type": "exploit",
                    "target_aspect": "auth_bypass",
                    "priority": 1,
                    "status": "pending"
                }
            ]
        }

    async def say_done(self):
        """Signal that pentest is complete"""
        return {"status": "DONE", "final_report": {...}}
```

### 3. EXECUTER (Coordination Logic)
```python
# Main orchestration loop
class ExecuterAgent:
    async def execute_cycle(self, plan):
        """
        Cycle execution:
        1. Select 2 scenarios from plan (pending, priority-ordered)
        2. Run them in parallel
        3. Don't wait - fire results to Perceptor as they complete
        """
        pending_scenarios = filter(lambda s: s["status"] == "pending", plan["scenarios"])

        # Pick 1 recon (highest priority)
        recon_task = next((s for s in pending_scenarios if s["type"] == "recon"), None)

        # Pick 1 exploit (highest priority)
        exploit_task = next((s for s in pending_scenarios if s["type"] == "exploit"), None)

        tasks = [t for t in [recon_task, exploit_task] if t is not None]

        # PARALLEL execution - no blocking
        for task in tasks:
            asyncio.create_task(self.run_agent(task))
            # Fire and forget - agent sends results directly to Perceptor

    async def run_agent(self, scenario):
        """Execute agent and stream results to Perceptor"""
        if scenario["type"] == "recon":
            result = await recon_agent.execute(scenario)
        else:
            result = await exploit_agent.execute(scenario)

        # Send to Perceptor WITHOUT WAITING
        await perceptor.ingest_finding(result)
        # Mark scenario as done in plan
        scenario["status"] = "done"
```

### 4. RECON Agent (Parallel Worker)
```python
class ReconAgent:
    async def execute(self, scenario):
        """
        Run recon scan
        Returns result immediately to Perceptor
        Doesn't wait for Exploit agent
        """
        result = await self.scan_web_app()
        # Perceptor will receive this while Exploit is still running
        return {
            "type": "recon",
            "findings": [...],
            "timestamp": now(),
            "scenario_id": scenario["id"]
        }
```

### 5. EXPLOIT Agent (Parallel Worker)
```python
class ExploitAgent:
    async def execute(self, scenario):
        """
        Run exploit attempts
        Returns result independently to Perceptor
        Doesn't wait for Recon agent
        """
        result = await self.try_exploits()
        # Perceptor will receive this whenever it completes
        return {
            "type": "exploit",
            "findings": [...],
            "timestamp": now(),
            "scenario_id": scenario["id"]
        }
```

### 6. PERCEPTOR (Dynamic Decision Engine)
```python
class PerceptorAgent:
    def __init__(self):
        self.inbox = asyncio.Queue()  # Streaming results
        self.organized_findings = []

    async def process_stream(self):
        """
        Start processing immediately when first result arrives
        Don't wait for all agents to finish
        """
        while True:
            # Non-blocking receive
            result = await asyncio.wait_for(
                self.inbox.get(),
                timeout=10  # Wait max 10s for next result
            )

            # Process this result immediately
            await self.analyze_result(result)

    async def analyze_result(self, result):
        """
        Decision Logic:
        - Finding is CRITICAL → Call Verify immediately
        - Finding is EXPLOITED → Call Retest immediately
        - Finding is CHAIN → Call both Verify + Retest
        - Finding is just INFO → Queue for Planner
        """
        for finding in result["findings"]:
            if finding["severity"] == "CRITICAL":
                # Verify immediately
                verified = await verify_agent.verify(finding)
                self.organized_findings.append(verified)

            elif finding["type"] == "EXPLOIT_SUCCESS":
                # Retest for consistency
                retested = await retest_agent.retest(finding, iterations=3)
                self.organized_findings.append(retested)

            elif finding.get("is_chain"):
                # Do both: verify full chain, then retest
                verified = await verify_agent.verify(finding)
                retested = await retest_agent.retest(verified, iterations=2)
                self.organized_findings.append(retested)

            else:
                # Just info, queue for planner
                self.organized_findings.append(finding)

    async def consolidate(self):
        """
        After both Recon and Exploit finish:
        - Wait for any pending Verify/Retest to complete
        - Organize all findings
        - Send to Intel for historical consolidation
        """
        await asyncio.sleep(1)  # Small buffer for pending tasks

        # Consolidate to Intel
        await intel_agent.update_history(self.organized_findings)

        # Send to Planner
        return {
            "status": "findings_ready",
            "findings": self.organized_findings,
            "recommendation": "update_plan" or "continue" or "done"
        }
```

### 7. VERIFY Agent (Triggered)
```python
class VerifyAgent:
    async def verify(self, finding):
        """
        Called on-demand by Perceptor for critical/chain findings
        Returns snapshot + PoC
        """
        return {
            "original_finding": finding,
            "verified": True,
            "proof_of_existence": {...},
            "snapshot": {...}
        }
```

### 8. RETEST Agent (Triggered)
```python
class RetestAgent:
    async def retest(self, finding, iterations=3):
        """
        Called on-demand by Perceptor for exploited findings
        Tests consistency across multiple attempts
        """
        results = []
        for i in range(iterations):
            result = await self.re_exploit(finding)
            results.append(result)

        return {
            "original_finding": finding,
            "retest_iterations": iterations,
            "success_count": sum(1 for r in results if r["success"]),
            "consistency": sum(1 for r in results if r["success"]) / iterations
        }
```

## Execution Timeline Example

```
T=0s    │ INTEL creates checklist
        │
T=1s    │ PLANNER creates plan with 2 scenarios:
        │ ├─ Recon (priority 1)
        │ └─ Exploit (priority 1)
        │
T=2s    │ EXECUTER launches both
        │ ├─ Recon agent starts
        │ └─ Exploit agent starts
        │
T=3s    │ PERCEPTOR starts listening
        │
T=5s    │ Recon FINISHES → Result sent to Perceptor
        │ ├─ Finds 3 endpoints
        │ ├─ Perceptor receives immediately
        │ └─ Processes: queue to Planner
        │
        │ [Exploit STILL RUNNING in parallel]
        │
T=7s    │ Exploit FINISHES → Result sent to Perceptor
        │ ├─ Finds 1 CRITICAL auth bypass
        │ ├─ Perceptor receives immediately
        │ └─ CRITICAL decision: Call VERIFY
        │
T=8s    │ VERIFY agent starts on critical finding
        │
T=10s   │ VERIFY completes → Result to Perceptor
        │
T=11s   │ PERCEPTOR consolidates all findings
        │ ├─ Recon: 3 endpoints (INFO)
        │ ├─ Exploit: auth bypass (VERIFIED)
        │ └─ Send to Intel for history
        │
T=12s   │ PLANNER receives consolidated findings
        │ ├─ Reviews findings
        │ ├─ Updates plan for next cycle
        │ └─ Returns next 2 scenarios
        │
T=13s   │ EXECUTER launches new cycle...
        │
        └─ Loop continues until Planner says "done"
```

## Key Communication Patterns

### Results Flow (Fire & Forget)
```
Recon Agent → Perceptor.ingest_finding()  [async, no blocking]
Exploit Agent → Perceptor.ingest_finding()  [async, no blocking]
```

### Dynamic Triggering
```
Perceptor → Verify.verify(critical_finding)   [on-demand]
Perceptor → Retest.retest(exploited_finding)  [on-demand]
```

### Consolidation Flow
```
Perceptor → Intel.update_history(findings)    [after processing]
Intel → Planner.next_cycle(findings)          [history + context]
Planner → Executer.execute_cycle(plan)        [updated plan]
```

## Context Window Management

Each agent maintains its own 15k token context:
- **Intel**: Checklist history (small)
- **Planner**: Plan evolution + finding context (grows with cycles)
- **Recon**: Scan state (auto-compress)
- **Exploit**: Exploitation attempts (auto-compress)
- **Perceptor**: Finding analysis + decisions (auto-compress)
- **Verify**: Finding verification (auto-compress)
- **Retest**: Consistency testing (auto-compress)

Compression happens when reaching max tokens, summarizing:
```
[OLD ENTRIES 1-20] → SUMMARY → [RECENT ENTRIES 21-26]
```

## Stop Conditions

The application STOPS when:
1. Executer has no more pending scenarios in plan
2. All agents finish their current tasks
3. **Planner explicitly returns: `{"status": "DONE"}`**

At this point:
- Intel has consolidated full history
- All findings are verified/retested as needed
- Planner has reviewed and approved completion
