# Verify-Driven Orchestration Architecture - Summary

## Before vs After

### OLD FLOW (Parallel Branching)
```
Recon/Exploit Results
         ↓
     PERCEPTOR
    / | | \
   /  | |  \
[CRITICAL] [HIGH] [MEDIUM] [LOW] [INFO]
  ↓      ↓      ↓       ↓      ↓
VERIFY  RETEST RETEST PLANNER PLANNER
```
**Problem**: Multiple routes, complex decision-making, Retest could run without Verify

---

### NEW FLOW (Linear Chain with Gatekeeper)
```
Recon/Exploit Results
         ↓
     PERCEPTOR
    /         \
[Finding]   [INFO]
  ↓          ↓
VERIFY   PLANNER
  │         ↑
  ├─ [Real Vuln] → PLANNER (update) + RETEST (report) ─→┘
  │
  └─ [False Positive] → PLANNER (rejection report) ──────┘
```
**Benefit**: Single entry point (Verify) filters false positives, guarantees report quality

---

## Key Role Changes

| Agent | OLD Role | NEW Role | Called By |
|-------|----------|----------|-----------|
| **Perceptor** | Route by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) | Classify: finding or info? | Executer |
| **Verify** | Confirm CRITICAL findings only | Gate: filter false positives, split real/fake | Perceptor (all findings) |
| **Retest** | Consistency test (3 attempts, success rate) | Report builder (PoC + structure) | Verify (real vulns only) |
| **Planner** | Receive from Perceptor+Verify | Receive from Perceptor+Verify+False-Positive | Orchestrator |

---

## Decision Points

### Perceptor Question:
> **Is this a security finding (vulnerability) or just reconnaissance data?**
- **Finding** → Route to VERIFY
- **INFO** → Route to PLANNER directly

### Verify Verdict:
> **Is this finding a real vulnerability or a false positive?**
- **Real Vulnerability** → Planner (plan update) + Retest (PoC report)
- **False Positive** → Planner only (rejection report, no Retest)
- **Inconclusive** → Planner only (needs manual review, no Retest)

### Retest Report Entry:
> **Build structured vulnerability report for project database**
- Execute PoC 1-2 times for proof
- Capture evidence (screenshots, logs, data)
- Generate CVSS score
- Create remediation guidance
- Save to project report

---

## Execution Timeline (Example)

```
T=0s    Cycle starts: Recon & Exploit launched (parallel)

T=5s    RECON finishes: "Found 5 API endpoints"
        → Perceptor analyzes
        → Decision: INFO only
        → Route to PLANNER
        → Planner queues for plan update

T=8s    EXPLOIT finishes: "Auth bypass on /api/login"
        → Perceptor analyzes
        → Decision: FINDING (vulnerability)
        → Route to VERIFY

T=10s   VERIFY agent starts confirming auth bypass
        → Reproduce the attack
        → Capture evidence
        → Analyze for false positives

T=15s   VERIFY finishes: "Real vulnerability confirmed"
        → Verdict: real_vulnerability
        → Send to PLANNER: "Confirmed auth bypass - update plan"
        → Send to RETEST: "Build report entry for this vuln"

T=20s   RETEST builds report:
        → Execute PoC 1-2 more times
        → Generate CVSS score
        → Create "Unauthorized Access via Default Creds" entry
        → Save to project report database

T=21s   PLANNER receives evidence:
        - 5 endpoints discovered
        - 1 authentication bypass verified & reported
        → Updates plan
        → Returns to EXECUTER for cycle 2

T=22s   Cycle continues...
```

---

## Quality Assurance Pipeline

```
┌─────────────────────────────────────────────────┐
│         Raw Findings (Recon/Exploit)           │
└──────────────────┬──────────────────────────────┘
                   │
        ┌──────────▼──────────┐
        │    PERCEPTOR        │ [Finding or Info?]
        │  - Classify type    │
        └──────────┬──────────┘
                   │
        ┌──────────┴───────────┐
        ▼                      ▼
    [Finding]            [INFO Only]
        │                      │
        ▼                      ▼
    VERIFY □               PLANNER ←─────┐
    [Confirm?]                           │
       │                                 │
    ┌──┴──┐                              │
    ▼     ▼                              │
[Real] [False]                           │
    │    └─ Report ──→ PLANNER ────────┐ │
    │                                   │ │
    └─ Report ──→ RETEST →┐             │ │
                           ▼             │ │
                  [Save to Report DB]   │ │
                           │             │ │
                           └────────────→ │
                                         ▼
                                    [Update Plan]
                                         │
                                         ▼
                                   [Next Cycle]
```

---

## What This Achieves

✅ **False Positive Filtering**: Verify eliminates fake vulnerabilities before reporting
✅ **Quality Assurance**: All reported findings are verified as real
✅ **Structured Reporting**: Retest builds professional report entries
✅ **Cleaner Architecture**: Linear flow instead of parallel routes
✅ **Better Context**: Planner knows what was verified vs just informational
✅ **Report Database**: Finding data saved immediately after confirmation

---

## Prompt Changes Summary

| File | Change |
|------|--------|
| `perceptor/prompts.py` | Decision simplified: "vulnerability" or "info" only |
| `verify/prompts.py` | Output format changed to verdict + send_to_planner + send_to_retest |
| `retest/prompts.py` | Role changed from consistency tester to report builder |
| `orchestrator.py` | Execution flow changed to linear chain: Finding → Verify → [Real→Planner+Retest] OR [False→Planner] |

---

## Notes for Implementation

- Perceptor now outputs: `{finding_type: "vulnerability"|"info", compact_summary: "..."}`
- Verify outputs: `{verdict: "real_vulnerability"|"false_positive"|"inconclusive", send_to_planner: {...}, send_to_retest: {...}|null}`
- Retest saves findings to project report database (new responsibility)
- All three agents use updated prompts reflecting new roles
- Orchestrator implements linear chain in `_run_execution_cycle()`
