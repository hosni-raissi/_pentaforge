# PentaForge Orchestration - Verify-Driven Chain Architecture

## New Agent Flow

```
RECON (parallel)          EXPLOIT (parallel)
   ↓                         ↓
   └─────────────┬───────────┘
                 ↓
           PERCEPTOR (decision)
                 │
        ┌────────┴────────┐
        ↓                 ↓
    [Vuln Found]      [INFO Only]
        ↓                 ↓
      VERIFY          PLANNER
        ↓                 ↑
    [Real Vuln]      [Updates Plan]
        │                 ↑
        ├─→ PLANNER ──────┘  (update plan with confirmed vuln)
        │
        └─→ RETEST (called by Verify only)
                ↓
            [Save PoC]
                ↓
            [Save to Report]
                ↓
              DONE

    [False Positive]
        ↓
    PLANNER (short report: "not a real vuln")
        ↓
      [Updates Plan]
```

## Key Changes

### 1. **Perceptor Role (Simplified)**
- Receives results from Recon/Exploit
- Decision: Is this a vulnerability finding OR just information?
  - **Finding** → route to VERIFY (all vulns, regardless of severity)
  - **INFO only** → route directly to PLANNER

### 2. **Verify Agent Role (Gatekeeper)**
- **Input**: Finding from Perceptor with evidence
- **Process**:
  - Reproduce finding under controlled conditions
  - Eliminate false positives using vision/analysis
  - Confirm real vulnerability with clear indicators
- **Output Two Paths**:
  - **Real Vulnerability**: Send to both PLANNER (for plan update) AND RETEST (for PoC confirmation)
  - **False Positive**: Send short report to PLANNER only (don't call Retest)

### 3. **Retest Agent Role (Report Builder)**
- **Input**: Confirmed vulnerability from Verify (with PoC)
- **Process**:
  - Execute PoC 1-3 times
  - Generate report data (screenshots, logs, evidence)
  - Build structured finding for project report
- **Output**: Save to project report database
- **Note**: Called ONLY by Verify, not by Perceptor

### 4. **Planner Role (Plan Updater)**
- **Receives From**:
  - Perceptor: INFO findings (direct, no verification needed)
  - Verify: Confirmed vulnerabilities (real) with verification data
  - Verify: False positive reports (short, for awareness)
- **Updates Plan** based on all evidence
- **Says "done"** when all critical items tested

## Execution Timeline

```
T=0s    Executer selects & launches Recon + Exploit

T=5s    Recon finishes: Found 5 endpoints
        → Send to Perceptor immediately

T=8s    Exploit finishes: Found auth bypass
        → Send to Perceptor immediately

T=9s    Perceptor analyzes Recon results
        → 5 endpoints = INFO only
        → Route directly to PLANNER

T=10s   Perceptor analyzes Exploit results
        → Auth bypass = VULNERABILITY (not just info)
        → Route to VERIFY (call Verify agent)

T=15s   VERIFY finishes analyzing auth bypass
        → Result: REAL VULNERABILITY ✓
        → Send to PLANNER: "confirmed auth bypass"
        → Send to RETEST: "here's the PoC"

T=16s   PLANNER receives and queues
        - Info: 5 endpoints
        - Confirmed vuln: auth bypass

T=20s   RETEST executes PoC 2x
        → Both succeed
        → Save to project report

T=21s   PLANNER updates plan
        → Marks recon/exploit scenarios done
        → Adds next scenarios
        → Returns to Executer for cycle 2

T=22s   Cycle continues...
```

## Comparison: Old vs New

### OLD Flow (Parallel Decisions)
```
Perceptor
├─ CRITICAL → Verify
├─ EXPLOITED → Retest (independent)
├─ HIGH → Retest
└─ INFO → Planner
```
**Problem**: Retest could run without Verify confirmation

### NEW Flow (Linear Chain)
```
Perceptor
├─ Finding → Verify → [Real] → Planner + Retest
│                    → [False Positive] → Planner (short report)
└─ INFO → Planner
```
**Benefit**: False positives filtered before Retest, PoC data guaranteed valid

## Updated Prompt Structures

### Perceptor Prompt (Simplified)
```
Decision: Is this a finding (vulnerability) or just info?
- Finding: Route to Verify (all findings, all severities)
- INFO: Route directly to Planner

Return: {
  "finding_type": "vulnerability|info",
  "route": "verify|planner",  # Always one of these two
  "compact_summary": "...",
}
```

### Verify Prompt (Gatekeeper)
```
Input: Finding with evidence from Perceptor
Output: {
  "verdict": "real_vulnerability|false_positive|inconclusive",
  "send_to_planner": {
    "type": "confirmed_vulnerability|false_positive_report",
    "summary": "...",
  },
  "send_to_retest": {...} if verdict is "real_vulnerability" else null
}
```

### Retest Prompt (Report Builder)
```
Input: Confirmed vulnerability + PoC from Verify
Output: Save finding to project report database
{
  "report_entry": {
    "vulnerability": "...",
    "poc_evidence": {...},
    "reproducibility": "3/3 successful",
    "severity": "...",
  }
}
```

## Implementation Summary

1. **Perceptor** becomes simpler: only decides "finding vs info"
2. **Verify** becomes gatekeeper: confirms real vulns + filters false positives
3. **Retest** only triggered by Verify: builds report entry, not consistency tester
4. **Planner** receives from all three sources: Perceptor (info), Verify (confirmed vulns + FP reports)
5. **Report building** happens inside Retest (not separate reporting agent)

This creates a **linear quality assurance chain** instead of parallel branching paths.
