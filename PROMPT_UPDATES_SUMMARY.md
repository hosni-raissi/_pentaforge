# 3-ROUND PROMPT STRUCTURE - IMPLEMENTATION SUMMARY

## Changes Completed ✅

### 1. **Exploit Agent Prompts** (`server/agents/executer/exploit/prompts.py`)
**Updated Structure:**
- **Round 1**: Planning phase - analyze scenario, select 2 tools, execute
- **Round 2**: Execution & Analysis phase - create SUMMARY of Round 1, select 2 next tools
- **Round 3**: Consolidation phase - JSON ONLY, no tools, combine all findings

**Key Addition - Round 2 Summary Format:**
```
SUMMARY OF ROUND 1:
  **Tools Executed:** [tool names and purposes]
  **Key Findings:** [what was discovered, vulnerabilities status]
  **Observations:** [important insights from results]
```

---

### 2. **Recon Agent Prompts** (`server/agents/executer/recon/prompts.py`)
**Updated Structure:**
- **Round 1**: Planning & Discovery - select reconnaissance tools
- **Round 2**: Validation & Enrichment - summarize Round 1, select validation tools
- **Round 3**: Consolidation & Report - JSON ONLY with all findings

**Key Addition - Round 2 Summary Format:**
```
SUMMARY OF ROUND 1:
  **Tools Executed:** [tool names and targets]
  **Key Findings:** [hosts, ports, domains, services discovered]
  **Status Assessment:** [objectives met/partial/not met]
  **Observations:** [patterns, anomalies, interesting data]
```

---

### 3. **Verify Agent Prompts** (`server/agents/executer/verify/prompts.py`)
**Updated Structure:**
- **Round 1**: Initial Reproduction - execute 2 verification tools
- **Round 2**: Confirmation & Analysis - summarize Round 1, execute confirmation tools
- **Round 3**: Verdict & Consolidation - JSON ONLY with final verdict

**Key Addition - Round 2 Summary Format:**
```
SUMMARY OF ROUND 1:
  **Tools Executed:** [tool names and what they tested]
  **Evidence Found:** [responses, indicators, screenshots]
  **False Positive Assessment:** [protection mechanisms detected]
  **Preliminary Verdict:** [real/false/inconclusive so far]
```

---

## Critical Changes from Original Flow

| Aspect | Before | After |
|--------|--------|-------|
| **Round 1 Output** | Raw tool outputs | Tool execution + results |
| **Round 2 Input** | Just raw outputs | Raw outputs + Summary |
| **Round 2 Output** | Just more raw outputs | Summary + Next tools + Results |
| **Round 3 Input** | All raw outputs stacked | Only Round 2 summary |
| **Round 3 Output** | JSON structure | JSON ONLY (no prose) |
| **Token Efficiency** | High redundancy (3x outputs) | Optimized (summaries reduce bloat) |
| **Context Clarity** | Raw data everywhere | Structured summaries + selective raw data |

---

## What Each Round Now Does

### **ROUND 1: Discovery & Execution**
```
INPUT:
  - System prompt
  - Scenario/Finding details

PROCESSING:
  - Select 2 tools based on scenario
  - Execute tools
  - Collect results

OUTPUT:
  - Tool execution logs
  - Raw tool results (responses, screenshots, data)
```

### **ROUND 2: Analysis & Planning**
```
INPUT:
  - System prompt
  - Scenario/Finding details
  - Tool Results from Round 1 (raw)
  - Execution context

PROCESSING:
  - ANALYZE Round 1 results
  - CREATE SUMMARY (what ran, what was found, key assessment)
  - SELECT next tools based on findings
  - EXECUTE next tools

OUTPUT:
  - SUMMARY OF ROUND 1 (structured recap)
  - Tool execution logs
  - Raw tool results from Round 2
```

### **ROUND 3: Consolidation**
```
INPUT:
  - System prompt
  - Scenario/Finding details
  - SUMMARY from Round 2 (NOT raw Round 1 outputs)
  - Tool Results from Round 2 (raw)

PROCESSING:
  - CONSOLIDATE all findings from Rounds 1-2
  - Synthesize into FINAL ASSESSMENT
  - Prepare VERDICT/REPORT

OUTPUT:
  - JSON ONLY (no prose, no tools)
  - Complete findings summary
  - Final verdict or recommendations
```

---

## Test Expectations

When you run the test with the updated prompts, you should see:

### **Exploit Agent Test Output:**
```
Round 1/3:
  [exploit] starting run
  [exploit] LLM round 1/3
  [exploit] tool call: nmap → port 22 SSH detected
  [exploit] tool call: searchsploit → CVE-2020-14145 found
  ✅ Completed Round 1 with 2 tools

Round 2/3:
  [exploit] LLM round 2/3
  ✅ SUMMARY FROM ROUND 1:
    - Tools executed: nmap, searchsploit
    - Found: SSH 6.6.1p1, CVE-2020-14145 applicable
    - Observations: Version is vulnerable to this CVE
  [exploit] tool call: ssh-auth-methods → test CVE authenticity
  ✅ Completed Round 2 with 1 tool

Round 3/3:
  [exploit] LLM round 3/3
  ✅ NO TOOLS
  ✅ FINAL VERDICT (JSON ONLY):
  {
    "status": "vulnerable",
    "vulnerability_type": "ssh_weak_auth",
    "findings": [...],
    "summary": "SSH 6.6.1p1 vulnerable to CVE-2020-14145. Tested across 3 tools, weak algorithms confirmed.",
    "tools_executed": ["nmap", "searchsploit", "ssh-auth-methods"]
  }
```

### **Recon Agent Test Output:**
```
Round 1/3:
  [recon] tool call: amass_enum → 5 subdomains found
  [recon] tool call: ssl_tls_analysis → certificates verified
  ✅ Completed Round 1 with 2 tools

Round 2/3:
  ✅ SUMMARY FROM ROUND 1:
    - Tools: amass_enum (subdomain discovery), ssl_tls_analysis (cert validation)
    - Found: 5 subdomains with valid SSL certificates
    - Status: Objectives partially met
    - Observation: All subdomains have same certificate issuer
  [recon] tool call: dns_recon → verify DNS records
  ✅ Completed Round 2 with 1 tool

Round 3/3:
  ✅ NO TOOLS
  ✅ FINAL REPORT (JSON ONLY):
  {
    "status": "complete",
    "findings": [...],
    "evidence": [...],
    "summary": "Discovered 5 subdomains for target.com. All DNS and SSL verified.",
    "tools_executed": ["amass_enum", "ssl_tls_analysis", "dns_recon"]
  }
```

### **Verify Agent Test Output:**
```
Round 1/3:
  [verify] tool call: run_custom (curl with SQLi payload)
  [verify] Output: Time-based SLEEP delay detected ✓
  [verify] tool call: capture_screenshot → SQLi payload response captured
  ✅ Completed Round 1 with 2 tools

Round 2/3:
  ✅ SUMMARY FROM ROUND 1:
    - Tools: run_custom (payload execution), capture_screenshot (evidence)
    - Evidence: SLEEP(5) returned 5+ second delay, confirmed time-based SQLi
    - False positive check: No encoding detected, payload executed
    - Preliminary: REAL VULNERABILITY
  [verify] tool call: run_custom (alternative encoding test)
  ✅ Completed Round 2 with 1 tool

Round 3/3:
  ✅ NO TOOLS
  ✅ FINAL VERDICT (JSON ONLY):
  {
    "verdict": "real_vulnerability",
    "summary": "SQL injection confirmed in POST /api/login username parameter via time-based delays. Tested across 2 rounds with 3 tools. Exploitation successful.",
    "confidence": 0.95,
    "evidence": [...],
    "send_to_planner": {...},
    "send_to_retest": {...},
    "tools_executed": ["run_custom", "capture_screenshot", "run_custom"]
  }
```

---

## How to Run Tests

```bash
# Run exploit agent test
python -m server.test.test_exploit_agent

# Run recon agent test
python -m server.test.test_recon_agent

# Run both
bash run_agent_tests.sh
```

---

## Benefits of New Structure

1. ✅ **Clearer Context Flow** - Each round has explicit input/processing/output
2. ✅ **Token Efficiency** - Summaries replace raw output repetition
3. ✅ **Better LLM Reasoning** - Round 2 can reason about Round 1 findings
4. ✅ **Final JSON Focus** - Round 3 consolidates without distraction
5. ✅ **Easier Debugging** - Clear summary shows what agent decided after each round
6. ✅ **Structured Evidence** - All findings organized by round with context
7. ✅ **Reduced Hallucination** - Summaries anchor LLM to facts, not raw noise

---

## Files Modified

1. ✅ `server/agents/executer/exploit/prompts.py` - Updated SYSTEM_PROMPT
2. ✅ `server/agents/executer/recon/prompts.py` - Updated SYSTEM_PROMPT
3. ✅ `server/agents/executer/verify/prompts.py` - Updated SYSTEM_PROMPT
4. ✅ `server/test/test_exploit_agent.py` - Uses Mistral provider
5. ✅ `server/test/test_recon_agent.py` - Uses Mistral provider

---

## Next Steps

1. Run tests to verify new prompt structure works
2. Monitor log output for:
   - ✅ Round summaries appearing in Round 2
   - ✅ Round 3 returning JSON ONLY (no prose)
   - ✅ Tools called only in Rounds 1-2 (never Round 3)
3. Verify agent findings are more coherent and better organized
4. Check token usage to confirm efficiency improvement
