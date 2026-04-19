# Agent Testing Suite

Individual agent tests with full step-by-step output for PentaForge agents.

## Available Tests

### 1. **test_exploit_agent.py** - Exploit Agent Test
Tests the Exploit executor agent in isolation.

**What it tests:**
- Exploit agent initialization
- LLM-driven tool selection and execution
- Multi-round exploitation strategies
- Finding extraction and reporting

**Tests:**
1. **SSH Version Vulnerability Test** - Tests for CVE-2020-14145 on SSH service
2. **Directory Traversal Test** - Tests for path traversal vulnerabilities

**Run:**
```bash
python server/test/test_exploit_agent.py
```

**Output includes:**
- Round-by-round LLM thinking and tool selection
- Tool execution results (curl, ffuf, nmap, etc.)
- Findings with severity levels
- Complete execution timeline
- Step-by-step log of all actions

---

### 2. **test_recon_agent.py** - Recon Agent Test
Tests the Recon executor agent in isolation.

**What it tests:**
- Recon agent initialization
- Reconnaissance tool selection (nmap, web_fuzz, etc.)
- Port scanning and service enumeration
- Web application discovery

**Tests:**
1. **Port Scanning Test** - Identifies open ports and running services
2. **Web Enumeration Test** - Discovers web directories, endpoints, and technologies

**Run:**
```bash
python server/test/test_recon_agent.py
```

**Output includes:**
- Port scan results with service versions
- Discovered web directories and endpoints
- Technology stack identification
- Enumeration findings

---

## Running the Tests

### Option 1: Run Individual Tests
```bash
# Test Exploit Agent
python server/test/test_exploit_agent.py

# Test Recon Agent
python server/test/test_recon_agent.py
```

### Option 2: Run Both Tests in Sequence
```bash
bash server/test/run_tests.sh
```

---

## What Each Test Shows

### 📋 Scenario Information
- Task description
- Target URL
- Target type (web_app, api, etc.)
- Phase and priority

### 🚀 LLM Round Execution
Each round shows:
- Round number (1/3, 2/3, etc.)
- LLM reasoning and thinking
- Tool selection and parameters
- Tool execution results

### 🔧 Tool Results
- Tool name and arguments
- Tool output (first N characters)
- Execution status and timing

### 🎯 Findings
- Finding type (vulnerability, info, etc.)
- Severity level
- Finding summary
- Detailed findings

### 📝 Execution Summary
- Overall status (complete, incomplete, failed)
- Total rounds executed
- Total tools used
- Evidence collected

### 🔓 Tool Approvals
- List of tools auto-approved during test
- Approval timing

### 📦 Result Structure
Complete JSON structure with:
- Status
- Rounds executed
- Round labels
- Findings count
- Evidence count
- Tool results count
- Discovered target types

---

## Example Output Structure

```
================================================================================
EXPLOIT AGENT TEST - scanme.nmap.org
================================================================================

📋 SCENARIO:
  Task: Test for open ports and known vulnerabilities on SSH (port 22)
  Target: http://scanme.nmap.org
  Target Types: ['web_app']

🚀 STARTING EXPLOIT AGENT RUN...
--------------------------------------------------------------------------------
  → [exploit] starting run
  → [exploit] LLM round 1/3
  → LLM Round 1: Calling tools → ['curl', 'nmap_scan']
  🔓 [AUTO-APPROVE] exploit tool 'run_custom' (call_id=abc123)
  ✓ [exploit] tool 'run_custom' completed (500 chars)
  → [exploit] LLM round 2/3
  ...

================================================================================
✅ EXPLOIT AGENT COMPLETED
================================================================================

📊 FINAL RESULT:
  Status: complete
  Completed Rounds: 3

  Round Details:
    Round 1: LLM planning + tool selection
    Round 2: Tool execution + analysis
    Round 3: Findings consolidation

🔧 TOOLS USED:
  Tool 1: curl
    Output: HTTP/1.1 200 OK...
  Tool 2: nmap_scan
    Output: PORT   STATE  SERVICE...

🎯 FINDINGS:
  Total: 2

  Finding #1:
    Type: vulnerability
    Severity: high
    Summary: SSH service detected on port 22
    Details: OpenSSH 7.4 detected - vulnerable to CVE-2020-14145...

  Finding #2:
    Type: info
    Severity: info
    Summary: Web server detected
    Details: Apache/2.4.6 running on port 80...

📝 SUMMARY:
  Successfully identified SSH service vulnerability and web server...

📋 STEP-BY-STEP LOG (15 steps):
  1. [exploit] starting run
  2. [exploit] LLM round 1/3
  3. LLM Round 1: Calling tools → ['curl', 'nmap_scan']
  ...

🔓 TOOL APPROVALS (2):
  - exploit: run_custom
  - exploit: run_custom

📦 FULL RESULT STRUCTURE:
{
  "status": "complete",
  "rounds_executed": 3,
  "findings_count": 2,
  "evidence_count": 0,
  "tool_results_count": 2,
  "discovered_target_types": ["web_app"],
  "summary": "..."
}
```

---

## Key Features

### ✅ Auto-Approval
Tools are automatically approved during tests so you don't need to manually approve each tool request.

### ✅ Detailed Logging
Every step is logged and displayed, including:
- LLM round progression
- Tool decisions and parameters
- Execution results
- Auto-approvals

### ✅ Structured Output
Results are presented in a clear structure with:
- Scenario details at the top
- Step-by-step execution in the middle
- Consolidated findings at the bottom
- Full JSON structure for programmatic analysis

### ✅ Error Handling
Full exception traces are displayed if anything goes wrong.

---

## Interpreting Results

### Status Values
- `complete` - Agent completed all rounds successfully
- `incomplete` - Agent stopped before max rounds (ran out of ideas)
- `failed` - Agent encountered an error

### Tool Results Order
Tools are executed in the order selected by the LLM. Each tool's output is shown immediately after execution.

### Round Labels
- `LLM planning + tool selection` - Agent decides what to do
- `Tool execution + analysis` - Agent runs tools and analyzes results
- `Findings consolidation` - Agent prepares final output

### Findings
Each finding shows:
- `type`: vulnerability, info, evidence, or other
- `severity`: critical, high, medium, low, info
- `summary`: Short description
- `details`: Full details and context

---

## Debugging

If a test fails:

1. **Check the full exception trace** - shown at the end
2. **Review the step log** - shows exactly where it stopped
3. **Check tool approvals** - if tools weren't approved, they may have been skipped
4. **Check LLM errors** - LLM rate limiting or API errors are shown

---

## Next Steps

After running individual agent tests:

1. **Compare Results** - See how Recon vs Exploit agents behave
2. **Full Scan Test** - Run `orchestrator.test_full_scan()` to test all agents together
3. **Batch Processing Test** - Verify batch verify/planner execution in orchestrator
4. **6-part Context Test** - Check planner context window in loop rounds

---

## Files

- `test_exploit_agent.py` - Exploit agent unit test
- `test_recon_agent.py` - Recon agent unit test
- `run_tests.sh` - Bash runner script
- `TEST_README.md` - This file
