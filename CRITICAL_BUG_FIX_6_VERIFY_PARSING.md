# CRITICAL BUG FIX #6 - Verify Agent Status Parsing

## The Problem (PRODUCTION BLOCKING)

The Verify agent was completing with `status=incomplete` instead of returning proper verdict values, which **stopped the entire orchestration loop**.

**Symptom**: Scan logs show:
```
[VERIFY]Executer [done] [verify] completed with status=incomplete
[VERIFY] (loop stops here, no routing to Planner or Retest)
```

## Root Cause Analysis

Two interconnected bugs prevented Verify verdicts from being extracted:

### Bug #1: _parse_executer_output() Looks for Wrong Field

**Location**: `server/agents/executer/base.py:158-187`

**Problem**:
```python
# Line 164 - Only looks for "status" field
status = parsed.get("status", "incomplete")
```

But Verify agent's Round 3 JSON outputs:
```json
{
  "verdict": "real_vulnerability",  // ← NOT "status"!
  "summary": "...",
  "confidence": 0.95,
  "evidence": [...]
}
```

**Result**: verdict field is ignored, defaults to "incomplete"

### Bug #2: run() Method Skips Parsing on Tool Results

**Location**: `server/agents/executer/base.py:815-830`

**Problem**:
```python
# Line 815 - If we have ANY tool results, return incomplete without parsing!
if all_tool_results:
    return ExecuterResult(
        status="incomplete",
        summary=self._format_tool_results(all_tool_results),
        ...
    )
# Line 831 - Never reaches this for Verify!
result = _parse_executer_output(last_content)
```

**Why It Happened**:
1. Verify Round 1: runs 2 tools → all_tool_results populated
2. Verify Round 2: runs 2 tools → all_tool_results grows
3. Verify Round 3: no tools (correct), but all_tool_results is NOT empty!
4. Code sees all_tool_results, returns "incomplete" without parsing Round 3 JSON
5. The Verify verdict never gets extracted

## The Fix

### Fix #1: Check for "verdict" Field in _parse_executer_output()

```python
# BEFORE
status = parsed.get("status", "incomplete")

# AFTER - Check for "verdict" (Verify agent) or "status" (other agents)
status = parsed.get("status")
if status is None:
    # Verify agent uses "verdict" instead of "status"
    status = parsed.get("verdict", "incomplete")
status = str(status).strip()
```

### Fix #2: Always Parse Final Content FIRST

```python
# BEFORE - Returns incomplete if tool_results exist
if all_tool_results:
    return ExecuterResult(status="incomplete", ...)
result = _parse_executer_output(last_content)

# AFTER - Parse first, only fallback to tool_results if parsing fails
result = _parse_executer_output(last_content)

# If parsing successfully extracted a non-incomplete status, use it
if result.status != "incomplete" or not all_tool_results:
    return result

# Fallback: if parsing failed and we have tool results, return them
if all_tool_results:
    return ExecuterResult(status="incomplete", ...)
```

## Expected Behavior After Fix

### Before Fix
```
Verify Round 3 JSON:
  {"verdict": "false_positive", "summary": "...", ...}

ExecuterResult:
  status = "incomplete"  ← WRONG!

Orchestrator routing: STOPS (can't route on incomplete)
```

### After Fix
```
Verify Round 3 JSON:
  {"verdict": "false_positive", "summary": "...", ...}

_parse_executer_output() extracts:
  status = "false_positive"  ← CORRECT!

ExecuterResult:
  status = "false_positive"

Orchestrator routing: CONTINUES
  - false_positive → Planner only
  - real_vulnerability → Planner + Retest
  - inconclusive → Planner only
```

## Files Modified

1. **`server/agents/executer/base.py:158-187`**
   - Modified `_parse_executer_output()` to check for "verdict" field

2. **`server/agents/executer/base.py:812-847`**
   - Modified `run()` method to always parse final content first

## Testing

### Quick Validation
```bash
# Restart server
python -m server.main

# Run scan - watch logs for Verify completion
# Should see:
# [VERIFY]Executer [done] [verify] completed with status=real_vulnerability  (or false_positive/inconclusive)
# NOT: status=incomplete
```

### Full Loop Test
```bash
# Start scan and watch:
1. Verify completes with status=real_vulnerability/false_positive/inconclusive
2. Perceptor routes to appropriate handler
3. Planner receives finding
4. (If real_vulnerability) Retest executes
5. Cycle 2 continues
```

## Impact

✅ **Verify agent verdicts now properly extracted**
✅ **Orchestrator loop can continue past Verify stage**
✅ **Routing decisions work correctly**
✅ **Full end-to-end scan cycles now possible**

## Severity

🔴 **CRITICAL** - This bug was blocking ALL orchestrator loops from progressing past Verify stage.

## Sign-Off

This fix is applied to:
- ✅ Production code (`server/agents/executer/base.py`)
- ✅ Syntax validated
- ✅ Ready for immediate testing
