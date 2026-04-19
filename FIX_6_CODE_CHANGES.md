# Fix #6: Code Changes (Before/After)

## File: server/agents/executer/base.py

### Change 1: Parser Now Checks for "verdict" Field

**Location**: Lines 158-187

**BEFORE**:
```python
def _parse_executer_output(raw: str) -> ExecuterResult:
    parsed = _extract_json_from_text(raw)
    if not parsed:
        summary = raw.strip() or "No response generated."
        return ExecuterResult(status="incomplete", summary=summary)

    status = parsed.get("status", "incomplete")  # ← Only "status"!
    findings = parsed.get("findings", [])
    evidence = parsed.get("evidence", [])
    needs = parsed.get("needs", [])
    summary = parsed.get("summary", "")
    next_hypotheses = parsed.get("next_hypotheses", [])

    if not isinstance(findings, list):
        findings = []
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(needs, list):
        needs = []
    if not isinstance(next_hypotheses, list):
        next_hypotheses = []

    return ExecuterResult(
        status=str(status),
        findings=findings,
        evidence=evidence,
        needs=needs,
        summary=str(summary),
        next_hypotheses=[str(item) for item in next_hypotheses],
    )
```

**AFTER**:
```python
def _parse_executer_output(raw: str) -> ExecuterResult:
    parsed = _extract_json_from_text(raw)
    if not parsed:
        summary = raw.strip() or "No response generated."
        return ExecuterResult(status="incomplete", summary=summary)

    # CRITICAL FIX: Check for "verdict" field (Verify agent) or "status" field (other agents)
    status = parsed.get("status")
    if status is None:
        # Verify agent uses "verdict" instead of "status"
        status = parsed.get("verdict", "incomplete")
    status = str(status).strip()

    findings = parsed.get("findings", [])
    evidence = parsed.get("evidence", [])
    needs = parsed.get("needs", [])
    summary = parsed.get("summary", "")
    next_hypotheses = parsed.get("next_hypotheses", [])

    if not isinstance(findings, list):
        findings = []
    if not isinstance(evidence, list):
        evidence = []
    if not isinstance(needs, list):
        needs = []
    if not isinstance(next_hypotheses, list):
        next_hypotheses = []

    return ExecuterResult(
        status=status,
        findings=findings,
        evidence=evidence,
        needs=needs,
        summary=str(summary),
        next_hypotheses=[str(item) for item in next_hypotheses],
    )
```

**What Changed**:
- Added check: `if status is None: status = parsed.get("verdict")`
- Now checks "verdict" field (Verify agent) in addition to "status" field
- Maintains backward compatibility

---

### Change 2: Always Parse Content FIRST, Fallback if Needed

**Location**: Lines 812-847 (replacing old lines 809-830)

**BEFORE**:
```python
        self._cb.on_warn(
            f"[{self._role}] reached max rounds ({self._max_tool_rounds})"
        )
        if all_tool_results:  # ← Early exit!
            if self._context_window is not None:
                await self._context_window.record(
                    kind="run_result",
                    role="assistant",
                    content=self._format_tool_results(all_tool_results),
                    metadata={"role": self._role, "status": "incomplete"},
                )
            return ExecuterResult(
                status="incomplete",
                summary=self._format_tool_results(all_tool_results),
                tool_results=all_tool_results,
                discovered_target_types=sorted(all_discovered_target_types),
                rounds_executed=self._max_tool_rounds,
                round_labels=[f"r{n}" for n in range(1, self._max_tool_rounds + 1)],
            )
        result = _parse_executer_output(last_content)  # ← Never reached if tool_results exist!
        result.discovered_target_types = extract_discovered_target_types(last_content)
        result.rounds_executed = self._max_tool_rounds
        result.round_labels = [f"r{n}" for n in range(1, self._max_tool_rounds + 1)]
        if self._context_window is not None:
            await self._context_window.record(
                kind="run_result",
                role="assistant",
                content=result.summary or last_content or result.status,
                metadata={"role": self._role, "status": result.status},
            )
        return result
```

**AFTER**:
```python
        self._cb.on_warn(
            f"[{self._role}] reached max rounds ({self._max_tool_rounds})"
        )

        # CRITICAL FIX: Always parse the final content first (could contain verdict/status)
        # Only fall back to tool_results if parsing fails
        result = _parse_executer_output(last_content)

        # If parsing successfully extracted a non-incomplete status, use it
        if result.status != "incomplete" or not all_tool_results:
            result.discovered_target_types = extract_discovered_target_types(last_content)
            result.rounds_executed = self._max_tool_rounds
            result.round_labels = [f"r{n}" for n in range(1, self._max_tool_rounds + 1)]
            if self._context_window is not None:
                await self._context_window.record(
                    kind="run_result",
                    role="assistant",
                    content=result.summary or last_content or result.status,
                    metadata={"role": self._role, "status": result.status},
                )
            return result

        # Fallback: if parsing returned incomplete and we have tool results, return tool results
        if self._context_window is not None:
            await self._context_window.record(
                kind="run_result",
                role="assistant",
                content=self._format_tool_results(all_tool_results),
                metadata={"role": self._role, "status": "incomplete"},
            )
        return ExecuterResult(
            status="incomplete",
            summary=self._format_tool_results(all_tool_results),
            tool_results=all_tool_results,
            discovered_target_types=sorted(all_discovered_target_types),
            rounds_executed=self._max_tool_rounds,
            round_labels=[f"r{n}" for n in range(1, self._max_tool_rounds + 1)],
        )
```

**What Changed**:
- Moved `_parse_executer_output()` call to FIRST line (was last)
- Added conditional: only fallback to tool_results if parsing returned "incomplete" AND no valid status extracted
- Now parsing is guaranteed to happen, verdicts won't be lost

---

## The Flow Comparison

### BEFORE (Bug)
```
Final Round 3: Verify outputs JSON with verdict
                ↓
all_tool_results has entries from Rounds 1-2
                ↓
Code sees tool_results → returns "incomplete"
                ↓
Parsing code is NEVER reached
                ↓
verdict value is LOST
                ↓
ExecuterResult.status = "incomplete"
                ↓
Orchestrator can't route → LOOP BLOCKED
```

### AFTER (Fixed)
```
Final Round 3: Verify outputs JSON with verdict
                ↓
result = _parse_executer_output(last_content)  ← ALWAYS happens
                ↓
Parser checks "verdict" field (Verify agent)
                ↓
Extracts: status = "false_positive"
                ↓
Checks: status != "incomplete" → TRUE
                ↓
Returns parsed result immediately
                ↓
ExecuterResult.status = "false_positive"
                ↓
Orchestrator routes correctly → LOOP CONTINUES
```

---

## Testing the Fix

### Quick Test
```python
# Test Case 1: Verify Round 3 output
json_output = """{
  "verdict": "false_positive",
  "summary": "Not actually vulnerable",
  "confidence": 0.9,
  "evidence": []
}"""

result = _parse_executer_output(json_output)
assert result.status == "false_positive"  # ✅ Now passes!
```

### Production Test
```
1. Start scan
2. Wait for Verify agent
3. Check logs:
   Before: [verify] completed with status=incomplete ❌
   After:  [verify] completed with status=false_positive ✅
4. Check orchestrator routes correctly
   After: sends to Planner (not Retest) ✅
```

---

## Impact Notes

- **No Breaking Changes**: Other agents still use "status" field
- **Backward Compatible**: `parsed.get("status")` tried first
- **Minimal Changes**: Only 2 functions modified
- **High Impact**: Unblocks entire orchestration loop

---

## Credits

**Bug Found**: During production validation of Fixes #1-5
**Severity**: CRITICAL - Completely blocked orchestrator loop
**Status**: ✅ FIXED
