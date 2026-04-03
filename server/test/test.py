"""
Inspect Intel checklist output, then re-send it to LLM for priority assignment only.

This helper is intentionally transparent for debugging:
1) Runs IntelAgent and prints the checklist output.
2) Removes all priority fields from items.
3) Sends the checklist to LLM with a simple prompt: add priority 1..5 to each item.
4) Prints raw LLM output and parsed JSON (if valid).

Usage:
    python -m server.test.test_intel_output_llm_refine
    python -m server.test.test_intel_output_llm_refine --target-type web_app --info "target has auth + upload"
"""

from __future__ import annotations

import argparse
import asyncio
import json
from typing import Any

from server.agents.intel.agent import IntelAgent
from server.core.llm import ChatMessage


class _PrintCallback:
    def on_step(self, message: str) -> None:
        print(f"[INTEL][step] {message}")

    def on_done(self, message: str) -> None:
        print(f"[INTEL][done] {message}")

    def on_warn(self, message: str) -> None:
        print(f"[INTEL][warn] {message}")


def _strip_priorities(payload: dict[str, Any]) -> dict[str, Any]:
    cloned = json.loads(json.dumps(payload))
    blocks = cloned.get("checklist", [])
    if not isinstance(blocks, list):
        return cloned

    for block in blocks:
        if not isinstance(block, dict):
            continue
        items = block.get("items", [])
        if not isinstance(items, list):
            continue
        for idx, item in enumerate(items):
            if isinstance(item, dict):
                name = str(item.get("name", "")).strip()
                if name:
                    items[idx] = {"name": name}
            elif isinstance(item, str):
                items[idx] = {"name": item.strip()}
    return cloned


def _parse_json_best_effort(raw: str) -> dict[str, Any] | list[Any] | None:
    text = (raw or "").strip()
    if not text:
        return None

    candidates = [text]
    if "```" in text:
        parts = text.split("```")
        for part in parts:
            candidate = part.strip()
            if candidate.lower().startswith("json"):
                candidate = candidate[4:].strip()
            if candidate:
                candidates.append(candidate)

    for candidate in candidates:
        try:
            parsed = json.loads(candidate)
            if isinstance(parsed, (dict, list)):
                return parsed
        except (TypeError, json.JSONDecodeError):
            continue
    return None


async def _run(target_type: str, info: str) -> None:
    agent = IntelAgent(callback=_PrintCallback())
    try:
        intel_result = await agent.run(target_type=target_type, info=info)
        checklist = intel_result.checklist if isinstance(intel_result.checklist, dict) else {}

        print("\n=== INTEL CHECKLIST OUTPUT ===")
        print(json.dumps(checklist, indent=2, ensure_ascii=False))

        if not checklist:
            print("\nNo checklist returned by Intel agent.")
            return

        checklist_no_priority = _strip_priorities(checklist)
        print("\n=== CHECKLIST RE-SENT TO LLM (WITHOUT PRIORITIES) ===")
        print(json.dumps(checklist_no_priority, indent=2, ensure_ascii=False))

        prompt = (
            "Add priority from 1 to 5 to each checklist item.\n"
            "Return strict JSON only, with the exact same structure.\n"
            "Each item must be: {\"name\": \"...\", \"priority\": 1}.\n"
            "Priority must be integer 1..5.\n\n"
            f"Target: {target_type}\n"
            f"Info: {info or 'none'}\n\n"
            f"Checklist:\n{json.dumps(checklist_no_priority, ensure_ascii=True)}"
        )

        llm_response = await agent._llm.chat(
            [
                ChatMessage(role="system", content="Return JSON only."),
                ChatMessage(role="user", content=prompt),
            ],
            temperature=0,
            max_tokens=11000,
        )

        raw = llm_response.content or ""
        print("\n=== RAW LLM RESPONSE ===")
        print(raw)

        parsed = _parse_json_best_effort(raw)
        print("\n=== PARSED LLM RESPONSE ===")
        if parsed is None:
            print("Could not parse LLM response as JSON.")
        else:
            print(json.dumps(parsed, indent=2, ensure_ascii=False))

    finally:
        await agent._llm.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Debug Intel checklist output and LLM priority refinement.")
    parser.add_argument("--target-type", default="web_app", help="Intel target type (default: web_app)")
    parser.add_argument("--info", default="", help="Optional Intel info/context")
    args = parser.parse_args()

    asyncio.run(_run(target_type=args.target_type, info=args.info))


if __name__ == "__main__":
    main()
