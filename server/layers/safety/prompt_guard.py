"""Prompt Injection Guard — sanitizes tool outputs before LLM context injection."""

from __future__ import annotations

import re

import structlog

from .config import PROMPT_GUARD_MAX_LINE_LENGTH, PROMPT_GUARD_MAX_OUTPUT_CHARS

logger = structlog.get_logger(__name__)

# ── Injection patterns ─────────────────────────────────────────────


_INJECTION_PATTERNS: list[tuple[re.Pattern, str]] = [
    # Direct instruction override.
    (re.compile(r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|rules?|context)",
                re.IGNORECASE), "instruction_override"),
    # Role hijacking.
    (re.compile(r"you\s+are\s+(now|actually|really)\s+",
                re.IGNORECASE), "role_hijack"),
    # System prompt injection.
    (re.compile(r"(system\s*prompt|system\s*message|<\|system\|>|<<\s*SYS\s*>>)",
                re.IGNORECASE), "system_prompt_inject"),
    # Delimiter escape.
    (re.compile(r"(```\s*(system|assistant|user)|<\|im_start\|>|<\|im_end\|>|\[INST\]|\[/INST\])",
                re.IGNORECASE), "delimiter_escape"),
    # Instruction injection in HTML/comments.
    (re.compile(r"<!--\s*(ignore|forget|override|you\s+are|new\s+instructions?)",
                re.IGNORECASE), "html_comment_inject"),
    # Direct command to change behavior.
    (re.compile(r"(forget\s+everything|disregard\s+all|new\s+instructions?\s*:)",
                re.IGNORECASE), "behavior_override"),
    # Jailbreak keywords in output context.
    (re.compile(r"(DAN\s+mode|jailbreak|do\s+anything\s+now)",
                re.IGNORECASE), "jailbreak_attempt"),
]

# Characters that should never appear in tool output fed to LLM.
_DANGEROUS_CHARS = str.maketrans({
    "\x00": "",     # Null bytes.
    "\x08": "",     # Backspace.
    "\x7f": "",     # Delete.
})


class PromptInjectionGuard:
    """Sanitizes tool output before it enters the LLM context.

    Three layers of defense:
    1. Pattern matching — strips known injection phrases.
    2. Structural sanitization — enforces length, removes control chars.
    3. Context isolation — wraps output in explicit delimiters.
    """

    def __init__(
        self,
        max_chars: int = PROMPT_GUARD_MAX_OUTPUT_CHARS,
        max_line_length: int = PROMPT_GUARD_MAX_LINE_LENGTH,
    ) -> None:
        self._max_chars = max_chars
        self._max_line = max_line_length

    def sanitize(self, text: str, source: str = "tool") -> str:
        """Clean tool output for safe LLM injection.

        Args:
            text: Raw tool output.
            source: Label for logging (tool name, etc.).

        Returns:
            Sanitized string safe for LLM context.
        """
        if not text:
            return ""

        original_len = len(text)
        result = text

        # 1. Remove dangerous control characters.
        result = result.translate(_DANGEROUS_CHARS)

        # 2. Detect and strip injection patterns.
        detections: list[str] = []
        for pattern, label in _INJECTION_PATTERNS:
            if pattern.search(result):
                detections.append(label)
                result = pattern.sub(f"[REDACTED:{label}]", result)

        if detections:
            logger.warning(
                "prompt_injection_detected",
                source=source,
                patterns=detections,
                original_length=original_len,
            )

        # 3. Truncate overly long lines (common in base64 blobs, etc.).
        lines = result.splitlines()
        truncated_lines: list[str] = []
        for line in lines:
            if len(line) > self._max_line:
                truncated_lines.append(line[: self._max_line] + "…[line truncated]")
            else:
                truncated_lines.append(line)
        result = "\n".join(truncated_lines)

        # 4. Enforce total length.
        if len(result) > self._max_chars:
            result = result[: self._max_chars] + f"\n[TRUNCATED at {self._max_chars} chars]"

        # 5. Wrap in isolation delimiters.
        result = self._wrap_with_delimiters(result, source)

        return result

    def scan_only(self, text: str) -> list[str]:
        """Scan for injection patterns without modifying text.

        Returns list of detected pattern labels (empty = clean).
        """
        detections: list[str] = []
        for pattern, label in _INJECTION_PATTERNS:
            if pattern.search(text):
                detections.append(label)
        return detections

    @staticmethod
    def _wrap_with_delimiters(text: str, source: str) -> str:
        """Wrap sanitized output in explicit context boundaries.

        This tells the LLM "this is tool output, not instructions."
        """
        return (
            f"[TOOL_OUTPUT source={source}]\n"
            f"{text}\n"
            f"[/TOOL_OUTPUT]"
        )