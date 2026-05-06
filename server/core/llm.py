"""
LLMClient — Unified async chat completion client for PentaForge.

Supports Cerebras (Qwen-3), Mistral, Groq, OpenAI, and any OpenAI-compatible endpoint.
Configuration is read directly from environment variables.

Usage:
    from server.core.llm import get_llm, ChatMessage

    async with get_llm() as llm:
        response = await llm.chat([
            ChatMessage(role="system", content="You are a helpful assistant."),
            ChatMessage(role="user", content="Hello!"),
        ])
        print(response.content)
"""

from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

import httpx
import structlog

logger = structlog.get_logger(__name__)

# ── Environment file loading ──────────────────────────────────────────────────

_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"

def _load_env_file() -> None:
    """Load .env file if it exists (simple key=value parsing)."""
    if not _ENV_FILE.exists():
        return
    try:
        with open(_ENV_FILE, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except Exception:
        pass

_load_env_file()

# ── Debug flag ────────────────────────────────────────────────────────────────

_LLM_DEBUG_LOGS = os.getenv("LLM_DEBUG_LOGS", "").strip().lower() in {"1", "true", "yes", "on"}

# ── LLM Configuration ─────────────────────────────────────────────────────────

LLMProvider = Literal["cerebras", "mistral", "groq", "openai", "together", "ollama", "nvidia", "custom"]

_PROVIDER_DEFAULTS: dict[str, dict[str, Any]] = {
    "cerebras": {
        "model": "qwen-3-235b-a22b-instruct-2507",
        "api_url": "https://api.cerebras.ai/v1",
        "max_tokens": 9000,
    },
    "mistral": {
        "model": "mistral-large-latest",
        "api_url": "https://api.mistral.ai/v1",
        "max_tokens": 8096,
    },
    "groq": {
        "model": "llama-3.3-70b-versatile",
        "api_url": "https://api.groq.com/openai/v1",
        "max_tokens": 8096,
    },
    "openai": {
        "model": "gpt-4o",
        "api_url": "https://api.openai.com/v1",
        "max_tokens": 4096,
    },
    "together": {
        "model": "meta-llama/Meta-Llama-3.1-70B-Instruct-Turbo",
        "api_url": "https://api.together.xyz/v1",
        "max_tokens": 4096,
    },
    "ollama": {
        "model": "qwen3:4b",
        "api_url": "http://localhost:11434/v1",
        "max_tokens": 8192,
    },
    "nvidia": {
        "model": "meta/llama-3.1-70b-instruct",
        "api_url": "https://integrate.api.nvidia.com/v1",
        "max_tokens": 4096,
    },
}


def _env_first(*keys: str, default: str = "") -> str:
    for key in keys:
        value = os.getenv(key)
        if value is not None and str(value).strip() != "":
            return str(value).strip()
    return default


def _provider_defaults(provider: str) -> dict[str, Any]:
    return _PROVIDER_DEFAULTS.get(provider, _PROVIDER_DEFAULTS["cerebras"])


def _agent_role_token(agent_role: str | None) -> str:
    return str(agent_role or "").strip().lower().replace("-", "_")


_ROLE_ALIASES: dict[str, str] = {
    "reporting": "report",
}


_ROLE_GROUPS: dict[str, str] = {
    "intel": "INTEL_REPORT",
    "report": "INTEL_REPORT",
    "assistant": "PLANNER",
    "information_gathering": "INFO_MEMORY",
    "planner": "PLANNER",
    "recon": "RECON",
    "exploit": "EXPLOIT",
    "system_memory": "INFO_MEMORY",
    "retest": "RETEST_VERIFY",
    "verify": "RETEST_VERIFY",
}

@dataclass(frozen=True)
class LLMConfig:
    """Unified LLM configuration."""

    provider: str = "cerebras"
    model: str = "qwen-3-235b-a22b-instruct-2507"
    api_url: str = "https://api.cerebras.ai/v1"
    api_key: str = ""
    temperature: float = 0.0
    max_tokens: int = 9000

    @classmethod
    def from_env(cls, prefix: str = "AGENT_LLM_") -> LLMConfig:
        """Load configuration from environment variables."""
        provider = os.getenv(f"{prefix}API_PROVIDER", "cerebras").strip().lower()
        provider_defaults = _provider_defaults(provider)

        return cls(
            provider=provider,
            model=os.getenv(f"{prefix}MODEL", provider_defaults["model"]),
            api_url=os.getenv(f"{prefix}API_URL", provider_defaults["api_url"]),
            api_key=os.getenv(f"{prefix}API_KEY", ""),
            temperature=float(os.getenv(f"{prefix}TEMPERATURE", "0.0")),
            max_tokens=int(os.getenv(f"{prefix}MAX_TOKENS", str(provider_defaults["max_tokens"]))),
        )

    @classmethod
    def local(cls) -> LLMConfig:
        """Load local (Ollama) configuration."""
        return cls(
            provider="ollama",
            model=os.getenv("LOCAL_LLM_MODEL", "qwen3:4b"),
            api_url=os.getenv("LOCAL_LLM_API_URL", "http://localhost:11434/v1"),
            api_key="",
            temperature=float(os.getenv("LOCAL_LLM_TEMPERATURE", "0.7")),
            max_tokens=int(os.getenv("LOCAL_LLM_MAX_TOKENS", "8192")),
        )


# ── Singleton configs ─────────────────────────────────────────────────────────

def get_llm_mode() -> str:
    """Get the current LLM mode (public or local)."""
    return os.getenv("AGENT_LLM_MODE", "public").strip().lower()


def get_config() -> LLMConfig:
    """Get the appropriate LLM config based on current mode."""
    mode = get_llm_mode()
    if mode == "local":
        return LLMConfig.local()
    return LLMConfig.from_env()


def get_public_agent_config(agent_role: str | None = None) -> LLMConfig:
    """Resolve public LLM config with optional role-specific overrides.

    Resolution order for each field:
    1) AGENT_LLM_<ROLE>_* override
    2) AGENT_LLM_GROUP_<GROUP>_* override (optional shared profile)
    3) AGENT_LLM_* global setting
    4) Provider defaults

    NVIDIA compatibility:
    - Accepts both NVIDIA_* and legacy misspelled NVIDEA_* variables.
    - If provider is nvidia and role-specific API key is unset, uses NVIDIA_API_KEY/NVIDEA_API_KEY.
    """
    base = LLMConfig.from_env("AGENT_LLM_")
    role_token = _agent_role_token(agent_role)
    role_token = _ROLE_ALIASES.get(role_token, role_token)
    if not role_token:
        return base

    role_prefix = f"AGENT_LLM_{role_token.upper()}_"
    group_name = _ROLE_GROUPS.get(role_token, "")
    group_prefix = f"AGENT_LLM_GROUP_{group_name}_" if group_name else ""

    provider = _env_first(
        f"{role_prefix}API_PROVIDER",
        *((f"{group_prefix}API_PROVIDER",) if group_prefix else ()),
        default=base.provider,
    ).lower()
    defaults = _provider_defaults(provider)

    if provider == "nvidia":
        default_model = _env_first("NVIDIA_MODEL", "NVIDEA_MODEL", default=str(defaults["model"]))
        default_url = _env_first("NVIDIA_API_URL", "NVIDEA_API_URL", default=str(defaults["api_url"]))
        default_key = _env_first("NVIDIA_API_KEY", "NVIDEA_API_KEY", default=base.api_key)
    else:
        default_model = str(defaults["model"])
        default_url = str(defaults["api_url"])
        default_key = base.api_key

    model = _env_first(
        f"{role_prefix}MODEL",
        *((f"{group_prefix}MODEL",) if group_prefix else ()),
        default=base.model or default_model,
    )
    api_url = _env_first(
        f"{role_prefix}API_URL",
        *((f"{group_prefix}API_URL",) if group_prefix else ()),
        default=base.api_url or default_url,
    )
    api_key = _env_first(
        f"{role_prefix}API_KEY",
        *((f"{group_prefix}API_KEY",) if group_prefix else ()),
        default=default_key,
    )

    temperature_raw = _env_first(
        f"{role_prefix}TEMPERATURE",
        *((f"{group_prefix}TEMPERATURE",) if group_prefix else ()),
        default=str(base.temperature),
    )
    max_tokens_raw = _env_first(
        f"{role_prefix}MAX_TOKENS",
        *((f"{group_prefix}MAX_TOKENS",) if group_prefix else ()),
        default=str(base.max_tokens),
    )

    try:
        temperature = float(temperature_raw)
    except (TypeError, ValueError):
        temperature = float(base.temperature)

    try:
        max_tokens = int(max_tokens_raw)
    except (TypeError, ValueError):
        max_tokens = int(base.max_tokens)

    return LLMConfig(
        provider=provider,
        model=model or default_model,
        api_url=api_url or default_url,
        api_key=api_key,
        temperature=temperature,
        max_tokens=max_tokens,
    )


def get_backup_llm_config() -> LLMConfig | None:
    """Get backup LLM configuration for rate limit fallback.

    Returns the backup config if all required env vars are set, otherwise None.
    This is used when the main LLM hits rate limit (429) to continue execution.
    """
    provider = os.getenv("BACKUP_LLM_API_PROVIDER", "").strip().lower()
    if not provider:
        return None

    api_key = os.getenv("BACKUP_LLM_API_KEY", "").strip()
    if not api_key:
        return None

    defaults = _provider_defaults(provider)

    return LLMConfig(
        provider=provider,
        model=os.getenv("BACKUP_LLM_MODEL", defaults["model"]),
        api_url=os.getenv("BACKUP_LLM_API_URL", defaults["api_url"]),
        api_key=api_key,
        temperature=0.2,  # Lower temperature for consistency
        max_tokens=4000,
    )


# ── Chat message ──────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class ChatMessage:
    """A single message in a conversation."""

    role: str  # "system" | "user" | "assistant" | "tool"
    content: str | None = None
    tool_calls: list[dict[str, Any]] = field(default_factory=list)
    tool_call_id: str | None = None
    name: str | None = None

    def to_api(self) -> dict[str, Any]:
        """Serialize to the OpenAI API message format."""
        msg: dict[str, Any] = {"role": self.role}
        if self.content is not None:
            msg["content"] = self.content
        if self.tool_calls:
            msg["tool_calls"] = self.tool_calls
        if self.tool_call_id is not None:
            msg["tool_call_id"] = self.tool_call_id
        if self.name is not None:
            msg["name"] = self.name
        return msg


# ── LLM Response ──────────────────────────────────────────────────────────────

@dataclass
class LLMResponse:
    """Parsed response from the LLM."""

    content: str | None
    tool_calls: list[dict[str, Any]]
    finish_reason: str
    usage: dict[str, int]


# ── Mistral SDK Client (optional) ─────────────────────────────────────────────

class _MistralClient:
    """Thin wrapper around Mistral SDK for native API support."""

    def __init__(self, config: LLMConfig) -> None:
        self._config = config
        self._client: Any = None

    async def _ensure_client(self) -> Any:
        if self._client is None:
            try:
                from mistralai import Mistral
                self._client = Mistral(api_key=self._config.api_key)
            except ImportError:
                raise RuntimeError("mistralai package not installed. Run: pip install mistralai")
        return self._client

    async def chat(
        self,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]] | None = None,
        temperature: float = 0.0,
        max_tokens: int | None = None,
    ) -> dict[str, Any]:
        client = await self._ensure_client()

        kwargs: dict[str, Any] = {
            "model": self._config.model,
            "messages": messages,
            "temperature": temperature,
            "stream": False,
        }
        if max_tokens is not None:
            kwargs["max_tokens"] = max_tokens
        if tools:
            kwargs["tools"] = tools
            kwargs["tool_choice"] = "auto"

        response = await asyncio.to_thread(client.chat.complete, **kwargs)

        choice = response.choices[0]
        message = choice.message

        # Handle content that might be a list (Mistral quirk)
        raw_content = message.content or ""
        if isinstance(raw_content, list):
            content = "\n".join(
                (item.get("text", "") if isinstance(item, dict) else str(item))
                for item in raw_content
            )
        else:
            content = raw_content

        # Extract tool calls
        tool_calls: list[dict[str, Any]] = []
        if hasattr(message, "tool_calls") and message.tool_calls:
            for tc in message.tool_calls:
                tool_calls.append({
                    "id": tc.id,
                    "type": "function",
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                })

        usage = response.usage
        return {
            "content": content,
            "tool_calls": tool_calls,
            "finish_reason": str(choice.finish_reason or "stop"),
            "usage": {
                "prompt_tokens": getattr(usage, "prompt_tokens", 0),
                "completion_tokens": getattr(usage, "completion_tokens", 0),
                "total_tokens": getattr(usage, "total_tokens", 0),
            },
        }

    async def close(self) -> None:
        self._client = None


# ── Main LLM Client ───────────────────────────────────────────────────────────

class LLMClient:
    """Unified async client for all LLM providers."""

    def __init__(
        self,
        config: LLMConfig | None = None,
        mode: str | None = None,
        *,
        client_name: str | None = None,
    ) -> None:
        # mode parameter is accepted for backward compatibility but ignored
        # (the config itself determines behavior)
        _ = mode
        self._config = config or get_config()
        self._provider = self._config.provider
        self._is_local = self._provider == "ollama"
        self._client_name = str(client_name or "").strip()

        # Use Mistral SDK for native support (if available)
        self._use_mistral_sdk = False
        self._mistral: _MistralClient | None = None
        self._http: httpx.AsyncClient | None = None

        if self._provider == "mistral":
            try:
                # Validate the symbol we actually use later; some environments
                # have mismatched mistralai builds that import but lack Mistral.
                from mistralai import Mistral  # noqa: F401
                self._use_mistral_sdk = True
                self._mistral = _MistralClient(self._config)
            except Exception:
                # Fallback to HTTP client (Mistral API is OpenAI-compatible)
                self._use_mistral_sdk = False
                self._mistral = None

        if not self._use_mistral_sdk:
            self._http = self._build_http_client()

        logger.debug(
            "llm_client_initialized",
            client_name=self._client_name or None,
            provider=self._provider,
            model=self._config.model,
            api_url=self._config.api_url[:50] + "..." if len(self._config.api_url) > 50 else self._config.api_url,
        )

    @property
    def model(self) -> str:
        """Get the model name."""
        return self._config.model

    @property
    def provider(self) -> str:
        """Get the provider name."""
        return self._provider

    @property
    def max_tokens(self) -> int:
        """Get the max tokens setting."""
        return self._config.max_tokens

    @property
    def temperature(self) -> float:
        """Get the temperature setting."""
        return self._config.temperature

    def _build_http_client(self) -> httpx.AsyncClient:
        headers = {"Content-Type": "application/json"}
        api_key = self._config.api_key.strip()
        if api_key and not self._is_local:
            headers["Authorization"] = f"Bearer {api_key}"

        return httpx.AsyncClient(
            base_url=self._config.api_url,
            headers=headers,
            timeout=httpx.Timeout(
                600.0,
                connect=10.0,
            ),
        )

    async def chat(
        self,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None = None,
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        use_config_max_tokens: bool = True,
        max_retries: int = 3,
    ) -> LLMResponse:
        """Send a chat completion request and return the parsed response."""

        # ── 1. Determine parameters ───────────────────────────────────────────
        payload_max_tokens: int | None
        if max_tokens is not None:
            payload_max_tokens = max_tokens
        elif use_config_max_tokens:
            payload_max_tokens = self._config.max_tokens
        else:
            payload_max_tokens = None

        effective_temp = temperature if temperature is not None else self._config.temperature

        # ── 2. PrivacyGate Anonymization ──────────────────────────────────────
        # Check global database settings first, then fallback to ENV
        use_privacy_gate = True
        try:
            from server.api.dependencies import projects_store
            from server.api.routes.settings import SETTINGS_ID
            settings_data = projects_store.get_project(SETTINGS_ID)
            if settings_data and "privacy_gate" in settings_data:
                use_privacy_gate = bool(settings_data["privacy_gate"])
            else:
                use_privacy_gate = os.getenv("PRIVACYGATE_ENABLED", "1").lower() in ("1", "true", "yes", "on")
        except Exception:
            # Fallback to ENV if DB is not available or during early startup
            use_privacy_gate = os.getenv("PRIVACYGATE_ENABLED", "1").lower() in ("1", "true", "yes", "on")
        
        session_id = None

        if use_privacy_gate:
            from server.layers.PrivacyGate.node import anonymize, deanonymize
            
            _sep = "\n\n---PRIVACYGATE_MSG_SEP---\n\n"
            raw_contents = [m.content or "" for m in messages]
            combined_prompt = _sep.join(raw_contents)
            
            # Use a generic engagement_id for chat, the UUID inside anonymize prevents collisions
            anon_combined, session_id, _mapping = anonymize(
                combined_prompt,
                engagement_id="llm_chat",
                verbose=True
            )
            
            anon_contents = anon_combined.split(_sep)
            
            anon_messages = []
            for orig_m, anon_content in zip(messages, anon_contents):
                anon_messages.append(ChatMessage(
                    role=orig_m.role,
                    content=anon_content if orig_m.content else None,
                    tool_calls=orig_m.tool_calls,
                    tool_call_id=orig_m.tool_call_id,
                    name=orig_m.name,
                ))
        else:
            anon_messages = messages

        # ── 3. Dispatch to Provider ───────────────────────────────────────────
        result_content = ""
        result_tool_calls: list[dict[str, Any]] = []
        result_finish_reason = "stop"
        result_usage: dict[str, int] = {}

        # Use Mistral SDK if configured
        if self._use_mistral_sdk and self._mistral is not None:
            try:
                result = await self._mistral.chat(
                    messages=[m.to_api() for m in anon_messages],
                    tools=tools,
                    temperature=effective_temp,
                    max_tokens=payload_max_tokens,
                )
                result_content = str(result.get("content", "") or "")
                result_tool_calls = list(result.get("tool_calls", []) or [])
                result_finish_reason = str(result.get("finish_reason", "stop") or "stop")
                result_usage = result.get("usage", {}) if isinstance(result.get("usage"), dict) else {}
            except Exception as exc:
                logger.warning(
                    "mistral_sdk_fallback_http",
                    error=repr(exc),
                    model=self._config.model,
                )
                self._use_mistral_sdk = False
                self._mistral = None
                if self._http is None:
                    self._http = self._build_http_client()

        # Use OpenAI-compatible HTTP client
        if not self._use_mistral_sdk and self._http is not None:
            payload: dict[str, Any] = {
                "model": self._config.model,
                "messages": [m.to_api() for m in anon_messages],
                "temperature": effective_temp,
            }
            if payload_max_tokens is not None:
                payload["max_tokens"] = payload_max_tokens
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"

            if _LLM_DEBUG_LOGS:
                logger.debug(
                    "llm_request",
                    provider=self._provider,
                    model=self._config.model,
                    messages=len(anon_messages),
                    tools=len(tools) if tools else 0,
                )

            resp = await self._http.post("/chat/completions", json=payload)

            # Log error body for non-2xx responses (except 429 which is retried)
            if resp.status_code >= 400 and resp.status_code != 429:
                logger.error(
                    "llm_api_error",
                    provider=self._provider,
                    status=resp.status_code,
                    body=resp.text[:500],
                )

            # Retry on rate-limit (429) with exponential backoff
            retries = 0
            while resp.status_code == 429 and retries < max_retries:
                retries += 1
                wait_raw = float(resp.headers.get("retry-after", 2 ** retries))
                wait = min(wait_raw, 30.0)
                logger.warning("llm_rate_limited", retry=retries, wait=wait, original_wait=wait_raw)
                await asyncio.sleep(wait)
                resp = await self._http.post("/chat/completions", json=payload)

            if resp.status_code == 429:
                # Try backup provider if configured
                backup_config = get_backup_llm_config()
                if backup_config and backup_config.provider != self._provider:
                    logger.warning(
                        "llm_rate_limit_fallback",
                        original_provider=self._provider,
                        backup_provider=backup_config.provider,
                    )
                    # Use a fresh client for the backup request
                    async with LLMClient(backup_config, client_name=f"{self._client_name}_fallback") as fallback_llm:
                        return await fallback_llm.chat(
                            messages=messages,
                            tools=tools,
                            temperature=temperature,
                            max_tokens=max_tokens,
                            use_config_max_tokens=use_config_max_tokens,
                            max_retries=1,  # Avoid deep recursion
                        )

            resp.raise_for_status()
            data = resp.json()

            choice = data["choices"][0]
            msg = choice["message"]
            result_content = msg.get("content") or ""
            
            # Handle local LLM quirks
            if self._is_local and not result_content.strip() and msg.get("reasoning"):
                logger.warning("local_llm_content_empty_reasoning_dropped")
                result_content = ""

            result_tool_calls = msg.get("tool_calls") or []
            result_finish_reason = choice.get("finish_reason", "stop")
            result_usage = data.get("usage", {})

        # ── 4. PrivacyGate Deanonymization ────────────────────────────────────
        
        # Restore actual values in LLM text output if PrivacyGate was used
        if session_id:
            from server.layers.PrivacyGate.node import deanonymize
            if result_content:
                result_content = deanonymize(result_content, session_id)
                
            # Restore actual values inside JSON tool arguments
            for tc in result_tool_calls:
                if isinstance(tc, dict) and "function" in tc:
                    func = tc["function"]
                    if "arguments" in func:
                        args = func["arguments"]
                        if isinstance(args, str):
                            func["arguments"] = deanonymize(args, session_id)
                        elif isinstance(args, dict):
                            # Recursively deanonymize dict values
                            def _deanonymize_recursive(obj):
                                if isinstance(obj, str):
                                    return deanonymize(obj, session_id)
                                elif isinstance(obj, dict):
                                    return {k: _deanonymize_recursive(v) for k, v in obj.items()}
                                elif isinstance(obj, list):
                                    return [_deanonymize_recursive(x) for x in obj]
                                return obj
                            func["arguments"] = _deanonymize_recursive(args)

        # ── 5. Clean up Thinking Blocks ───────────────────────────────────────
        
        # Strip <think>...</think> tags used by models like DeepSeek-R1
        if result_content and "<think>" in result_content:
            import re
            result_content = re.sub(r"<think>.*?</think>", "", result_content, flags=re.DOTALL).strip()

        return LLMResponse(
            content=result_content,
            tool_calls=result_tool_calls,
            finish_reason=result_finish_reason,
            usage=result_usage,
        )

    async def close(self) -> None:
        """Close the client and release resources."""
        if self._mistral is not None:
            await self._mistral.close()
        if self._http is not None:
            await self._http.aclose()

    async def __aenter__(self) -> LLMClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self.close()


# ── Factory function ──────────────────────────────────────────────────────────

def get_llm(config: LLMConfig | None = None) -> LLMClient:
    """Get an LLM client with the specified or default configuration.

    Args:
        config: Optional custom configuration. If None, uses environment config.

    Returns:
        LLMClient instance ready to use.

    Example:
        async with get_llm() as llm:
            response = await llm.chat([ChatMessage(role="user", content="Hi!")])
    """
    return LLMClient(config)


# ── Backward compatibility exports ────────────────────────────────────────────
# These are deprecated but kept for existing code

# Alias for old config classes (will be removed in future)
PublicLLMConfig = LLMConfig
LocalLLMConfig = LLMConfig

def _get_public_config() -> LLMConfig:
    return LLMConfig.from_env()

def _get_local_config() -> LLMConfig:
    return LLMConfig.local()

# Lazy-loaded singletons for backward compat
class _ConfigProxy:
    def __init__(self, loader):
        self._loader = loader
        self._config: LLMConfig | None = None

    def _get(self) -> LLMConfig:
        if self._config is None:
            self._config = self._loader()
        return self._config

    def __getattr__(self, name: str) -> Any:
        return getattr(self._get(), name)

public_llm_config = _ConfigProxy(_get_public_config)
local_llm_config = _ConfigProxy(_get_local_config)

class _ModeProxy:
    @property
    def mode(self) -> str:
        return get_llm_mode()

llm_mode = _ModeProxy()
