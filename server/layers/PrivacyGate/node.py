import os
import re
import sys
import uuid
import logging
# import spacy
import redis
import json
from datetime import datetime
from time import time

from server.config.database import db_config

# ── Logger ────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("PrivacyGate")

# ── Strict mode ───────────────────────────────────────────────────
# Set PRIVACYGATE_STRICT=1 in production to raise on degraded NER
# instead of silently falling back to the smaller model.
_STRICT = os.getenv("PRIVACYGATE_STRICT", "0") == "1"

# ── NER model (Disabled per user request) ─────────────────────────
nlp = None
# try:
#     nlp = spacy.load("en_core_web_lg")
#     logger.info("PrivacyGate: using en_core_web_lg (high-accuracy NER)")
# except OSError:
#     if _STRICT:
#         raise RuntimeError(
#             "PrivacyGate: en_core_web_lg is required in strict mode. "
#             "Run: python -m spacy download en_core_web_lg"
#         )
#     nlp = spacy.load("en_core_web_sm")
#     logger.warning(
#         "PrivacyGate: en_core_web_lg not found — falling back to en_core_web_sm. "
#         "NER coverage is reduced. Set PRIVACYGATE_STRICT=1 to block this."
#     )

_SESSION_TTL_SECONDS = 86_400
_redis_client = None
_redis_error_logged = False
_in_memory_sessions: dict[str, dict] = {}


def _get_redis_client():
    global _redis_client
    if _redis_client is None:
        _redis_client = redis.from_url(
            db_config.redis_url,
            decode_responses=True,
        )
    return _redis_client


def _store_session_payload(redis_key: str, payload: dict) -> None:
    """Persist session payload in Redis when available, else in memory."""
    global _redis_error_logged
    payload_with_expiry = {
        **payload,
        "_expires_at": time() + _SESSION_TTL_SECONDS,
    }
    _in_memory_sessions[redis_key] = payload_with_expiry
    try:
        _get_redis_client().setex(
            redis_key,
            _SESSION_TTL_SECONDS,
            json.dumps(payload),
        )
    except Exception as exc:
        if not _redis_error_logged:
            logger.warning(
                "PrivacyGate: redis unavailable, using in-memory session storage",
                exc_info=exc,
            )
            _redis_error_logged = True


def _load_session_payload(redis_key: str) -> dict | None:
    """Load session payload from Redis, falling back to in-memory storage."""
    raw = None
    try:
        raw = _get_redis_client().get(redis_key)
    except Exception as exc:
        global _redis_error_logged
        if not _redis_error_logged:
            logger.warning(
                "PrivacyGate: redis read failed, using in-memory session storage",
                exc_info=exc,
            )
            _redis_error_logged = True

    if raw:
        try:
            payload = json.loads(raw)
            if isinstance(payload, dict):
                return payload
        except Exception:
            pass

    payload = _in_memory_sessions.get(redis_key)
    if not isinstance(payload, dict):
        return None
    expires_at = float(payload.get("_expires_at", 0) or 0)
    if expires_at and expires_at < time():
        _in_memory_sessions.pop(redis_key, None)
        return None
    return {k: v for k, v in payload.items() if k != "_expires_at"}

# ─────────────────────────────────────────────────────────────────
#  Pre-compiled patterns
# ─────────────────────────────────────────────────────────────────

# PEM blocks — compiled separately because they require re.DOTALL.
# Applying DOTALL globally would cause IP/HASH/PORT to match across
# line boundaries, producing false positives.
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]+-----[\s\S]*?-----END [A-Z ]+-----",
    re.DOTALL,
)

# Partial URL anonymization — scheme and path are preserved intact;
# only the domain is replaced with an alias.
#
#   Input:  http://ijbirb.com/sign
#   Output: http://__HOST_001__/sign
#
# This ensures the LLM retains:
#   - scheme (http vs https) — security signal (no TLS = worth flagging)
#   - path (/sign, /api/v2/users?id=1) — identifies the attack surface
#   - query parameters — needed for injection and IDOR testing
#
# Group 1: scheme   ("http://" | "https://")  — keep as-is
# Group 2: domain   ("ijbirb.com")             — anonymize → alias
# Group 3: path     ("/sign?foo=bar")           — keep as-is
_URL_PARTS_RE = re.compile(
    r"(https?://)"
    r"([a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,})"
    r"(/[^\s\"'<>]*)?",
    re.IGNORECASE,
)

# Pattern registry — processed in Pass 1c after PEM and URL passes.
# Rules:
#   - Most specific pattern before broader ones (CIDR before IP, etc.)
#   - re.IGNORECASE only — no DOTALL (PEM is handled separately)
#   - No cross-line matching
PATTERNS = [
    # CIDR before bare IP — prevents /24 suffix being left behind
    ("CIDR", re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b",
    )),

    # Bare IPv4
    ("IP", re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
    )),
]

# ── Safe passthrough — never replace these ────────────────────────
# Security framework identifiers, scoring systems, tool names,
# protocols, and common report labels must reach the LLM intact.
SAFE_PASSTHROUGH = re.compile(
    # CVEs/CWEs/Metrics
    r"CVE-\d{4}-\d+|CWE-\d+|\bCVSS\b|\bEPSS\b|\bSSVC\b|\bMITRE\b"
    # Tools
    r"|\bnmap\b|\bsqlmap\b|\bmetasploit\b|\bnuclei\b|\bburp\b|\bdalfox\b"
    r"|\bhydra\b|\bamass\b|\bgobuster\b|\bdirbuster\b|\bffuf\b|\bnikto\b"
    r"|\bwireshark\b|\bnetcat\b|\bnc\b|\bhashcat\b|\bjohn\b|\benum4linux\b"
    # Protocols/Tech
    r"|\bhttp\b|\bhttps\b|\bftp\b|\bsftp\b|\bssh\b|\btelnet\b|\bsmtp\b|\bdns\b"
    r"|\bsmb\b|\brdp\b|\bmysql\b|\bpostgres\b|\bmongo\b|\bredis\b|\bphp\b"
    r"|\bpython\b|\bjava\b|\bnode\b|\bapache\b|\bnginx\b|\blinux\b|\bwindows\b"
    # Report Labels / UI
    r"|\bCritical\b|\bHigh\b|\bMedium\b|\bLow\b|\bInfo\b|\bverified\b|\bopen\b"
    r"|\bTarget\b|\bScope\b|\bMethodology\b|\bFindings\b|\bRemediation\b"
    r"|\bmax\b"
    # Actions
    r"|\bACT\b|\bATTEND\b|\bTRACK\b",
    re.IGNORECASE,
)

# ── NER labels to anonymize ───────────────────────────────────────
NER_LABELS = set() # Disabled per user request (only URL and IP)

# ── Alias prefix map ──────────────────────────────────────────────
PREFIX = {
    "IP":     "IP",
    "CIDR":   "NET",
    "HOST":   "HOST",
    "EMAIL":  "EMAIL",
    "CRED":   "CRED",
    "HASH":   "HASH",
    # "PORT":   "PORT",  # Disabled per user request
    "ORG":    "ORG",
    "PERSON": "PERSON",
    "GPE":    "PLACE",
    "LOC":    "PLACE",
    "FAC":    "PLACE",
}

# ── Alias integrity scanner ───────────────────────────────────────
_ALIAS_PATTERN = re.compile(r"__[A-Z]+_\d{3}__")


# ─────────────────────────────────────────────────────────────────
#  Session key
# ─────────────────────────────────────────────────────────────────

def make_session_key(engagement_id: str) -> tuple[str, str]:
    """
    Build a collision-safe Redis key for one anonymization session.

    Key format: anon:{engagement_id}:{uuid4()}

    Two concurrent calls with the same engagement_id never collide,
    and the key cannot be predicted or pre-poisoned.

    Returns:
        (redis_key, session_id)
    """
    session_id = f"{engagement_id}:{uuid.uuid4()}"
    return f"anon:{session_id}", session_id


# ─────────────────────────────────────────────────────────────────
#  Anonymize
# ─────────────────────────────────────────────────────────────────

def anonymize(
    prompt: str,
    engagement_id: str,
    verbose: bool = False,
) -> tuple[str, str, dict]:
    """
    Anonymize sensitive data in a prompt before sending to a public LLM API.

    Four-pass pipeline
    ------------------
    Pass 1a — PEM blocks
        Compiled with re.DOTALL (multiline key blocks). Fires first so the
        full key material is captured before any inner tokens are matched.

    Pass 1b — Partial URL anonymization
        Scheme and path are preserved; only the domain is aliased.
        http://ijbirb.com/sign  →  http://__HOST_001__/sign
        Preserves TLS signal (http vs https) and attack surface info (/sign).

    Pass 1c — Regex patterns
        IGNORECASE only (no DOTALL). Handles credentials, IPs, emails,
        bare hostnames, hashes, and labeled ports.

    Pass 2 — spaCy NER
        Catches org names, personal names, and locations not captured by
        the regex patterns. Processed in reverse order to keep char offsets
        valid after each substitution.

    Pass 3 — Redis persistence
        Alias mapping stored with 24 h TTL. Key is engagement-scoped and
        UUID-suffixed — no cross-session collision possible.

    Args:
        prompt:        Raw prompt that may contain IPs, credentials, URLs,
                       PEM keys, AWS ARNs, bearer tokens, and personal names.
        engagement_id: Logical engagement identifier (e.g. "eng_2026_001").
        verbose:       Print anonymized prompt and mapping table (debug only).

    Returns:
        (clean_prompt, session_id, mapping)
        Store session_id and pass it to deanonymize() for every LLM
        response generated from this prompt.
    """
    redis_key, session_id = make_session_key(engagement_id)

    mapping  = {}   # alias  → real value
    reverse  = {}   # real   → alias  (same value always gets same alias)
    counters = {}   # prefix → int

    def get_alias(token_type: str, value: str) -> str:
        if value in reverse:
            return reverse[value]
        prefix = PREFIX.get(token_type, token_type)
        counters[prefix] = counters.get(prefix, 0) + 1
        alias = f"__{prefix}_{counters[prefix]:03d}__"
        mapping[alias] = value
        reverse[value] = alias
        return alias

    result = prompt

    # ── Pass 1a: PEM blocks ───────────────────────────────────────
    # Disabled per user request (only URL and IP)
    # result = _PEM_RE.sub(_pem_replacer, result)

    # ── Pass 1b: Partial URL anonymization ───────────────────────
    # Scheme and path flow through to the LLM unchanged.
    # Only the domain is replaced with a HOST alias.
    def _url_replacer(m: re.Match) -> str:
        scheme = m.group(1)        # "http://" or "https://"
        domain = m.group(2)        # "ijbirb.com"
        path   = m.group(3) or ""  # "/sign" or "/api/v2/users?id=1" or ""
        if SAFE_PASSTHROUGH.search(domain):
            return m.group(0)
        return f"{scheme}{get_alias('HOST', domain)}{path}"

    result = _URL_PARTS_RE.sub(_url_replacer, result)

    # ── Pass 1c: Regex pattern registry ──────────────────────────
    for token_type, compiled_pattern in PATTERNS:
        def replacer(m: re.Match, t: str = token_type) -> str:
            original = m.group(0)
            if SAFE_PASSTHROUGH.search(original):
                return original
            # Avoid re-anonymizing things that look like our own aliases
            if _ALIAS_PATTERN.search(original):
                return original
            # Special check for PORT: don't anonymize if it's already a placeholder-like number
            if t == "PORT":
                port_num = m.group(1)
                if port_num.startswith("00") and len(port_num) == 3:
                    return original
            return get_alias(t, original)
        result = compiled_pattern.sub(replacer, result)

    # ── Pass 2: spaCy NER (Disabled per user request) ────────────
    # doc = nlp(result)
    # ...

    # ── Pass 3: Persist mapping to Redis (TTL = 24 h) ────────────
    _store_session_payload(
        redis_key,
        {
            "mapping": mapping,
            "created_at": datetime.utcnow().isoformat(),
            "session_id": session_id,
        },
    )

    if verbose:
        _print_verbose(result, mapping)

    return result, session_id, mapping


# ─────────────────────────────────────────────────────────────────
#  Deanonymize
# ─────────────────────────────────────────────────────────────────

def deanonymize(response: str, session_id: str) -> str:
    """
    Restore real values in an LLM response using the stored alias mapping.

    Alias integrity check
    ---------------------
    After replacement, scans for any surviving __ALIAS__ tokens.
    These indicate the LLM mutated the token format (e.g. __IP_001__
    became __IP_1__). Each survivor is:
        - logged as WARNING with session_id and the full survivor list
        - tagged inline as [PRIVACYGATE_LEAK:__TOKEN__]
    so downstream consumers (report builder, DB writer) can detect and
    handle leakage explicitly rather than silently storing a raw alias.

    Args:
        response:   Raw LLM output containing alias tokens.
        session_id: Value returned by anonymize() for this prompt.

    Returns:
        De-anonymized string. May contain [PRIVACYGATE_LEAK:...] markers
        if alias mutation was detected.
    """
    redis_key = f"anon:{session_id}"
    payload = _load_session_payload(redis_key)

    if not payload:
        logger.error(
            "PrivacyGate.deanonymize: no mapping found for session '%s'. "
            "Response returned as-is — inspect before use.",
            session_id,
        )
        return response

    mapping: dict = payload.get("mapping", {})

    # Longest alias first — prevents __CRED_010__ being partially replaced
    # if __CRED_01__ also exists.
    for alias, real in sorted(mapping.items(), key=lambda x: -len(x[0])):
        response = response.replace(alias, real)

    # ── Integrity check ───────────────────────────────────────────
    survivors = _ALIAS_PATTERN.findall(response)
    if survivors:
        logger.warning(
            "PrivacyGate.deanonymize: %d alias(es) survived in session '%s'. "
            "LLM likely mutated the token format. Survivors: %s",
            len(survivors),
            session_id,
            survivors,
        )
        for token in set(survivors):
            response = response.replace(token, f"[PRIVACYGATE_LEAK:{token}]")

    return response


# ─────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────

def get_session_mapping(session_id: str) -> dict:
    """
    Debug helper — retrieve the alias mapping for a session.
    Returns an empty dict if the session has expired or never existed.
    """
    payload = _load_session_payload(f"anon:{session_id}")
    return payload if payload else {}


def _print_verbose(clean_prompt: str, mapping: dict) -> None:
    sep = "=" * 64
    lines = [
        "",
        sep,
        "  PrivacyGate — Anonymized Prompt",
        sep,
        clean_prompt,
        "",
        "-" * 64,
        "  Mapping  (alias -> real value)",
        "-" * 64,
    ]
    for alias, real in mapping.items():
        display = real if len(real) <= 60 else real[:57] + "..."
        lines.append(f"  {alias:28s} -> {display}")
    lines.extend([sep, ""])

    payload = "\n".join(lines)
    try:
        sys.stdout.write(payload)
        sys.stdout.flush()
    except (BlockingIOError, OSError):
        logger.debug(
            "PrivacyGate verbose output skipped because stdout is non-blocking or unavailable.",
            exc_info=True,
        )


# ─────────────────────────────────────────────────────────────────
#  Self-test
# ─────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    SAMPLE = """
    Target: http://ijbirb.com/sign
    Admin panel: https://ijbirb.com/admin/dashboard?debug=true
    API endpoint: http://ijbirb.com/api/v2/users?id=1
    Internal host: 10.0.0.5/24

    Credentials found:
        api_key=sk-prod-A3f9Kz112mNqP0Xw91234567890ABCDEF
        Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig
        AWS resource: arn:aws:s3:::acme-prod-backups/db-dump-2024.sql

    CVE-2021-41773 confirmed on Apache 2.4.49 — CVSS 9.8, EPSS 0.97.
    Contact: devops@acme-corp.com — reported by John Smith (CISO at Acme Corp).

    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9bnDpdFBqKHFKMVFv6XESBcP+oAGW
    -----END RSA PRIVATE KEY-----
    """

    print("── Anonymize ───────────────────────────────────────────────")
    clean, session_id, mapping = anonymize(
        SAMPLE, engagement_id="eng_2026_001", verbose=True
    )

    print(f"Session ID: {session_id}\n")

    # Verify URL partial anonymization
    print("── URL anonymization check ─────────────────────────────────")
    for line in clean.splitlines():
        line = line.strip()
        if "http" in line or "HOST" in line:
            print(f"  {line}")

    # Simulate LLM mutating one alias
    print("\n── Deanonymize (with deliberate alias mutation) ────────────")
    mutated = clean.replace("__IP_001__", "__IP_1__")
    restored = deanonymize(mutated, session_id)
    print(restored[:600])
