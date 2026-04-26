import re
import spacy
import redis
import json
import hashlib
from datetime import datetime

nlp = spacy.load("en_core_web_sm")
r = redis.Redis(host="localhost", port=6379, decode_responses=True)

# ── Pattern registry (order matters — most specific first) ────────
PATTERNS = [
    ("CIDR",  r"\b(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}\b"),          # before IP
    ("IP",    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    ("EMAIL", r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),# before HOST
    ("URL",   r"https?://[^\s\"'<>]+"),                            # before HOST
    ("HOST",  r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|org|net|io|tn|local|corp|int|lan|gov|edu)\b"),
    ("CRED",  r"(?:password|passwd|secret|token|api_?key|auth)\s*[:=]\s*\S+"),
    ("HASH",  r"\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b"),  # MD5/SHA1/SHA256
    ("PORT",  r"\b(?:port|PORT)\s+(\d{1,5})\b"),                  # labeled ports only
]

# ── Tokens that must NEVER be replaced ───────────────────────────
SAFE_PASSTHROUGH = re.compile(
    r"CVE-\d{4}-\d+"           # CVE IDs
    r"|CWE-\d+"                # CWE IDs
    r"|\bCVSS\b|\bEPSS\b"     # scoring systems
    r"|\bSSVC\b|\bMITRE\b"    # frameworks
    r"|\bnmap\b|\bsqlmap\b|\bmetasploit\b|\bnuclei\b"   # tools
    r"|\bburp\b|\bdalfox\b|\bhydra\b|\bamass\b"
    r"|\bACT\b|\bATTEND\b|\bTRACK\b",                  # SSVC decisions
    re.IGNORECASE
)

# ── NER labels to anonymize ───────────────────────────────────────
NER_LABELS = {"ORG", "PERSON", "GPE", "LOC", "FAC"}

# ── Prefix map for readable aliases ──────────────────────────────
PREFIX = {
    "IP":     "IP",
    "CIDR":   "NET",
    "URL":    "URL",
    "HOST":   "HOST",
    "EMAIL":  "EMAIL",
    "CRED":   "CRED",
    "HASH":   "HASH",
    "PORT":   "PORT",
    "ORG":    "ORG",
    "PER":    "PERSON",
    "GPE":    "PLACE",
    "LOC":    "PLACE",
    "FAC":    "PLACE",
}


def anonymize(prompt: str, session_id: str) -> tuple[str, dict]:
    """
    Anonymize sensitive data in prompt before sending to public LLM API.
    Returns (clean_prompt, mapping) and saves mapping to Redis.
    """
    mapping = {}   # alias  → real value
    reverse = {}   # real   → alias      (dedup)
    counters = {}  # type   → int counter

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

    # ── Pass 1: Regex — structured sensitive data ─────────────────
    for token_type, pattern in PATTERNS:
        def replacer(m, t=token_type):
            original = m.group(0)
            if SAFE_PASSTHROUGH.search(original):
                return original
            return get_alias(t, original)
        result = re.sub(pattern, replacer, result, flags=re.IGNORECASE)

    # ── Pass 2: spaCy NER — names, orgs, locations ────────────────
    doc = nlp(result)
    for ent in reversed(doc.ents):   # reversed keeps char offsets valid
        if ent.label_ in NER_LABELS:
            if SAFE_PASSTHROUGH.search(ent.text):
                continue
            alias = get_alias(ent.label_, ent.text)
            result = result[:ent.start_char] + alias + result[ent.end_char:]

    # ── Pass 3: Persist to Redis (TTL = 24h) ─────────────────────
    redis_key = f"anon:{session_id}"
    r.setex(redis_key, 86400, json.dumps({
        "mapping":    mapping,
        "created_at": datetime.utcnow().isoformat(),
        "session_id": session_id,
    }))

    return result, mapping


def deanonymize(response: str, session_id: str) -> str:
    """
    Restore real values in LLM response using the Redis mapping.
    """
    raw = r.get(f"anon:{session_id}")
    if not raw:
        return response

    data = json.loads(raw)
    mapping: dict = data["mapping"]

    # Longest alias first — prevents partial replacements
    for alias, real in sorted(mapping.items(), key=lambda x: -len(x[0])):
        response = response.replace(alias, real)

    return response


def get_session_mapping(session_id: str) -> dict:
    """Debug helper — inspect what was anonymized in a session."""
    raw = r.get(f"anon:{session_id}")
    return json.loads(raw) if raw else {}