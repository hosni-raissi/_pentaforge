"""
Simple direct test for the PrivacyGate layer.

Just calls anonymize() and deanonymize() with a realistic prompt,
prints everything so you can see exactly what happens before/after the LLM.

Run:  python -m server.test.test_privacy_gate_e2e
"""

import sys
import json
from unittest.mock import MagicMock
from dataclasses import dataclass

# ── Fake spaCy / Redis so we can run without external services ────


@dataclass
class _FakeSpan:
    text: str
    label_: str
    start_char: int
    end_char: int


class _FakeDoc:
    def __init__(self, text, entities=None):
        self._text = text
        self.ents = entities or []


def _make_nlp(entity_defs=None):
    def _nlp(text):
        spans = []
        if entity_defs:
            for surface, label in entity_defs:
                idx = text.find(surface)
                if idx != -1:
                    spans.append(_FakeSpan(surface, label, idx, idx + len(surface)))
        return _FakeDoc(text, spans)
    return _nlp


class _FakeRedis:
    def __init__(self):
        self.store = {}
        self.ttls = {}

    def setex(self, key, ttl, value):
        self.store[key] = value
        self.ttls[key] = ttl

    def get(self, key):
        return self.store.get(key)


# Inject fakes before importing node.py
_mock_spacy = MagicMock()
_mock_spacy.load.return_value = _make_nlp([
    ("John Smith", "PERSON"),
    ("Acme Corp", "ORG"),
])
sys.modules.setdefault("spacy", _mock_spacy)

_fake_redis = _FakeRedis()
_mock_redis = MagicMock()
_mock_redis.Redis.return_value = _fake_redis
sys.modules.setdefault("redis", _mock_redis)

# Now safe to import
from server.layers.PrivacyGate.node import anonymize, deanonymize
import server.layers.PrivacyGate.node as _node

# Point module globals to our fakes
_node.r = _fake_redis
_node.nlp = _make_nlp([
    ("John Smith", "PERSON"),
    ("Acme Corp", "ORG"),
])

# =====================================================================
#  THE PROMPT (as if an agent is about to send this to an external LLM)
# =====================================================================

PROMPT = """
During the penetration test for Acme Corp, engineer John Smith discovered
that the server 192.168.10.42 (db-primary.acmecorp.com) exposes an admin
panel at https://internal.acmecorp.com/admin/config?debug=true.

The internal network 10.0.0.0/8 is in scope. Credentials found:
password: Sup3rS3cret!
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.payload.sig

AWS resource: arn:aws:s3:::acme-prod-backups/db-dump-2024.sql

Contact john.doe@acmecorp.com for access. Hash in config:
5d41402abc4b2a76b9719d911017c592

Vulnerability CVE-2024-31337 (CWE-89) was confirmed using sqlmap.
The nmap scan also revealed port 3306 open on 10.0.0.5.

-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA2a2rwplBQLzHPZe5RJr9bnDpdFBqKHFKMVFv6XESBcP+oAGW
-----END RSA PRIVATE KEY-----
""".strip()

SESSION = "test-session-001"

# =====================================================================
#  STEP 1 — Anonymize (before sending to LLM)
# =====================================================================

print("\n" + "█" * 60)
print("  STEP 1: ORIGINAL PROMPT (contains sensitive data)")
print("█" * 60)
print(PROMPT)

# verbose=True will print the anonymized version and the mapping
anon_prompt, returned_session_id, mapping = anonymize(PROMPT, engagement_id=SESSION, verbose=True)

# =====================================================================
#  STEP 2 — Simulate LLM response (using the aliases it received)
# =====================================================================

# Build a fake LLM response that uses the aliases from the anonymized prompt
import re
aliases = re.findall(r"__[A-Z]+_\d{3}__", anon_prompt)

llm_response = "Based on the analysis:\n"
for alias in aliases:
    llm_response += f"  - {alias} is a high-value target and should be investigated.\n"
llm_response += "\nRecommendation: patch the SQL injection (CVE-2024-31337) immediately."

# Deliberately mutate one alias to simulate an LLM hallucination and trigger the leak detector
if "__IP_001__" in llm_response:
    llm_response = llm_response.replace("__IP_001__", "__IP_1__")

print("█" * 60)
print("  STEP 2: LLM RESPONSE (with simulated alias mutation '__IP_1__')")
print("█" * 60)
print(llm_response)

# =====================================================================
#  STEP 3 — Deanonymize (restore real values in LLM response)
# =====================================================================

restored = deanonymize(llm_response, returned_session_id)

print("\n" + "█" * 60)
print("  STEP 3: RESTORED RESPONSE (real values back + leak tags)")
print("█" * 60)
print(restored)

# =====================================================================
#  Summary
# =====================================================================

print("\n" + "=" * 60)
print("  SUMMARY")
print("=" * 60)
print(f"  Original sensitive tokens:  {len(mapping)}")
print(f"  Aliases created:            {len(mapping)}")
leftover = re.findall(r"\[PRIVACYGATE_LEAK:__[A-Z]+_\d+__\]", restored)
print(f"  Aliases remaining after restore: {len(leftover)}")
if leftover:
    print(f"    ⚠ Leaked aliases successfully tagged: {leftover}")
else:
    print("  ✓ All aliases correctly replaced — no data leakage.")
print("=" * 60 + "\n")
