from __future__ import annotations

from server.layers.PrivacyGate import node as privacy_gate


def test_privacy_gate_falls_back_to_in_memory_storage_when_redis_is_unavailable(monkeypatch) -> None:
    monkeypatch.setattr(
        privacy_gate,
        "_get_redis_client",
        lambda: (_ for _ in ()).throw(ConnectionError("redis down")),
    )
    monkeypatch.setattr(privacy_gate, "_redis_error_logged", False)
    monkeypatch.setattr(privacy_gate, "_in_memory_sessions", {})

    prompt = "Visit http://example.com/admin from 192.168.1.9"
    anonymized, session_id, mapping = privacy_gate.anonymize(prompt, engagement_id="test")

    assert session_id
    assert mapping
    assert "__HOST_001__" in anonymized or "__IP_001__" in anonymized

    restored = privacy_gate.deanonymize(anonymized, session_id)

    assert "http://example.com/admin" in restored
    assert "192.168.1.9" in restored
