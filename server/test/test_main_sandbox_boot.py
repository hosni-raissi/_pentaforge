from __future__ import annotations

from types import SimpleNamespace

import server.main as main_module


def test_main_uses_existing_local_sandbox_without_spawning(monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.delenv("PENTAFORGE_SANDBOX_SERVICE", raising=False)
    monkeypatch.setattr(main_module, "_port_accepting_connections", lambda port, host="127.0.0.1", timeout=0.25: True)

    spawned: list[object] = []

    def _unexpected_spawn(*args, **kwargs):
        spawned.append((args, kwargs))
        raise AssertionError("sandbox subprocess should not be spawned when port 8010 is already listening")

    monkeypatch.setattr(main_module.subprocess, "Popen", _unexpected_spawn)

    main_module._start_local_sandbox_service()

    assert main_module._sandbox_executor_url() == "http://127.0.0.1:8010"
    assert spawned == []


def test_main_spawns_local_sandbox_when_needed(monkeypatch) -> None:
    monkeypatch.delenv("SANDBOX_EXECUTOR_URL", raising=False)
    monkeypatch.delenv("PENTAFORGE_SANDBOX_SERVICE", raising=False)
    monkeypatch.setattr(main_module, "_SANDBOX_PROC", None)

    checks = iter([False, True])
    monkeypatch.setattr(
        main_module,
        "_port_accepting_connections",
        lambda port, host="127.0.0.1", timeout=0.25: next(checks),
    )
    monkeypatch.setattr(main_module.time, "sleep", lambda _: None)

    class FakeProc:
        def poll(self):
            return None

        def terminate(self):
            return None

        def wait(self, timeout=None):
            return None

        def kill(self):
            return None

    captured: dict[str, object] = {}

    def _fake_popen(cmd, env=None, stdout=None, stderr=None, text=None):
        captured["cmd"] = cmd
        captured["env"] = env
        return FakeProc()

    monkeypatch.setattr(main_module.subprocess, "Popen", _fake_popen)
    monkeypatch.setattr(main_module.atexit, "register", lambda fn: None)

    main_module._start_local_sandbox_service()

    assert captured["cmd"] == [
        main_module.sys.executable,
        "-m",
        "uvicorn",
        "server.sandbox_service.app:app",
        "--host",
        "127.0.0.1",
        "--port",
        "8010",
    ]
    assert isinstance(captured["env"], dict)
    assert captured["env"]["PENTAFORGE_SANDBOX_SERVICE"] == "1"
    assert main_module._sandbox_executor_url() == "http://127.0.0.1:8010"
