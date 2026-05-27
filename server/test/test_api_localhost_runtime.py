from __future__ import annotations

from server.agents.executer.recon.tools.api._common import is_valid_http_target
from server.agents.executer.recon.tools.api._common import prepare_runtime_http_target
from server.agents.executer.recon.tools.api.api_endpoint_discovery import APIDiscoveryRequest
from server.agents.executer.recon.tools.api.api_passive_enum import PassiveEnumRequest


def test_api_tools_accept_localhost_targets() -> None:
    discovery = APIDiscoveryRequest(tool="manual", target="http://localhost:8888/v2/api-docs")
    passive = PassiveEnumRequest(target="http://localhost:8888/v2/api-docs")

    assert discovery.target == "http://localhost:8888/v2/api-docs"
    assert passive.target == "http://localhost:8888/v2/api-docs"
    assert is_valid_http_target("http://localhost:8888")
    assert is_valid_http_target("localhost:8888")


def test_prepare_runtime_http_target_rewrites_loopback_inside_container(monkeypatch) -> None:
    monkeypatch.setattr(
        "server.agents.executer.recon.tools.api._common.is_containerized_runtime",
        lambda: True,
    )

    assert (
        prepare_runtime_http_target("http://localhost:8888/v2/api-docs")
        == "http://host.docker.internal:8888/v2/api-docs"
    )
    assert (
        prepare_runtime_http_target("https://127.0.0.1:8443/swagger.json")
        == "https://host.docker.internal:8443/swagger.json"
    )
