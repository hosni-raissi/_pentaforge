from __future__ import annotations

from server.agents.executer.recon.tools.api import api_service_recon as api_service_recon_module


def test_api_service_recon_aggregates_protocol_results(monkeypatch) -> None:
    def fake_graphql_recon(**kwargs):
        assert kwargs["target"] == "https://api.example.com:50051"
        return {
            "success": True,
            "endpoints_found": 1,
            "all_issues": ["GraphQL IDE exposed"],
        }

    def fake_grpc_recon(**kwargs):
        assert kwargs["target"] == "api.example.com:50051"
        return {
            "success": True,
            "detected": True,
            "services": [{"name": "demo.Service"}],
            "findings": [{"title": "Reflection enabled"}],
        }

    def fake_soap_wsdl_recon(**kwargs):
        assert kwargs["target"] == "https://api.example.com:50051"
        return {
            "success": False,
            "error": "No WSDL/SOAP definitions discovered",
            "wsdl_documents": [],
            "findings": [],
        }

    monkeypatch.setattr(api_service_recon_module, "graphql_recon", fake_graphql_recon)
    monkeypatch.setattr(api_service_recon_module, "grpc_recon", fake_grpc_recon)
    monkeypatch.setattr(api_service_recon_module, "soap_wsdl_recon", fake_soap_wsdl_recon)

    result = api_service_recon_module.api_service_recon(
        target="api.example.com:50051",
        protocols=["graphql", "grpc", "soap_wsdl"],
        verify_tls=False,
    )

    assert result["success"] is True
    assert result["http_target"] == "https://api.example.com:50051"
    assert result["grpc_target"] == "api.example.com:50051"
    assert result["protocols_with_findings"] == ["graphql", "grpc"]
    assert result["graphql"]["success"] is True
    assert result["grpc"]["detected"] is True
    assert result["soap_wsdl"]["success"] is False


def test_api_service_recon_rejects_unknown_protocol() -> None:
    result = api_service_recon_module.api_service_recon(
        target="https://api.example.com",
        protocols=["graphql", "bogus"],
    )

    assert result["success"] is False
    assert "Unsupported protocol" in str(result["error"])
