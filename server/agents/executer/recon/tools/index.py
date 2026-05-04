"""Recon tool scope index."""

from __future__ import annotations

from typing import Iterable

from .web.runtime_policy import (
    WEB_ALIAS_BACKED_TOOL_NAMES,
    WEB_ALIAS_MODULES,
    WEB_SMART_PYTHON_MODULES,
    WEB_SMART_PYTHON_TOOL_NAMES,
)

_RECON_MODULES_BY_SCOPE: dict[str, tuple[str, ...]] = {
    "shared": (
        "all.run_custom",
        "all.run_python",
    ),
    "api": (
        "api.api_endpoint_discovery",
        "api.api_passive_enum",
        "api.api_response_analyzer",
        "api.graphql_recon",
        "api.grpc_recon",
        "api.oauth_oidc_check",
        "api.soap_wsdl_recon",
        "api.zap_daemon_scan",
    ),
    "cloud": (
        "cloud.cloud_misconfig_scan",
        "cloud.cloud_storage_enum",
    ),
    "container": (
        "container.container_image_scan",
        "container.container_layer_analysis",
        "container.container_registry_enum",
        "container.container_runtime_audit",
        "container.container_startup_config_audit",
    ),
    "infra": (
        "infra.binary_analysis",
    ),
    "iot": (
        "iot.firmware_analysis",
        "iot.iot_protocol_scan",
    ),
    "mobile": (
        "mobile.mobile_dynamic_analysis",
        "mobile.mobile_static_analysis",
        "mobile.mobile_storage_check",
    ),
    "network": (
        "network.arp_scan",
        "network.dns_recon",
        "network.ike_scan",
        "network.name_service_surface",
        "network.remote_access_recon",
        "network.route_topology",
        "network.traffic_analyze",
        "network.voip_recon",
        "network.wireless_scan",
        "network.zgrab2_enrich",
    ),
    "repository": (
        "repository.ci_cd_pipeline_audit",
        "repository.dependency_scan",
        "repository.git_history_audit",
        "repository.iac_security_scan",
        "repository.sast_scan",
        "repository.secret_scan",
        "repository.sensitive_files_scan",
    ),
    "server": (
        "server.db_enum_and_audit",
        "server.smb_deep_enum",
        "server.snmp_fast_enum",
    ),
    "web": (
        *WEB_ALIAS_MODULES,
        *WEB_SMART_PYTHON_MODULES,
    ),
}

_RECON_TOOL_SCOPE_INDEX: dict[str, tuple[str, ...]] = {
    "shared": (
        "run_custom",
        "run_python",
    ),
    "api": (
        "api_endpoint_discovery",
        "api_passive_enum",
        "api_response_analyzer",
        "graphql_recon",
        "grpc_recon",
        "oauth_oidc_check",
        "soap_wsdl_recon",
        "zap_daemon_scan",
    ),
    "cloud": (
        "cloud_misconfig_scan",
        "cloud_storage_enum",
    ),
    "container": (
        "container_image_scan",
        "container_layer_analysis",
        "container_registry_enum",
        "container_runtime_audit",
        "container_startup_config_audit",
    ),
    "infra": (
        "binary_analysis",
    ),
    "iot": (
        "firmware_analysis",
        "iot_protocol_scan",
    ),
    "mobile": (
        "mobile_dynamic_analysis",
        "mobile_static_analysis",
        "mobile_storage_check",
    ),
    "network": (
        "arp_scan",
        "dns_recon",
        "ike_scan",
        "name_service_surface",
        "remote_access_recon",
        "route_topology",
        "traffic_analyze",
        "voip_recon",
        "wireless_scan",
        "zgrab2_enrich",
    ),
    "repository": (
        "ci_cd_pipeline_audit",
        "dependency_scan",
        "git_history_audit",
        "iac_security_scan",
        "sast_scan",
        "secret_scan",
        "sensitive_files_scan",
    ),
    "server": (
        "db_enum_and_audit",
        "smb_deep_enum",
        "snmp_fast_enum",
    ),
    "web": (
        *WEB_ALIAS_BACKED_TOOL_NAMES,
        *WEB_SMART_PYTHON_TOOL_NAMES,
    ),
}

_RECON_TARGET_TYPES_BY_SCOPE: dict[str, set[str]] = {
    "shared": {"shared"},
    "api": {"api", "web_app"},
    "cloud": {"cloud"},
    "container": {"container"},
    "infra": {"infra"},
    "iot": {"iot", "network"},
    "mobile": {"mobile"},
    "network": {"network", "infra", "linux_server"},
    "repository": {"repository"},
    "server": {"linux_server", "infra", "network"},
    "web": {"web_app", "api"},
}

_RECON_TARGET_TYPE_OVERRIDES: dict[str, set[str]] = {
    "binary_analysis": {"desktop"},
    "container_registry_enum": {"cloud", "container"},
    "db_enum_and_audit": {
        "web_app",
        "api",
        "network",
        "infra",
        "linux_server",
        "mobile",
        "desktop",
        "cloud",
        "container",
        "repository",
        "iot",
    },
    "dns_recon": {"network", "infra", "web_app", "api"},
    "secret_scan": {"repository", "cloud"},
    "ssl_tls_analysis": {"web_app", "api", "network"},
}


def _selected_scopes(scopes: Iterable[str] | None = None) -> list[str]:
    if scopes is None:
        return list(_RECON_MODULES_BY_SCOPE.keys())
    selected: list[str] = []
    for scope in scopes:
        clean = str(scope or "").strip().lower()
        if clean and clean in _RECON_MODULES_BY_SCOPE and clean not in selected:
            selected.append(clean)
    return selected


def enabled_recon_module_names(
    package_name: str,
    scopes: Iterable[str] | None = None,
) -> list[str]:
    module_names: list[str] = []
    for scope in _selected_scopes(scopes):
        module_names.extend(f"{package_name}.{module_name}" for module_name in _RECON_MODULES_BY_SCOPE[scope])
    return module_names


def load_recon_tool_scope_index() -> dict[str, list[str]]:
    return {scope: list(tool_names) for scope, tool_names in _RECON_TOOL_SCOPE_INDEX.items()}


def load_recon_target_type_mapping() -> dict[str, set[str]]:
    mapping: dict[str, set[str]] = {}
    for scope, tool_names in _RECON_TOOL_SCOPE_INDEX.items():
        target_types = _RECON_TARGET_TYPES_BY_SCOPE.get(scope, set())
        for tool_name in tool_names:
            mapping.setdefault(tool_name, set()).update(target_types)
    for tool_name, target_types in _RECON_TARGET_TYPE_OVERRIDES.items():
        mapping[tool_name] = set(target_types)
    return mapping
