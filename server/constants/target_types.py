"""Target type catalog + schema field extraction for project creation."""

from __future__ import annotations

from enum import Enum
from types import UnionType
from typing import Any, Union, get_args, get_origin

from pydantic import BaseModel

from server.schemas.scan_request.api import ApiScanRequest
from server.schemas.scan_request.cloud import CloudScanRequest
from server.schemas.scan_request.container import ContainerScanRequest
from server.schemas.scan_request.database import DatabaseScanRequest
from server.schemas.scan_request.desktop import DesktopScanRequest
from server.schemas.scan_request.iot import IotScanRequest
from server.schemas.scan_request.linux_server import LinuxServerScanRequest
from server.schemas.scan_request.mobile import MobileScanRequest
from server.schemas.scan_request.network import NetworkScanRequest
from server.schemas.scan_request.repository import RepositoryScanRequest
from server.schemas.scan_request.web_app import WebAppScanRequest

_TYPE_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {"value": "web_app", "label": "Web Application", "schema": WebAppScanRequest},
    {"value": "api", "label": "API", "schema": ApiScanRequest},
    {"value": "mobile", "label": "Mobile App", "schema": MobileScanRequest},
    {"value": "network", "label": "Network", "schema": NetworkScanRequest},
    {"value": "iot", "label": "IoT", "schema": IotScanRequest},
    {"value": "linux_server", "label": "Linux Server", "schema": LinuxServerScanRequest},
    {"value": "desktop", "label": "Desktop App", "schema": DesktopScanRequest},
    {"value": "cloud", "label": "Cloud", "schema": CloudScanRequest},
    {"value": "container", "label": "Container", "schema": ContainerScanRequest},
    {"value": "database", "label": "Database", "schema": DatabaseScanRequest},
    {"value": "repository", "label": "Repository", "schema": RepositoryScanRequest},
)

TARGET_TYPES = [item["value"] for item in _TYPE_DEFINITIONS]
TARGET_TYPE_LABELS = {item["value"]: item["label"] for item in _TYPE_DEFINITIONS}
TARGET_TYPE_SCHEMAS = {item["value"]: item["schema"] for item in _TYPE_DEFINITIONS}


def get_target_type_options() -> list[dict[str, str]]:
    return [{"value": item["value"], "label": item["label"]} for item in _TYPE_DEFINITIONS]


def get_target_schema_fields(target_type: str, required_only: bool = False) -> list[dict[str, Any]]:
    schema = TARGET_TYPE_SCHEMAS.get(target_type)
    if schema is None:
        return []
    return _collect_fields(schema, required_only=required_only)


def _strip_optional(annotation: Any) -> tuple[Any, bool]:
    origin = get_origin(annotation)
    if origin in (Union, UnionType):
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        if len(args) == 1:
            return args[0], True
    return annotation, False


def _collect_fields(
    model: type[BaseModel],
    *,
    prefix: str = "",
    required_only: bool,
    parent_required: bool = True,
) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []

    for name, field in model.model_fields.items():
        key = f"{prefix}.{name}" if prefix else name
        is_required = parent_required and field.is_required()
        if required_only and not is_required:
            continue

        annotation, _ = _strip_optional(field.annotation)
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            fields.extend(
                _collect_fields(
                    annotation,
                    prefix=key,
                    required_only=required_only,
                    parent_required=is_required,
                )
            )
            continue

        origin = get_origin(annotation)
        if origin in (list, tuple, set):
            args = get_args(annotation)
            item_annotation = args[0] if args else str
            item_annotation, _ = _strip_optional(item_annotation)
            if isinstance(item_annotation, type) and issubclass(item_annotation, BaseModel):
                # Expand list-of-object fields (e.g., credentials, endpoints) into
                # their object members so the UI can render concrete inputs.
                fields.extend(
                    _collect_fields(
                        item_annotation,
                        prefix=key,
                        required_only=required_only,
                        parent_required=is_required,
                    )
                )
                continue

        data_type, options = _annotation_to_ui_type(annotation)
        fields.append(
            {
                "key": key,
                "label": _label_from_key(key),
                "required": is_required,
                "data_type": data_type,
                "options": options,
            }
        )

    return fields


def _annotation_to_ui_type(annotation: Any) -> tuple[str, list[str]]:
    origin = get_origin(annotation)
    if origin in (list, tuple, set):
        args = get_args(annotation)
        item = args[0] if args else str
        item, _ = _strip_optional(item)
        if isinstance(item, type) and issubclass(item, Enum):
            return "array", [str(member.value) for member in item]
        return "array", []

    if isinstance(annotation, type) and issubclass(annotation, Enum):
        return "enum", [str(member.value) for member in annotation]

    if annotation is bool:
        return "boolean", []
    if annotation is int:
        return "integer", []
    if annotation is float:
        return "number", []

    return "string", []


def _label_from_key(key: str) -> str:
    acronyms = {"id", "ip", "os", "url", "db", "api", "cidr", "dns", "ssh", "tls"}
    parts = key.replace(".", " ").replace("_", " ").split()
    words = [part.upper() if part.lower() in acronyms else part.capitalize() for part in parts]
    return " ".join(words)
