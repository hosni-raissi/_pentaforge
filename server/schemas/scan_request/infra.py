# schemas/scan_request/infra.py
from pydantic import BaseModel
from typing import Optional, List

from .credentials import Credential


class InfraScanRequest(BaseModel):
    # Required anchor for broad infrastructure engagements.
    primary_scope: str  # CIDR, domain, or asset group label

    # Optional scope detail across infrastructure layers.
    network_cidrs: Optional[List[str]] = None
    hostnames: Optional[List[str]] = None
    linux_hosts: Optional[List[str]] = None
    cloud_accounts: Optional[List[str]] = None
    container_targets: Optional[List[str]] = None

    # Layer toggles for combined infra assessments.
    include_network: Optional[bool] = True
    include_linux_server: Optional[bool] = True
    include_cloud: Optional[bool] = True
    include_container: Optional[bool] = True

    credentials: Optional[List[Credential]] = None
    notes: Optional[str] = None
