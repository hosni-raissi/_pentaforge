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

    credentials: Optional[List[Credential]] = None
    description:        Optional[str]  = None
