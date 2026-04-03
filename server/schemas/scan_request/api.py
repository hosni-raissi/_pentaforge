# schemas/scan_request/api.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class ApiFormat(str, Enum):
    rest        = "rest"
    graphql     = "graphql"
    soap        = "soap"
    grpc        = "grpc"

class AuthType(str, Enum):
    bearer      = "bearer"
    basic       = "basic"
    api_key     = "api_key"
    oauth2      = "oauth2"
    cookie      = "cookie"
    none        = "none"

class ApiAuthConfig(BaseModel):
    type:           AuthType
    token:          Optional[str]  = None
    api_key:        Optional[str]  = None
    api_key_header: Optional[str]  = None       # e.g. "X-API-Key"

class ApiEndpoint(BaseModel):
    path:       str                             # e.g. /api/v1/users
    method:     str                             # GET POST PUT DELETE
    params:     Optional[dict] = None
    body:       Optional[dict] = None
    headers:    Optional[dict] = None

class ApiScanRequest(BaseModel):
    # --- Base ---
    base_url:           str
    format:             ApiFormat
    # --- Definition ---
    spec_url:           Optional[str]  = None   # Swagger / OpenAPI URL
    endpoints:          Optional[List[ApiEndpoint]] = None
    # --- Auth ---
    auth:               Optional[ApiAuthConfig] = None
    credentials:        Optional[List[Credential]] = None
    description:        Optional[str]  = None