# schemas/scan_request/cloud.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum

class CloudProvider(str, Enum):
    aws     = "aws"
    azure   = "azure"
    gcp     = "gcp"

class CloudScanRequest(BaseModel):
    provider:           CloudProvider
    # --- Auth ---
    access_key:         Optional[str]  = None       # AWS access key
    secret_key:         Optional[str]  = None       # AWS secret key
    subscription_id:    Optional[str]  = None       # Azure subscription
    project_id:         Optional[str]  = None       # GCP project
    token:              Optional[str]  = None       # any cloud token
    # --- Scope ---
    region:             Optional[str]  = None       # e.g. "us-east-1"
    services:           Optional[List[str]] = None  # ["S3", "EC2", "IAM"]
    description:        Optional[str]  = None
 