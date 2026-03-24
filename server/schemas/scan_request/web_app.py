# schemas/scan_request/web_app.py
from pydantic import BaseModel
from typing import Optional, List
from .credentials import Credential

class WebAppScanRequest(BaseModel):
    url:         str
    credentials: Optional[List[Credential]] = None
    cookies:     Optional[dict] = None
    headers:     Optional[dict] = None