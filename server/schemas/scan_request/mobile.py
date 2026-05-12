# schemas/scan_request/mobile.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class MobilePlatform(str, Enum):
    android = "android"
    ios     = "ios"

class MobileInputType(str, Enum):
    apk     = "apk"       # Android app file
    ipa     = "ipa"       # iOS app file


class MobileScanRequest(BaseModel):
    input_type:         MobileInputType          # apk | ipa
    file_path:          Optional[str]  = None    # uploaded apk/ipa path
    package_name:       Optional[str]  = None    # e.g. com.target.app
    platform:           MobilePlatform
    os_version:         Optional[str]  = None    # "13", "17"rooted Android 
    credentials:        Optional[List[Credential]] = None
    api_backend:        Optional[str] = None
