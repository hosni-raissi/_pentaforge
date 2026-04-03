# schemas/scan_request/desktop.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class DesktopOS(str, Enum):
    windows = "windows"
    linux   = "linux"
    macos   = "macos"

class DesktopInputType(str, Enum):
    installer   = "installer"   # .exe / .msi / .deb / .dmg
    binary      = "binary"      # compiled binary
    local       = "local"       # already installed, path provided

class DesktopScanRequest(BaseModel):
    # --- App ---
    os:                 DesktopOS
    input_type:         DesktopInputType
    file_path:          Optional[str]  = None   # uploaded installer/binary
    install_path:       Optional[str]  = None   # if already installed
    technology:         Optional[str] = None
    version:            Optional[str]  = None

    # --- Auth ---
    credentials:        Optional[List[Credential]] = None

    # --- API Backend ---
    api_backend_url:    Optional[str]  = None   # if app talks to a backend
    api_spec_url:       Optional[str]  = None

    description:        Optional[str]  = None