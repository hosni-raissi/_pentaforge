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

class DesktopTechnology(str, Enum):
    electron    = "electron"    # JS-based desktop app
    dotnet      = "dotnet"      # C# / .NET
    java        = "java"        # Java Swing / JavaFX
    qt          = "qt"          # C++ Qt
    native      = "native"      # pure C / C++

class DesktopScanRequest(BaseModel):
    # --- App ---
    os:                 DesktopOS
    input_type:         DesktopInputType
    file_path:          Optional[str]  = None   # uploaded installer/binary
    install_path:       Optional[str]  = None   # if already installed
    technology:         Optional[DesktopTechnology] = None
    version:            Optional[str]  = None

    # --- Auth ---
    credentials:        Optional[List[Credential]] = None

    # --- API Backend ---
    api_backend_url:    Optional[str]  = None   # if app talks to a backend
    api_spec_url:       Optional[str]  = None

    # --- Checks ---
    check_memory:       Optional[bool] = True   # memory corruption, buffer overflow
    check_privileges:   Optional[bool] = True   # privilege escalation
    check_network:      Optional[bool] = True   # traffic interception
    check_storage:      Optional[bool] = True   # sensitive data in local files/registry
    check_update:       Optional[bool] = True   # insecure auto-update mechanism
    check_electron:     Optional[bool] = False  # nodeIntegration, contextIsolation
