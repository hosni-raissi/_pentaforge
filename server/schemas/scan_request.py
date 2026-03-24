# schemas/scan_request/scan_request.py
from pydantic import BaseModel
from typing import Optional, Union
from enum import Enum

from .scan_request.web_app         import WebAppScanRequest
from .scan_request.api             import ApiScanRequest
from .scan_request.mobile          import MobileScanRequest
from .scan_request.network         import NetworkScanRequest
from .scan_request.iot             import IotScanRequest
from .scan_request.linux_server    import LinuxServerScanRequest
from .scan_request.desktop         import DesktopScanRequest
from .scan_request.cloud           import CloudScanRequest
from .scan_request.container       import ContainerScanRequest
from .scan_request.database        import DatabaseScanRequest
from .scan_request.repository      import RepositoryScanRequest


class TargetType(str, Enum):
    web_app          = "web_app"
    api              = "api"
    mobile           = "mobile"
    network          = "network"
    iot              = "iot"
    linux_server     = "linux_server"
    desktop          = "desktop"
    cloud            = "cloud"
    container        = "container"
    database         = "database"
    repository       = "repository"


class ScanRules(BaseModel):
    max_threads:        Optional[int]  = 10      # parallel threads
    timeout:            Optional[int]  = 30      # seconds per request
    rate_limit:         Optional[int]  = 100     # requests per second
    stealth_mode:       Optional[bool] = False   # slow and quiet
    auto_exploit:       Optional[bool] = False   # auto exploit found vulns
    auto_approve:       Optional[bool] = False   # skip human approval gate
    max_depth:          Optional[int]  = 3       # crawl / scan depth
    stop_on_critical:   Optional[bool] = False   # stop if critical found


TargetConfig = Union[
    WebAppScanRequest,
    ApiScanRequest,
    MobileScanRequest,
    NetworkScanRequest,
    IotScanRequest,
    LinuxServerScanRequest,
    DesktopScanRequest,
    CloudScanRequest,
    ContainerScanRequest,
    DatabaseScanRequest,
    RepositoryScanRequest,
]


class ScanRequest(BaseModel):
    target_type:    TargetType      # what type of target
    informations:    Optional[str]  = None   # context for the LLM
    rules:          Optional[ScanRules] = None   # how to behave
    config:         TargetConfig    # the actual target config
    scan_type: str
    target_type: str
    project_id: str