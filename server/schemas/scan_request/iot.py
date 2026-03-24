# schemas/scan_request/iot.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class IotProtocol(str, Enum):
    mqtt     = "mqtt"
    coap     = "coap"
    modbus   = "modbus"
    zigbee   = "zigbee"
    zwave    = "zwave"
    upnp     = "upnp"

class IotScanRequest(BaseModel):
    cidr:               str                         # IoT subnet
    protocols:          Optional[List[IotProtocol]] = None
    firmware_url:       Optional[str]  = None       # firmware to analyze
    default_creds:      Optional[bool] = True       # test default credentials
    credentials:        Optional[List[Credential]]  = None
    description:        Optional[str]  = None