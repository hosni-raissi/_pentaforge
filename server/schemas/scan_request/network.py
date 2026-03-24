# schemas/scan_request/network.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class NetworkType(str, Enum):
    full_infrastructure = "full_infrastructure"  # full internal network
    wifi                = "wifi"                 # wireless network
    voip                = "voip"                 # VoIP / SIP
    firewall            = "firewall"             # firewall / ACL rules
    vpn                 = "vpn"                  # VPN gateway

# ─────────────────────────────────────────────
# Sub-configs per network type
# ─────────────────────────────────────────────

class InfrastructureConfig(BaseModel):
    cidr:               List[str]                # ["192.168.1.0/24", "10.0.0.0/16"]
    excluded_hosts:     Optional[List[str]] = None  # IPs to never touch
    gateway:            Optional[str]  = None    # e.g. "192.168.1.1"
    dns_server:         Optional[str]  = None    # e.g. "192.168.1.53"
    port_range:         Optional[str]  = "1-65535"
    stealth_mode:       Optional[bool] = False   # slow scan to avoid IDS

class WifiConfig(BaseModel):
    ssid:               str    # target network name
    bssid:              Optional[str]  = None    # target MAC address
    interface:          Optional[str]  = None    # e.g. "wlan0"
    channel:            Optional[int]  = None    # WiFi channel
    capture_file:       Optional[str]  = None    # uploaded .cap / .pcap file

class WifiEncryption(str, Enum):
    wep     = "wep"
    wpa     = "wpa"
    wpa2    = "wpa2"
    wpa3    = "wpa3"
    open    = "open"

class WifiScanConfig(WifiConfig):
    config:             WifiConfig  
    encryption:         Optional[WifiEncryption] = None
    

class VoipConfig(BaseModel):
    target_ip:          str                      # SIP server IP
    port:               Optional[int]  = 5060    # default SIP port
    protocol:           Optional[str]  = "udp"  # udp | tcp
    extension_range:    Optional[str]  = None    # e.g. "100-999"
    credentials:        Optional[List[Credential]] = None

class VpnConfig(BaseModel):
    gateway:            str                      # VPN gateway IP / hostname
    protocol:           Optional[str]  = None    # OpenVPN | IPSec | WireGuard | L2TP
    credentials:        Optional[List[Credential]] = None
    certificate:        Optional[str]  = None    # client cert path

class FirewallConfig(BaseModel):
    target_ip:          str                      # firewall IP
    test_bypass:        Optional[bool] = True    # test ACL bypass techniques
    test_dos:           Optional[bool] = False   # DoS resistance (careful!)
    test_fragmentation: Optional[bool] = True    # fragmented packet evasion


# ─────────────────────────────────────────────
# Main Request
# ─────────────────────────────────────────────

class NetworkScanRequest(BaseModel):
    network_type:       NetworkType
    depth:              Optional[int]  = 3       # how deep to scan (e.g. for pivoting)
    infrastructure:     Optional[InfrastructureConfig] = None
    wifi:               Optional[WifiScanConfig]       = None
    voip:               Optional[VoipConfig]           = None
    vpn:                Optional[VpnConfig]            = None
    firewall:           Optional[FirewallConfig]       = None