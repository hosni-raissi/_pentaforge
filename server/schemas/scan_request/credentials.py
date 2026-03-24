# schemas/scan_request/credentials.py
from pydantic import BaseModel
from typing import Optional
from enum import Enum

class TwoFactorType(str, Enum):
    totp       = "totp"        # Google Authenticator, Authy
    sms        = "sms"         # SMS code
    email      = "email"       # Email OTP
    backup_code = "backup_code" # Static backup code
    none       = "none"

class TwoFactorAuth(BaseModel):
    type:       TwoFactorType
    secret:     Optional[str] = None  # TOTP secret key (base32)
    code:       Optional[str] = None  # static code if already known
    phone:      Optional[str] = None  # for SMS type
    email:      Optional[str] = None  # for email type

class Credential(BaseModel):
    username:   str
    password:   str
    email:      Optional[str] = None
    role:       Optional[str] = None  # "admin", "user", "guest"
    two_factor: Optional[TwoFactorAuth] = None