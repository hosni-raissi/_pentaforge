# schemas/scan_request/database.py
from pydantic import BaseModel
from typing import Optional, List
from enum import Enum
from .credentials import Credential

class DatabaseType(str, Enum):
    mysql       = "mysql"
    postgresql  = "postgresql"
    mssql       = "mssql"
    oracle      = "oracle"
    mongodb     = "mongodb"
    redis       = "redis"
    cassandra   = "cassandra"

class DatabaseScanRequest(BaseModel):
    db_type:            DatabaseType
    host:               str                         # IP or hostname
    port:               Optional[int]  = None       # default per db_type
    database_name:      Optional[str]  = None       # target DB name
    credentials:        Optional[List[Credential]]  = None

    description:        Optional[str]  = None