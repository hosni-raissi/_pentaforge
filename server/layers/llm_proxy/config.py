import os
from dataclasses import dataclass
from typing import Literal

@dataclass
class Config:
    # Storage type: "static" or "postgres"
    STORAGE_TYPE: Literal["static", "postgres"] = "static"
    
    # Encryption
    ENCRYPTION_KEY: str = os.getenv("ENCRYPTION_KEY", "your-secret-key-32-bytes-long!!")
    
    # PostgreSQL (for future use)
    POSTGRES_HOST: str = os.getenv("POSTGRES_HOST", "localhost")
    POSTGRES_PORT: int = int(os.getenv("POSTGRES_PORT", "5432"))
    POSTGRES_DB: str = os.getenv("POSTGRES_DB", "llm_proxy")
    POSTGRES_USER: str = os.getenv("POSTGRES_USER", "postgres")
    POSTGRES_PASSWORD: str = os.getenv("POSTGRES_PASSWORD", "password")
    
    # Placeholder prefix
    PLACEHOLDER_PREFIX: str = "[[MASKED_"
    PLACEHOLDER_SUFFIX: str = "]]"

config = Config()