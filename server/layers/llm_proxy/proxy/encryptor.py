import base64
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from server.layers.llm_proxy.config import config

class Encryptor:
    """Handles encryption and decryption of sensitive data"""
    
    def __init__(self, key: str = None):
        self.key = key or config.ENCRYPTION_KEY
        self.fernet = self._create_fernet()
    
    def _create_fernet(self) -> Fernet:
        """Create Fernet instance from key"""
        # Derive a proper key from the password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'llm_proxy_salt_v1',  # In production, use random salt per entry
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.key.encode()))
        return Fernet(key)
    
    def encrypt(self, plaintext: str) -> str:
        """Encrypt plaintext and return base64 encoded ciphertext"""
        encrypted = self.fernet.encrypt(plaintext.encode())
        return base64.urlsafe_b64encode(encrypted).decode()
    
    def decrypt(self, ciphertext: str) -> str:
        """Decrypt base64 encoded ciphertext"""
        encrypted = base64.urlsafe_b64decode(ciphertext.encode())
        return self.fernet.decrypt(encrypted).decode()
    
    def generate_hash(self, data: str) -> str:
        """Generate a hash for quick lookup"""
        return hashlib.sha256(data.encode()).hexdigest()[:16]