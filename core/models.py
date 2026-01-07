# PKIshare - Secure Digital Certificate and File Sharing System
# core/models.py

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class DigitalCertificate:
    """X.509 Digital Certificate for secure identity verification."""
    version: str = "1.0"
    serial: str = ""
    subject: str = ""
    issuer: str = "PKIshare CA"
    valid_from: str = ""
    valid_to: str = ""
    public_key_pem: str = ""
    signature: bytes = b""


@dataclass
class UserAccount:
    """User account with PKI-based authentication and file sharing capabilities."""
    username: str
    password_hash: str
    salt: bytes
    private_key_encrypted: bytes
    certificate: DigitalCertificate = None
    shared_files: List[str] = field(default_factory=list)
    # Share-specific fields
    share_password_hash: str = ""
    share_salt: bytes = b""


@dataclass
class EncryptedFile:
    """Encrypted file with distributed access control via digital certificates."""
    file_id: str
    filename: str
    owner: str
    encrypted_sym_key: Dict[str, bytes]
    signature: bytes
    file_hash: str
    timestamp: str


# Ensure newline at end of file

