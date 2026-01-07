# PKIshare - Secure Digital Certificate and File Sharing System
# core/utils.py

import base64

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet


def generate_rsa_key_pair():
    """Generate a 2048-bit RSA key pair."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return private_pem, public_pem


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Derive a 32-byte key from password using Scrypt KDF."""
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode())


def encrypt_private_key(private_pem: bytes, password: str, salt: bytes) -> bytes:
    """Encrypt private key PEM with password-derived key."""
    key = derive_key_from_password(password, salt)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.encrypt(private_pem)


def decrypt_private_key(encrypted: bytes, password: str, salt: bytes):
    """Decrypt private key PEM with password-derived key."""
    key = derive_key_from_password(password, salt)
    f = Fernet(base64.urlsafe_b64encode(key))
    return f.decrypt(encrypted)


def encrypt_sym_key_with_public(sym_key: bytes, public_pem: bytes) -> bytes:
    """Encrypt symmetric key with RSA public key."""
    public_key = serialization.load_pem_public_key(public_pem)
    return public_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def decrypt_sym_key_with_private(encrypted_sym: bytes, private_key) -> bytes:
    """Decrypt symmetric key with RSA private key."""
    return private_key.decrypt(
        encrypted_sym,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )


def sign_data(data: bytes, private_key) -> bytes:
    """Create digital signature using RSA private key."""
    return private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )


def verify_signature(data: bytes, signature: bytes, public_pem: bytes) -> bool:
    """Verify digital signature using RSA public key."""
    public_key = serialization.load_pem_public_key(public_pem)
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


# Ensure newline at end of file

