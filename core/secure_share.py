# PKIshare - Secure Digital Certificate and File Sharing System
# core/secure_share.py

import datetime
import base64
from pathlib import Path
from typing import Optional, Dict, Any, List

from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet
import hashlib
import os

from .models import UserAccount, DigitalCertificate, EncryptedFile
from .database import DatabaseManager
from .utils import (
    generate_rsa_key_pair,
    encrypt_private_key,
    decrypt_private_key,
    encrypt_sym_key_with_public,
    decrypt_sym_key_with_private,
    sign_data,
    verify_signature,
)


class PKIshareCore:
    """Core engine for PKI-based file sharing with SQLite database."""
    
    def __init__(self, data_dir: str = "data", db_url: Optional[str] = None):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        (self.data_dir / "files").mkdir(exist_ok=True)
        (self.data_dir / "share").mkdir(exist_ok=True)
        
        # Initialize SQLite database
        db_path = db_url or f"{data_dir}/pki_share.db"
        self.db = DatabaseManager(db_path)
        
        self.current_user_id: int | None = None
        self.current_username: str | None = None
    
    # ==================== USER MANAGEMENT ====================
    def create_user_account(self, username: str, password: str) -> bool:
        """Create a new user account with auto-generated digital certificate."""
        if self.get_user_id_by_username(username):
            return False
        
        salt = os.urandom(16)
        private_pem, public_pem = generate_rsa_key_pair()
        encrypted_private = encrypt_private_key(private_pem, password, salt)
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        # Create user in database
        user_id = self.db.create_user(username, password_hash, salt, encrypted_private)
        
        # Create certificate
        serial = f"CRT_{datetime.datetime.now().strftime('%Y%m%d')}_{user_id:04d}"
        cert = DigitalCertificate(
            serial=serial,
            subject=username,
            issuer="PKIshare CA",
            valid_from=datetime.datetime.now().isoformat(),
            valid_to=(datetime.datetime.now() + datetime.timedelta(days=365)).isoformat(),
            public_key_pem=public_pem.decode("utf-8"),
            signature=b""
        )
        
        self.db.create_certificate(
            user_id=user_id,
            serial=cert.serial,
            subject=cert.subject,
            issuer=cert.issuer,
            valid_from=cert.valid_from,
            valid_to=cert.valid_to,
            public_key_pem=cert.public_key_pem,
            signature=cert.signature
        )
        
        return True
    
    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user with password."""
        user = self.db.get_user_by_username(username)
        if not user:
            return False
        
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] != expected_hash:
            return False
        
        try:
            decrypt_private_key(user["private_key_encrypted"], password, user["salt"])
            self.current_user_id = user["id"]
            self.current_username = username
            return True
        except Exception:
            return False
    
    def get_user_id_by_username(self, username: str) -> Optional[int]:
        """Get user ID by username."""
        user = self.db.get_user_by_username(username)
        return user["id"] if user else None
    
    def get_private_key_pem(self, password: str) -> bytes:
        """Get the user's private key PEM."""
        user = self.db.get_user_by_id(self.current_user_id)
        private_pem = decrypt_private_key(user["private_key_encrypted"], password, user["salt"])
        return private_pem
    
    def get_private_key(self, password: str):
        """Get the user's private key object."""
        private_pem = self.get_private_key_pem(password)
        return serialization.load_pem_private_key(private_pem, password=None)
    
    def get_certificate(self) -> Optional[Dict[str, Any]]:
        """Get the current user's certificate."""
        if not self.current_user_id:
            return None
        return self.db.get_certificate_by_user(self.current_user_id)
    
    def get_public_key_pem(self) -> str:
        """Get the user's public key PEM."""
        cert = self.get_certificate()
        return cert["public_key_pem"] if cert else ""
    
    # ==================== FILE SHARING ====================
    def distribute_file(self, filepath: str, recipients: list[str], password: str) -> bool:
        """Encrypt and distribute a file to multiple recipients."""
        if not self.current_user_id:
            return False
        
        try:
            sym_key = Fernet.generate_key()
            cipher = Fernet(sym_key)
            
            with open(filepath, "rb") as f:
                plaintext = f.read()
            
            encrypted_data = cipher.encrypt(plaintext)
            file_hash = hashlib.sha256(plaintext).hexdigest()
            hash_bytes = file_hash.encode()
            
            # Generate file ID
            file_id = f"enc_{datetime.datetime.now().timestamp()}_{hashlib.md5(plaintext, usedforsecurity=False).hexdigest()[:8]}"
            enc_path = self.data_dir / "files" / f"{file_id}.dat"
            with open(enc_path, "wb") as f:
                f.write(encrypted_data)
            
            # Sign the file hash
            private_key = self.get_private_key(password)
            signature = sign_data(hash_bytes, private_key)
            
            # Store in database
            file_db_id = self.db.create_encrypted_file(
                file_id=file_id,
                filename=Path(filepath).name,
                owner_id=self.current_user_id,
                file_hash=file_hash,
                signature=signature,
                timestamp=datetime.datetime.now().isoformat()
            )
            
            # Add keys for owner and recipients
            owner_pub_pem = self.get_public_key_pem().encode()
            owner_enc_key = encrypt_sym_key_with_public(sym_key, owner_pub_pem)
            self.db.add_file_key(file_db_id, self.current_user_id, owner_enc_key)
            
            for recipient in recipients:
                recipient_id = self.get_user_id_by_username(recipient)
                if recipient_id:
                    pub_pem = self.db.get_certificate_by_user(recipient_id)["public_key_pem"].encode()
                    enc_key = encrypt_sym_key_with_public(sym_key, pub_pem)
                    self.db.add_file_key(file_db_id, recipient_id, enc_key)
            
            return True
        
        except Exception as e:
            print(f"Error distributing file: {e}")
            return False
    
    def fetch_shared_collection(self) -> List[Dict[str, Any]]:
        """Get all files accessible by the current user."""
        if not self.current_user_id:
            return []
        return self.db.get_user_files(self.current_user_id)
    
    def retrieve_file(self, file_id: str, save_path: str, password: str) -> bool:
        """Decrypt and download a shared file."""
        file_data = self.db.get_file_by_id(file_id)
        if not file_data:
            return False
        
        # Check access
        file_keys = self.db.get_file_keys(file_data["id"])
        user_has_access = any(k["user_id"] == self.current_user_id for k in file_keys)
        if not user_has_access:
            return False
        
        try:
            enc_path = self.data_dir / "files" / f"{file_id}.dat"
            with open(enc_path, "rb") as f:
                enc_data = f.read()
            
            # Find user's encrypted key
            user_key = next((k for k in file_keys if k["user_id"] == self.current_user_id), None)
            if not user_key:
                return False
            
            private_key = self.get_private_key(password)
            sym_key = decrypt_sym_key_with_private(user_key["encrypted_key"], private_key)
            
            cipher = Fernet(sym_key)
            decrypted = cipher.decrypt(enc_data)
            
            # Verify integrity
            if hashlib.sha256(decrypted).hexdigest() != file_data["file_hash"]:
                return False
            
            # Verify signature
            owner_pub_pem = self.db.get_certificate_by_user(file_data["owner_id"])["public_key_pem"].encode()
            if not verify_signature(file_data["file_hash"].encode(), file_data["signature"], owner_pub_pem):
                return False
            
            with open(save_path, "wb") as f:
                f.write(decrypted)
            return True
        
        except Exception as e:
            print(f"Error retrieving file: {e}")
            return False
    
    def remove_file_access(self, file_id: str, username: str) -> bool:
        """Revoke a user's access to a file."""
        file_data = self.db.get_file_by_id(file_id)
        if not file_data:
            return False
        
        if file_data["owner_id"] != self.current_user_id:
            return False
        
        user_id = self.get_user_id_by_username(username)
        if not user_id:
            return False
        
        return self.db.remove_file_access(file_data["id"], user_id)
    
    def grant_file_access(self, file_id: str, username: str, password: str) -> bool:
        """Grant file access to a user who previously had their access revoked."""
        file_data = self.db.get_file_by_id(file_id)
        if not file_data:
            return False
        
        if file_data["owner_id"] != self.current_user_id:
            return False
        
        user_id = self.get_user_id_by_username(username)
        if not user_id:
            return False
        
        # Check if user already has access
        file_keys = self.db.get_file_keys(file_data["id"])
        if any(k["user_id"] == user_id for k in file_keys):
            return True
        
        try:
            private_key = self.get_private_key(password)
            
            # Decrypt the symmetric key using owner's key
            owner_key = next((k for k in file_keys if k["user_id"] == self.current_user_id), None)
            if not owner_key:
                return False
            
            sym_key = decrypt_sym_key_with_private(owner_key["encrypted_key"], private_key)
            
            # Re-encrypt the symmetric key with the recipient's public key
            recipient_cert = self.db.get_certificate_by_user(user_id)
            recipient_pub_pem = recipient_cert["public_key_pem"].encode()
            new_enc_key = encrypt_sym_key_with_public(sym_key, recipient_pub_pem)
            
            self.db.grant_file_access(file_data["id"], user_id, new_enc_key)
            return True
        
        except Exception as e:
            print(f"Error granting file access: {e}")
            return False
    
    def get_all_users(self) -> List[str]:
        """Get list of all registered users."""
        users = self.db.get_all_users()
        return [u["username"] for u in users]
    
    def delete_account(self, password: str) -> bool:
        """Delete the current user's account. Requires password confirmation."""
        if not self.current_user_id:
            return False
        
        user = self.db.get_user_by_id(self.current_user_id)
        if not user:
            return False
        
        # Verify password
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        if user["password_hash"] != expected_hash:
            return False
        
        # Delete the user account (cascades to files, keys, certificates)
        success = self.db.delete_user(self.current_user_id)
        if success:
            self.current_user_id = None
            self.current_username = None
            self.session_key = None
        return success
    
    # ==================== SHARE PASSWORD METHODS ====================
    def check_share_protection(self, username: str) -> bool:
        """Check if user has set a share password."""
        user = self.db.get_user_by_username(username)
        if not user:
            return False
        return bool(user["share_password_hash"])
    
    def configure_share_password(self, password: str) -> bool:
        """Set or update the share password for the current user."""
        if not self.current_user_id:
            return False
        
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        salt = os.urandom(16)
        self.db.update_share_password(self.current_user_id, password_hash, salt)
        return True
    
    def validate_share_credentials(self, username: str, password: str) -> bool:
        """Verify if the provided share password matches the user's share password."""
        user = self.db.get_user_by_username(username)
        if not user or not user["share_password_hash"]:
            return False
        
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        return user["share_password_hash"] == expected_hash
    
    # ==================== SHARED REPOSITORY ====================
    def store_in_share(self, filepath: str, password: str) -> bool:
        """Encrypt and store a file in the shared repository."""
        if not self.current_user_id:
            return False
        
        try:
            sym_key = Fernet.generate_key()
            cipher = Fernet(sym_key)
            
            with open(filepath, "rb") as f:
                plaintext = f.read()
            
            encrypted_data = cipher.encrypt(plaintext)
            file_hash = hashlib.sha256(plaintext).hexdigest()
            
            # Generate share ID
            share_id = f"sh_{datetime.datetime.now().timestamp()}_{hashlib.md5(plaintext, usedforsecurity=False).hexdigest()[:8]}"
            enc_path = self.data_dir / "share" / f"{share_id}.dat"
            with open(enc_path, "wb") as f:
                f.write(encrypted_data)
            
            # Encrypt the symmetric key with user's public key
            private_key = self.get_private_key(password)
            encrypted_key = encrypt_sym_key_with_public(sym_key, self.get_public_key_pem().encode())
            
            self.db.create_shared_file(
                share_id=share_id,
                owner_id=self.current_user_id,
                filename=Path(filepath).name,
                file_hash=file_hash,
                encrypted_key=base64.b64encode(encrypted_key).decode(),
                timestamp=datetime.datetime.now().isoformat(),
                size=len(plaintext)
            )
            return True
        
        except Exception as e:
            print(f"Error storing in share: {e}")
            return False
    
    def list_share_contents(self) -> List[Dict[str, Any]]:
        """Get list of files in the current user's shared repository."""
        if not self.current_user_id:
            return []
        return self.db.get_shared_files(self.current_user_id)
    
    def extract_from_share(self, share_id: str, save_path: str, password: str) -> bool:
        """Decrypt and download a file from the shared repository."""
        sf = self.db.get_shared_file_by_id(share_id)
        if not sf:
            return False
        
        # Security check: only the owner can download their files
        if sf["owner_id"] != self.current_user_id:
            return False
        
        try:
            enc_path = self.data_dir / "share" / f"{share_id}.dat"
            if not enc_path.exists():
                return False
            
            with open(enc_path, "rb") as f:
                enc_data = f.read()
            
            private_key = self.get_private_key(password)
            enc_sym_key = base64.b64decode(sf["encrypted_key"])
            sym_key = decrypt_sym_key_with_private(enc_sym_key, private_key)
            
            cipher = Fernet(sym_key)
            decrypted = cipher.decrypt(enc_data)
            
            # Verify integrity
            if hashlib.sha256(decrypted).hexdigest() != sf["file_hash"]:
                return False
            
            with open(save_path, "wb") as f:
                f.write(decrypted)
            return True
        
        except Exception as e:
            print(f"Error extracting from share: {e}")
            return False
    
    def remove_from_share(self, share_id: str) -> bool:
        """Delete a file from the shared repository."""
        sf = self.db.get_shared_file_by_id(share_id)
        if not sf:
            return False
        
        # Security check: only the owner can delete their files
        if sf["owner_id"] != self.current_user_id:
            return False
        
        enc_path = self.data_dir / "share" / f"{share_id}.dat"
        if enc_path.exists():
            enc_path.unlink()
        
        self.db.delete_shared_file(share_id)
        return True


# Ensure newline at end of file

