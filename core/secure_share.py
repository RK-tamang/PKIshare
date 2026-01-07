# PKIshare - Secure Digital Certificate and File Sharing System
# core/secure_share.py

import json
import datetime
import base64
from pathlib import Path
from dataclasses import asdict

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.fernet import Fernet
import hashlib
import os

from .models import UserAccount, DigitalCertificate, EncryptedFile
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
    """Core engine for PKI-based file sharing with digital certificates."""
    
    def __init__(self, data_dir="data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(exist_ok=True)
        (self.data_dir / "files").mkdir(exist_ok=True)
        (self.data_dir / "share").mkdir(exist_ok=True)

        self.users: dict[str, UserAccount] = {}
        self.encrypted_files: dict[str, EncryptedFile] = {}
        self.share_files: dict[str, dict] = {}
        self.revoked_certs: set[str] = set()
        self.current_user: str | None = None

        self._load_data()

    def create_user_account(self, username: str, password: str) -> bool:
        """Create a new user account with auto-generated digital certificate."""
        if username in self.users:
            return False

        salt = os.urandom(16)
        private_pem, public_pem = generate_rsa_key_pair()
        encrypted_private = encrypt_private_key(private_pem, password, salt)

        cert = DigitalCertificate(
            serial=f"CRT_{datetime.datetime.now().strftime('%Y%m%d')}_{len(self.users)+1:04d}",
            subject=username,
            valid_from=datetime.datetime.now().isoformat(),
            valid_to=(datetime.datetime.now() + datetime.timedelta(days=365)).isoformat(),
            public_key_pem=public_pem.decode("utf-8"),
            signature=b""
        )

        user = UserAccount(
            username=username,
            password_hash=hashlib.sha256(password.encode()).hexdigest(),
            salt=salt,
            private_key_encrypted=encrypted_private,
            certificate=cert,
            shared_files=[]
        )

        self.users[username] = user
        self._save_data()
        return True

    def authenticate_user(self, username: str, password: str) -> bool:
        """Authenticate user with password and verify private key decryption."""
        if username not in self.users:
            return False

        user = self.users[username]
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        if user.password_hash != expected_hash:
            return False

        try:
            decrypt_private_key(user.private_key_encrypted, password, user.salt)
            self.current_user = username
            return True
        except Exception:
            return False

    def get_private_key(self, password: str):
        """Retrieve the user's private key after decryption."""
        user = self.users[self.current_user]
        private_pem = decrypt_private_key(user.private_key_encrypted, password, user.salt)
        return serialization.load_pem_private_key(private_pem, password=None)

    def distribute_file(self, filepath: str, recipients: list[str], password: str) -> bool:
        """Encrypt and distribute a file to multiple recipients using their certificates."""
        if not self.current_user:
            return False

        try:
            sym_key = Fernet.generate_key()
            cipher = Fernet(sym_key)

            with open(filepath, "rb") as f:
                plaintext = f.read()

            encrypted_data = cipher.encrypt(plaintext)
            file_hash = hashlib.sha256(plaintext).hexdigest()
            hash_bytes = file_hash.encode()

            file_id = f"enc_{datetime.datetime.now().timestamp()}_{hashlib.md5(plaintext, usedforsecurity=False).hexdigest()[:8]}"
            enc_path = self.data_dir / "files" / f"{file_id}.dat"
            with open(enc_path, "wb") as f:
                f.write(encrypted_data)

            private_key = self.get_private_key(password)
            signature = sign_data(hash_bytes, private_key)

            encrypted_keys = {}
            owner_pub_pem = self.users[self.current_user].certificate.public_key_pem.encode()
            encrypted_keys[self.current_user] = encrypt_sym_key_with_public(sym_key, owner_pub_pem)

            for recipient in recipients:
                pub_pem = self.users[recipient].certificate.public_key_pem.encode()
                encrypted_keys[recipient] = encrypt_sym_key_with_public(sym_key, pub_pem)

            encrypted_file = EncryptedFile(
                file_id=file_id,
                filename=Path(filepath).name,
                owner=self.current_user,
                encrypted_sym_key=encrypted_keys,
                signature=signature,
                file_hash=file_hash,
                timestamp=datetime.datetime.now().isoformat()
            )

            self.encrypted_files[file_id] = encrypted_file
            self.users[self.current_user].shared_files.append(file_id)
            self._save_data()
            return True

        except Exception as e:
            print(f"Error distributing file: {e}")
            return False

    def fetch_shared_collection(self):
        """Get all files accessible by the current user."""
        if not self.current_user:
            return []

        files = []
        for ef in self.encrypted_files.values():
            if ef.owner == self.current_user or self.current_user in ef.encrypted_sym_key:
                files.append(ef)
        return files

    def retrieve_file(self, file_id: str, save_path: str, password: str) -> bool:
        """Decrypt and download a shared file with signature verification."""
        if file_id not in self.encrypted_files:
            return False

        ef = self.encrypted_files[file_id]
        if self.current_user not in ef.encrypted_sym_key:
            return False

        try:
            enc_path = self.data_dir / "files" / f"{file_id}.dat"
            with open(enc_path, "rb") as f:
                enc_data = f.read()

            private_key = self.get_private_key(password)
            enc_sym_key = ef.encrypted_sym_key[self.current_user]
            sym_key = decrypt_sym_key_with_private(enc_sym_key, private_key)

            cipher = Fernet(sym_key)
            decrypted = cipher.decrypt(enc_data)

            if hashlib.sha256(decrypted).hexdigest() != ef.file_hash:
                return False

            owner_pub_pem = self.users[ef.owner].certificate.public_key_pem.encode()
            if not verify_signature(ef.file_hash.encode(), ef.signature, owner_pub_pem):
                return False

            with open(save_path, "wb") as f:
                f.write(decrypted)
            return True

        except Exception as e:
            print(f"Error retrieving file: {e}")
            return False

    def remove_file_access(self, file_id: str, username: str) -> bool:
        """Revoke a user's access to a file."""
        if file_id not in self.encrypted_files:
            return False

        ef = self.encrypted_files[file_id]
        if ef.owner != self.current_user:
            return False

        if username in ef.encrypted_sym_key:
            del ef.encrypted_sym_key[username]
            self._save_data()
            return True
        return False

    def grant_file_access(self, file_id: str, username: str, password: str) -> bool:
        """Grant file access to a user who previously had their access revoked."""
        if file_id not in self.encrypted_files:
            return False

        ef = self.encrypted_files[file_id]
        if ef.owner != self.current_user:
            return False

        if username not in self.users:
            return False

        if username in ef.encrypted_sym_key:
            return True

        try:
            private_key = self.get_private_key(password)
            owner_pub_pem = self.users[ef.owner].certificate.public_key_pem.encode()
            enc_sym_key = ef.encrypted_sym_key[ef.owner]
            sym_key = decrypt_sym_key_with_private(enc_sym_key, private_key)

            recipient_pub_pem = self.users[username].certificate.public_key_pem.encode()
            new_enc_key = encrypt_sym_key_with_public(sym_key, recipient_pub_pem)

            ef.encrypted_sym_key[username] = new_enc_key
            self._save_data()
            return True

        except Exception as e:
            print(f"Error granting file access: {e}")
            return False

    def get_all_users(self):
        """Get list of all registered users."""
        return list(self.users.keys())

    def check_share_protection(self, username: str) -> bool:
        """Check if user has set a share password."""
        if username not in self.users:
            return False
        user = self.users[username]
        return bool(user.share_password_hash)

    def configure_share_password(self, password: str) -> bool:
        """Set or update the share password for the current user."""
        if not self.current_user:
            return False
        
        user = self.users[self.current_user]
        user.share_password_hash = hashlib.sha256(password.encode()).hexdigest()
        user.share_salt = os.urandom(16)
        self._save_data()
        return True

    def validate_share_credentials(self, username: str, password: str) -> bool:
        """Verify if the provided share password matches the user's share password."""
        if username not in self.users:
            return False
        
        user = self.users[username]
        if not user.share_password_hash:
            return False
        
        expected_hash = hashlib.sha256(password.encode()).hexdigest()
        return user.share_password_hash == expected_hash

    def get_share_key(self) -> str:
        """Get the share password for the current user."""
        return ""

    def store_in_share(self, filepath: str, password: str) -> bool:
        """Encrypt and store a file in the shared repository."""
        if not self.current_user:
            return False

        try:
            sym_key = Fernet.generate_key()
            cipher = Fernet(sym_key)

            with open(filepath, "rb") as f:
                plaintext = f.read()

            encrypted_data = cipher.encrypt(plaintext)
            file_hash = hashlib.sha256(plaintext).hexdigest()

            share_id = f"sh_{datetime.datetime.now().timestamp()}_{hashlib.md5(plaintext, usedforsecurity=False).hexdigest()[:8]}"
            enc_path = self.data_dir / "share" / f"{share_id}.dat"
            with open(enc_path, "wb") as f:
                f.write(encrypted_data)

            private_key = self.get_private_key(password)
            encrypted_key = encrypt_sym_key_with_public(sym_key, 
                self.users[self.current_user].certificate.public_key_pem.encode())

            share_file = {
                "share_id": share_id,
                "owner": self.current_user,
                "filename": Path(filepath).name,
                "file_hash": file_hash,
                "encrypted_key": base64.b64encode(encrypted_key).decode(),
                "timestamp": datetime.datetime.now().isoformat(),
                "size": len(plaintext)
            }

            self.share_files[share_id] = share_file
            self._save_data()
            return True

        except Exception as e:
            print(f"Error storing in share: {e}")
            return False

    def list_share_contents(self) -> list[dict]:
        """Get list of files in the current user's shared repository."""
        if not self.current_user:
            return []

        files = []
        for sf in self.share_files.values():
            if sf.get("owner") == self.current_user:
                files.append(sf)
        return sorted(files, key=lambda x: x["timestamp"], reverse=True)

    def extract_from_share(self, share_id: str, save_path: str, password: str) -> bool:
        """Decrypt and download a file from the shared repository."""
        if share_id not in self.share_files:
            return False

        sf = self.share_files[share_id]
        
        if sf.get("owner") != self.current_user:
            print(f"Unauthorized access attempt: {self.current_user} tried to access {sf.get('owner')}'s shared file")
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
        if share_id not in self.share_files:
            return False

        sf = self.share_files[share_id]
        
        if sf.get("owner") != self.current_user:
            print(f"Unauthorized delete attempt: {self.current_user} tried to delete {sf.get('owner')}'s shared file")
            return False

        enc_path = self.data_dir / "share" / f"{share_id}.dat"
        if enc_path.exists():
            enc_path.unlink()

        del self.share_files[share_id]
        self._save_data()
        return True

    def _save_data(self):
        """Persist all data to JSON files."""
        users_data = {}
        for u in self.users.values():
            cert_dict = asdict(u.certificate)
            cert_dict["signature"] = base64.b64encode(cert_dict["signature"]).decode()

            users_data[u.username] = {
                "username": u.username,
                "password_hash": u.password_hash,
                "salt": base64.b64encode(u.salt).decode(),
                "private_key_encrypted": base64.b64encode(u.private_key_encrypted).decode(),
                "certificate": cert_dict,
                "shared_files": u.shared_files,
                "share_password_hash": u.share_password_hash,
                "share_salt": base64.b64encode(u.share_salt).decode() if u.share_salt else "",
            }

        with open(self.data_dir / "accounts.json", "w") as f:
            json.dump(users_data, f, indent=2)

        files_data = {}
        for fid, ef in self.encrypted_files.items():
            data = asdict(ef)
            data["encrypted_sym_key"] = {
                k: base64.b64encode(v).decode() for k, v in data["encrypted_sym_key"].items()
            }
            data["signature"] = base64.b64encode(data["signature"]).decode()
            files_data[fid] = data

        with open(self.data_dir / "encrypted_files.json", "w") as f:
            json.dump(files_data, f, indent=2)

        share_data = {}
        for sid, sf in self.share_files.items():
            share_data[sid] = sf
        with open(self.data_dir / "shared_repository.json", "w") as f:
            json.dump(share_data, f, indent=2)

    def _load_data(self):
        """Load all data from JSON files on startup."""
        users_file = self.data_dir / "accounts.json"
        if users_file.exists():
            with open(users_file) as f:
                data = json.load(f)

            migrated = False
            for ud in data.values():
                cert_data = ud.get("certificate")
                if cert_data and "public_key" in cert_data and "public_key_pem" not in cert_data:
                    cert_data["public_key_pem"] = cert_data.pop("public_key")
                    migrated = True
            if migrated:
                with open(users_file, "w") as f:
                    json.dump(data, f, indent=2)

            for ud in data.values():
                cert_data = ud["certificate"]
                signature_b64 = cert_data.get("signature", "")
                cert_data["signature"] = base64.b64decode(signature_b64) if signature_b64 else b""

                cert = DigitalCertificate(**cert_data)

                vault_pwd = ud.get("vault_password_hash", "")
                vault_salt = ud.get("vault_salt", "")
                share_pwd = ud.get("share_password_hash", "")
                
                user = UserAccount(
                    username=ud["username"],
                    password_hash=ud["password_hash"],
                    salt=base64.b64decode(ud["salt"]),
                    private_key_encrypted=base64.b64decode(ud["private_key_encrypted"]),
                    certificate=cert,
                    shared_files=ud.get("shared_files", []),
                    share_password_hash=share_pwd or vault_pwd,
                    share_salt=base64.b64decode(ud["share_salt"]) if ud.get("share_salt") else (
                        base64.b64decode(vault_salt) if vault_salt else b""
                    ),
                )
                self.users[user.username] = user

        files_file = self.data_dir / "encrypted_files.json"
        if files_file.exists():
            with open(files_file) as f:
                data = json.load(f)

            for fid, fd in data.items():
                fd["encrypted_sym_key"] = {
                    k: base64.b64decode(v) for k, v in fd["encrypted_sym_key"].items()
                }
                fd["signature"] = base64.b64decode(fd["signature"])
                ef = EncryptedFile(**fd)
                self.encrypted_files[fid] = ef

        share_file = self.data_dir / "shared_repository.json"
        vault_file = self.data_dir / "private_vault.json"
        
        if share_file.exists():
            with open(share_file) as f:
                data = json.load(f)
            for sid, sf in data.items():
                self.share_files[sid] = sf
        elif vault_file.exists():
            with open(vault_file) as f:
                data = json.load(data)
            for vid, vf in data.items():
                self.share_files[vid] = vf


# Ensure newline at end of file

