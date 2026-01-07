# core/database.py - SQLite database layer for PKIshare

import sqlite3
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any, List
import base64


class DatabaseManager:
    """SQLite database manager for PKIshare."""
    
    def __init__(self, db_path: str = "data/pki_share.db"):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
    
    def _get_connection(self) -> sqlite3.Connection:
        """Get a database connection with row factory."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn
    
    def _init_db(self):
        """Initialize the database schema."""
        with self._get_connection() as conn:
            # Users table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    salt BLOB NOT NULL,
                    private_key_encrypted BLOB NOT NULL,
                    share_password_hash TEXT,
                    share_salt BLOB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Certificates table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    version TEXT DEFAULT '1.0',
                    serial TEXT UNIQUE NOT NULL,
                    subject TEXT NOT NULL,
                    issuer TEXT NOT NULL,
                    valid_from TEXT NOT NULL,
                    valid_to TEXT NOT NULL,
                    public_key_pem TEXT NOT NULL,
                    signature BLOB,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Encrypted files table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS encrypted_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id TEXT UNIQUE NOT NULL,
                    filename TEXT NOT NULL,
                    owner_id INTEGER NOT NULL,
                    file_hash TEXT NOT NULL,
                    signature BLOB NOT NULL,
                    timestamp TEXT NOT NULL,
                    encrypted_data_path TEXT,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # File keys table (encrypted symmetric keys per recipient)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS file_keys (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    file_id INTEGER NOT NULL,
                    user_id INTEGER NOT NULL,
                    encrypted_key BLOB NOT NULL,
                    FOREIGN KEY (file_id) REFERENCES encrypted_files(id) ON DELETE CASCADE,
                    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                    UNIQUE(file_id, user_id)
                )
            """)
            
            # Shared repository files table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS shared_files (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    share_id TEXT UNIQUE NOT NULL,
                    owner_id INTEGER NOT NULL,
                    filename TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    encrypted_key TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    size INTEGER NOT NULL,
                    encrypted_data_path TEXT,
                    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
                )
            """)
            
            # Revoked certificates table
            conn.execute("""
                CREATE TABLE IF NOT EXISTS revoked_certs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    serial TEXT UNIQUE NOT NULL,
                    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            conn.commit()
    
    # User operations
    def create_user(self, username: str, password_hash: str, salt: bytes, 
                   private_key_encrypted: bytes) -> int:
        """Create a new user and return user ID."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                "INSERT INTO users (username, password_hash, salt, private_key_encrypted) VALUES (?, ?, ?, ?)",
                (username, password_hash, salt, private_key_encrypted)
            )
            conn.commit()
            return cursor.lastrowid
    
    def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, salt, private_key_encrypted, share_password_hash, share_salt FROM users WHERE username = ?",
                (username,)
            ).fetchone()
            return dict(row) if row else None
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT id, username, password_hash, salt, private_key_encrypted, share_password_hash, share_salt FROM users WHERE id = ?",
                (user_id,)
            ).fetchone()
            return dict(row) if row else None
    
    def update_share_password(self, user_id: int, password_hash: str, salt: bytes):
        """Update user's share password."""
        with self._get_connection() as conn:
            conn.execute(
                "UPDATE users SET share_password_hash = ?, share_salt = ? WHERE id = ?",
                (password_hash, salt, user_id)
            )
            conn.commit()
    
    # Certificate operations
    def create_certificate(self, user_id: int, serial: str, subject: str, issuer: str,
                          valid_from: str, valid_to: str, public_key_pem: str, signature: bytes):
        """Create a certificate for a user."""
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO certificates (user_id, serial, subject, issuer, valid_from, valid_to, public_key_pem, signature)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (user_id, serial, subject, issuer, valid_from, valid_to, public_key_pem, signature)
            )
            conn.commit()
    
    def get_certificate_by_user(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get certificate for a user."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM certificates WHERE user_id = ?",
                (user_id,)
            ).fetchone()
            return dict(row) if row else None
    
    # Encrypted file operations
    def create_encrypted_file(self, file_id: str, filename: str, owner_id: int, 
                             file_hash: str, signature: bytes, timestamp: str) -> int:
        """Create an encrypted file record."""
        with self._get_connection() as conn:
            cursor = conn.execute(
                """INSERT INTO encrypted_files (file_id, filename, owner_id, file_hash, signature, timestamp)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (file_id, filename, owner_id, file_hash, signature, timestamp)
            )
            conn.commit()
            return cursor.lastrowid
    
    def add_file_key(self, file_id: int, user_id: int, encrypted_key: bytes):
        """Add an encrypted symmetric key for a user."""
        with self._get_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO file_keys (file_id, user_id, encrypted_key) VALUES (?, ?, ?)",
                (file_id, user_id, encrypted_key)
            )
            conn.commit()
    
    def get_file_by_id(self, file_id: str) -> Optional[Dict[str, Any]]:
        """Get file by file_id."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT ef.*, u.username as owner_name FROM encrypted_files ef JOIN users u ON ef.owner_id = u.id WHERE ef.file_id = ?",
                (file_id,)
            ).fetchone()
            return dict(row) if row else None
    
    def get_file_keys(self, file_id: int) -> List[Dict[str, Any]]:
        """Get all encrypted keys for a file."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT fk.*, u.username FROM file_keys fk JOIN users u ON fk.user_id = u.id WHERE fk.file_id = ?",
                (file_id,)
            ).fetchall()
            return [dict(row) for row in rows]
    
    def get_user_files(self, user_id: int) -> List[Dict[str, Any]]:
        """Get all files accessible by a user (owned or shared)."""
        with self._get_connection() as conn:
            rows = conn.execute("""
                SELECT ef.*, u.username as owner_name
                FROM encrypted_files ef
                JOIN users u ON ef.owner_id = u.id
                WHERE ef.owner_id = ? OR ef.id IN (
                    SELECT fk.file_id FROM file_keys fk WHERE fk.user_id = ?
                )
            """, (user_id, user_id)).fetchall()
            return [dict(row) for row in rows]
    
    def remove_file_access(self, file_id: int, user_id: int) -> bool:
        """Remove a user's access to a file."""
        with self._get_connection() as conn:
            result = conn.execute(
                "DELETE FROM file_keys WHERE file_id = ? AND user_id = ?",
                (file_id, user_id)
            )
            conn.commit()
            return result.rowcount > 0
    
    def grant_file_access(self, file_id: int, user_id: int, encrypted_key: bytes):
        """Grant a user access to a file."""
        self.add_file_key(file_id, user_id, encrypted_key)
    
    def delete_file(self, file_id: str):
        """Delete a file and all its keys."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM file_keys WHERE file_id IN (SELECT id FROM encrypted_files WHERE file_id = ?)", (file_id,))
            conn.execute("DELETE FROM encrypted_files WHERE file_id = ?", (file_id,))
            conn.commit()
    
    # Shared repository operations
    def create_shared_file(self, share_id: str, owner_id: int, filename: str, 
                          file_hash: str, encrypted_key: str, timestamp: str, size: int):
        """Create a shared file record."""
        with self._get_connection() as conn:
            conn.execute(
                """INSERT INTO shared_files (share_id, owner_id, filename, file_hash, encrypted_key, timestamp, size)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (share_id, owner_id, filename, file_hash, encrypted_key, timestamp, size)
            )
            conn.commit()
    
    def get_shared_files(self, owner_id: int) -> List[Dict[str, Any]]:
        """Get all shared files for a user."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM shared_files WHERE owner_id = ? ORDER BY timestamp DESC",
                (owner_id,)
            ).fetchall()
            return [dict(row) for row in rows]
    
    def get_shared_file_by_id(self, share_id: str) -> Optional[Dict[str, Any]]:
        """Get a shared file by share_id."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM shared_files WHERE share_id = ?",
                (share_id,)
            ).fetchone()
            return dict(row) if row else None
    
    def delete_shared_file(self, share_id: str):
        """Delete a shared file."""
        with self._get_connection() as conn:
            conn.execute("DELETE FROM shared_files WHERE share_id = ?", (share_id,))
            conn.commit()
    
    # Certificate revocation
    def revoke_certificate(self, serial: str):
        """Revoke a certificate."""
        with self._get_connection() as conn:
            conn.execute("INSERT OR IGNORE INTO revoked_certs (serial) VALUES (?)", (serial,))
            conn.commit()
    
    def is_revoked(self, serial: str) -> bool:
        """Check if a certificate is revoked."""
        with self._get_connection() as conn:
            row = conn.execute(
                "SELECT 1 FROM revoked_certs WHERE serial = ?",
                (serial,)
            ).fetchone()
            return row is not None
    
    # Utility
    def get_all_users(self) -> List[Dict[str, Any]]:
        """Get all users."""
        with self._get_connection() as conn:
            rows = conn.execute(
                "SELECT id, username, created_at FROM users ORDER BY username"
            ).fetchall()
            return [dict(row) for row in rows]
    
    def close(self):
        """Close database connection (for connection pooling if needed)."""
        pass

