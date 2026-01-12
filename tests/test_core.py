"""Test suite for PKIshare core functionality.

This module contains minimal tests to verify the core functionality
of the PKI-based secure file sharing system.
"""

import pytest
import tempfile
import os
from pathlib import Path

# Import core modules for testing
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.secure_share import PKIshareCore


class TestPKIshareCore:
    """Test cases for PKIshareCore class."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    @pytest.fixture
    def core(self, temp_dir):
        """Create a PKIshareCore instance with temp directory."""
        return PKIshareCore(data_dir=temp_dir)
    
    def test_create_user_account(self, core):
        """Test user account creation."""
        result = core.create_user_account("testuser", "password123")
        assert result is True
        
        # Duplicate user should fail
        result = core.create_user_account("testuser", "password123")
        assert result is False
    
    def test_authenticate_user(self, core):
        """Test user authentication."""
        # Create user first
        core.create_user_account("testuser", "password123")
        
        # Test correct password
        assert core.authenticate_user("testuser", "password123") is True
        assert core.current_username == "testuser"
        
        # Test wrong password
        assert core.authenticate_user("testuser", "wrongpassword") is False
    
    def test_authenticate_nonexistent_user(self, core):
        """Test authentication of non-existent user."""
        assert core.authenticate_user("nonexistent", "password") is False
    
    def test_get_all_users(self, core):
        """Test getting all users."""
        core.create_user_account("user1", "password1")
        core.create_user_account("user2", "password2")
        
        users = core.get_all_users()
        assert len(users) == 2
        assert "user1" in users
        assert "user2" in users
    
    def test_file_distribution_requires_auth(self, core):
        """Test that file distribution requires authentication."""
        result = core.distribute_file("/nonexistent/file.txt", [], "password")
        assert result is False
    
    def test_fetch_shared_collection_requires_auth(self, core):
        """Test that fetching shared collection requires authentication."""
        files = core.fetch_shared_collection()
        assert files == []
    
    def test_get_certificate_requires_auth(self, core):
        """Test that getting certificate requires authentication."""
        cert = core.get_certificate()
        assert cert is None
    
    def test_share_repository_requires_auth(self, core):
        """Test that share repository operations require authentication."""
        files = core.list_share_contents()
        assert files == []


class TestDatabaseOperations:
    """Test cases for database operations."""
    
    @pytest.fixture
    def temp_dir(self):
        """Create a temporary directory for testing."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
    
    def test_database_initialization(self, temp_dir):
        """Test that database is properly initialized."""
        from core.database import DatabaseManager
        
        db_path = os.path.join(temp_dir, "test.db")
        db = DatabaseManager(db_path)
        
        # Database should exist
        assert os.path.exists(db_path)
        
        # Should be able to create user
        user_id = db.create_user(
            "testuser",
            "hash",
            b"salt",
            b"encrypted_key"
        )
        assert user_id is not None
        
        db.close()
    
    def test_get_user_by_username(self, temp_dir):
        """Test retrieving user by username."""
        from core.database import DatabaseManager
        
        db_path = os.path.join(temp_dir, "test.db")
        db = DatabaseManager(db_path)
        
        # Create user
        db.create_user("testuser", "hash", b"salt", b"encrypted_key")
        
        # Retrieve user
        user = db.get_user_by_username("testuser")
        assert user is not None
        assert user["username"] == "testuser"
        
        # Non-existent user
        user = db.get_user_by_username("nonexistent")
        assert user is None
        
        db.close()


class TestCryptoOperations:
    """Test cases for cryptographic operations."""
    
    def test_key_pair_generation(self):
        """Test RSA key pair generation."""
        from core.utils import generate_rsa_key_pair
        
        private_pem, public_pem = generate_rsa_key_pair()
        
        # Keys should be PEM encoded
        assert b"-----BEGIN PRIVATE KEY-----" in private_pem
        assert b"-----BEGIN PUBLIC KEY-----" in public_pem
    
    def test_key_encryption_decryption(self):
        """Test private key encryption and decryption."""
        from core.utils import (
            generate_rsa_key_pair,
            derive_key_from_password,
            encrypt_private_key,
            decrypt_private_key
        )
        
        password = "testpassword"
        salt = b"1234567890123456"
        
        private_pem, _ = generate_rsa_key_pair()
        
        # Encrypt private key
        encrypted = encrypt_private_key(private_pem, password, salt)
        assert encrypted != private_pem
        
        # Decrypt private key
        decrypted = decrypt_private_key(encrypted, password, salt)
        assert decrypted == private_pem
    
    def test_symmetric_encryption(self):
        """Test symmetric key encryption."""
        from cryptography.fernet import Fernet
        
        key = Fernet.generate_key()
        cipher = Fernet(key)
        
        original_data = b"Hello, World!"
        encrypted = cipher.encrypt(original_data)
        decrypted = cipher.decrypt(encrypted)
        
        assert decrypted == original_data
    
    def test_signing_and_verification(self):
        """Test digital signature creation and verification."""
        from core.utils import (
            generate_rsa_key_pair,
            sign_data,
            verify_signature
        )
        from cryptography.hazmat.primitives import serialization
        
        private_pem, public_pem = generate_rsa_key_pair()
        private_key = serialization.load_pem_private_key(
            private_pem, password=None
        )
        
        data = b"Test data to sign"
        signature = sign_data(data, private_key)
        
        # Verification should succeed
        assert verify_signature(data, signature, public_pem) is True
        
        # Verification with wrong data should fail
        assert verify_signature(b"wrong data", signature, public_pem) is False


class TestModels:
    """Test cases for data models."""
    
    def test_digital_certificate_creation(self):
        """Test DigitalCertificate dataclass."""
        from core.models import DigitalCertificate
        
        cert = DigitalCertificate(
            serial="CRT_20240101_0001",
            subject="testuser",
            issuer="PKIshare CA",
            valid_from="2024-01-01",
            valid_to="2025-01-01",
            public_key_pem="-----BEGIN PUBLIC KEY-----..."
        )
        
        assert cert.serial == "CRT_20240101_0001"
        assert cert.subject == "testuser"
        assert cert.issuer == "PKIshare CA"
    
    def test_user_account_creation(self):
        """Test UserAccount dataclass."""
        from core.models import UserAccount
        
        account = UserAccount(
            username="testuser",
            password_hash="hash",
            salt=b"salt",
            private_key_encrypted=b"encrypted"
        )
        
        assert account.username == "testuser"
        assert account.password_hash == "hash"
        assert account.certificate is None
    
    def test_encrypted_file_creation(self):
        """Test EncryptedFile dataclass."""
        from core.models import EncryptedFile
        
        file_obj = EncryptedFile(
            file_id="enc_123",
            filename="test.txt",
            owner="testuser",
            encrypted_sym_key={"user1": b"key1"},
            signature=b"sig",
            file_hash="abc123",
            timestamp="2024-01-01"
        )
        
        assert file_obj.file_id == "enc_123"
        assert file_obj.filename == "test.txt"


# Run tests if executed directly
if __name__ == "__main__":
    pytest.main([__file__, "-v"])

