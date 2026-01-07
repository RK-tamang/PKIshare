# PKIshare - Secure Digital Certificate File Sharing System

A secure file sharing application built with Public Key Infrastructure (PKI) principles, featuring RSA encryption, digital certificates, and a user-friendly GUI interface.

## Features

- **User Authentication**: Secure registration and login with password-based authentication
- **Digital Certificates**: Auto-generated X.509 digital certificates for each user
- **File Encryption**: Fernet symmetric encryption for files with RSA key wrapping
- **Digital Signatures**: Cryptographic signatures for file integrity verification
- **Access Control**: Granular file sharing with recipient selection and access revocation
- **Secure Storage**: Personal encrypted file repository with password protection
- **SQLite Database**: All data stored in SQLite database with proper schema

## Architecture

```
PKIshare/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── Dockerfile             # Docker container definition
├── docker-compose.yml     # Docker Compose for app + SQLite
├── .gitignore             # Git ignore rules
├── README.md              # This file
├── core/
│   ├── __init__.py
│   ├── models.py          # Data models (DigitalCertificate, UserAccount, EncryptedFile)
│   ├── secure_share.py    # Core engine (PKIshareCore class)
│   ├── database.py        # SQLite database layer
│   └── utils.py           # Cryptographic utility functions
├── gui/
│   ├── __init__.py
│   └── app.py             # Tkinter GUI application (PKIshareApp class)
└── data/                   # Application data (auto-created)
    └── pki_share.db        # SQLite database
        ├── users           # User accounts
        ├── certificates    # Digital certificates
        ├── encrypted_files # Shared file metadata
        ├── file_keys       # Encrypted symmetric keys
        └── shared_files    # Personal file storage
```

## Security Features

1. **RSA Key Generation**: 2048-bit RSA key pairs for each user
2. **Password-Based Key Derivation**: Scrypt KDF for key derivation
3. **Hybrid Encryption**: Symmetric (Fernet) for files, asymmetric (RSA) for key exchange
4. **Digital Signatures**: SHA-256 with RSA for file integrity and authenticity
5. **Certificate-Based Identity**: X.509 style self-signed certificates

## Installation

### Option 1: Local Development

```bash
# Clone the repository
git clone https://github.com/RK-tamang/PKIshare.git
cd PKIshare

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Option 2: Docker Compose (Recommended)

```bash
# Build and run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f

# Stop the application
docker-compose down
```

The application will be available at http://localhost:5000

## Docker Configuration

The Docker setup includes:
- Python 3.11 slim container
- SQLite database persisted in Docker volume
- Health check for container monitoring
- Automatic restart policy

## Database Schema

### users table
- id, username, password_hash, salt, private_key_encrypted
- share_password_hash, share_salt, created_at

### certificates table
- id, user_id, version, serial, subject, issuer
- valid_from, valid_to, public_key_pem, signature

### encrypted_files table
- id, file_id, filename, owner_id, file_hash
- signature, timestamp, encrypted_data_path

### file_keys table
- id, file_id, user_id, encrypted_key

### shared_files table
- id, share_id, owner_id, filename, file_hash
- encrypted_key, timestamp, size, encrypted_data_path

### revoked_certs table
- id, serial, revoked_at

## Usage

### Registration
1. Launch the application
2. Switch to the "Register" tab
3. Enter username and password (minimum 8 characters)
4. Click "Register" - a digital certificate is auto-generated

### Login
1. Enter your credentials on the "Login" tab
2. Click "Login" to authenticate

### Sharing Files
1. Go to "Share File" tab
2. Select a file using "Browse..."
3. Choose recipients from the registered users
4. Click "Encrypt & Share File"

### Managing Files
- **My Files**: View all files you own or have access to
- **Download**: Decrypt and download shared files
- **Revoke Access**: Remove access for specific recipients

### Personal Repository
1. Set a share password when first accessing the repository
2. Add files to your personal encrypted storage
3. Download or delete files as needed

## Security Considerations

- Passwords are hashed using SHA-256 (demo purposes - use bcrypt/argon2 in production)
- Private keys are encrypted with password-derived keys
- All files are encrypted with unique symmetric keys
- Digital signatures ensure file integrity and authenticity
- SQLite database provides persistent storage with proper relationships

## Development

```bash
# Set up development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run the application
python main.py

# Run tests (when available)
pytest

# Lint code
flake8 .
```

## API Reference

### PKIshareCore Methods

- `create_user_account(username, password)` - Create new user with certificate
- `authenticate_user(username, password)` - Authenticate user
- `distribute_file(filepath, recipients, password)` - Share file with recipients
- `retrieve_file(file_id, save_path, password)` - Download and decrypt file
- `store_in_share(filepath, password)` - Store file in personal repository
- `list_share_contents()` - List personal repository files
- `extract_from_share(share_id, save_path, password)` - Download from repository

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b dev`)
3. Commit your changes (`git commit -am 'Add new feature'`)
4. Push to the branch (`git push origin dev`)
5. Create a Pull Request

## License

This project is licensed under the MIT License.

## Author

PKIshare - Secure Digital Certificate File Sharing System

