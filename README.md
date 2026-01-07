# PKIshare - Secure Digital Certificate File Sharing System

A secure file sharing application built with Public Key Infrastructure (PKI) principles, featuring RSA encryption, digital certificates, and a user-friendly GUI interface.

## Features

- **User Authentication**: Secure registration and login with password-based authentication
- **Digital Certificates**: Auto-generated X.509 digital certificates for each user
- **File Encryption**: Fernet symmetric encryption for files with RSA key wrapping
- **Digital Signatures**: Cryptographic signatures for file integrity verification
- **Access Control**: Granular file sharing with recipient selection and access revocation
- **Secure Storage**: Personal encrypted file repository with password protection
- **User Management**: View registered users and their certificate status

## Architecture

```
PKIshare/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
├── core/
│   ├── __init__.py
│   ├── models.py          # Data models (DigitalCertificate, UserAccount, EncryptedFile)
│   ├── secure_share.py    # Core engine (PKIshareCore class)
│   └── utils.py           # Cryptographic utility functions
├── gui/
│   ├── __init__.py
│   └── app.py             # Tkinter GUI application (PKIshareApp class)
└── data/                   # Application data (auto-created)
    ├── accounts.json       # User accounts and certificates
    ├── encrypted_files.json # Shared file metadata
    └── shared_repository.json # Personal file storage metadata
```

## Security Features

1. **RSA Key Generation**: 2048-bit RSA key pairs for each user
2. **Password-Based Key Derivation**: Scrypt KDF for key derivation
3. **Hybrid Encryption**: Symmetric (Fernet) for files, asymmetric (RSA) for key exchange
4. **Digital Signatures**: SHA-256 with RSA for file integrity and authenticity
5. **Certificate-Based Identity**: X.509 style self-signed certificates

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/PKIshare.git
cd PKIshare

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

## Dependencies

- Python 3.8+
- cryptography>=41.0.0
- Pillow>=10.0.0
- tkinter (included with Python)

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

## Development

```bash
# Set up development environment
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run tests (when available)
pytest

# Lint code
flake8 .
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License.

## Author

PKIshare - Secure Digital Certificate File Sharing System

