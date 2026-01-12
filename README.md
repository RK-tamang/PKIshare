# PKIshare - Secure Digital Certificate File Sharing System

A secure file sharing application built with Public Key Infrastructure (PKI) principles, featuring RSA encryption, digital certificates, and a user-friendly GUI interface.

![PKIshare Screenshot](docs/screenshot.png)

## Table of Contents

- [Features](#features)
- [Security Features](#security-features)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Project Structure](#project-structure)
- [Database Schema](#database-schema)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [License](#license)

## Features

### User Management
- **Secure Registration** - Create accounts with password-based authentication
- **Login System** - Authenticate with username and password
- **Account Deletion** - Permanently delete your account and all associated data
- **Certificate Auto-Generation** - Each user receives an auto-generated digital certificate

### File Sharing
- **Encrypted File Sharing** - Share files with specific users using hybrid encryption
- **Recipient Selection** - Choose which users can access your shared files
- **Access Revocation** - Remove access from specific users
- **Access Granting** - Re-grant access to previously revoked users
- **Digital Signatures** - All files are cryptographically signed for integrity verification

### Personal Repository
- **Secure Storage** - Personal encrypted file repository with password protection
- **File Encryption** - Encrypt and store files in your personal vault
- **File Management** - Download or delete files from your repository
- **Change Password** - Update your repository password anytime

### Certificate Management
- **Digital Certificates** - Auto-generated X.509-style certificates for each user
- **Certificate Info** - View your certificate details (serial, validity, issuer)
- **Key Management** - RSA key pairs encrypted with your password

### GUI Features
- **Modern Interface** - Clean, modern Tkinter-based GUI
- **File Preview** - Preview text and image files before downloading
- **User List** - View all registered users in the system
- **Responsive Design** - Resizable window with proper layout

## Security Features

1. **Hybrid Encryption System**
   - **Fernet Symmetric Encryption** - Files encrypted with AES-128 in CBC mode
   - **RSA Asymmetric Encryption** - 2048-bit keys for key exchange

2. **Password-Based Key Derivation**
   - SHA-256 for password hashing
   - Unique salt per user for rainbow table resistance

3. **Digital Signatures**
   - SHA-256 with RSA for file integrity verification
   - Cryptographic signatures on all shared files

4. **Certificate-Based Identity**
   - X.509-style self-signed certificates
   - Certificate serial numbers for tracking
   - Validity period tracking

5. **Access Control**
   - Per-file access control lists
   - Owner-based permissions
   - Revocation support

## Architecture

```
PKIshare/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── Dockerfile             # Docker container definition
├── README.md              # This file
├── core/
│   ├── __init__.py
│   ├── models.py          # Data models (UserAccount, DigitalCertificate, EncryptedFile)
│   ├── secure_share.py    # Core engine (PKIshareCore class)
│   ├── database.py        # SQLite database layer
│   └── utils.py           # Cryptographic utility functions
├── gui/
│   ├── __init__.py
│   └── app.py             # Tkinter GUI application (PKIshareApp class)
└── data/                   # Application data (auto-created)
    ├── pki_share.db        # SQLite database
    ├── files/              # Encrypted shared files
    └── share/              # Personal repository files
```

## Installation

### Option 1: Local Development

```bash
# Clone the repository
git clone https://github.com/RK-tamang/PKIshare.git
cd PKIshare

# Create virtual environment (optional but recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Run the application
python main.py
```

### Option 2: Docker

```bash
# Build the Docker image
docker build -t pki-share .

# Run the container
docker run -p 5000:5000 -v $(pwd)/data:/app/data pki-share
```

### Dependencies

- Python 3.10+
- cryptography>=41.0.0
- Pillow>=10.0.0
- Tkinter (included with Python)
- SQLite3 (included with Python)

## Usage

### Starting the Application

```bash
python main.py
```

The application window will appear, centered on your screen.

### Registration

1. Launch the application
2. Switch to the "Register" tab
3. Enter a username (must be unique)
4. Enter a password (minimum 8 characters)
5. Confirm your password
6. Click "Create Account"

A digital certificate will be auto-generated for your account.

### Login

1. Enter your username on the "Login" tab
2. Enter your password
3. Click "Login"

### Sharing a File

1. Go to the "Share File" tab
2. Click "Browse" to select a file
3. Select recipients by checking their names
4. Click "Encrypt & Share File"

The file will be encrypted and made available to selected recipients.

### Managing Files

1. Go to the "My Files" tab
2. View all files you own or have access to
3. Click a file to see a preview (text and image files)
4. Click "Download" to decrypt and save a file
5. Click "Revoke Access" to remove access from a user
6. Click "Grant Access" to restore access to a previously revoked user

### Personal Repository

1. Go to the "Shared Repository" tab
2. If first time, set a share password
3. Enter the password to unlock your repository
4. Click "Browse" to select a file
5. Click "Encrypt & Store" to add it to your repository
6. Use "Download" or "Delete" to manage stored files

### Deleting Your Account

1. Click "🗑️ Delete My Account" button in the header
2. Type your username to confirm
3. Review the warning about data deletion
4. Click "Delete My Account" to confirm

**Warning:** This action is irreversible and will delete all your files, certificates, and account data.

## Project Structure

### Core Module (`core/`)

- **secure_share.py** - Main core class handling all operations
  - User management (create, authenticate, delete)
  - File operations (share, retrieve, revoke)
  - Repository operations (store, list, extract)
  - Certificate management

- **database.py** - SQLite database layer
  - User table management
  - Certificate storage
  - File metadata and keys
  - Shared repository tracking

- **models.py** - Data model classes
  - UserAccount
  - DigitalCertificate
  - EncryptedFile

- **utils.py** - Cryptographic utilities
  - RSA key pair generation
  - Private key encryption/decryption
  - Symmetric key encryption with RSA
  - Digital signatures

### GUI Module (`gui/`)

- **app.py** - Tkinter-based GUI application
  - Authentication pages (login/register)
  - Dashboard with tabbed interface
  - File sharing panel
  - Files management panel with preview
  - Users panel
  - Shared repository panel
  - Certificate viewer

## Database Schema

### users table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Unique username |
| password_hash | TEXT | SHA-256 hash of password |
| salt | BLOB | Random salt for key derivation |
| private_key_encrypted | BLOB | Encrypted RSA private key |
| share_password_hash | TEXT | Hash for repository password |
| share_salt | BLOB | Salt for share password |
| created_at | TIMESTAMP | Account creation time |

### certificates table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to users |
| version | TEXT | Certificate version |
| serial | TEXT | Unique serial number |
| subject | TEXT | Certificate subject (username) |
| issuer | TEXT | Certificate issuer |
| valid_from | TEXT | Validity start date |
| valid_to | TEXT | Validity end date |
| public_key_pem | TEXT | PEM-encoded public key |
| signature | BLOB | Certificate signature |

### encrypted_files table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| file_id | TEXT | Unique file identifier |
| filename | TEXT | Original filename |
| owner_id | INTEGER | Foreign key to users |
| file_hash | TEXT | SHA-256 hash of file content |
| signature | BLOB | Digital signature |
| timestamp | TEXT | Creation timestamp |

### file_keys table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| file_id | INTEGER | Foreign key to encrypted_files |
| user_id | INTEGER | Foreign key to users |
| encrypted_key | BLOB | RSA-encrypted symmetric key |

### shared_files table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| share_id | TEXT | Unique share identifier |
| owner_id | INTEGER | Foreign key to users |
| filename | TEXT | Original filename |
| file_hash | TEXT | SHA-256 hash of content |
| encrypted_key | TEXT | Encrypted symmetric key |
| timestamp | TEXT | Creation timestamp |
| size | INTEGER | File size in bytes |

### revoked_certs table
| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| serial | TEXT | Revoked certificate serial |
| revoked_at | TIMESTAMP | Revocation timestamp |

## API Reference

### PKIshareCore Methods

#### User Management

```python
# Create a new user account
create_user_account(username: str, password: str) -> bool

# Authenticate a user
authenticate_user(username: str, password: str) -> bool

# Get user ID by username
get_user_id_by_username(username: str) -> Optional[int]

# Get user's certificate
get_certificate() -> Optional[Dict[str, Any]]

# Delete current user's account
delete_account(password: str) -> bool
```

#### File Sharing

```python
# Distribute a file to recipients
distribute_file(filepath: str, recipients: list[str], password: str) -> bool

# Retrieve and decrypt a file
retrieve_file(file_id: str, save_path: str, password: str) -> bool

# Get all accessible files
fetch_shared_collection() -> List[Dict[str, Any]]

# Revoke user access
remove_file_access(file_id: str, username: str) -> bool

# Grant access to previously revoked user
grant_file_access(file_id: str, username: str, password: str) -> bool

# Get all registered users
get_all_users() -> List[str]
```

#### Shared Repository

```python
# Check if share password is set
check_share_protection(username: str) -> bool

# Set or update share password
configure_share_password(password: str) -> bool

# Validate share password
validate_share_credentials(username: str, password: str) -> bool

# Store file in repository
store_in_share(filepath: str, password: str) -> bool

# List repository contents
list_share_contents() -> List[Dict[str, Any]]

# Extract file from repository
extract_from_share(share_id: str, save_path: str, password: str) -> bool

# Remove file from repository
remove_from_share(share_id: str) -> bool
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Security Note

This is a demonstration project for educational purposes. For production use, consider:
- Using bcrypt or Argon2 for password hashing
- Implementing proper certificate validation
- Adding rate limiting and brute-force protection
- Using a proper Certificate Authority
- Implementing audit logging
- Adding two-factor authentication

## Author

**RK-tamang**

- GitHub: [@RK-tamang](https://github.com/RK-tamang)
- Email: rktamang@example.com

## Acknowledgments

- [cryptography](https://cryptography.io/) - Modern cryptographic library
- [Python](https://www.python.org/) - Programming language
- [Tkinter](https://docs.python.org/3/library/tkinter.html) - GUI toolkit

