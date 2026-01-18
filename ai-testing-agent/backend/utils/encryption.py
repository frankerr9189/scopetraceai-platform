"""
Encryption utilities for storing sensitive credentials.

Uses Fernet symmetric encryption from the cryptography library.
Requires INTEGRATION_SECRET_KEY environment variable.
"""
import os
from cryptography.fernet import Fernet
from dotenv import load_dotenv

# Load environment variables
try:
    load_dotenv()
except (PermissionError, OSError):
    pass

# Get encryption key from environment
INTEGRATION_SECRET_KEY = os.getenv("INTEGRATION_SECRET_KEY")

if not INTEGRATION_SECRET_KEY:
    raise RuntimeError(
        "INTEGRATION_SECRET_KEY environment variable is required for credential encryption. "
        "Generate a key with: python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    )

# Initialize Fernet cipher
try:
    # Ensure key is bytes
    if isinstance(INTEGRATION_SECRET_KEY, str):
        key_bytes = INTEGRATION_SECRET_KEY.encode()
    else:
        key_bytes = INTEGRATION_SECRET_KEY
    
    # Fernet requires a 32-byte URL-safe base64-encoded key
    # If the key is not in the right format, try to decode it
    if len(key_bytes) != 44:  # Fernet keys are 44 bytes when base64-encoded
        raise ValueError("INTEGRATION_SECRET_KEY must be a valid Fernet key (44 bytes base64-encoded)")
    
    cipher = Fernet(key_bytes)
except Exception as e:
    raise RuntimeError(
        f"Failed to initialize encryption cipher: {str(e)}. "
        "INTEGRATION_SECRET_KEY must be a valid Fernet key. "
        "Generate one with: python3 -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())'"
    ) from e


def encrypt_secret(plaintext: str) -> str:
    """
    Encrypt a plaintext secret using Fernet symmetric encryption.
    
    Args:
        plaintext: Plain text secret to encrypt
    
    Returns:
        str: Base64-encoded ciphertext
    
    Raises:
        RuntimeError: If encryption fails
    """
    if not plaintext:
        raise ValueError("plaintext cannot be empty")
    
    try:
        plaintext_bytes = plaintext.encode('utf-8')
        ciphertext_bytes = cipher.encrypt(plaintext_bytes)
        return ciphertext_bytes.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Failed to encrypt secret: {str(e)}") from e


def decrypt_secret(ciphertext: str) -> str:
    """
    Decrypt a ciphertext secret using Fernet symmetric encryption.
    
    Args:
        ciphertext: Base64-encoded ciphertext to decrypt
    
    Returns:
        str: Decrypted plaintext
    
    Raises:
        RuntimeError: If decryption fails
    """
    if not ciphertext:
        raise ValueError("ciphertext cannot be empty")
    
    try:
        ciphertext_bytes = ciphertext.encode('utf-8')
        plaintext_bytes = cipher.decrypt(ciphertext_bytes)
        return plaintext_bytes.decode('utf-8')
    except Exception as e:
        raise RuntimeError(f"Failed to decrypt secret: {str(e)}") from e
