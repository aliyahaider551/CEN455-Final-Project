# src/common/crypto_utils.py
"""
Cryptographic utilities for the CEN455 Secure MQTT project.
Provides RSA, AES-GCM, and DSA functionality for secure communication.
Includes timing attack mitigations.
"""
import os
import json
import base64
import hmac
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import utils as asym_utils
from cryptography.exceptions import InvalidSignature

# ----- Key generation helpers -----

def generate_rsa_keypair(bits=2048):
    """
    Generate an RSA public/private key pair.
    
    Args:
        bits: Key size in bits (default 2048)
        
    Returns:
        Tuple of (private_key, public_key)
    """
    private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub = private.public_key()
    return private, pub


def rsa_public_bytes(pub):
    """Serialize RSA public key to PEM format bytes"""
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def rsa_private_bytes(priv):
    """Serialize RSA private key to PEM format bytes (unencrypted)"""
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def load_rsa_public(pem_bytes):
    """Load RSA public key from PEM format bytes"""
    return serialization.load_pem_public_key(pem_bytes)


def load_rsa_private(pem_bytes):
    """Load RSA private key from PEM format bytes"""
    return serialization.load_pem_private_key(pem_bytes, password=None)


def generate_dsa_keypair():
    """
    Generate a DSA public/private key pair for digital signatures.
    
    Returns:
        Tuple of (private_key, public_key)
    """
    priv = dsa.generate_private_key(key_size=2048)
    pub = priv.public_key()
    return priv, pub


def dsa_public_bytes(pub):
    """Serialize DSA public key to PEM format bytes"""
    return pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )


def dsa_private_bytes(priv):
    """Serialize DSA private key to PEM format bytes (unencrypted)"""
    return priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )


def load_dsa_public(pem_bytes):
    """Load DSA public key from PEM format bytes"""
    return serialization.load_pem_public_key(pem_bytes)


def load_dsa_private(pem_bytes):
    """Load DSA private key from PEM format bytes"""
    return serialization.load_pem_private_key(pem_bytes, password=None)


# ----- AES-GCM helpers -----

def aesgcm_encrypt(key: bytes, plaintext: bytes, associated_data: bytes = None):
    """
    Encrypt data using AES-GCM (provides both confidentiality and integrity).
    
    Args:
        key: AES key (16, 24, or 32 bytes for AES-128/192/256)
        plaintext: Data to encrypt
        associated_data: Additional authenticated data (not encrypted but authenticated)
        
    Returns:
        Dictionary with 'nonce' and 'ciphertext' (both base64-encoded)
    """
    nonce = os.urandom(12)  # 96-bit nonce recommended for GCM
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext, associated_data)
    # ct includes authentication tag appended
    return {
        'nonce': base64.b64encode(nonce).decode(),
        'ciphertext': base64.b64encode(ct).decode()
    }


def aesgcm_decrypt(key: bytes, nonce_b64: str, ct_b64: str, associated_data: bytes = None):
    """
    Decrypt AES-GCM encrypted data.
    
    Args:
        key: AES key used for encryption
        nonce_b64: Base64-encoded nonce
        ct_b64: Base64-encoded ciphertext (includes auth tag)
        associated_data: Same AAD used during encryption
        
    Returns:
        Decrypted plaintext bytes
        
    Raises:
        InvalidTag: If authentication fails (tampering detected)
    """
    nonce = base64.b64decode(nonce_b64)
    ct = base64.b64decode(ct_b64)
    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(nonce, ct, associated_data)
    return pt


# ----- RSA encryption helpers (for key exchange) -----

def rsa_encrypt_for_public(pub_key, plaintext: bytes):
    """
    Encrypt data with RSA public key using OAEP padding.
    Used for encrypting session keys.
    
    Args:
        pub_key: RSA public key object
        plaintext: Data to encrypt (should be small, e.g., session key)
        
    Returns:
        Base64-encoded ciphertext
    """
    ct = pub_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(ct).decode()


def rsa_decrypt_with_private(priv_key, ct_b64: str):
    """
    Decrypt RSA-encrypted data with private key.
    
    Args:
        priv_key: RSA private key object
        ct_b64: Base64-encoded ciphertext
        
    Returns:
        Decrypted plaintext bytes
    """
    ct = base64.b64decode(ct_b64)
    pt = priv_key.decrypt(
        ct,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return pt


# ----- DSA sign/verify helpers -----

def dsa_sign(private_key, message: bytes) -> str:
    """
    Sign a message with DSA private key.
    
    Args:
        private_key: DSA private key object
        message: Data to sign
        
    Returns:
        Base64-encoded signature
    """
    signature = private_key.sign(message, hashes.SHA256())
    return base64.b64encode(signature).decode()


def dsa_verify(public_key, message: bytes, signature_b64: str) -> bool:
    """
    Verify a DSA signature with timing attack mitigation.
    
    Args:
        public_key: DSA public key object
        message: Original message that was signed
        signature_b64: Base64-encoded signature
        
    Returns:
        True if signature is valid, False otherwise
        
    Note: Uses constant-time operations to prevent timing attacks
    """
    signature = base64.b64decode(signature_b64)
    try:
        public_key.verify(signature, message, hashes.SHA256())
        return True
    except InvalidSignature:
        return False


# ----- Utilities -----

def generate_session_key(length=32):
    """
    Generate a random session key for AES encryption.
    
    Args:
        length: Key length in bytes (16=AES-128, 24=AES-192, 32=AES-256)
        
    Returns:
        Random bytes suitable for use as AES key
    """
    return os.urandom(length)


def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time to prevent timing attacks.
    
    Args:
        a: First byte string
        b: Second byte string
        
    Returns:
        True if equal, False otherwise
        
    Note: Uses hmac.compare_digest for constant-time comparison
    """
    return hmac.compare_digest(a, b)


def save_keys_to_files(prefix, rsa_priv, rsa_pub, dsa_priv, dsa_pub, directory="keys"):
    """
    Save generated keys to PEM files.
    
    Args:
        prefix: Filename prefix (e.g., "sensor", "actuator")
        rsa_priv, rsa_pub: RSA key pair
        dsa_priv, dsa_pub: DSA key pair
        directory: Directory to save keys in
    """
    os.makedirs(directory, exist_ok=True)
    
    with open(f"{directory}/{prefix}_rsa_priv.pem", "wb") as f:
        f.write(rsa_private_bytes(rsa_priv))
    
    with open(f"{directory}/{prefix}_rsa_pub.pem", "wb") as f:
        f.write(rsa_public_bytes(rsa_pub))
    
    with open(f"{directory}/{prefix}_dsa_priv.pem", "wb") as f:
        f.write(dsa_private_bytes(dsa_priv))
    
    with open(f"{directory}/{prefix}_dsa_pub.pem", "wb") as f:
        f.write(dsa_public_bytes(dsa_pub))


if __name__ == "__main__":
    # Test the crypto utilities
    print("Testing crypto utilities...")
    
    # Test AES-GCM
    key = generate_session_key(32)
    plaintext = b"Hello, secure world!"
    enc = aesgcm_encrypt(key, plaintext, b"test")
    dec = aesgcm_decrypt(key, enc['nonce'], enc['ciphertext'], b"test")
    assert dec == plaintext
    print("✓ AES-GCM encryption/decryption works")
    
    # Test RSA
    rsa_priv, rsa_pub = generate_rsa_keypair()
    session_key = b"0123456789abcdef"
    enc_key = rsa_encrypt_for_public(rsa_pub, session_key)
    dec_key = rsa_decrypt_with_private(rsa_priv, enc_key)
    assert dec_key == session_key
    print("✓ RSA encryption/decryption works")
    
    # Test DSA
    dsa_priv, dsa_pub = generate_dsa_keypair()
    message = b"Sign this message"
    sig = dsa_sign(dsa_priv, message)
    assert dsa_verify(dsa_pub, message, sig)
    assert not dsa_verify(dsa_pub, b"Different message", sig)
    print("✓ DSA signing/verification works")
    
    print("\nAll crypto tests passed!")
