# src/tests/test_crypto.py
"""
Unit tests for cryptographic utilities.
Tests encryption, decryption, signing, and verification.
"""
import pytest
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from common.crypto_utils import (
    generate_session_key, aesgcm_encrypt, aesgcm_decrypt,
    generate_rsa_keypair, rsa_encrypt_for_public, rsa_decrypt_with_private,
    generate_dsa_keypair, dsa_sign, dsa_verify,
    rsa_public_bytes, rsa_private_bytes, load_rsa_public, load_rsa_private,
    dsa_public_bytes, dsa_private_bytes, load_dsa_public, load_dsa_private,
    constant_time_compare
)


class TestAESGCM:
    """Test AES-GCM encryption and decryption"""
    
    def test_aes_roundtrip(self):
        """Test basic encryption and decryption"""
        key = generate_session_key(32)  # AES-256
        plaintext = b"Hello, secure world!"
        
        # Encrypt
        encrypted = aesgcm_encrypt(key, plaintext)
        assert 'nonce' in encrypted
        assert 'ciphertext' in encrypted
        
        # Decrypt
        decrypted = aesgcm_decrypt(key, encrypted['nonce'], encrypted['ciphertext'])
        assert decrypted == plaintext
    
    def test_aes_with_associated_data(self):
        """Test AES-GCM with associated authenticated data"""
        key = generate_session_key(32)
        plaintext = b"Secret message"
        aad = b"context|sensor_id"
        
        # Encrypt with AAD
        encrypted = aesgcm_encrypt(key, plaintext, aad)
        
        # Decrypt with correct AAD
        decrypted = aesgcm_decrypt(key, encrypted['nonce'], encrypted['ciphertext'], aad)
        assert decrypted == plaintext
        
        # Decrypt with wrong AAD should fail
        with pytest.raises(Exception):
            aesgcm_decrypt(key, encrypted['nonce'], encrypted['ciphertext'], b"wrong_context")
    
    def test_aes_different_key_sizes(self):
        """Test AES with different key sizes"""
        for key_size in [16, 24, 32]:  # AES-128, 192, 256
            key = generate_session_key(key_size)
            plaintext = b"Test data"
            
            encrypted = aesgcm_encrypt(key, plaintext)
            decrypted = aesgcm_decrypt(key, encrypted['nonce'], encrypted['ciphertext'])
            
            assert decrypted == plaintext
    
    def test_aes_tampering_detection(self):
        """Test that tampering is detected"""
        key = generate_session_key(32)
        plaintext = b"Original message"
        
        encrypted = aesgcm_encrypt(key, plaintext)
        
        # Tamper with ciphertext (modify first character)
        tampered_ct = "X" + encrypted['ciphertext'][1:]
        
        # Decryption should fail
        with pytest.raises(Exception):
            aesgcm_decrypt(key, encrypted['nonce'], tampered_ct)


class TestRSA:
    """Test RSA encryption and decryption"""
    
    def test_rsa_key_generation(self):
        """Test RSA key pair generation"""
        priv, pub = generate_rsa_keypair(2048)
        assert priv is not None
        assert pub is not None
    
    def test_rsa_roundtrip(self):
        """Test RSA encryption and decryption"""
        priv, pub = generate_rsa_keypair(2048)
        session_key = b"0123456789abcdef"  # 16-byte session key
        
        # Encrypt with public key
        encrypted = rsa_encrypt_for_public(pub, session_key)
        assert encrypted is not None
        
        # Decrypt with private key
        decrypted = rsa_decrypt_with_private(priv, encrypted)
        assert decrypted == session_key
    
    def test_rsa_serialization(self):
        """Test RSA key serialization and deserialization"""
        priv, pub = generate_rsa_keypair(2048)
        
        # Serialize
        priv_bytes = rsa_private_bytes(priv)
        pub_bytes = rsa_public_bytes(pub)
        
        # Deserialize
        loaded_priv = load_rsa_private(priv_bytes)
        loaded_pub = load_rsa_public(pub_bytes)
        
        # Test that loaded keys work
        plaintext = b"test data"
        encrypted = rsa_encrypt_for_public(loaded_pub, plaintext)
        decrypted = rsa_decrypt_with_private(loaded_priv, encrypted)
        assert decrypted == plaintext
    
    def test_rsa_wrong_key(self):
        """Test that decryption fails with wrong key"""
        priv1, pub1 = generate_rsa_keypair(2048)
        priv2, pub2 = generate_rsa_keypair(2048)
        
        plaintext = b"secret"
        encrypted = rsa_encrypt_for_public(pub1, plaintext)
        
        # Trying to decrypt with wrong private key should fail
        with pytest.raises(Exception):
            rsa_decrypt_with_private(priv2, encrypted)


class TestDSA:
    """Test DSA signing and verification"""
    
    def test_dsa_key_generation(self):
        """Test DSA key pair generation"""
        priv, pub = generate_dsa_keypair()
        assert priv is not None
        assert pub is not None
    
    def test_dsa_sign_verify(self):
        """Test DSA signature creation and verification"""
        priv, pub = generate_dsa_keypair()
        message = b"Message to sign"
        
        # Sign
        signature = dsa_sign(priv, message)
        assert signature is not None
        
        # Verify
        assert dsa_verify(pub, message, signature) is True
    
    def test_dsa_invalid_signature(self):
        """Test that invalid signatures are detected"""
        priv, pub = generate_dsa_keypair()
        message = b"Original message"
        
        signature = dsa_sign(priv, message)
        
        # Verify with different message should fail
        assert dsa_verify(pub, b"Different message", signature) is False
    
    def test_dsa_tampered_signature(self):
        """Test that tampered signatures are detected"""
        priv, pub = generate_dsa_keypair()
        message = b"Message"
        
        signature = dsa_sign(priv, message)
        
        # Tamper with signature
        tampered = "X" + signature[1:]
        
        # Verification should fail
        assert dsa_verify(pub, message, tampered) is False
    
    def test_dsa_serialization(self):
        """Test DSA key serialization and deserialization"""
        priv, pub = generate_dsa_keypair()
        
        # Serialize
        priv_bytes = dsa_private_bytes(priv)
        pub_bytes = dsa_public_bytes(pub)
        
        # Deserialize
        loaded_priv = load_dsa_private(priv_bytes)
        loaded_pub = load_dsa_public(pub_bytes)
        
        # Test that loaded keys work
        message = b"test message"
        signature = dsa_sign(loaded_priv, message)
        assert dsa_verify(loaded_pub, message, signature) is True


class TestSessionKeys:
    """Test session key generation"""
    
    def test_session_key_length(self):
        """Test session keys have correct length"""
        for length in [16, 24, 32]:
            key = generate_session_key(length)
            assert len(key) == length
    
    def test_session_key_randomness(self):
        """Test that session keys are different"""
        key1 = generate_session_key(32)
        key2 = generate_session_key(32)
        assert key1 != key2


class TestTimingAttackMitigation:
    """Test timing attack mitigation features"""
    
    def test_constant_time_compare_equal(self):
        """Test constant-time comparison with equal values"""
        a = b"secret_value_123"
        b = b"secret_value_123"
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_different(self):
        """Test constant-time comparison with different values"""
        a = b"secret_value_123"
        b = b"secret_value_456"
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_different_lengths(self):
        """Test constant-time comparison with different lengths"""
        a = b"short"
        b = b"much_longer_string"
        assert constant_time_compare(a, b) is False
    
    def test_constant_time_compare_empty(self):
        """Test constant-time comparison with empty strings"""
        a = b""
        b = b""
        assert constant_time_compare(a, b) is True
    
    def test_constant_time_compare_one_empty(self):
        """Test constant-time comparison with one empty string"""
        a = b"not_empty"
        b = b""
        assert constant_time_compare(a, b) is False


class TestIntegration:
    """Integration tests combining multiple crypto operations"""
    
    def test_full_message_flow(self):
        """Test complete message encryption/signing flow"""
        # Generate keys for sender and receiver
        sender_dsa_priv, sender_dsa_pub = generate_dsa_keypair()
        receiver_rsa_priv, receiver_rsa_pub = generate_rsa_keypair(2048)
        
        # Sender: Create encrypted and signed message
        plaintext = b"Secure message content"
        session_key = generate_session_key(32)
        
        # Encrypt message
        aad = b"topic|sender_id"
        encrypted = aesgcm_encrypt(session_key, plaintext, aad)
        
        # Encrypt session key for receiver
        enc_session_key = rsa_encrypt_for_public(receiver_rsa_pub, session_key)
        
        # Sign the encrypted message
        sign_data = encrypted['nonce'] + encrypted['ciphertext']
        signature = dsa_sign(sender_dsa_priv, sign_data.encode())
        
        # Receiver: Verify and decrypt
        # Verify signature
        assert dsa_verify(sender_dsa_pub, sign_data.encode(), signature)
        
        # Decrypt session key
        decrypted_session_key = rsa_decrypt_with_private(receiver_rsa_priv, enc_session_key)
        assert decrypted_session_key == session_key
        
        # Decrypt message
        decrypted = aesgcm_decrypt(
            decrypted_session_key,
            encrypted['nonce'],
            encrypted['ciphertext'],
            aad
        )
        assert decrypted == plaintext


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
