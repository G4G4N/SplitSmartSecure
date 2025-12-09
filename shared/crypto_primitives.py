"""
Core cryptographic primitives for SplitSmart application.
Implements key generation, encryption, signatures, and hashing.
"""

import os
import json
import base64
from typing import Tuple, Optional
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization, hmac
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .constants import (
    RSA_KEY_SIZE, AES_KEY_SIZE, DH_KEY_SIZE,
    GCM_NONCE_SIZE, KDF_INFO, HASH_ALGORITHM,
    ENCRYPTION_AES_GCM, ENCRYPTION_CHACHA20_POLY1305, ENCRYPTION_AES_CBC_HMAC,
    CHACHA20_NONCE_SIZE, AES_CBC_IV_SIZE, HMAC_SIZE,
    SMALL_MESSAGE_THRESHOLD, LARGE_MESSAGE_THRESHOLD
)


class CryptoPrimitives:
    """Core cryptographic operations."""
    
    @staticmethod
    def generate_rsa_keypair() -> Tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
        """
        Generate RSA key pair for signatures.
        
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def serialize_private_key(private_key: rsa.RSAPrivateKey, password: Optional[bytes] = None) -> bytes:
        """
        Serialize private key to PEM format.
        
        Args:
            private_key: RSA private key
            password: Optional password for encryption
            
        Returns:
            PEM-encoded private key
        """
        encryption = serialization.NoEncryption()
        if password:
            encryption = serialization.BestAvailableEncryption(password)
            
        return private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )
    
    @staticmethod
    def serialize_public_key(public_key: rsa.RSAPublicKey) -> bytes:
        """
        Serialize public key to PEM format.
        
        Args:
            public_key: RSA public key
            
        Returns:
            PEM-encoded public key
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def load_private_key(pem_data: bytes, password: Optional[bytes] = None) -> rsa.RSAPrivateKey:
        """
        Load private key from PEM format.
        
        Args:
            pem_data: PEM-encoded private key
            password: Optional password for decryption
            
        Returns:
            RSA private key
        """
        return serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )
    
    @staticmethod
    def load_public_key(pem_data: bytes) -> rsa.RSAPublicKey:
        """
        Load public key from PEM format.
        
        Args:
            pem_data: PEM-encoded public key
            
        Returns:
            RSA public key
        """
        return serialization.load_pem_public_key(
            pem_data,
            backend=default_backend()
        )
    
    @staticmethod
    def sign_data(private_key: rsa.RSAPrivateKey, data: bytes) -> bytes:
        """
        Sign data using RSA-PSS.
        
        Args:
            private_key: RSA private key
            data: Data to sign
            
        Returns:
            Signature bytes
        """
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature
    
    @staticmethod
    def verify_signature(public_key: rsa.RSAPublicKey, data: bytes, signature: bytes) -> bool:
        """
        Verify RSA-PSS signature.
        
        Args:
            public_key: RSA public key
            data: Original data
            signature: Signature to verify
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False
    
    @staticmethod
    def generate_dh_parameters() -> dh.DHParameters:
        """
        Generate Diffie-Hellman parameters.
        Note: In production, use pre-generated parameters for efficiency.
        
        Returns:
            DH parameters
        """
        # For demonstration, we'll use a standard 2048-bit group
        # In production, use RFC 3526 Group 14 or similar
        parameters = dh.generate_parameters(
            generator=2,
            key_size=DH_KEY_SIZE,
            backend=default_backend()
        )
        return parameters
    
    @staticmethod
    def generate_dh_keypair(parameters: dh.DHParameters) -> Tuple[dh.DHPrivateKey, dh.DHPublicKey]:
        """
        Generate DH key pair from parameters.
        
        Args:
            parameters: DH parameters
            
        Returns:
            Tuple of (private_key, public_key)
        """
        private_key = parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def compute_dh_shared_secret(private_key: dh.DHPrivateKey, peer_public_key: dh.DHPublicKey) -> bytes:
        """
        Compute DH shared secret.
        
        Args:
            private_key: Own DH private key
            peer_public_key: Peer's DH public key
            
        Returns:
            Shared secret bytes
        """
        shared_secret = private_key.exchange(peer_public_key)
        return shared_secret
    
    @staticmethod
    def derive_session_key(shared_secret: bytes, salt: Optional[bytes] = None) -> bytes:
        """
        Derive session key from shared secret using HKDF.
        
        Args:
            shared_secret: DH shared secret
            salt: Optional salt (uses empty bytes if not provided for deterministic derivation)
            
        Returns:
            256-bit session key for AES-GCM
        """
        if salt is None:
            # Use empty salt for deterministic key derivation
            # Both client and server will derive the same key from the same shared secret
            salt = b''
            
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256 bits for AES-256
            salt=salt,
            info=KDF_INFO,
            backend=default_backend()
        )
        session_key = hkdf.derive(shared_secret)
        return session_key
    
    @staticmethod
    def aes_gcm_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using AES-256-GCM.
        
        Args:
            key: 256-bit encryption key
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Tuple of (nonce, ciphertext_with_tag)
        """
        aesgcm = AESGCM(key)
        nonce = os.urandom(GCM_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    @staticmethod
    def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt data using AES-256-GCM.
        
        Args:
            key: 256-bit encryption key
            nonce: Nonce used for encryption
            ciphertext: Ciphertext with authentication tag
            associated_data: Optional additional authenticated data
            
        Returns:
            Plaintext if successful, None if authentication fails
        """
        try:
            aesgcm = AESGCM(key)
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception:
            return None
    
    @staticmethod
    def chacha20_poly1305_encrypt(key: bytes, plaintext: bytes, associated_data: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Encrypt data using ChaCha20-Poly1305.
        Better performance for smaller messages, especially on non-AES hardware.
        
        Args:
            key: 256-bit encryption key
            plaintext: Data to encrypt
            associated_data: Optional additional authenticated data
            
        Returns:
            Tuple of (nonce, ciphertext_with_tag)
        """
        chacha = ChaCha20Poly1305(key)
        nonce = os.urandom(CHACHA20_NONCE_SIZE)
        ciphertext = chacha.encrypt(nonce, plaintext, associated_data)
        return nonce, ciphertext
    
    @staticmethod
    def chacha20_poly1305_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt data using ChaCha20-Poly1305.
        
        Args:
            key: 256-bit encryption key
            nonce: Nonce used for encryption
            ciphertext: Ciphertext with authentication tag
            associated_data: Optional additional authenticated data
            
        Returns:
            Plaintext if successful, None if authentication fails
        """
        try:
            chacha = ChaCha20Poly1305(key)
            plaintext = chacha.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception:
            return None
    
    @staticmethod
    def aes_cbc_hmac_encrypt(key: bytes, plaintext: bytes) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-CBC with HMAC-SHA256.
        Provides authenticated encryption using Encrypt-then-MAC.
        
        Args:
            key: 256-bit encryption key (split into encryption and MAC keys)
            plaintext: Data to encrypt
            
        Returns:
            Tuple of (iv, ciphertext, hmac_tag)
        """
        # Split key: first 32 bytes for encryption, last 32 bytes for MAC
        if len(key) < 64:
            # Derive two keys from one key using HKDF
            enc_key = CryptoPrimitives.derive_key(key, b"encryption", 32)
            mac_key = CryptoPrimitives.derive_key(key, b"mac", 32)
        else:
            enc_key = key[:32]
            mac_key = key[32:64]
        
        # Generate IV
        iv = os.urandom(AES_CBC_IV_SIZE)
        
        # Encrypt
        cipher = Cipher(
            algorithms.AES(enc_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # PKCS7 padding
        pad_length = AES_CBC_BLOCK_SIZE - (len(plaintext) % AES_CBC_BLOCK_SIZE)
        padded_plaintext = plaintext + bytes([pad_length] * pad_length)
        
        ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()
        
        # Compute HMAC over IV || ciphertext (Encrypt-then-MAC)
        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
        h.update(iv + ciphertext)
        hmac_tag = h.finalize()
        
        return iv, ciphertext, hmac_tag
    
    @staticmethod
    def aes_cbc_hmac_decrypt(key: bytes, iv: bytes, ciphertext: bytes, hmac_tag: bytes) -> Optional[bytes]:
        """
        Decrypt data using AES-256-CBC with HMAC-SHA256.
        
        Args:
            key: 256-bit encryption key
            iv: Initialization vector
            ciphertext: Encrypted data
            hmac_tag: HMAC authentication tag
            
        Returns:
            Plaintext if successful, None if authentication fails
        """
        try:
            # Split key
            if len(key) < 64:
                enc_key = CryptoPrimitives.derive_key(key, b"encryption", 32)
                mac_key = CryptoPrimitives.derive_key(key, b"mac", 32)
            else:
                enc_key = key[:32]
                mac_key = key[32:64]
            
            # Verify HMAC first (MAC-then-Decrypt)
            h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
            h.update(iv + ciphertext)
            h.verify(hmac_tag)
            
            # Decrypt
            cipher = Cipher(
                algorithms.AES(enc_key),
                modes.CBC(iv),
                backend=default_backend()
            )
            decryptor = cipher.decryptor()
            padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            # Remove PKCS7 padding
            pad_length = padded_plaintext[-1]
            plaintext = padded_plaintext[:-pad_length]
            
            return plaintext
        except Exception:
            return None
    
    @staticmethod
    def derive_key(key: bytes, info: bytes, length: int) -> bytes:
        """
        Derive a key using HKDF.
        
        Args:
            key: Input key material
            info: Application-specific info
            length: Desired key length in bytes
            
        Returns:
            Derived key
        """
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=length,
            salt=None,
            info=info,
            backend=default_backend()
        )
        return hkdf.derive(key)
    
    @staticmethod
    def select_encryption_algorithm(plaintext_size: int, preferred: Optional[str] = None) -> str:
        """
        Select appropriate encryption algorithm based on message size and preferences.
        
        Args:
            plaintext_size: Size of plaintext in bytes
            preferred: Preferred algorithm (if None, auto-select)
            
        Returns:
            Algorithm identifier string
        """
        if preferred:
            if preferred in [ENCRYPTION_AES_GCM, ENCRYPTION_CHACHA20_POLY1305, ENCRYPTION_AES_CBC_HMAC]:
                return preferred
        
        # Auto-select based on message size
        if plaintext_size < SMALL_MESSAGE_THRESHOLD:
            # ChaCha20-Poly1305 is faster for small messages
            return ENCRYPTION_CHACHA20_POLY1305
        elif plaintext_size > LARGE_MESSAGE_THRESHOLD:
            # AES-GCM is better for large messages (hardware acceleration)
            return ENCRYPTION_AES_GCM
        else:
            # Default to AES-GCM for medium messages
            return ENCRYPTION_AES_GCM
    
    @staticmethod
    def encrypt_message(key: bytes, plaintext: bytes, algorithm: Optional[str] = None, associated_data: Optional[bytes] = None) -> Tuple[str, bytes, bytes]:
        """
        Encrypt message using selected algorithm.
        
        Args:
            key: Encryption key
            plaintext: Data to encrypt
            algorithm: Algorithm to use (auto-select if None)
            associated_data: Optional associated data
            
        Returns:
            Tuple of (algorithm, nonce/iv, ciphertext_with_tag)
        """
        if algorithm is None:
            algorithm = CryptoPrimitives.select_encryption_algorithm(len(plaintext))
        
        if algorithm == ENCRYPTION_CHACHA20_POLY1305:
            nonce, ciphertext = CryptoPrimitives.chacha20_poly1305_encrypt(key, plaintext, associated_data)
            return (algorithm, nonce, ciphertext)
        elif algorithm == ENCRYPTION_AES_CBC_HMAC:
            iv, ciphertext, hmac_tag = CryptoPrimitives.aes_cbc_hmac_encrypt(key, plaintext)
            # Combine ciphertext and tag
            combined = ciphertext + hmac_tag
            return (algorithm, iv, combined)
        else:  # Default to AES-GCM
            nonce, ciphertext = CryptoPrimitives.aes_gcm_encrypt(key, plaintext, associated_data)
            return (ENCRYPTION_AES_GCM, nonce, ciphertext)
    
    @staticmethod
    def decrypt_message(key: bytes, algorithm: str, nonce_iv: bytes, ciphertext: bytes, associated_data: Optional[bytes] = None) -> Optional[bytes]:
        """
        Decrypt message using specified algorithm.
        
        Args:
            key: Encryption key
            algorithm: Algorithm identifier
            nonce_iv: Nonce or IV
            ciphertext: Encrypted data (may include tag)
            associated_data: Optional associated data
            
        Returns:
            Plaintext if successful, None if authentication fails
        """
        if algorithm == ENCRYPTION_CHACHA20_POLY1305:
            return CryptoPrimitives.chacha20_poly1305_decrypt(key, nonce_iv, ciphertext, associated_data)
        elif algorithm == ENCRYPTION_AES_CBC_HMAC:
            # Split ciphertext and HMAC tag
            if len(ciphertext) < HMAC_SIZE:
                return None
            ciphertext_only = ciphertext[:-HMAC_SIZE]
            hmac_tag = ciphertext[-HMAC_SIZE:]
            return CryptoPrimitives.aes_cbc_hmac_decrypt(key, nonce_iv, ciphertext_only, hmac_tag)
        else:  # AES-GCM
            return CryptoPrimitives.aes_gcm_decrypt(key, nonce_iv, ciphertext, associated_data)
    
    @staticmethod
    def hash_data(data: bytes) -> bytes:
        """
        Compute SHA-256 hash of data.
        
        Args:
            data: Data to hash
            
        Returns:
            32-byte hash
        """
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data)
        return digest.finalize()
    
    @staticmethod
    def hash_chain_link(prev_hash: bytes, data: bytes) -> bytes:
        """
        Compute hash chain link: H(prev_hash || data).
        
        Args:
            prev_hash: Previous hash in chain
            data: Current data
            
        Returns:
            New hash
        """
        combined = prev_hash + data
        return CryptoPrimitives.hash_data(combined)
    
    @staticmethod
    def serialize_dh_public_key(public_key: dh.DHPublicKey) -> bytes:
        """
        Serialize DH public key.
        
        Args:
            public_key: DH public key
            
        Returns:
            Serialized key bytes
        """
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    @staticmethod
    def deserialize_dh_public_key(key_bytes: bytes) -> dh.DHPublicKey:
        """
        Deserialize DH public key.
        
        Args:
            key_bytes: Serialized key bytes
            
        Returns:
            DH public key
        """
        return serialization.load_pem_public_key(
            key_bytes,
            backend=default_backend()
        )
    
    @staticmethod
    def serialize_dh_parameters(parameters: dh.DHParameters) -> bytes:
        """
        Serialize DH parameters.
        
        Args:
            parameters: DH parameters
            
        Returns:
            Serialized parameters
        """
        return parameters.parameter_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.ParameterFormat.PKCS3
        )
    
    @staticmethod
    def deserialize_dh_parameters(param_bytes: bytes) -> dh.DHParameters:
        """
        Deserialize DH parameters.
        
        Args:
            param_bytes: Serialized parameters
            
        Returns:
            DH parameters
        """
        return serialization.load_pem_parameters(
            param_bytes,
            backend=default_backend()
        )


class MessageEncoder:
    """Utility for encoding/decoding messages."""
    
    @staticmethod
    def encode_message(msg_dict: dict) -> bytes:
        """
        Encode message dictionary to bytes.
        
        Args:
            msg_dict: Message as dictionary
            
        Returns:
            JSON-encoded bytes
        """
        return json.dumps(msg_dict).encode('utf-8')
    
    @staticmethod
    def decode_message(msg_bytes: bytes) -> dict:
        """
        Decode message bytes to dictionary.
        
        Args:
            msg_bytes: JSON-encoded bytes
            
        Returns:
            Message dictionary
        """
        return json.loads(msg_bytes.decode('utf-8'))
    
    @staticmethod
    def b64encode(data: bytes) -> str:
        """Base64 encode bytes to string."""
        return base64.b64encode(data).decode('utf-8')
    
    @staticmethod
    def b64decode(data: str) -> bytes:
        """Base64 decode string to bytes."""
        return base64.b64decode(data.encode('utf-8'))
