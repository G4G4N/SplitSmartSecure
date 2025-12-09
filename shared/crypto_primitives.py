"""
Core cryptographic primitives for SplitSmart application.
Implements key generation, encryption, signatures, and hashing.
"""

import os
import json
import base64
from typing import Tuple, Optional
from datetime import datetime

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

from .constants import (
    RSA_KEY_SIZE, AES_KEY_SIZE, DH_KEY_SIZE,
    GCM_NONCE_SIZE, KDF_INFO, HASH_ALGORITHM
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
