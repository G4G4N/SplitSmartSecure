"""
Client-side cryptographic operations for SplitSmart.
Handles key management, key exchange, and message encryption/decryption.
"""

import os
from typing import Optional, Tuple, Dict
from datetime import datetime

from cryptography.hazmat.primitives.asymmetric import rsa, dh

from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
from shared.protocols import create_dh_data_for_signing
from shared.constants import KEYS_DIR


class ClientCrypto:
    """Client-side cryptographic operations."""
    
    def __init__(self, user_id: str):
        """
        Initialize client crypto.
        
        Args:
            user_id: User identifier
        """
        self.user_id = user_id
        self.private_key = None
        self.public_key = None
        self.session_key = None
        self.session_id = None
        self.counter = 0
        
        self._ensure_keys_dir()
    
    def _ensure_keys_dir(self):
        """Ensure keys directory exists."""
        os.makedirs(KEYS_DIR, exist_ok=True)
    
    def generate_keys(self) -> str:
        """
        Generate new RSA key pair for user.
        
        Returns:
            Public key in PEM format
        """
        self.private_key, self.public_key = CryptoPrimitives.generate_rsa_keypair()
        
        # Save keys
        private_key_path = os.path.join(KEYS_DIR, f"{self.user_id}_private.pem")
        public_key_path = os.path.join(KEYS_DIR, f"{self.user_id}_public.pem")
        
        with open(private_key_path, 'wb') as f:
            f.write(CryptoPrimitives.serialize_private_key(self.private_key))
        with open(public_key_path, 'wb') as f:
            f.write(CryptoPrimitives.serialize_public_key(self.public_key))
        
        print(f"[Client] Generated keys for {self.user_id}")
        
        return CryptoPrimitives.serialize_public_key(self.public_key).decode('utf-8')
    
    def load_keys(self) -> bool:
        """
        Load existing keys for user.
        
        Returns:
            True if keys loaded successfully
        """
        private_key_path = os.path.join(KEYS_DIR, f"{self.user_id}_private.pem")
        public_key_path = os.path.join(KEYS_DIR, f"{self.user_id}_public.pem")
        
        if not os.path.exists(private_key_path) or not os.path.exists(public_key_path):
            return False
        
        with open(private_key_path, 'rb') as f:
            self.private_key = CryptoPrimitives.load_private_key(f.read())
        with open(public_key_path, 'rb') as f:
            self.public_key = CryptoPrimitives.load_public_key(f.read())
        
        print(f"[Client] Loaded keys for {self.user_id}")
        return True
    
    def get_public_key_pem(self) -> str:
        """
        Get public key in PEM format.
        
        Returns:
            PEM-encoded public key
        """
        return CryptoPrimitives.serialize_public_key(self.public_key).decode('utf-8')
    
    def initiate_key_exchange(self, dh_parameters: dh.DHParameters) -> Dict[str, str]:
        """
        Initiate key exchange with server.
        
        Args:
            dh_parameters: DH parameters from server
            
        Returns:
            Dictionary with client hello data
        """
        # Generate ephemeral DH key pair
        dh_private_key, dh_public_key = CryptoPrimitives.generate_dh_keypair(dh_parameters)
        
        # Serialize DH public key
        dh_public_key_bytes = CryptoPrimitives.serialize_dh_public_key(dh_public_key)
        
        # Sign DH public key
        data_to_sign = create_dh_data_for_signing(dh_public_key_bytes, self.user_id)
        signature = CryptoPrimitives.sign_data(self.private_key, data_to_sign)
        
        # Store for later use
        self._dh_private_key = dh_private_key
        
        return {
            "user_id": self.user_id,
            "dh_public_key": MessageEncoder.b64encode(dh_public_key_bytes),
            "signature": MessageEncoder.b64encode(signature)
        }
    
    def complete_key_exchange(self, server_dh_public_key_b64: str, 
                             server_signature_b64: str, 
                             server_public_key: rsa.RSAPublicKey,
                             session_id: str) -> bool:
        """
        Complete key exchange with server.
        
        Args:
            server_dh_public_key_b64: Server's DH public key (base64)
            server_signature_b64: Server's signature (base64)
            server_public_key: Server's long-term public key
            session_id: Session identifier
            
        Returns:
            True if successful
        """
        # Decode server's DH public key
        server_dh_public_key_bytes = MessageEncoder.b64decode(server_dh_public_key_b64)
        server_dh_public_key = CryptoPrimitives.deserialize_dh_public_key(server_dh_public_key_bytes)
        
        # Verify server's signature
        data_to_verify = create_dh_data_for_signing(server_dh_public_key_bytes, "server")
        server_signature = MessageEncoder.b64decode(server_signature_b64)
        
        if not CryptoPrimitives.verify_signature(server_public_key, data_to_verify, server_signature):
            print("[Client] Failed to verify server signature")
            return False
        
        print("[Client] Server signature verified")
        
        # Compute shared secret
        shared_secret = CryptoPrimitives.compute_dh_shared_secret(self._dh_private_key, server_dh_public_key)
        
        # Derive session key
        self.session_key = CryptoPrimitives.derive_session_key(shared_secret)
        self.session_id = session_id
        
        print(f"[Client] Session established: {session_id}")
        
        return True
    
    def encrypt_message(self, plaintext: bytes, algorithm: Optional[str] = None) -> Dict[str, str]:
        """
        Encrypt message with session key using selected algorithm.
        
        Args:
            plaintext: Message to encrypt
            algorithm: Encryption algorithm (auto-select if None)
            
        Returns:
            Dictionary with algorithm, nonce, and ciphertext (base64)
        """
        if not self.session_key:
            raise ValueError("No active session")
        
        # Use new encryption method with algorithm selection
        algo, nonce_iv, ciphertext = CryptoPrimitives.encrypt_message(
            self.session_key, plaintext, algorithm
        )
        
        return {
            "algorithm": algo,
            "nonce": MessageEncoder.b64encode(nonce_iv),
            "ciphertext": MessageEncoder.b64encode(ciphertext)
        }
    
    def decrypt_message(self, nonce_b64: str, ciphertext_b64: str, algorithm: Optional[str] = None) -> Optional[bytes]:
        """
        Decrypt message with session key.
        
        Args:
            nonce_b64: Nonce/IV (base64)
            ciphertext_b64: Ciphertext with tag (base64)
            algorithm: Encryption algorithm (defaults to AES-256-GCM for backward compatibility)
            
        Returns:
            Plaintext bytes or None if decryption fails
        """
        if not self.session_key:
            raise ValueError("No active session")
        
        nonce_iv = MessageEncoder.b64decode(nonce_b64)
        ciphertext = MessageEncoder.b64decode(ciphertext_b64)
        
        # Default to AES-GCM for backward compatibility
        if algorithm is None:
            algorithm = "AES-256-GCM"
        
        plaintext = CryptoPrimitives.decrypt_message(
            self.session_key, algorithm, nonce_iv, ciphertext
        )
        return plaintext
    
    def sign_expense(self, payer: str, amount: float, description: str, timestamp: str) -> Tuple[str, int]:
        """
        Sign expense data.
        
        Args:
            payer: User ID of payer
            amount: Amount paid
            description: Expense description
            timestamp: ISO timestamp
            
        Returns:
            Tuple of (signature_base64, counter)
        """
        # Increment counter
        self.counter += 1
        
        # Create data to sign
        from shared.protocols import create_expense_data_for_signing
        data = create_expense_data_for_signing(payer, amount, description, self.counter, timestamp)
        
        # Sign
        signature = CryptoPrimitives.sign_data(self.private_key, data)
        
        return MessageEncoder.b64encode(signature), self.counter
    
    def get_next_counter(self) -> int:
        """
        Get next counter value (without incrementing).
        
        Returns:
            Next counter value
        """
        return self.counter + 1
    
    def increment_counter(self) -> int:
        """
        Increment and return counter.
        
        Returns:
            New counter value
        """
        self.counter += 1
        return self.counter
    
    def has_session(self) -> bool:
        """Check if client has an active session."""
        return self.session_key is not None and self.session_id is not None
