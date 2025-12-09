"""
Server-side cryptographic operations for SplitSmart.
Handles key exchange, message encryption/decryption, and signature verification.
"""

import os
import uuid
from typing import Optional, Dict, Tuple
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa, dh

from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
from shared.protocols import create_dh_data_for_signing
from shared.constants import SESSION_TIMEOUT, KEYS_DIR


class ServerCrypto:
    """Server-side cryptographic operations."""
    
    def __init__(self, server_id: str = "server"):
        """
        Initialize server crypto.
        
        Args:
            server_id: Server identifier
        """
        self.server_id = server_id
        self.private_key = None
        self.public_key = None
        self.dh_parameters = None
        self.sessions = {}  # session_id -> session_data
        
        self._ensure_keys_dir()
        self._load_or_generate_keys()
        self._generate_dh_parameters()
    
    def _ensure_keys_dir(self):
        """Ensure keys directory exists."""
        os.makedirs(KEYS_DIR, exist_ok=True)
    
    def _load_or_generate_keys(self):
        """Load existing keys or generate new ones."""
        private_key_path = os.path.join(KEYS_DIR, f"{self.server_id}_private.pem")
        public_key_path = os.path.join(KEYS_DIR, f"{self.server_id}_public.pem")
        
        if os.path.exists(private_key_path) and os.path.exists(public_key_path):
            # Load existing keys
            with open(private_key_path, 'rb') as f:
                self.private_key = CryptoPrimitives.load_private_key(f.read())
            with open(public_key_path, 'rb') as f:
                self.public_key = CryptoPrimitives.load_public_key(f.read())
            print(f"[Server] Loaded existing keys for {self.server_id}")
        else:
            # Generate new keys
            self.private_key, self.public_key = CryptoPrimitives.generate_rsa_keypair()
            
            # Save keys
            with open(private_key_path, 'wb') as f:
                f.write(CryptoPrimitives.serialize_private_key(self.private_key))
            with open(public_key_path, 'wb') as f:
                f.write(CryptoPrimitives.serialize_public_key(self.public_key))
            print(f"[Server] Generated new keys for {self.server_id}")
    
    def _generate_dh_parameters(self):
        """Generate or load DH parameters."""
        params_path = os.path.join(KEYS_DIR, "dh_parameters.pem")
        
        if os.path.exists(params_path):
            # Load existing parameters
            with open(params_path, 'rb') as f:
                self.dh_parameters = CryptoPrimitives.deserialize_dh_parameters(f.read())
            print("[Server] Loaded existing DH parameters")
        else:
            # Generate new parameters (this can take a while)
            print("[Server] Generating DH parameters (this may take a moment)...")
            self.dh_parameters = CryptoPrimitives.generate_dh_parameters()
            
            # Save parameters
            with open(params_path, 'wb') as f:
                f.write(CryptoPrimitives.serialize_dh_parameters(self.dh_parameters))
            print("[Server] Generated and saved DH parameters")
    
    def handle_client_hello(self, user_id: str, client_dh_public_key_b64: str, 
                           client_signature_b64: str, user_public_key: rsa.RSAPublicKey) -> Optional[Dict]:
        """
        Handle client hello message and perform key exchange.
        
        Args:
            user_id: Client's user ID
            client_dh_public_key_b64: Client's DH public key (base64)
            client_signature_b64: Client's signature (base64)
            user_public_key: Client's long-term public key
            
        Returns:
            Dictionary with server hello data or None if verification fails
        """
        # Decode client's DH public key
        client_dh_public_key_bytes = MessageEncoder.b64decode(client_dh_public_key_b64)
        client_dh_public_key = CryptoPrimitives.deserialize_dh_public_key(client_dh_public_key_bytes)
        
        # Verify client's signature
        data_to_verify = create_dh_data_for_signing(client_dh_public_key_bytes, user_id)
        client_signature = MessageEncoder.b64decode(client_signature_b64)
        
        if not CryptoPrimitives.verify_signature(user_public_key, data_to_verify, client_signature):
            print(f"[Server] Failed to verify client signature for {user_id}")
            return None
        
        print(f"[Server] Client signature verified for {user_id}")
        
        # Generate server's ephemeral DH key pair
        server_dh_private_key, server_dh_public_key = CryptoPrimitives.generate_dh_keypair(self.dh_parameters)
        
        # Sign server's DH public key
        server_dh_public_key_bytes = CryptoPrimitives.serialize_dh_public_key(server_dh_public_key)
        data_to_sign = create_dh_data_for_signing(server_dh_public_key_bytes, self.server_id)
        server_signature = CryptoPrimitives.sign_data(self.private_key, data_to_sign)
        
        # Compute shared secret
        shared_secret = CryptoPrimitives.compute_dh_shared_secret(server_dh_private_key, client_dh_public_key)
        
        # Derive session key
        session_key = CryptoPrimitives.derive_session_key(shared_secret)
        
        # Create session
        session_id = str(uuid.uuid4())
        session_data = {
            "session_id": session_id,
            "user_id": user_id,
            "session_key": session_key,
            "created_at": datetime.utcnow(),
            "expires_at": datetime.utcnow() + timedelta(seconds=SESSION_TIMEOUT)
        }
        self.sessions[session_id] = session_data
        
        print(f"[Server] Created session {session_id} for {user_id}")
        
        # Return server hello data
        return {
            "session_id": session_id,
            "dh_public_key": MessageEncoder.b64encode(server_dh_public_key_bytes),
            "dh_parameters": MessageEncoder.b64encode(CryptoPrimitives.serialize_dh_parameters(self.dh_parameters)),
            "signature": MessageEncoder.b64encode(server_signature)
        }
    
    def get_session(self, session_id: str) -> Optional[Dict]:
        """
        Get session data.
        
        Args:
            session_id: Session identifier
            
        Returns:
            Session data or None if not found/expired
        """
        session = self.sessions.get(session_id)
        if not session:
            return None
        
        # Check expiration
        if datetime.utcnow() > session["expires_at"]:
            del self.sessions[session_id]
            return None
        
        return session
    
    def encrypt_message(self, session_id: str, plaintext: bytes, algorithm: Optional[str] = None) -> Optional[Dict]:
        """
        Encrypt message for a session using selected algorithm.
        
        Args:
            session_id: Session identifier
            plaintext: Message to encrypt
            algorithm: Encryption algorithm (auto-select if None)
            
        Returns:
            Dictionary with algorithm, nonce, and ciphertext (base64) or None
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        algo, nonce_iv, ciphertext = CryptoPrimitives.encrypt_message(
            session["session_key"], plaintext, algorithm
        )
        
        return {
            "algorithm": algo,
            "nonce": MessageEncoder.b64encode(nonce_iv),
            "ciphertext": MessageEncoder.b64encode(ciphertext)
        }
    
    def decrypt_message(self, session_id: str, nonce_b64: str, ciphertext_b64: str, algorithm: Optional[str] = None) -> Optional[bytes]:
        """
        Decrypt message from a session.
        
        Args:
            session_id: Session identifier
            nonce_b64: Nonce (base64)
            ciphertext_b64: Ciphertext with tag (base64)
            
        Returns:
            Plaintext bytes or None if decryption fails
        """
        session = self.get_session(session_id)
        if not session:
            return None
        
        nonce_iv = MessageEncoder.b64decode(nonce_b64)
        ciphertext = MessageEncoder.b64decode(ciphertext_b64)
        
        # Default to AES-GCM for backward compatibility
        if algorithm is None:
            algorithm = "AES-256-GCM"
        
        plaintext = CryptoPrimitives.decrypt_message(
            session["session_key"], algorithm, nonce_iv, ciphertext
        )
        return plaintext
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions."""
        now = datetime.utcnow()
        expired = [sid for sid, session in self.sessions.items() if now > session["expires_at"]]
        for sid in expired:
            del self.sessions[sid]
        if expired:
            print(f"[Server] Cleaned up {len(expired)} expired sessions")
    
    def get_public_key_pem(self) -> str:
        """
        Get server's public key in PEM format.
        
        Returns:
            PEM-encoded public key as string
        """
        return CryptoPrimitives.serialize_public_key(self.public_key).decode('utf-8')
