"""
Main SplitSmart server application.
Handles client connections, message processing, and ledger management.
"""

import json
from typing import Optional, Dict, Any

from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
from shared.protocols import (
    ProtocolMessage, EncryptedMessage,
    ClientHelloMessage, ServerHelloMessage,
    ExpenseSubmitMessage, ExpenseResponseMessage,
    LedgerRequestMessage, LedgerResponseMessage,
    BalanceRequestMessage, BalanceResponseMessage,
    ErrorMessage, create_expense_data_for_signing,
    create_receipt_data_for_signing
)
from datetime import datetime
from shared.constants import (
    MSG_TYPE_CLIENT_HELLO, MSG_TYPE_EXPENSE_SUBMIT,
    MSG_TYPE_LEDGER_REQUEST, MSG_TYPE_BALANCE_REQUEST,
    ERROR_INVALID_SIGNATURE, ERROR_REPLAY_DETECTED,
    ERROR_INVALID_COUNTER, ERROR_DECRYPTION_FAILED,
    ERROR_USER_NOT_FOUND, ERROR_INVALID_MESSAGE
)

from .storage import Storage
from .ledger import Ledger
from .crypto_server import ServerCrypto


class SplitSmartServer:
    """Main server application."""
    
    def __init__(self):
        """Initialize server."""
        self.storage = Storage()
        self.ledger = Ledger(self.storage)
        self.crypto = ServerCrypto()
        
        print("[Server] SplitSmart server initialized")
        print(f"[Server] Genesis hash: {self.ledger.genesis_hash}")
        
        # Verify ledger integrity on startup
        self._verify_ledger_on_startup()
    
    def _verify_ledger_on_startup(self):
        """Verify ledger integrity on server startup."""
        print("[Server] Verifying ledger integrity...")
        is_valid, error = self.ledger.verify_chain_integrity()
        
        if is_valid:
            entries = self.ledger.get_all_entries()
            print(f"[Server] ✓ Ledger integrity verified ({len(entries)} entries)")
        else:
            print(f"[Server] ✗ LEDGER INTEGRITY VIOLATION: {error}")
            print("[Server] WARNING: Ledger has been tampered with!")
    
    def register_user(self, user_id: str, public_key_pem: str, password_hash: Optional[str] = None) -> bool:
        """
        Register a new user.
        
        Args:
            user_id: User identifier
            public_key_pem: User's public key (PEM format)
            password_hash: Hashed password (optional, for password-based auth)
            
        Returns:
            True if successful
        """
        success = self.storage.register_user(user_id, public_key_pem, password_hash)
        if success:
            print(f"[Server] Registered user: {user_id}")
        else:
            print(f"[Server] User already exists: {user_id}")
        return success
    
    def verify_user_password(self, user_id: str, password: str) -> bool:
        """
        Verify user password.
        
        Args:
            user_id: User identifier
            password: Plain text password
            
        Returns:
            True if password is correct
        """
        return self.storage.verify_user_password(user_id, password)
    
    def handle_client_hello(self, message: ProtocolMessage) -> ProtocolMessage:
        """
        Handle CLIENT_HELLO message.
        
        Args:
            message: Client hello message
            
        Returns:
            Server hello or error message
        """
        payload = message.payload
        user_id = payload.get("user_id")
        dh_public_key = payload.get("dh_public_key")
        signature = payload.get("signature")
        
        # Get user's public key
        user_public_key_pem = self.storage.get_user_public_key(user_id)
        if not user_public_key_pem:
            return ErrorMessage(ERROR_USER_NOT_FOUND, f"User {user_id} not found")
        
        # Load user's public key
        user_public_key = CryptoPrimitives.load_public_key(user_public_key_pem.encode('utf-8'))
        
        # Perform key exchange
        server_hello_data = self.crypto.handle_client_hello(
            user_id, dh_public_key, signature, user_public_key
        )
        
        if not server_hello_data:
            return ErrorMessage(ERROR_INVALID_SIGNATURE, "Failed to verify client signature")
        
        # Create server hello message
        return ServerHelloMessage(
            dh_public_key=server_hello_data["dh_public_key"],
            dh_parameters=server_hello_data["dh_parameters"],
            signature=server_hello_data["signature"],
            session_id=server_hello_data["session_id"]
        )
    
    def handle_expense_submit(self, session_id: str, message: ProtocolMessage) -> ProtocolMessage:
        """
        Handle EXPENSE_SUBMIT message.
        
        Args:
            session_id: Session identifier
            message: Expense submit message
            
        Returns:
            Expense response or error message
        """
        payload = message.payload
        payer = payload.get("payer")
        amount = payload.get("amount")
        description = payload.get("description")
        counter = payload.get("counter")
        signature_b64 = payload.get("signature")
        timestamp = payload.get("timestamp")
        
        # Get session
        session = self.crypto.get_session(session_id)
        if not session:
            return ErrorMessage(ERROR_INVALID_MESSAGE, "Invalid or expired session")
        
        user_id = session["user_id"]
        
        # Get user's public key
        user_public_key_pem = self.storage.get_user_public_key(user_id)
        user_public_key = CryptoPrimitives.load_public_key(user_public_key_pem.encode('utf-8'))
        
        # Verify counter (replay protection)
        stored_counter = self.storage.get_user_counter(user_id)
        if counter <= stored_counter:
            return ErrorMessage(ERROR_REPLAY_DETECTED, f"Invalid counter: {counter} <= {stored_counter}")
        
        # Verify signature (use timestamp from payload, not message wrapper)
        expense_data = create_expense_data_for_signing(payer, amount, description, counter, timestamp)
        signature = MessageEncoder.b64decode(signature_b64)
        
        if not CryptoPrimitives.verify_signature(user_public_key, expense_data, signature):
            return ErrorMessage(ERROR_INVALID_SIGNATURE, "Invalid expense signature")
        
        # Add to ledger (use timestamp from payload)
        entry_result = self.ledger.add_entry(
            user_id=user_id,
            payer=payer,
            amount=amount,
            description=description,
            timestamp=timestamp,
            counter=counter,
            signature=signature_b64
        )
        
        if not entry_result:
            return ErrorMessage(ERROR_INVALID_MESSAGE, "Failed to add entry to ledger")
        
        # Update user's counter
        self.storage.update_user_counter(user_id, counter)
        
        print(f"[Server] Added expense entry {entry_result['id']} from {user_id}")
        
        # Generate cryptographic receipt (server signs the entry)
        receipt_timestamp = datetime.utcnow().isoformat()
        receipt_data = create_receipt_data_for_signing(
            entry_result['id'],
            entry_result['entry_hash'],
            user_id,
            receipt_timestamp
        )
        receipt_signature = CryptoPrimitives.sign_data(self.crypto.private_key, receipt_data)
        receipt_b64 = MessageEncoder.b64encode(receipt_signature)
        
        return ExpenseResponseMessage(
            success=True,
            message="Expense recorded successfully",
            entry_id=entry_result["id"],
            entry_hash=entry_result["entry_hash"],
            receipt=receipt_b64,
            receipt_timestamp=receipt_timestamp
        )
    
    def handle_ledger_request(self, session_id: str, message: ProtocolMessage) -> ProtocolMessage:
        """
        Handle LEDGER_REQUEST message.
        
        Args:
            session_id: Session identifier
            message: Ledger request message
            
        Returns:
            Ledger response or error message
        """
        payload = message.payload
        counter = payload.get("counter")
        
        # Get session
        session = self.crypto.get_session(session_id)
        if not session:
            return ErrorMessage(ERROR_INVALID_MESSAGE, "Invalid or expired session")
        
        user_id = session["user_id"]
        
        # Verify counter
        stored_counter = self.storage.get_user_counter(user_id)
        if counter <= stored_counter:
            return ErrorMessage(ERROR_REPLAY_DETECTED, f"Invalid counter: {counter} <= {stored_counter}")
        
        # Update counter
        self.storage.update_user_counter(user_id, counter)
        
        # Get all ledger entries
        entries = self.ledger.get_all_entries()
        
        print(f"[Server] Sending ledger ({len(entries)} entries) to {user_id}")
        
        return LedgerResponseMessage(
            entries=entries,
            genesis_hash=self.ledger.genesis_hash
        )
    
    def handle_balance_request(self, session_id: str, message: ProtocolMessage) -> ProtocolMessage:
        """
        Handle BALANCE_REQUEST message.
        
        Args:
            session_id: Session identifier
            message: Balance request message
            
        Returns:
            Balance response or error message
        """
        payload = message.payload
        counter = payload.get("counter")
        
        # Get session
        session = self.crypto.get_session(session_id)
        if not session:
            return ErrorMessage(ERROR_INVALID_MESSAGE, "Invalid or expired session")
        
        user_id = session["user_id"]
        
        # Verify counter
        stored_counter = self.storage.get_user_counter(user_id)
        if counter <= stored_counter:
            return ErrorMessage(ERROR_REPLAY_DETECTED, f"Invalid counter: {counter} <= {stored_counter}")
        
        # Update counter
        self.storage.update_user_counter(user_id, counter)
        
        # Calculate balances
        balances = self.ledger.calculate_balances()
        simplified = self.ledger.get_simplified_balances()
        
        print(f"[Server] Sending balances to {user_id}")
        
        return BalanceResponseMessage(
            balances={
                "detailed": balances,
                "simplified": simplified
            }
        )
    
    def process_message(self, session_id: Optional[str], encrypted_msg: Dict) -> Dict:
        """
        Process an encrypted message from client.
        
        Args:
            session_id: Session identifier (None for CLIENT_HELLO)
            encrypted_msg: Encrypted message dictionary
            
        Returns:
            Encrypted response dictionary
        """
        # Handle CLIENT_HELLO (not encrypted)
        if session_id is None:
            # This is a CLIENT_HELLO message (not encrypted)
            message = ProtocolMessage.from_dict(encrypted_msg)
            response = self.handle_client_hello(message)
            return response.to_dict()
        
        # Decrypt message (support algorithm selection)
        algorithm = encrypted_msg.get("algorithm", "AES-256-GCM")  # Default for backward compatibility
        plaintext = self.crypto.decrypt_message(
            session_id,
            encrypted_msg["nonce"],
            encrypted_msg["ciphertext"],
            algorithm
        )
        
        if plaintext is None:
            error_response = ErrorMessage(ERROR_DECRYPTION_FAILED, "Failed to decrypt message")
            return error_response.to_dict()
        
        # Parse message
        message = ProtocolMessage.from_bytes(plaintext)
        
        # Route to appropriate handler
        if message.msg_type == MSG_TYPE_EXPENSE_SUBMIT:
            response = self.handle_expense_submit(session_id, message)
        elif message.msg_type == MSG_TYPE_LEDGER_REQUEST:
            response = self.handle_ledger_request(session_id, message)
        elif message.msg_type == MSG_TYPE_BALANCE_REQUEST:
            response = self.handle_balance_request(session_id, message)
        else:
            response = ErrorMessage(ERROR_INVALID_MESSAGE, f"Unknown message type: {message.msg_type}")
        
        # Encrypt response
        response_bytes = response.to_bytes()
        encrypted_response = self.crypto.encrypt_message(session_id, response_bytes)
        
        if encrypted_response is None:
            error_response = ErrorMessage(ERROR_INVALID_MESSAGE, "Session expired")
            return error_response.to_dict()
        
        return encrypted_response
    
    def get_server_public_key(self) -> str:
        """Get server's public key in PEM format."""
        return self.crypto.get_public_key_pem()
    
    def list_users(self) -> list:
        """Get list of registered users."""
        return self.storage.list_users()


def main():
    """Main server entry point (for testing)."""
    server = SplitSmartServer()
    print("\n[Server] Server ready")
    print(f"[Server] Registered users: {server.list_users()}")


if __name__ == "__main__":
    main()
