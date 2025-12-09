"""
Protocol message definitions and handling for SplitSmart.
Defines the structure of all messages exchanged between client and server.
"""

from typing import Optional, Dict, Any
from datetime import datetime
import json

from .constants import (
    MSG_TYPE_CLIENT_HELLO, MSG_TYPE_SERVER_HELLO,
    MSG_TYPE_EXPENSE_SUBMIT, MSG_TYPE_EXPENSE_RESPONSE,
    MSG_TYPE_LEDGER_REQUEST, MSG_TYPE_LEDGER_RESPONSE,
    MSG_TYPE_BALANCE_REQUEST, MSG_TYPE_BALANCE_RESPONSE,
    MSG_TYPE_ERROR
)
from .crypto_primitives import MessageEncoder


class ProtocolMessage:
    """Base class for protocol messages."""
    
    def __init__(self, msg_type: str, payload: Dict[str, Any]):
        self.msg_type = msg_type
        self.payload = payload
        self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> dict:
        """Convert message to dictionary."""
        return {
            "type": self.msg_type,
            "timestamp": self.timestamp,
            "payload": self.payload
        }
    
    def to_bytes(self) -> bytes:
        """Serialize message to bytes."""
        return MessageEncoder.encode_message(self.to_dict())
    
    @staticmethod
    def from_bytes(data: bytes) -> 'ProtocolMessage':
        """Deserialize message from bytes."""
        msg_dict = MessageEncoder.decode_message(data)
        return ProtocolMessage(
            msg_type=msg_dict["type"],
            payload=msg_dict["payload"]
        )
    
    @staticmethod
    def from_dict(msg_dict: dict) -> 'ProtocolMessage':
        """Create message from dictionary."""
        return ProtocolMessage(
            msg_type=msg_dict["type"],
            payload=msg_dict["payload"]
        )


class ClientHelloMessage(ProtocolMessage):
    """
    Client initiates key exchange.
    
    Payload:
        - user_id: Client's user ID
        - dh_public_key: Client's ephemeral DH public key (base64)
        - signature: Signature over DH public key (base64)
    """
    
    def __init__(self, user_id: str, dh_public_key: str, signature: str):
        payload = {
            "user_id": user_id,
            "dh_public_key": dh_public_key,
            "signature": signature
        }
        super().__init__(MSG_TYPE_CLIENT_HELLO, payload)


class ServerHelloMessage(ProtocolMessage):
    """
    Server responds to key exchange.
    
    Payload:
        - dh_public_key: Server's ephemeral DH public key (base64)
        - dh_parameters: DH parameters (base64)
        - signature: Signature over DH public key (base64)
        - session_id: Unique session identifier
    """
    
    def __init__(self, dh_public_key: str, dh_parameters: str, signature: str, session_id: str):
        payload = {
            "dh_public_key": dh_public_key,
            "dh_parameters": dh_parameters,
            "signature": signature,
            "session_id": session_id
        }
        super().__init__(MSG_TYPE_SERVER_HELLO, payload)


class ExpenseSubmitMessage(ProtocolMessage):
    """
    Client submits an expense entry.
    
    Payload (encrypted):
        - payer: User ID of who paid
        - amount: Amount paid
        - description: Expense description
        - counter: Client's counter value
        - signature: User's signature over expense data (base64)
        - timestamp: Timestamp used in signature (ISO format)
    """
    
    def __init__(self, payer: str, amount: float, description: str, counter: int, signature: str, timestamp: str):
        payload = {
            "payer": payer,
            "amount": amount,
            "description": description,
            "counter": counter,
            "signature": signature,
            "timestamp": timestamp
        }
        super().__init__(MSG_TYPE_EXPENSE_SUBMIT, payload)


class ExpenseResponseMessage(ProtocolMessage):
    """
    Server acknowledges expense submission.
    
    Payload:
        - success: Boolean indicating success
        - entry_id: Ledger entry ID (if successful)
        - entry_hash: Hash of the ledger entry (if successful)
        - message: Status message
        - error_code: Error code (if failed)
        - receipt: Cryptographic receipt (server signature, if successful)
        - receipt_timestamp: When receipt was issued
    """
    
    def __init__(self, success: bool, message: str, entry_id: Optional[int] = None, 
                 entry_hash: Optional[str] = None, error_code: Optional[str] = None,
                 receipt: Optional[str] = None, receipt_timestamp: Optional[str] = None):
        payload = {
            "success": success,
            "message": message
        }
        if entry_id is not None:
            payload["entry_id"] = entry_id
        if entry_hash is not None:
            payload["entry_hash"] = entry_hash
        if error_code is not None:
            payload["error_code"] = error_code
        if receipt is not None:
            payload["receipt"] = receipt
            payload["receipt_timestamp"] = receipt_timestamp
        super().__init__(MSG_TYPE_EXPENSE_RESPONSE, payload)


class LedgerRequestMessage(ProtocolMessage):
    """
    Client requests the ledger.
    
    Payload:
        - counter: Client's counter value
    """
    
    def __init__(self, counter: int):
        payload = {
            "counter": counter
        }
        super().__init__(MSG_TYPE_LEDGER_REQUEST, payload)


class LedgerResponseMessage(ProtocolMessage):
    """
    Server sends the ledger.
    
    Payload:
        - entries: List of ledger entries
        - genesis_hash: Genesis hash for verification
    """
    
    def __init__(self, entries: list, genesis_hash: str):
        payload = {
            "entries": entries,
            "genesis_hash": genesis_hash
        }
        super().__init__(MSG_TYPE_LEDGER_RESPONSE, payload)


class BalanceRequestMessage(ProtocolMessage):
    """
    Client requests balance calculation.
    
    Payload:
        - counter: Client's counter value
    """
    
    def __init__(self, counter: int):
        payload = {
            "counter": counter
        }
        super().__init__(MSG_TYPE_BALANCE_REQUEST, payload)


class BalanceResponseMessage(ProtocolMessage):
    """
    Server sends calculated balances.
    
    Payload:
        - balances: Dictionary of user balances
    """
    
    def __init__(self, balances: dict):
        payload = {
            "balances": balances
        }
        super().__init__(MSG_TYPE_BALANCE_RESPONSE, payload)


class ErrorMessage(ProtocolMessage):
    """
    Error message.
    
    Payload:
        - error_code: Error code
        - message: Error description
    """
    
    def __init__(self, error_code: str, message: str):
        payload = {
            "error_code": error_code,
            "message": message
        }
        super().__init__(MSG_TYPE_ERROR, payload)


class EncryptedMessage:
    """
    Wrapper for encrypted messages with algorithm selection.
    
    Structure:
        - algorithm: Encryption algorithm used (AES-256-GCM, ChaCha20-Poly1305, AES-256-CBC-HMAC-SHA256)
        - nonce: Nonce/IV (base64)
        - ciphertext: Encrypted payload with auth tag (base64)
    """
    
    def __init__(self, nonce: str, ciphertext: str, algorithm: str = "AES-256-GCM"):
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.algorithm = algorithm
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "algorithm": self.algorithm,
            "nonce": self.nonce,
            "ciphertext": self.ciphertext
        }
    
    def to_bytes(self) -> bytes:
        """Serialize to bytes."""
        return MessageEncoder.encode_message(self.to_dict())
    
    @staticmethod
    def from_bytes(data: bytes) -> 'EncryptedMessage':
        """Deserialize from bytes."""
        msg_dict = MessageEncoder.decode_message(data)
        return EncryptedMessage(
            nonce=msg_dict["nonce"],
            ciphertext=msg_dict["ciphertext"]
        )
    
    @staticmethod
    def from_dict(msg_dict: dict) -> 'EncryptedMessage':
        """Create from dictionary."""
        return EncryptedMessage(
            nonce=msg_dict["nonce"],
            ciphertext=msg_dict["ciphertext"],
            algorithm=msg_dict.get("algorithm", "AES-256-GCM")
        )


def create_expense_data_for_signing(payer: str, amount: float, description: str, 
                                   counter: int, timestamp: str) -> bytes:
    """
    Create canonical expense data for signing.
    
    Args:
        payer: User ID of payer
        amount: Amount paid
        description: Expense description
        counter: Counter value
        timestamp: ISO timestamp
        
    Returns:
        Bytes to be signed
    """
    data = {
        "payer": payer,
        "amount": amount,
        "description": description,
        "counter": counter,
        "timestamp": timestamp
    }
    return json.dumps(data, sort_keys=True).encode('utf-8')


def create_dh_data_for_signing(dh_public_key: bytes, user_id: str) -> bytes:
    """
    Create canonical DH data for signing during handshake.
    
    Args:
        dh_public_key: DH public key bytes
        user_id: User identifier
        
    Returns:
        Bytes to be signed
    """
    data = {
        "dh_public_key": MessageEncoder.b64encode(dh_public_key),
        "user_id": user_id
    }
    return json.dumps(data, sort_keys=True).encode('utf-8')


def create_receipt_data_for_signing(entry_id: int, entry_hash: str, user_id: str, 
                                    timestamp: str) -> bytes:
    """
    Create canonical receipt data for server signing.
    
    Args:
        entry_id: Ledger entry ID
        entry_hash: Hash of the ledger entry
        user_id: User who submitted the expense
        timestamp: Receipt timestamp
        
    Returns:
        Bytes to be signed by server
    """
    data = {
        "entry_id": entry_id,
        "entry_hash": entry_hash,
        "user_id": user_id,
        "timestamp": timestamp
    }
    return json.dumps(data, sort_keys=True).encode('utf-8')
