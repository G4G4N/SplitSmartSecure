"""
Main SplitSmart client application.
Handles communication with server and user operations.
"""

from typing import Optional, Dict, Any
from datetime import datetime

from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
from shared.protocols import (
    ProtocolMessage, ClientHelloMessage, ExpenseSubmitMessage,
    LedgerRequestMessage, BalanceRequestMessage
)
from shared.constants import (
    MSG_TYPE_SERVER_HELLO, MSG_TYPE_EXPENSE_RESPONSE,
    MSG_TYPE_LEDGER_RESPONSE, MSG_TYPE_BALANCE_RESPONSE,
    MSG_TYPE_ERROR
)

from .crypto_client import ClientCrypto


class SplitSmartClient:
    """Main client application."""
    
    def __init__(self, user_id: str, server):
        """
        Initialize client.
        
        Args:
            user_id: User identifier
            server: Server instance (for direct communication in this demo)
        """
        self.user_id = user_id
        self.server = server
        self.crypto = ClientCrypto(user_id)
        self.server_public_key = None
        
        print(f"[Client] Initialized client for {user_id}")
    
    def register(self) -> bool:
        """
        Register user with server.
        
        Returns:
            True if successful
        """
        # Generate keys if not exists
        if not self.crypto.load_keys():
            public_key_pem = self.crypto.generate_keys()
        else:
            public_key_pem = self.crypto.get_public_key_pem()
        
        # Register with server
        success = self.server.register_user(self.user_id, public_key_pem)
        
        if success:
            print(f"[Client] Successfully registered {self.user_id}")
        else:
            print(f"[Client] User {self.user_id} already registered")
        
        return success
    
    def login(self) -> bool:
        """
        Establish secure session with server.
        
        Returns:
            True if successful
        """
        # Load keys
        if not self.crypto.load_keys():
            print("[Client] Keys not found. Please register first.")
            return False
        
        # Load server's public key
        server_public_key_pem = self.server.get_server_public_key()
        self.server_public_key = CryptoPrimitives.load_public_key(server_public_key_pem.encode('utf-8'))
        
        # For initial handshake, we need DH parameters from server
        # In this demo, we'll get them from the server directly
        # In a real implementation, these would be sent in the first message
        dh_params = self.server.crypto.dh_parameters
        
        # Initiate key exchange
        client_hello_data = self.crypto.initiate_key_exchange(dh_params)
        client_hello = ClientHelloMessage(
            user_id=client_hello_data["user_id"],
            dh_public_key=client_hello_data["dh_public_key"],
            signature=client_hello_data["signature"]
        )
        
        print(f"[Client] Sending CLIENT_HELLO...")
        
        # Send to server (no encryption for handshake)
        response_dict = self.server.process_message(None, client_hello.to_dict())
        response = ProtocolMessage.from_dict(response_dict)
        
        if response.msg_type == MSG_TYPE_ERROR:
            print(f"[Client] Login failed: {response.payload['message']}")
            return False
        
        if response.msg_type != MSG_TYPE_SERVER_HELLO:
            print(f"[Client] Unexpected response: {response.msg_type}")
            return False
        
        # Complete key exchange
        success = self.crypto.complete_key_exchange(
            server_dh_public_key_b64=response.payload["dh_public_key"],
            server_signature_b64=response.payload["signature"],
            server_public_key=self.server_public_key,
            session_id=response.payload["session_id"]
        )
        
        if success:
            print(f"[Client] ✓ Logged in successfully")
            return True
        else:
            print(f"[Client] ✗ Login failed")
            return False
    
    def add_expense(self, payer: str, amount: float, description: str) -> bool:
        """
        Submit an expense to the server.
        
        Args:
            payer: User ID of who paid
            amount: Amount paid
            description: Expense description
            
        Returns:
            True if successful
        """
        if not self.crypto.has_session():
            print("[Client] No active session. Please login first.")
            return False
        
        # Create timestamp
        timestamp = datetime.utcnow().isoformat()
        
        # Sign expense
        signature, counter = self.crypto.sign_expense(payer, amount, description, timestamp)
        
        # Create expense message (include timestamp in payload)
        expense_msg = ExpenseSubmitMessage(
            payer=payer,
            amount=amount,
            description=description,
            counter=counter,
            signature=signature,
            timestamp=timestamp
        )
        
        # Encrypt message
        encrypted = self.crypto.encrypt_message(expense_msg.to_bytes())
        
        print(f"[Client] Submitting expense: {payer} paid ${amount:.2f} for '{description}'")
        
        # Send to server
        response_dict = self.server.process_message(self.crypto.session_id, encrypted)
        
        # Check if response is encrypted or plain error
        if "nonce" in response_dict and "ciphertext" in response_dict:
            # Decrypt response
            algorithm = response_dict.get("algorithm", "AES-256-GCM")  # Default for backward compatibility
            plaintext = self.crypto.decrypt_message(
                response_dict["nonce"], 
                response_dict["ciphertext"],
                algorithm
            )
            if plaintext is None:
                print("[Client] Failed to decrypt response")
                return False
            response = ProtocolMessage.from_bytes(plaintext)
        else:
            # Plain error response
            response = ProtocolMessage.from_dict(response_dict)
        
        if response.msg_type == MSG_TYPE_ERROR:
            print(f"[Client] Error: {response.payload['message']}")
            return False
        
        if response.msg_type == MSG_TYPE_EXPENSE_RESPONSE:
            if response.payload["success"]:
                print(f"[Client] ✓ Expense recorded (ID: {response.payload['entry_id']})")
                print(f"[Client]   Entry hash: {response.payload['entry_hash'][:16]}...")
                return True
            else:
                print(f"[Client] ✗ Failed: {response.payload['message']}")
                return False
        
        return False
    
    def view_ledger(self) -> Optional[list]:
        """
        Request and display the ledger.
        
        Returns:
            List of ledger entries or None
        """
        if not self.crypto.has_session():
            print("[Client] No active session. Please login first.")
            return None
        
        # Create ledger request
        counter = self.crypto.increment_counter()
        ledger_req = LedgerRequestMessage(counter=counter)
        
        # Encrypt message
        encrypted = self.crypto.encrypt_message(ledger_req.to_bytes())
        
        print(f"[Client] Requesting ledger...")
        
        # Send to server
        response_dict = self.server.process_message(self.crypto.session_id, encrypted)
        
        # Check if response is encrypted or plain error
        if "nonce" in response_dict and "ciphertext" in response_dict:
            algorithm = response_dict.get("algorithm", "AES-256-GCM")  # Default for backward compatibility
            plaintext = self.crypto.decrypt_message(
                response_dict["nonce"], 
                response_dict["ciphertext"],
                algorithm
            )
            if plaintext is None:
                print("[Client] Failed to decrypt response")
                return None
            response = ProtocolMessage.from_bytes(plaintext)
        else:
            response = ProtocolMessage.from_dict(response_dict)
        
        if response.msg_type == MSG_TYPE_ERROR:
            print(f"[Client] Error: {response.payload['message']}")
            return None
        
        if response.msg_type == MSG_TYPE_LEDGER_RESPONSE:
            entries = response.payload["entries"]
            genesis_hash = response.payload["genesis_hash"]
            
            print(f"\n[Client] Ledger ({len(entries)} entries):")
            print(f"[Client] Genesis hash: {genesis_hash[:16]}...")
            print("-" * 80)
            
            for entry in entries:
                print(f"ID {entry['id']}: {entry['payer']} paid ${entry['amount']:.2f} - {entry['description']}")
                print(f"  Timestamp: {entry['timestamp']}")
                print(f"  Hash: {entry['entry_hash'][:16]}...")
            
            print("-" * 80)
            
            # Verify hash chain
            self._verify_ledger_chain(entries, genesis_hash)
            
            return entries
        
        return None
    
    def _verify_ledger_chain(self, entries: list, genesis_hash: str):
        """
        Verify the integrity of the ledger hash chain.
        
        Args:
            entries: List of ledger entries
            genesis_hash: Genesis hash
        """
        print("\n[Client] Verifying ledger integrity...")
        
        if not entries:
            print("[Client] ✓ Empty ledger is valid")
            return
        
        # Check first entry
        if entries[0]["prev_hash"] != genesis_hash:
            print("[Client] ✗ First entry does not link to genesis!")
            return
        
        # Verify each entry
        for i, entry in enumerate(entries):
            # Recompute hash
            entry_data = {
                "user_id": entry["user_id"],
                "payer": entry["payer"],
                "amount": entry["amount"],
                "description": entry["description"],
                "timestamp": entry["timestamp"],
                "counter": entry["counter"]
            }
            
            data_bytes = MessageEncoder.encode_message(entry_data)
            prev_hash_bytes = bytes.fromhex(entry["prev_hash"])
            computed_hash = CryptoPrimitives.hash_chain_link(prev_hash_bytes, data_bytes)
            
            if computed_hash.hex() != entry["entry_hash"]:
                print(f"[Client] ✗ Entry {entry['id']} has invalid hash!")
                return
            
            # Check linkage
            if i < len(entries) - 1:
                next_entry = entries[i + 1]
                if next_entry["prev_hash"] != entry["entry_hash"]:
                    print(f"[Client] ✗ Chain broken between entries {entry['id']} and {next_entry['id']}!")
                    return
        
        print("[Client] ✓ Ledger integrity verified - all hashes valid")
    
    def view_balances(self) -> Optional[Dict]:
        """
        Request and display balances.
        
        Returns:
            Balance dictionary or None
        """
        if not self.crypto.has_session():
            print("[Client] No active session. Please login first.")
            return None
        
        # Create balance request
        counter = self.crypto.increment_counter()
        balance_req = BalanceRequestMessage(counter=counter)
        
        # Encrypt message
        encrypted = self.crypto.encrypt_message(balance_req.to_bytes())
        
        print(f"[Client] Requesting balances...")
        
        # Send to server
        response_dict = self.server.process_message(self.crypto.session_id, encrypted)
        
        # Check if response is encrypted or plain error
        if "nonce" in response_dict and "ciphertext" in response_dict:
            algorithm = response_dict.get("algorithm", "AES-256-GCM")  # Default for backward compatibility
            plaintext = self.crypto.decrypt_message(
                response_dict["nonce"], 
                response_dict["ciphertext"],
                algorithm
            )
            if plaintext is None:
                print("[Client] Failed to decrypt response")
                return None
            response = ProtocolMessage.from_bytes(plaintext)
        else:
            response = ProtocolMessage.from_dict(response_dict)
        
        if response.msg_type == MSG_TYPE_ERROR:
            print(f"[Client] Error: {response.payload['message']}")
            return None
        
        if response.msg_type == MSG_TYPE_BALANCE_RESPONSE:
            balances = response.payload["balances"]
            
            print(f"\n[Client] Balances:")
            print("-" * 80)
            print("Detailed balances:")
            for user, balance in balances["detailed"].items():
                status = "is owed" if balance > 0 else "owes"
                print(f"  {user}: ${abs(balance):.2f} {status}")
            
            print("\nSimplified settlements:")
            if balances["simplified"]:
                for debt in balances["simplified"]:
                    print(f"  {debt['from']} → {debt['to']}: ${debt['amount']:.2f}")
            else:
                print("  All settled!")
            
            print("-" * 80)
            
            return balances
        
        return None
