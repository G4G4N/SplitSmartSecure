"""
Ledger management with hash chain for SplitSmart server.
Implements tamper-evident append-only ledger.
"""

from typing import Optional, List, Dict, Any
from datetime import datetime

from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
from shared.constants import GENESIS_HASH
from .storage import Storage


class Ledger:
    """
    Manages the hash-chained ledger.
    Provides tamper-evident append-only storage for expense entries.
    """
    
    def __init__(self, storage: Storage):
        """
        Initialize ledger.
        
        Args:
            storage: Storage instance
        """
        self.storage = storage
        self.genesis_hash = self._get_or_create_genesis_hash()
    
    def _get_or_create_genesis_hash(self) -> str:
        """
        Get or create genesis hash.
        
        Returns:
            Genesis hash (hex string)
        """
        genesis = self.storage.get_metadata("genesis_hash")
        if genesis is None:
            # Create genesis hash
            genesis_bytes = CryptoPrimitives.hash_data(GENESIS_HASH.encode('utf-8'))
            genesis = genesis_bytes.hex()
            self.storage.set_metadata("genesis_hash", genesis)
        return genesis
    
    def get_last_hash(self) -> str:
        """
        Get the hash of the last entry in the chain.
        
        Returns:
            Last entry hash or genesis hash if ledger is empty
        """
        last_entry = self.storage.get_last_ledger_entry()
        if last_entry:
            return last_entry["entry_hash"]
        return self.genesis_hash
    
    def compute_entry_hash(self, prev_hash: str, entry_data: Dict[str, Any]) -> str:
        """
        Compute hash for a new entry.
        
        Args:
            prev_hash: Previous entry hash (hex string)
            entry_data: Entry data dictionary
            
        Returns:
            Entry hash (hex string)
        """
        # Create canonical representation of entry data
        canonical_data = {
            "user_id": entry_data["user_id"],
            "payer": entry_data["payer"],
            "amount": entry_data["amount"],
            "description": entry_data["description"],
            "timestamp": entry_data["timestamp"],
            "counter": entry_data["counter"]
        }
        
        # Serialize to bytes
        data_bytes = MessageEncoder.encode_message(canonical_data)
        
        # Compute hash chain link
        prev_hash_bytes = bytes.fromhex(prev_hash)
        entry_hash_bytes = CryptoPrimitives.hash_chain_link(prev_hash_bytes, data_bytes)
        
        return entry_hash_bytes.hex()
    
    def add_entry(self, user_id: str, payer: str, amount: float, description: str,
                  timestamp: str, counter: int, signature: str) -> Optional[Dict[str, Any]]:
        """
        Add a new entry to the ledger.
        
        Args:
            user_id: User who created the entry
            payer: User who paid
            amount: Amount paid
            description: Expense description
            timestamp: ISO timestamp
            counter: Counter value
            signature: User's signature (base64)
            
        Returns:
            Entry dictionary with id and hash if successful, None otherwise
        """
        # Get previous hash
        prev_hash = self.get_last_hash()
        
        # Prepare entry data
        entry_data = {
            "user_id": user_id,
            "payer": payer,
            "amount": amount,
            "description": description,
            "timestamp": timestamp,
            "counter": counter
        }
        
        # Compute entry hash
        entry_hash = self.compute_entry_hash(prev_hash, entry_data)
        
        # Add to storage
        entry_id = self.storage.add_ledger_entry(
            user_id=user_id,
            payer=payer,
            amount=amount,
            description=description,
            timestamp=timestamp,
            counter=counter,
            signature=signature,
            prev_hash=prev_hash,
            entry_hash=entry_hash
        )
        
        if entry_id:
            return {
                "id": entry_id,
                "entry_hash": entry_hash,
                "prev_hash": prev_hash
            }
        return None
    
    def get_all_entries(self) -> List[Dict[str, Any]]:
        """
        Get all ledger entries.
        
        Returns:
            List of entry dictionaries
        """
        return self.storage.get_ledger_entries()
    
    def verify_chain_integrity(self) -> tuple[bool, Optional[str]]:
        """
        Verify the integrity of the entire hash chain.
        
        Returns:
            Tuple of (is_valid, error_message)
        """
        entries = self.get_all_entries()
        
        if not entries:
            # Empty ledger is valid
            return True, None
        
        # Check first entry links to genesis
        first_entry = entries[0]
        if first_entry["prev_hash"] != self.genesis_hash:
            return False, f"First entry does not link to genesis hash"
        
        # Verify each entry's hash
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
            
            computed_hash = self.compute_entry_hash(entry["prev_hash"], entry_data)
            
            if computed_hash != entry["entry_hash"]:
                return False, f"Entry {entry['id']} has invalid hash"
            
            # Check chain linkage (except for last entry)
            if i < len(entries) - 1:
                next_entry = entries[i + 1]
                if next_entry["prev_hash"] != entry["entry_hash"]:
                    return False, f"Chain broken between entries {entry['id']} and {next_entry['id']}"
        
        return True, None
    
    def calculate_balances(self) -> Dict[str, float]:
        """
        Calculate balances from ledger entries.
        
        Returns:
            Dictionary mapping user_id to balance
            Positive balance means user is owed money
            Negative balance means user owes money
        """
        entries = self.get_all_entries()
        balances = {}
        
        # Get all unique users
        users = set()
        for entry in entries:
            users.add(entry["payer"])
            users.add(entry["user_id"])
        
        # Initialize balances
        for user in users:
            balances[user] = 0.0
        
        # Calculate balances
        # Simple model: payer gets credited, others split the cost
        for entry in entries:
            payer = entry["payer"]
            amount = entry["amount"]
            
            # For now, assume equal split among all users
            # In a real app, you'd specify who participated in each expense
            num_users = len(users)
            per_person = amount / num_users
            
            # Payer gets credited for the full amount
            balances[payer] += amount
            
            # Everyone (including payer) owes their share
            for user in users:
                balances[user] -= per_person
        
        # Round to 2 decimal places
        for user in balances:
            balances[user] = round(balances[user], 2)
        
        return balances
    
    def get_simplified_balances(self) -> List[Dict[str, Any]]:
        """
        Get simplified "who owes whom" representation.
        
        Returns:
            List of debt relationships
        """
        balances = self.calculate_balances()
        
        # Separate creditors and debtors
        creditors = {user: bal for user, bal in balances.items() if bal > 0.01}
        debtors = {user: -bal for user, bal in balances.items() if bal < -0.01}
        
        # Create simplified debt list
        debts = []
        
        # Match debtors with creditors
        for debtor, debt_amount in sorted(debtors.items(), key=lambda x: -x[1]):
            for creditor, credit_amount in sorted(creditors.items(), key=lambda x: -x[1]):
                if debt_amount < 0.01 or credit_amount < 0.01:
                    continue
                
                # Transfer amount
                transfer = min(debt_amount, credit_amount)
                debts.append({
                    "from": debtor,
                    "to": creditor,
                    "amount": round(transfer, 2)
                })
                
                # Update remaining amounts
                debt_amount -= transfer
                credit_amount -= transfer
                creditors[creditor] = credit_amount
        
        return debts
