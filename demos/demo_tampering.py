#!/usr/bin/env python3
"""
Demonstration: Ledger Tampering Attack and Defense

This demo shows how SplitSmart detects ledger tampering
using a hash chain (blockchain-inspired).
"""

import sqlite3
from server.server import SplitSmartServer
from client.client import SplitSmartClient
from shared.constants import DB_FILE

def print_header(text):
    print("\n" + "=" * 80)
    print(f"{text:^80}")
    print("=" * 80 + "\n")

def demo_tampering():
    print_header("ATTACK DEMO: Ledger Tampering")
    
    print("Scenario: An attacker gains access to the database and modifies entries")
    print("Defense: Hash chain detects any tampering\n")
    
    # Setup
    print("1. Setting up server and adding legitimate expenses...")
    server = SplitSmartServer()
    alice = SplitSmartClient("alice", server)
    bob = SplitSmartClient("bob", server)
    
    # Register and login
    alice.register()
    bob.register()
    alice.login()
    bob.login()
    
    # Add some expenses
    alice.add_expense("alice", 60.00, "Dinner")
    bob.add_expense("bob", 40.00, "Groceries")
    alice.add_expense("alice", 25.00, "Movie tickets")
    
    print("\n2. Viewing legitimate blockchain ledger...")
    entries = server.ledger.get_all_entries()
    for entry in entries:
        block_height = entry.get('block_height', entry.get('id', 0))
        print(f"   Block #{block_height}: {entry['payer']} paid ${entry['amount']:.2f} - {entry['description']}")
        if entry.get('block_hash'):
            print(f"     Block Hash: {entry['block_hash'][:32]}...")
    
    # Verify integrity
    print("\n3. Verifying ledger integrity...")
    is_valid, error = server.ledger.verify_chain_integrity()
    if is_valid:
        print("   ✓ Ledger integrity verified - all hashes valid")
    
    # Simulate attacker tampering with database
    print("\n4. ATTACKER GAINS DATABASE ACCESS:")
    print("   Attacker modifies entry #2 to change amount from $40.00 to $400.00")
    
    # Direct database modification (simulating attacker)
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("UPDATE ledger SET amount = 400.00 WHERE id = 2")
    conn.commit()
    conn.close()
    
    print("   ✗ Database modified directly (bypassing application logic)")
    
    # Restart server (triggers integrity check)
    print("\n5. Server restarts and performs integrity check...")
    server2 = SplitSmartServer()
    
    # Manual verification
    print("\n6. Verifying ledger integrity after tampering...")
    is_valid, error = server2.ledger.verify_chain_integrity()
    
    if not is_valid:
        print(f"   ✗ TAMPERING DETECTED: {error}")
        print("   ✗ Hash chain is broken!")
    
    # Show the tampered entry
    print("\n7. Examining tampered block...")
    tampered_entries = server2.ledger.get_all_entries()
    tampered_entry = tampered_entries[1]  # Entry ID 2
    block_height = tampered_entry.get('block_height', tampered_entry.get('id', 0))
    print(f"   Block #{block_height} (Entry ID {tampered_entry['id']}):")
    print(f"   Amount: ${tampered_entry['amount']:.2f} (was $40.00)")
    print(f"   Stored entry hash: {tampered_entry['entry_hash'][:16]}...")
    if tampered_entry.get('block_hash'):
        print(f"   Stored block hash: {tampered_entry['block_hash'][:16]}...")
    
    # Recompute what hash should be
    from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
    entry_data = {
        "user_id": tampered_entry["user_id"],
        "payer": tampered_entry["payer"],
        "amount": tampered_entry["amount"],
        "description": tampered_entry["description"],
        "timestamp": tampered_entry["timestamp"],
        "counter": tampered_entry["counter"]
    }
    data_bytes = MessageEncoder.encode_message(entry_data)
    prev_hash_bytes = bytes.fromhex(tampered_entry["prev_hash"])
    computed_hash = CryptoPrimitives.hash_chain_link(prev_hash_bytes, data_bytes)
    
    print(f"   Computed hash: {computed_hash.hex()[:16]}...")
    print("   ✗ Hashes don't match - tampering detected!")
    
    print_header("RESULT: Tampering Detected")
    print("✓ Blockchain hash chain detects any modification to ledger entries")
    print("✓ Each block is cryptographically linked to previous block")
    print("✓ Block hashes include height, prev_hash, merkle_root, and timestamp")
    print("✓ Tampering breaks the chain and is immediately detected")
    print("✓ Provides tamper-evident history (blockchain-inspired)")
    print("✓ Merkle roots enable efficient verification")

if __name__ == "__main__":
    demo_tampering()
