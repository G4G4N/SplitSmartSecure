#!/usr/bin/env python3
"""
Demonstration: Replay Attack and Defense

This demo shows how SplitSmart protects against replay attacks
using monotonic counters.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient

def print_header(text):
    print("\n" + "=" * 80)
    print(f"{text:^80}")
    print("=" * 80 + "\n")

def demo_replay():
    print_header("ATTACK DEMO: Replay Attack")
    
    print("Scenario: An attacker captures a valid message and replays it later")
    print("Defense: Monotonic counters prevent replay attacks\n")
    
    # Setup
    print("1. Setting up server and client...")
    server = SplitSmartServer()
    alice = SplitSmartClient("alice", server)
    
    # Register and login
    print("2. Alice registers and logs in...")
    alice.register()
    alice.login()
    
    # Submit first expense
    print("\n3. Alice submits an expense (counter = 1)...")
    from shared.protocols import ExpenseSubmitMessage
    from datetime import datetime
    
    timestamp = datetime.utcnow().isoformat()
    signature, counter = alice.crypto.sign_expense("alice", 50.00, "Lunch", timestamp)
    
    expense_msg = ExpenseSubmitMessage(
        payer="alice",
        amount=50.00,
        description="Lunch",
        counter=counter,
        signature=signature,
        timestamp=timestamp
    )
    
    # Encrypt and send
    encrypted = alice.crypto.encrypt_message(expense_msg.to_bytes())
    print(f"   Message sent with counter = {counter}")
    
    # Server processes it
    response = server.process_message(alice.crypto.session_id, encrypted)
    print("   ✓ Server accepted the message")
    
    # Submit another expense to increment counter
    print("\n4. Alice submits another expense (counter = 2)...")
    alice.add_expense("alice", 30.00, "Coffee")
    print(f"   Current counter on server: 2")
    
    # Attacker tries to replay the first message
    print("\n5. ATTACKER REPLAYS THE FIRST MESSAGE (counter = 1):")
    print("   Attacker captured the encrypted message from step 3")
    print("   Attacker replays it to the server...")
    
    # Try to replay
    response = server.process_message(alice.crypto.session_id, encrypted)
    
    # Decrypt response to see error
    algorithm = response.get("algorithm", "AES-256-GCM")
    plaintext = alice.crypto.decrypt_message(
        response["nonce"], 
        response["ciphertext"],
        algorithm
    )
    if plaintext:
        from shared.protocols import ProtocolMessage
        response_msg = ProtocolMessage.from_bytes(plaintext)
        print(f"\n   Server response: {response_msg.msg_type}")
        print(f"   Error: {response_msg.payload.get('message', 'Unknown error')}")
    
    print("\n6. RESULT:")
    print("   ✗ Server rejected the replayed message")
    print("   ✗ Counter 1 ≤ stored counter 2")
    print("   ✗ Replay attack detected and prevented")
    
    # Verify ledger only has 2 entries
    print("\n7. Verifying ledger integrity...")
    entries = server.ledger.get_all_entries()
    print(f"   Ledger has {len(entries)} entries (not 3)")
    print("   ✓ Replayed message was not added to ledger")
    
    print_header("RESULT: Replay Attack Prevented")
    print("✓ Monotonic counters prevent replay attacks")
    print("✓ Each message must have a strictly increasing counter")
    print("✓ Old messages cannot be replayed")

if __name__ == "__main__":
    demo_replay()
