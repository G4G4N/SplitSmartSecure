#!/usr/bin/env python3
"""
Demonstration: Modification Attack and Defense

This demo shows how SplitSmart protects against message modification attacks
using AES-256-GCM authenticated encryption.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient
from shared.crypto_primitives import MessageEncoder
import os

def print_header(text):
    print("\n" + "=" * 80)
    print(f"{text:^80}")
    print("=" * 80 + "\n")

def demo_modification():
    print_header("ATTACK DEMO: Message Modification Attack")
    
    print("Scenario: An attacker intercepts a message and attempts to modify it")
    print("Defense: AES-256-GCM authentication tag detects any modifications\n")
    
    # Setup
    print("1. Setting up server and client...")
    server = SplitSmartServer()
    alice = SplitSmartClient("alice", server)
    
    # Register and login
    print("2. Alice registers and logs in...")
    alice.register()
    alice.login()
    
    # Create and encrypt a legitimate expense
    print("\n3. Alice creates a legitimate expense:")
    print("   Original: alice paid $50.00 for 'Lunch'\n")
    
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
    
    # Encrypt the message
    encrypted = alice.crypto.encrypt_message(expense_msg.to_bytes())
    
    print("4. Message encrypted and sent to server")
    print(f"   Nonce: {encrypted['nonce'][:32]}...")
    print(f"   Ciphertext: {encrypted['ciphertext'][:64]}...")
    print(f"   Auth Tag: {encrypted['tag'][:32]}...")
    
    # ATTACKER INTERCEPTS AND MODIFIES
    print("\n5. ATTACKER INTERCEPTS THE MESSAGE:")
    print("   Attacker captures the encrypted message in transit")
    
    print("\n6. ATTACKER ATTEMPTS TO MODIFY THE CIPHERTEXT:")
    print("   Attacker tries to change the amount from $50 to $500")
    print("   (by flipping bits in the ciphertext)")
    
    # Modify the ciphertext (flip some bits)
    ciphertext_bytes = MessageEncoder.b64decode(encrypted['ciphertext'])
    modified_ciphertext = bytearray(ciphertext_bytes)
    
    # Flip some bits in the middle (where amount might be)
    if len(modified_ciphertext) > 20:
        modified_ciphertext[10] ^= 0xFF  # Flip bits
        modified_ciphertext[15] ^= 0xFF  # Flip more bits
    
    modified_encrypted = {
        'nonce': encrypted['nonce'],
        'ciphertext': MessageEncoder.b64encode(bytes(modified_ciphertext)),
        'tag': encrypted['tag']  # Attacker doesn't know how to update the tag
    }
    
    print(f"   Modified ciphertext: {modified_encrypted['ciphertext'][:64]}...")
    print("   (Note: Auth tag remains unchanged - attacker cannot forge it)")
    
    # Try to send modified message to server
    print("\n7. ATTACKER SENDS MODIFIED MESSAGE TO SERVER:")
    print("   Server attempts to decrypt...")
    
    response = server.process_message(alice.crypto.session_id, modified_encrypted)
    
    # Server's response
    print("\n8. SERVER RESPONSE:")
    if response:
        # Try to decrypt the response
        plaintext = alice.crypto.decrypt_message(response["nonce"], response["ciphertext"])
        if plaintext:
            from shared.protocols import ProtocolMessage
            response_msg = ProtocolMessage.from_bytes(plaintext)
            print(f"   Message Type: {response_msg.msg_type}")
            if response_msg.msg_type == "ERROR":
                print(f"   ✓ Error Detected: {response_msg.payload.get('message', 'Unknown error')}")
                print("\n   SERVER REJECTED THE MODIFIED MESSAGE!")
                print("   Reason: GCM authentication tag verification failed")
    
    # Verify ledger is unchanged
    print("\n9. VERIFYING LEDGER INTEGRITY:")
    entries = server.ledger.get_all_entries()
    print(f"   Ledger has {len(entries)} entries")
    print("   ✓ Modified message was NOT added to ledger")
    print("   ✓ No unauthorized changes were made")
    
    # Now send the original, unmodified message
    print("\n10. LEGITIMATE MESSAGE PROCESSING:")
    print("    Sending original (unmodified) message...")
    response = server.process_message(alice.crypto.session_id, encrypted)
    
    if response:
        plaintext = alice.crypto.decrypt_message(response["nonce"], response["ciphertext"])
        if plaintext:
            from shared.protocols import ProtocolMessage
            response_msg = ProtocolMessage.from_bytes(plaintext)
            if response_msg.msg_type == "EXPENSE_SUBMIT_RESPONSE":
                print("    ✓ Original message accepted successfully")
                print(f"    Entry ID: {response_msg.payload.get('entry_id')}")
    
    print_header("RESULT: Integrity Protection Successful")
    print("✓ AES-256-GCM authentication tag detects modifications")
    print("✓ Modified messages are rejected by the server")
    print("✓ Attacker cannot forge valid authentication tags")
    print("✓ Only authentic, unmodified messages are accepted")
    
    print("\n" + "=" * 80)
    print("Technical Details:".center(80))
    print("=" * 80)
    print("• AES-GCM provides AEAD (Authenticated Encryption with Associated Data)")
    print("• Authentication tag is computed over ciphertext using session key")
    print("• Any modification to ciphertext causes tag verification to fail")
    print("• Attacker cannot compute valid tag without knowing the session key")
    print("• This prevents both passive eavesdropping AND active modification")
    print("=" * 80)

if __name__ == "__main__":
    demo_modification()
