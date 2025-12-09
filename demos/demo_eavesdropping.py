#!/usr/bin/env python3
"""
Demonstration: Eavesdropping Attack and Defense

This demo shows how SplitSmart protects against eavesdropping attacks
by encrypting all communication with AES-256-GCM.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient
from shared.crypto_primitives import MessageEncoder

def print_header(text):
    print("\n" + "=" * 80)
    print(f"{text:^80}")
    print("=" * 80 + "\n")

def demo_eavesdropping():
    print_header("ATTACK DEMO: Eavesdropping")
    
    print("Scenario: An attacker intercepts network traffic between client and server")
    print("Defense: All messages are encrypted with AES-256-GCM\n")
    
    # Setup
    print("1. Setting up server and client...")
    server = SplitSmartServer()
    alice = SplitSmartClient("alice", server)
    
    # Register and login
    print("2. Alice registers and logs in...")
    alice.register()
    alice.login()
    
    # Create an expense
    print("\n3. Alice submits an expense...")
    print("   Plaintext: 'alice paid $100.00 for Secret dinner plans'\n")
    
    # Capture the encrypted message
    from shared.protocols import ExpenseSubmitMessage
    from datetime import datetime
    
    timestamp = datetime.utcnow().isoformat()
    signature, counter = alice.crypto.sign_expense("alice", 100.00, "Secret dinner plans", timestamp)
    
    expense_msg = ExpenseSubmitMessage(
        payer="alice",
        amount=100.00,
        description="Secret dinner plans",
        counter=counter,
        signature=signature,
        timestamp=timestamp
    )
    
    # Encrypt
    encrypted = alice.crypto.encrypt_message(expense_msg.to_bytes())
    
    print("4. ATTACKER INTERCEPTS THE MESSAGE:")
    print(f"   Nonce: {encrypted['nonce'][:32]}...")
    print(f"   Ciphertext: {encrypted['ciphertext'][:64]}...")
    print("\n5. ATTACKER ATTEMPTS TO DECRYPT:")
    print("   ✗ Without the session key, the ciphertext is unintelligible")
    print("   ✗ The attacker cannot read the expense details")
    print("   ✗ The attacker cannot determine the amount or description")
    
    # Try to decode without key
    try:
        ciphertext_bytes = MessageEncoder.b64decode(encrypted['ciphertext'])
        print(f"\n   Raw ciphertext bytes: {ciphertext_bytes[:32].hex()}...")
        print("   This is cryptographically secure random data to the attacker")
    except:
        pass
    
    print("\n6. LEGITIMATE SERVER DECRYPTS SUCCESSFULLY:")
    # Send the encrypted message to server
    response = server.process_message(alice.crypto.session_id, encrypted)
    if response:
        # Handle algorithm field
        algorithm = response.get("algorithm", "AES-256-GCM")
        plaintext = alice.crypto.decrypt_message(
            response["nonce"], 
            response["ciphertext"],
            algorithm
        )
        if plaintext:
            from shared.protocols import ProtocolMessage
            response_msg = ProtocolMessage.from_bytes(plaintext)
            if response_msg.msg_type == "EXPENSE_SUBMIT_RESPONSE":
                print("   ✓ Server successfully decrypted and processed the expense")
                print(f"   Entry ID: {response_msg.payload.get('entry_id')}")
                print(f"   Algorithm used: {algorithm}")
            else:
                print("   ✓ Server successfully decrypted the message")
                print(f"   Algorithm used: {algorithm}")
    
    print_header("RESULT: Confidentiality Preserved")
    print("✓ Multiple encryption algorithms protect against eavesdropping:")
    print("  • AES-256-GCM: Hardware-accelerated, best for large messages")
    print("  • ChaCha20-Poly1305: Fast software implementation, best for small messages")
    print("  • AES-256-CBC-HMAC: Compatibility option")
    print("✓ Attacker cannot read message contents without session key")
    print("✓ Only parties with the session key can decrypt")
    print("✓ Algorithm automatically selected based on message size")

if __name__ == "__main__":
    demo_eavesdropping()
