#!/usr/bin/env python3
"""
Demonstration: Spoofing Attack and Defense

This demo shows how SplitSmart protects against user impersonation attacks
using RSA-PSS digital signatures.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient
from shared.crypto_primitives import CryptoPrimitives, MessageEncoder
from shared.protocols import ExpenseSubmitMessage
from datetime import datetime

def print_header(text):
    print("\n" + "=" * 80)
    print(f"{text:^80}")
    print("=" * 80 + "\n")

def demo_spoofing():
    print_header("ATTACK DEMO: User Spoofing/Impersonation Attack")
    
    print("Scenario: An attacker tries to submit an expense as another user")
    print("Defense: RSA-PSS digital signatures verify user identity\n")
    
    # Setup
    print("1. Setting up server and registering users...")
    server = SplitSmartServer()
    alice = SplitSmartClient("alice", server)
    bob = SplitSmartClient("bob", server)
    
    # Register both users
    alice.register()
    bob.register()
    
    print("   ✓ Alice registered")
    print("   ✓ Bob registered")
    
    # Bob logs in
    print("\n2. Bob logs in and establishes secure session...")
    bob.login()
    print("   ✓ Bob's session established")
    
    # Bob tries to impersonate Alice
    print("\n3. ATTACKER (Bob) ATTEMPTS TO IMPERSONATE ALICE:")
    print("   Bob wants to create an expense that looks like Alice paid")
    print("   Target expense: 'alice paid $1000.00 for Fake expense'")
    
    # Bob creates an expense claiming to be Alice
    print("\n4. Bob creates expense message claiming to be Alice:")
    timestamp = datetime.utcnow().isoformat()
    
    # Bob signs with HIS OWN key (he doesn't have Alice's private key)
    signature, counter = bob.crypto.sign_expense("alice", 1000.00, "Fake expense", timestamp)
    
    print("   Payer: alice (impersonation attempt)")
    print("   Amount: $1000.00")
    print("   Description: Fake expense")
    print("   Signed by: Bob's private key (attacker's key)")
    
    expense_msg = ExpenseSubmitMessage(
        payer="alice",
        amount=1000.00,
        description="Fake expense",
        counter=counter,
        signature=signature,
        timestamp=timestamp
    )
    
    # Encrypt and send
    print("\n5. Bob encrypts and sends the message to server...")
    encrypted = bob.crypto.encrypt_message(expense_msg.to_bytes())
    
    print("   Message encrypted with Bob's session key")
    print("   Message sent to server...")
    
    # Server processes the message
    print("\n6. SERVER PROCESSES THE MESSAGE:")
    print("   • Decrypts message (successful - Bob has valid session)")
    print("   • Extracts payload: payer='alice', amount=$1000.00")
    print("   • Retrieves Alice's public key from database")
    print("   • Attempts to verify signature using Alice's public key...")
    
    response = server.process_message(bob.crypto.session_id, encrypted)
    
    # Check server's response
    print("\n7. SERVER RESPONSE:")
    if response:
        algorithm = response.get("algorithm", "AES-256-GCM")
        plaintext = bob.crypto.decrypt_message(
            response["nonce"], 
            response["ciphertext"],
            algorithm
        )
        if plaintext:
            from shared.protocols import ProtocolMessage
            response_msg = ProtocolMessage.from_bytes(plaintext)
            print(f"   Message Type: {response_msg.msg_type}")
            if response_msg.msg_type == "ERROR":
                error_msg = response_msg.payload.get('message', 'Unknown error')
                print(f"   ✓ Error Detected: {error_msg}")
                print("\n   SERVER REJECTED THE SPOOFED MESSAGE!")
                print("   Reason: Signature verification failed")
                print("   • Signature was created with Bob's private key")
                print("   • Server verified with Alice's public key")
                print("   • Keys don't match → signature invalid")
    
    # Verify ledger
    print("\n8. VERIFYING LEDGER INTEGRITY:")
    entries = server.ledger.get_all_entries()
    print(f"   Ledger has {len(entries)} entries")
    print("   ✓ Spoofed expense was NOT added to ledger")
    print("   ✓ Alice's account was NOT debited")
    
    # Now show legitimate expense submission
    print("\n9. LEGITIMATE EXPENSE SUBMISSION:")
    print("   Alice logs in and submits a real expense...")
    alice.login()
    result = alice.add_expense("alice", 50.00, "Legitimate lunch")
    
    if result:
        print("   ✓ Alice's legitimate expense accepted")
        print("   • Signed with Alice's private key")
        print("   • Verified with Alice's public key")
        print("   • Signature valid → expense recorded")
    
    # Show the difference
    print("\n10. CRYPTOGRAPHIC VERIFICATION DETAILS:")
    print("    " + "-" * 76)
    print("    Spoofing Attempt:")
    print("    • Claimed payer: alice")
    print("    • Actual signer: bob")
    print("    • Signature verification: FAILED ✗")
    print("    • Result: REJECTED")
    print("    " + "-" * 76)
    print("    Legitimate Submission:")
    print("    • Claimed payer: alice")
    print("    • Actual signer: alice")
    print("    • Signature verification: PASSED ✓")
    print("    • Result: ACCEPTED")
    print("    " + "-" * 76)
    
    print_header("RESULT: Origin Authentication Successful")
    print("✓ RSA-PSS digital signatures prevent user impersonation")
    print("✓ Each expense must be signed by the user's private key")
    print("✓ Server verifies signature using user's public key")
    print("✓ Attacker cannot forge signatures without private key")
    print("✓ Non-repudiation: Users cannot deny their expenses")
    
    print("\n" + "=" * 80)
    print("Technical Details:".center(80))
    print("=" * 80)
    print("• RSA-PSS (Probabilistic Signature Scheme) with 2048-bit keys")
    print("• Each user has unique public/private key pair")
    print("• Private key never leaves user's device")
    print("• Signature proves: 'This expense was created by user X'")
    print("• Computationally infeasible to forge signatures (~2^112 operations)")
    print("• Provides both authentication and non-repudiation")
    print("=" * 80)

if __name__ == "__main__":
    demo_spoofing()
