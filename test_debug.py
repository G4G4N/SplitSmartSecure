#!/usr/bin/env python3
"""
Debug test to see what's happening with encryption/decryption.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient
import json

server = SplitSmartServer()
alice = SplitSmartClient('alice', server)
alice.register()
alice.login()

# Try to add expense
print('\n' + '='*80)
print('Attempting to add expense...')
print('='*80)

# Create expense message manually to see what happens
from shared.protocols import ExpenseSubmitMessage
from datetime import datetime

timestamp = datetime.utcnow().isoformat()
signature, counter = alice.crypto.sign_expense('alice', 50.00, 'Test', timestamp)

expense_msg = ExpenseSubmitMessage(
    payer='alice',
    amount=50.00,
    description='Test',
    counter=counter,
    signature=signature
)

print(f"\nExpense message created:")
print(f"  Counter: {counter}")
print(f"  Signature length: {len(signature)}")

# Encrypt message
encrypted = alice.crypto.encrypt_message(expense_msg.to_bytes())
print(f"\nEncrypted message:")
print(f"  Nonce: {encrypted['nonce'][:20]}...")
print(f"  Ciphertext length: {len(encrypted['ciphertext'])}")

# Send to server
print(f"\nSending to server (session: {alice.crypto.session_id})...")
response_dict = server.process_message(alice.crypto.session_id, encrypted)

print(f"\nServer response:")
print(f"  Keys: {list(response_dict.keys())}")
if 'nonce' in response_dict:
    print(f"  Nonce: {response_dict['nonce'][:20]}...")
    print(f"  Ciphertext length: {len(response_dict['ciphertext'])}")
    
    # Try to decrypt
    print(f"\nAttempting to decrypt response...")
    plaintext = alice.crypto.decrypt_message(response_dict["nonce"], response_dict["ciphertext"])
    if plaintext:
        print(f"  ✓ Decryption successful!")
        print(f"  Plaintext length: {len(plaintext)}")
    else:
        print(f"  ✗ Decryption failed!")
        
        # Try to see what the server's session key is
        print(f"\nDebug info:")
        print(f"  Client session key: {alice.crypto.session_key.hex()[:32]}...")
        server_session = server.crypto.get_session(alice.crypto.session_id)
        if server_session:
            print(f"  Server session key: {server_session['session_key'].hex()[:32]}...")
            if alice.crypto.session_key == server_session['session_key']:
                print(f"  ✓ Keys match!")
            else:
                print(f"  ✗ Keys don't match!")
else:
    print(f"  Response type: {response_dict.get('msg_type')}")
    print(f"  Full response: {json.dumps(response_dict, indent=2)}")
