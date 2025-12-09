#!/usr/bin/env python3
"""
Test signature creation and verification for expenses.
"""

from datetime import datetime
from shared.crypto_primitives import CryptoPrimitives
from shared.protocols import create_expense_data_for_signing, ExpenseSubmitMessage
from client.crypto_client import ClientCrypto

# Create client
client = ClientCrypto("alice")
client.generate_keys()

# Create expense data
payer = "alice"
amount = 50.00
description = "Test expense"
timestamp = datetime.utcnow().isoformat()

print("="*80)
print("Testing Expense Signature")
print("="*80)

# Client signs
signature_b64, counter = client.sign_expense(payer, amount, description, timestamp)
print(f"\n1. Client signed expense:")
print(f"   Payer: {payer}")
print(f"   Amount: {amount}")
print(f"   Description: {description}")
print(f"   Counter: {counter}")
print(f"   Timestamp: {timestamp}")
print(f"   Signature: {signature_b64[:50]}...")

# Create expense message
expense_msg = ExpenseSubmitMessage(
    payer=payer,
    amount=amount,
    description=description,
    counter=counter,
    signature=signature_b64
)

print(f"\n2. Created ExpenseSubmitMessage:")
print(f"   Message timestamp: {expense_msg.timestamp}")
print(f"   Payload timestamp: (not included)")

# Serialize and deserialize
msg_bytes = expense_msg.to_bytes()
recovered_msg = ExpenseSubmitMessage.from_bytes(msg_bytes)

print(f"\n3. After serialization:")
print(f"   Message timestamp: {recovered_msg.timestamp}")
print(f"   Payload: {recovered_msg.payload}")

# Now verify signature (as server would)
from shared.crypto_primitives import MessageEncoder

payload = recovered_msg.payload
signature = MessageEncoder.b64decode(payload["signature"])

# Try with message timestamp (WRONG)
print(f"\n4. Verifying with message timestamp (WRONG):")
data_wrong = create_expense_data_for_signing(
    payload["payer"],
    payload["amount"],
    payload["description"],
    payload["counter"],
    recovered_msg.timestamp  # This is WRONG - it's the wrapper timestamp
)
is_valid_wrong = CryptoPrimitives.verify_signature(client.public_key, data_wrong, signature)
print(f"   Valid: {is_valid_wrong}")

# Try with original timestamp (CORRECT)
print(f"\n5. Verifying with original timestamp (CORRECT):")
data_correct = create_expense_data_for_signing(
    payload["payer"],
    payload["amount"],
    payload["description"],
    payload["counter"],
    timestamp  # This is CORRECT - the original timestamp
)
is_valid_correct = CryptoPrimitives.verify_signature(client.public_key, data_correct, signature)
print(f"   Valid: {is_valid_correct}")

print("\n" + "="*80)
print("ISSUE IDENTIFIED:")
print("The signature is created with the expense timestamp,")
print("but the server is trying to verify with the message wrapper timestamp!")
print("="*80)
