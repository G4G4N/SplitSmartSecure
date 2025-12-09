#!/usr/bin/env python3
"""
Debug key exchange process.
"""

from server.crypto_server import ServerCrypto
from client.crypto_client import ClientCrypto
from shared.crypto_primitives import CryptoPrimitives

print("="*80)
print("Testing Key Exchange")
print("="*80)

# Initialize server crypto
server_crypto = ServerCrypto()
print("\n1. Server initialized")
print(f"   Server public key: {server_crypto.get_public_key_pem()[:50]}...")

# Initialize client crypto
client_crypto = ClientCrypto("test_user")
client_crypto.generate_keys()
print("\n2. Client initialized")
print(f"   Client public key: {client_crypto.get_public_key_pem()[:50]}...")

# Get DH parameters from server
dh_params = server_crypto.dh_parameters
print("\n3. Got DH parameters from server")

# Client initiates key exchange
client_hello_data = client_crypto.initiate_key_exchange(dh_params)
print("\n4. Client initiated key exchange")
print(f"   Client DH public key: {client_hello_data['dh_public_key'][:50]}...")
print(f"   Client signature: {client_hello_data['signature'][:50]}...")

# Server handles client hello
client_public_key = CryptoPrimitives.load_public_key(client_crypto.get_public_key_pem().encode('utf-8'))
server_hello_data = server_crypto.handle_client_hello(
    "test_user",
    client_hello_data["dh_public_key"],
    client_hello_data["signature"],
    client_public_key
)

if not server_hello_data:
    print("\n✗ Server failed to handle client hello!")
    exit(1)

print("\n5. Server handled client hello")
print(f"   Server DH public key: {server_hello_data['dh_public_key'][:50]}...")
print(f"   Server signature: {server_hello_data['signature'][:50]}...")
print(f"   Session ID: {server_hello_data['session_id']}")

# Client completes key exchange
server_public_key = CryptoPrimitives.load_public_key(server_crypto.get_public_key_pem().encode('utf-8'))
success = client_crypto.complete_key_exchange(
    server_dh_public_key_b64=server_hello_data["dh_public_key"],
    server_signature_b64=server_hello_data["signature"],
    server_public_key=server_public_key,
    session_id=server_hello_data["session_id"]
)

if not success:
    print("\n✗ Client failed to complete key exchange!")
    exit(1)

print("\n6. Client completed key exchange")
print(f"   Client session ID: {client_crypto.session_id}")
print(f"   Client session key: {client_crypto.session_key.hex()[:32]}...")

# Get server session
server_session = server_crypto.get_session(server_hello_data["session_id"])
print(f"\n7. Server session:")
print(f"   Server session key: {server_session['session_key'].hex()[:32]}...")

# Compare keys
print(f"\n8. Comparing keys:")
if client_crypto.session_key == server_session['session_key']:
    print("   ✓ Keys match!")
else:
    print("   ✗ Keys don't match!")
    print(f"   Client key: {client_crypto.session_key.hex()}")
    print(f"   Server key: {server_session['session_key'].hex()}")
    exit(1)

# Test encryption/decryption
print(f"\n9. Testing encryption/decryption:")
test_message = b"Hello, this is a test message!"
print(f"   Original: {test_message}")

# Client encrypts
encrypted = client_crypto.encrypt_message(test_message)
print(f"   Encrypted nonce: {encrypted['nonce'][:20]}...")
print(f"   Encrypted ciphertext length: {len(encrypted['ciphertext'])}")

# Server decrypts
decrypted = server_crypto.decrypt_message(
    server_hello_data["session_id"],
    encrypted["nonce"],
    encrypted["ciphertext"]
)

if decrypted == test_message:
    print(f"   ✓ Server decrypted successfully: {decrypted}")
else:
    print(f"   ✗ Server decryption failed!")
    print(f"   Expected: {test_message}")
    print(f"   Got: {decrypted}")
    exit(1)

# Server encrypts
encrypted2 = server_crypto.encrypt_message(server_hello_data["session_id"], test_message)
print(f"\n10. Server encrypts:")
print(f"   Encrypted nonce: {encrypted2['nonce'][:20]}...")

# Client decrypts
decrypted2 = client_crypto.decrypt_message(encrypted2["nonce"], encrypted2["ciphertext"])

if decrypted2 == test_message:
    print(f"   ✓ Client decrypted successfully: {decrypted2}")
else:
    print(f"   ✗ Client decryption failed!")
    print(f"   Expected: {test_message}")
    print(f"   Got: {decrypted2}")
    exit(1)

print("\n" + "="*80)
print("✓ All key exchange tests passed!")
print("="*80)
