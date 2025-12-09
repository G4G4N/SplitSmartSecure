#!/usr/bin/env python3
"""
Test cryptographic operations in isolation.
"""

from shared.crypto_primitives import CryptoPrimitives

def test_aes_gcm():
    print("Testing AES-GCM encryption/decryption...")
    
    # Generate a key
    key = CryptoPrimitives.derive_session_key(b"test_shared_secret")
    print(f"Key length: {len(key)} bytes")
    
    # Test data
    plaintext = b"Hello, World! This is a test message."
    print(f"Plaintext: {plaintext}")
    
    # Encrypt
    nonce, ciphertext = CryptoPrimitives.aes_gcm_encrypt(key, plaintext)
    print(f"Nonce length: {len(nonce)} bytes")
    print(f"Ciphertext length: {len(ciphertext)} bytes")
    
    # Decrypt
    decrypted = CryptoPrimitives.aes_gcm_decrypt(key, nonce, ciphertext)
    print(f"Decrypted: {decrypted}")
    
    if decrypted == plaintext:
        print("✓ AES-GCM test passed!")
        return True
    else:
        print("✗ AES-GCM test failed!")
        return False

def test_signatures():
    print("\nTesting RSA signatures...")
    
    # Generate keys
    private_key, public_key = CryptoPrimitives.generate_rsa_keypair()
    print("✓ Keys generated")
    
    # Test data
    data = b"This is the data to sign"
    
    # Sign
    signature = CryptoPrimitives.sign_data(private_key, data)
    print(f"Signature length: {len(signature)} bytes")
    
    # Verify
    is_valid = CryptoPrimitives.verify_signature(public_key, data, signature)
    print(f"Signature valid: {is_valid}")
    
    if is_valid:
        print("✓ Signature test passed!")
        return True
    else:
        print("✗ Signature test failed!")
        return False

def test_hash_chain():
    print("\nTesting hash chain...")
    
    genesis = CryptoPrimitives.hash_data(b"Genesis Block")
    print(f"Genesis hash: {genesis.hex()[:16]}...")
    
    data1 = b"Entry 1"
    hash1 = CryptoPrimitives.hash_chain_link(genesis, data1)
    print(f"Hash 1: {hash1.hex()[:16]}...")
    
    data2 = b"Entry 2"
    hash2 = CryptoPrimitives.hash_chain_link(hash1, data2)
    print(f"Hash 2: {hash2.hex()[:16]}...")
    
    # Verify chain
    recomputed_hash1 = CryptoPrimitives.hash_chain_link(genesis, data1)
    recomputed_hash2 = CryptoPrimitives.hash_chain_link(hash1, data2)
    
    if hash1 == recomputed_hash1 and hash2 == recomputed_hash2:
        print("✓ Hash chain test passed!")
        return True
    else:
        print("✗ Hash chain test failed!")
        return False

if __name__ == "__main__":
    print("=" * 80)
    print("Testing Cryptographic Primitives")
    print("=" * 80)
    
    results = []
    results.append(test_aes_gcm())
    results.append(test_signatures())
    results.append(test_hash_chain())
    
    print("\n" + "=" * 80)
    if all(results):
        print("✓ All cryptographic tests passed!")
    else:
        print("✗ Some tests failed!")
    print("=" * 80)
