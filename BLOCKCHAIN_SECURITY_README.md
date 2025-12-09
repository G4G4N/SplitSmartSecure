# Blockchain Ledger & Security Documentation

## Overview

SplitSmart implements a **blockchain-inspired ledger** with comprehensive cryptographic security. This document explains how the encryption works, why it's secure, and how the blockchain ledger provides tamper-evident record-keeping.

## Blockchain Ledger Architecture

### Structure

Each expense entry is stored as a **block** in the blockchain with the following structure:

```
Block Structure:
├── Block Height (sequential number)
├── Previous Block Hash (links to previous block)
├── Merkle Root (hash of block contents)
├── Block Hash (hash of entire block)
├── Entry Data:
│   ├── User ID (who created the entry)
│   ├── Payer (who paid)
│   ├── Amount
│   ├── Description
│   ├── Timestamp
│   ├── Counter (replay protection)
│   └── Digital Signature (RSA-PSS)
└── Entry Hash (hash of entry data)
```

### Genesis Block

The first block in the chain links to a **genesis hash**:
- Genesis hash: SHA-256("SplitSmart Genesis Block")
- All subsequent blocks link to previous blocks
- Creates an immutable chain

### Hash Chain

Each block contains:
1. **Previous Hash**: Hash of the previous block
2. **Entry Hash**: Hash of current entry data
3. **Block Hash**: Hash of block metadata (height, prev_hash, merkle_root, timestamp)

**Formula:**
```
entry_hash = SHA256(prev_hash || entry_data)
block_hash = SHA256(height || prev_hash || merkle_root || timestamp)
```

### Merkle Root

For each block, a Merkle root is computed:
- Single entry blocks: Merkle root = entry hash
- Multiple entries: Merkle root = root of Merkle tree

This allows efficient verification of block contents.

## Three-Layer Cryptographic Security

### Layer 1: Handshake-Level Authentication

**Technology**: Signed Diffie-Hellman Key Exchange (Station-to-Station Protocol)

**How It Works:**
1. Client generates ephemeral DH key pair
2. Client signs DH public key with RSA-PSS private key
3. Server verifies signature using client's public key
4. Server generates ephemeral DH key pair
5. Server signs DH public key with RSA-PSS private key
6. Client verifies signature using server's public key
7. Both parties compute shared secret
8. Session key derived using HKDF-SHA256

**Security Properties:**
- ✅ **Mutual Authentication**: Both parties verify each other
- ✅ **Forward Secrecy**: Ephemeral keys protect past sessions
- ✅ **MITM Prevention**: Signatures prevent man-in-the-middle attacks
- ✅ **Key Strength**: 2048-bit DH + 2048-bit RSA = ≥128-bit security

### Layer 2: Per-Entry Authentication

**Technology**: RSA-PSS Digital Signatures

**How It Works:**
1. User creates expense record
2. Data to sign: `payer || amount || description || counter || timestamp`
3. Sign with user's private key using RSA-PSS
4. Server verifies signature using user's public key
5. If valid, entry is added to blockchain

**Security Properties:**
- ✅ **Non-Repudiation**: Users cannot deny creating expenses
- ✅ **Origin Verification**: Proves who created the entry
- ✅ **Tamper Detection**: Any modification breaks signature
- ✅ **Key Strength**: 2048-bit RSA = ~112-bit security

**Signature Algorithm:**
- **Padding**: PSS (Probabilistic Signature Scheme)
- **Hash**: SHA-256
- **MGF**: MGF1 with SHA-256
- **Salt Length**: Maximum (for security)

### Layer 3: Per-Message Protection

**Technology**: Multiple AEAD Encryption Algorithms

#### Algorithm Selection

The system automatically selects the best algorithm based on message size:

| Message Size | Algorithm | Reason |
|--------------|-----------|--------|
| < 1KB | ChaCha20-Poly1305 | Faster on software, mobile devices |
| 1KB - 10KB | AES-256-GCM | Balanced performance |
| > 10KB | AES-256-GCM | Hardware acceleration available |

#### AES-256-GCM

**How It Works:**
1. Generate random 96-bit nonce
2. Encrypt plaintext with AES-256
3. Compute authentication tag using GHASH
4. Output: nonce + ciphertext + tag

**Security Properties:**
- ✅ **Confidentiality**: 256-bit key strength
- ✅ **Authenticity**: 128-bit authentication tag
- ✅ **Integrity**: Any modification detected
- ✅ **Performance**: Hardware-accelerated on modern CPUs

**Key Derivation:**
- Session key derived from DH shared secret using HKDF-SHA256
- 256-bit key length
- Unique per session

#### ChaCha20-Poly1305

**How It Works:**
1. Generate random 96-bit nonce
2. Encrypt plaintext with ChaCha20 stream cipher
3. Compute authentication tag using Poly1305 MAC
4. Output: nonce + ciphertext + tag

**Security Properties:**
- ✅ **Confidentiality**: 256-bit key strength
- ✅ **Authenticity**: 128-bit authentication tag
- ✅ **Timing Resistance**: Constant-time operations
- ✅ **Performance**: Excellent software performance

#### AES-256-CBC-HMAC

**How It Works:**
1. Split key: 128 bits encryption + 128 bits MAC
2. Generate random 128-bit IV
3. Encrypt with AES-256-CBC (with PKCS7 padding)
4. Compute HMAC-SHA256 over IV || ciphertext
5. Output: IV + ciphertext + HMAC tag

**Security Properties:**
- ✅ **Confidentiality**: 256-bit encryption
- ✅ **Authenticity**: 256-bit HMAC
- ✅ **Encrypt-then-MAC**: Prevents padding oracle attacks
- ✅ **Compatibility**: Works with legacy systems

## Why This Is Secure

### 1. Multiple Layers of Defense

```
┌─────────────────────────────────────┐
│  Layer 3: Message Encryption        │  ← Prevents eavesdropping
│  (AES-GCM / ChaCha20-Poly1305)     │
├─────────────────────────────────────┤
│  Layer 2: Digital Signatures       │  ← Prevents spoofing
│  (RSA-PSS)                          │
├─────────────────────────────────────┤
│  Layer 1: Authenticated Key Exchange│  ← Prevents MITM
│  (Signed DH)                        │
└─────────────────────────────────────┘
```

### 2. Cryptographic Strength

All algorithms provide **≥128-bit security**:
- AES-256: 256-bit security
- ChaCha20: 256-bit security
- RSA-2048: ~112-bit security (still secure)
- SHA-256: 256-bit security
- DH-2048: ~112-bit security

### 3. Defense in Depth

Even if one layer is compromised, others provide protection:
- If encryption is broken → Signatures still protect
- If signatures are broken → Encryption still protects
- If key exchange is broken → Past sessions still protected (forward secrecy)

### 4. Tamper Evidence

**Blockchain Properties:**
- **Immutability**: Cannot modify past blocks without breaking chain
- **Detectability**: Any tampering immediately detected
- **Verifiability**: Anyone can verify chain integrity
- **Transparency**: All entries are cryptographically linked

**Tampering Detection:**
1. Hash chain verification on startup
2. Signature verification on each entry
3. Counter verification prevents replay
4. Block hash verification ensures integrity

### 5. Attack Resistance

| Attack | Defense | Result |
|--------|---------|--------|
| **Eavesdropping** | AES-256-GCM/ChaCha20 encryption | ✗ Cannot read messages |
| **Modification** | GCM tags + HMAC + Signatures | ✗ Tampering detected |
| **Spoofing** | RSA-PSS signatures | ✗ Cannot impersonate |
| **Replay** | Monotonic counters | ✗ Old messages rejected |
| **Tampering** | Hash chain | ✗ Chain breaks |
| **MITM** | Signed DH key exchange | ✗ Cannot intercept |
| **Brute Force** | Rate limiting + strong keys | ✗ Attacks prevented |

## Blockchain Security Features

### 1. Hash Chain

**How It Works:**
- Each block contains hash of previous block
- Creates cryptographic link between blocks
- Any modification breaks the chain

**Example:**
```
Genesis → Block 1 → Block 2 → Block 3
   ↓         ↓         ↓         ↓
 Hash0    Hash1    Hash2    Hash3
```

If Block 2 is modified:
- Block 2's hash changes
- Block 3's prev_hash no longer matches
- Chain breaks → Tampering detected!

### 2. Merkle Root

**How It Works:**
- Each block has Merkle root of its contents
- Allows efficient verification
- Changes to any entry change the root

**Benefits:**
- Fast verification (logarithmic time)
- Efficient proofs
- Tamper detection

### 3. Digital Signatures

**How It Works:**
- Every expense signed by creator's private key
- Server verifies signature before adding to blockchain
- Invalid signatures rejected

**Benefits:**
- Non-repudiation
- Origin authentication
- Tamper detection

### 4. Block Height

**How It Works:**
- Sequential numbering of blocks
- Prevents reordering attacks
- Enables efficient queries

### 5. Timestamp

**How It Works:**
- Each block has timestamp
- Used in block hash computation
- Prevents timestamp manipulation

## Security Guarantees

### Confidentiality
- ✅ All messages encrypted end-to-end
- ✅ Only authorized parties can decrypt
- ✅ Session keys never transmitted

### Integrity
- ✅ Authentication tags detect modifications
- ✅ Hash chain detects tampering
- ✅ Digital signatures verify authenticity

### Authentication
- ✅ Mutual authentication during key exchange
- ✅ Per-entry signatures verify origin
- ✅ Cannot impersonate without private key

### Non-Repudiation
- ✅ Digital signatures provide proof
- ✅ Users cannot deny their expenses
- ✅ Cryptographic evidence of actions

### Availability
- ✅ Rate limiting prevents DoS
- ✅ Request validation prevents attacks
- ✅ Efficient algorithms ensure performance

## Comparison to Traditional Blockchains

| Feature | Bitcoin/Ethereum | SplitSmart |
|---------|------------------|------------|
| Consensus | Proof of Work/Stake | Centralized (for small groups) |
| Blocks | Multiple transactions | One transaction per block |
| Mining | Required | Not required |
| Public/Private | Public ledger | Private ledger |
| Cryptography | ECDSA signatures | RSA-PSS signatures |
| Encryption | Not encrypted | Fully encrypted |
| Purpose | Public transactions | Private expense splitting |

**Key Differences:**
- SplitSmart is **private** (not public)
- SplitSmart uses **encryption** (Bitcoin doesn't)
- SplitSmart is **centralized** (suitable for small groups)
- SplitSmart focuses on **confidentiality** (Bitcoin focuses on decentralization)

## Security Best Practices Implemented

1. ✅ **Strong Cryptography**: All algorithms provide ≥128-bit security
2. ✅ **Key Management**: Keys stored securely, never transmitted
3. ✅ **Forward Secrecy**: Ephemeral keys protect past sessions
4. ✅ **Defense in Depth**: Multiple layers of security
5. ✅ **Input Validation**: All inputs validated and sanitized
6. ✅ **Rate Limiting**: Prevents brute force and DoS attacks
7. ✅ **Tamper Detection**: Hash chain detects any modifications
8. ✅ **Non-Repudiation**: Digital signatures provide proof
9. ✅ **Secure Headers**: HTTP security headers implemented
10. ✅ **Error Handling**: Generic errors prevent information leakage

## Mathematical Security

### Breaking Encryption

**AES-256-GCM:**
- Key space: 2^256 possibilities
- Brute force: ~2^256 operations required
- Estimated time: Longer than age of universe

**ChaCha20-Poly1305:**
- Key space: 2^256 possibilities
- Brute force: ~2^256 operations required
- Estimated time: Longer than age of universe

### Breaking Signatures

**RSA-2048:**
- Key space: ~2^112 possibilities (factoring)
- Best known attack: Number Field Sieve
- Estimated time: Decades with current technology

### Breaking Hash Chain

**SHA-256:**
- Hash space: 2^256 possibilities
- Collision resistance: 2^128 operations
- Preimage resistance: 2^256 operations
- Tampering requires: Breaking all subsequent blocks

## Real-World Security

### What Attackers See

**Without Session Key:**
```
Ciphertext: a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2
Nonce: x7y8z9a0b1c2d3e4f5g6h7i8j9k0l1m2
Algorithm: AES-256-GCM
```

**What They Cannot Do:**
- ✗ Decrypt the message
- ✗ Modify the message (tag verification fails)
- ✗ Replay the message (counter check fails)
- ✗ Forge a signature (without private key)

### Attack Scenarios

**Scenario 1: Network Eavesdropper**
- **Attack**: Intercepts encrypted messages
- **Defense**: AES-256-GCM encryption
- **Result**: ✗ Cannot decrypt without session key

**Scenario 2: Active Attacker**
- **Attack**: Modifies encrypted messages
- **Defense**: GCM authentication tags
- **Result**: ✗ Modification detected, message rejected

**Scenario 3: Impersonation**
- **Attack**: Tries to create expense as another user
- **Defense**: RSA-PSS signatures
- **Result**: ✗ Signature verification fails

**Scenario 4: Replay Attack**
- **Attack**: Resends old valid message
- **Defense**: Monotonic counters
- **Result**: ✗ Counter check rejects old message

**Scenario 5: Database Tampering**
- **Attack**: Modifies database directly
- **Defense**: Hash chain verification
- **Result**: ✗ Chain breaks, tampering detected

## Conclusion

SplitSmart provides **military-grade security** through:

1. **Multiple encryption algorithms** with automatic selection
2. **Three-layer cryptographic architecture** (key exchange, signatures, encryption)
3. **Blockchain ledger** with tamper-evident properties
4. **Comprehensive attack protection** (rate limiting, validation, sanitization)
5. **Strong cryptographic primitives** (≥128-bit security throughout)

The system is designed to be **secure by default** and **resistant to common attacks**, making it suitable for sensitive financial data in expense splitting scenarios.

