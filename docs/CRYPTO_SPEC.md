# SplitSmart - Cryptographic Specification

## Table of Contents
1. [Overview](#overview)
2. [Cryptographic Primitives](#cryptographic-primitives)
3. [Key Management](#key-management)
4. [Authenticated Key Exchange](#authenticated-key-exchange)
5. [Message Encryption](#message-encryption)
6. [Digital Signatures](#digital-signatures)
7. [Hash Chain](#hash-chain)
8. [Replay Protection](#replay-protection)
9. [Cryptographic Receipts](#cryptographic-receipts)
10. [Security Analysis](#security-analysis)
11. [Implementation Details](#implementation-details)

---

## Overview

### Purpose
This document specifies all cryptographic mechanisms used in SplitSmart to achieve end-to-end security against eavesdropping, modification, spoofing, replay, and ledger tampering attacks.

### Security Goals

| Goal | Mechanism | Primitive |
|------|-----------|-----------|
| Confidentiality | Encryption | AES-256-GCM |
| Integrity | Authentication | GCM Tag + RSA-PSS |
| Authentication | Digital Signatures | RSA-PSS |
| Freshness | Counters | Monotonic Integers |
| Tamper Evidence | Hash Chain | SHA-256 |
| Forward Secrecy | Ephemeral Keys | DH-2048 |
| Non-Repudiation | Signatures + Receipts | RSA-PSS |

### Cryptographic Library
- **Library**: Python `cryptography` (v41.0.0+)
- **Backend**: OpenSSL
- **Rationale**: Industry-standard, well-audited, actively maintained

---

## Cryptographic Primitives

### 1. RSA (Rivest-Shamir-Adleman)

**Purpose**: Long-term identity keys, digital signatures

**Parameters:**
- Key size: 2048 bits
- Public exponent: 65537 (0x10001)
- Security level: ~112 bits

**Key Generation:**
```python
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()
```

**Justification:**
- 2048-bit RSA provides ~112-bit security
- Recommended by NIST until 2030
- Widely supported and understood
- Sufficient for academic demonstration

**Security Properties:**
- Hardness assumption: Integer factorization
- Best known attack: General Number Field Sieve (GNFS)
- Complexity: ~2¹¹² operations for 2048-bit keys

### 2. RSA-PSS (Probabilistic Signature Scheme)

**Purpose**: Digital signatures on expenses and receipts

**Parameters:**
- Signature scheme: RSA-PSS
- Hash function: SHA-256
- MGF (Mask Generation Function): MGF1 with SHA-256
- Salt length: Maximum (key_size - hash_size - 2)

**Signing:**
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signature = private_key.sign(
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**Verification:**
```python
public_key.verify(
    signature,
    data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**Justification:**
- PSS is provably secure (tight security reduction)
- Randomized (different signatures for same message)
- Resistant to existential forgery
- PKCS#1 v2.2 standard

**Security Properties:**
- Unforgeability under chosen message attack (UF-CMA)
- Security reduction to RSA problem
- Randomized padding prevents attacks

### 3. Diffie-Hellman Key Exchange

**Purpose**: Establish shared secret for session key derivation

**Parameters:**
- Group: MODP (Modular Exponentiation) Group
- Modulus size: 2048 bits
- Generator: 2
- Security level: ~112 bits

**Parameter Generation:**
```python
from cryptography.hazmat.primitives.asymmetric import dh

parameters = dh.generate_parameters(
    generator=2,
    key_size=2048
)
```

**Key Generation:**
```python
private_key = parameters.generate_private_key()
public_key = private_key.public_key()
```

**Shared Secret Computation:**
```python
shared_secret = private_key.exchange(peer_public_key)
```

**Justification:**
- 2048-bit DH provides ~112-bit security
- Matches RSA security level
- Enables forward secrecy with ephemeral keys
- Well-studied and standardized (RFC 2631)

**Security Properties:**
- Hardness assumption: Discrete Logarithm Problem (DLP)
- Best known attack: General Number Field Sieve
- Complexity: ~2¹¹² operations for 2048-bit group

### 4. AES-GCM (Advanced Encryption Standard - Galois/Counter Mode)

**Purpose**: Authenticated encryption of messages

**Parameters:**
- Key size: 256 bits
- Nonce size: 96 bits (12 bytes)
- Tag size: 128 bits (16 bytes)
- Security level: 128 bits

**Encryption:**
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

aesgcm = AESGCM(key)  # key is 32 bytes
nonce = os.urandom(12)  # 96-bit nonce
ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)
# ciphertext includes 16-byte authentication tag
```

**Decryption:**
```python
plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
# Raises exception if authentication fails
```

**Justification:**
- AEAD provides both confidentiality and authenticity
- Single primitive (simpler than encrypt-then-MAC)
- Efficient (hardware acceleration available)
- NIST approved (SP 800-38D)

**Security Properties:**
- IND-CPA: Indistinguishability under chosen plaintext attack
- INT-CTXT: Integrity of ciphertexts
- Nonce reuse catastrophic (must be unique per key)
- Tag forgery probability: 2⁻¹²⁸

**Nonce Management:**
- Generate random 96-bit nonce for each message
- Probability of collision: negligible for reasonable message counts
- Alternative: Counter-based nonces (requires state)

### 5. SHA-256 (Secure Hash Algorithm)

**Purpose**: Hash chain for ledger integrity

**Parameters:**
- Output size: 256 bits (32 bytes)
- Block size: 512 bits
- Security level: 128 bits (collision resistance)

**Hashing:**
```python
from cryptography.hazmat.primitives import hashes

digest = hashes.Hash(hashes.SHA256())
digest.update(data)
hash_value = digest.finalize()
```

**Justification:**
- 256-bit output provides 128-bit collision resistance
- Widely used and well-studied
- FIPS 180-4 standard
- Sufficient for hash chain application

**Security Properties:**
- Preimage resistance: 2²⁵⁶ operations
- Second preimage resistance: 2²⁵⁶ operations
- Collision resistance: 2¹²⁸ operations (birthday bound)

### 6. HKDF (HMAC-based Key Derivation Function)

**Purpose**: Derive session key from DH shared secret

**Parameters:**
- Hash function: SHA-256
- Salt: Empty (b'')
- Info: b'session_key'
- Output length: 32 bytes (256 bits)

**Key Derivation:**
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=b'',  # Empty salt for deterministic derivation
    info=b'session_key'
)
session_key = kdf.derive(shared_secret)
```

**Justification:**
- RFC 5869 standard
- Extracts uniform randomness from DH shared secret
- Expands to desired key length
- Cryptographically sound

**Security Properties:**
- Pseudorandom function (PRF)
- Extract-then-expand paradigm
- Security reduction to HMAC

---

## Key Management

### Key Types

#### 1. Long-Term Keys (RSA-2048)

**Server Keys:**
- **Private Key**: `keys/server_private.pem`
- **Public Key**: `keys/server_public.pem`
- **Purpose**: Sign DH parameters, generate receipts
- **Lifetime**: Indefinite (should rotate periodically)

**User Keys:**
- **Private Key**: `keys/{user}_private.pem`
- **Public Key**: `keys/{user}_public.pem`
- **Purpose**: Sign expenses, authenticate in key exchange
- **Lifetime**: Indefinite (per user)

**Storage Format**: PEM (Privacy-Enhanced Mail)
```
-----BEGIN PRIVATE KEY-----
Base64-encoded DER
-----END PRIVATE KEY-----
```

**Protection**: 
- Private keys stored on local filesystem
- Permissions: 600 (read/write owner only)
- No encryption at rest (acceptable for demo)
- Production: Use hardware security module (HSM) or encrypted storage

#### 2. Ephemeral Keys (DH-2048)

**Purpose**: Forward secrecy in key exchange

**Lifetime**: Single session

**Generation**: On-demand for each session

**Destruction**: Discarded after session key derivation

**Security Benefit**: 
- Compromise of long-term keys doesn't reveal past session keys
- Each session has independent security

#### 3. Session Keys (AES-256)

**Purpose**: Encrypt/decrypt messages in a session

**Derivation**: HKDF from DH shared secret

**Lifetime**: Single session (in-memory only)

**Storage**: Server maintains session dictionary:
```python
sessions = {
    "session_id": {
        "user_id": "alice",
        "session_key": bytes(32),  # AES-256 key
        "created_at": timestamp
    }
}
```

**Destruction**: Removed on logout or timeout

### Key Generation

#### Server Initialization
```python
# Generate server keys (once)
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Generate DH parameters (once, takes 2-5 seconds)
dh_parameters = dh.generate_parameters(
    generator=2,
    key_size=2048
)

# Save to disk
save_private_key(server_private_key, "keys/server_private.pem")
save_public_key(server_private_key.public_key(), "keys/server_public.pem")
save_dh_parameters(dh_parameters, "keys/dh_parameters.pem")
```

#### User Registration
```python
# Generate user keys
user_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# Save to disk
save_private_key(user_private_key, f"keys/{user_id}_private.pem")
save_public_key(user_private_key.public_key(), f"keys/{user_id}_public.pem")

# Send public key to server
server.register_user(user_id, public_key_pem)
```

### Key Distribution

**Public Keys**: 
- Distributed openly (no confidentiality needed)
- Server stores user public keys in database
- Clients have server public key (pre-distributed or first-use)

**Private Keys**:
- Never transmitted
- Remain on generating device
- Used only for signing/decryption

**Trust Model**:
- Trust on first use (TOFU) for server key
- Out-of-band verification recommended (e.g., fingerprint comparison)
- Production: Use PKI or web of trust

---

## Authenticated Key Exchange

### Protocol: Signed Diffie-Hellman (STS-style)

**Goal**: Establish shared session key with mutual authentication

**Security Properties**:
- Mutual authentication
- Forward secrecy
- MITM protection
- Key confirmation

### Protocol Flow

```
Client (Alice)                                    Server
─────────────────────────────────────────────────────────────
Load private key: SK_A
Load server public key: PK_S

Generate ephemeral DH key pair:
  (dh_private_A, dh_public_A) ← DH.KeyGen()

Sign DH public key:
  sig_A ← Sign(SK_A, dh_public_A || user_id)

Send CLIENT_HELLO:
  {user_id, dh_public_A, sig_A} ──────────────────→

                                    Receive CLIENT_HELLO
                                    
                                    Load user public key: PK_A
                                    
                                    Verify signature:
                                      Verify(PK_A, dh_public_A || user_id, sig_A)
                                    
                                    Generate ephemeral DH key pair:
                                      (dh_private_S, dh_public_S) ← DH.KeyGen()
                                    
                                    Sign DH public key:
                                      sig_S ← Sign(SK_S, dh_public_S)
                                    
                                    Compute shared secret:
                                      secret ← DH(dh_private_S, dh_public_A)
                                    
                                    Derive session key:
                                      K_session ← HKDF(secret, salt=b'', info=b'session_key')
                                    
                                    Create session:
                                      session_id ← random_uuid()
                                      sessions[session_id] ← {user_id, K_session}

                                    Send SERVER_HELLO:
←──────────────────  {dh_public_S, dh_parameters, sig_S, session_id}

Receive SERVER_HELLO

Verify signature:
  Verify(PK_S, dh_public_S, sig_S)

Compute shared secret:
  secret ← DH(dh_private_A, dh_public_S)

Derive session key:
  K_session ← HKDF(secret, salt=b'', info=b'session_key')

Store session:
  session_id, K_session

─────────────────────────────────────────────────────────────
Session established: Both parties have K_session
```

### Security Analysis

**Mutual Authentication**:
- Client proves identity by signing with SK_A
- Server proves identity by signing with SK_S
- MITM cannot forge signatures without private keys

**Forward Secrecy**:
- Ephemeral DH keys used once per session
- Compromise of SK_A or SK_S doesn't reveal past K_session
- Each session has independent security

**MITM Protection**:
- Attacker cannot compute shared secret without DH private keys
- Attacker cannot forge signatures
- Signed DH public keys bind identity to ephemeral keys

**Key Confirmation**:
- Implicit: Successful decryption of first message confirms key
- Explicit confirmation not needed (AEAD provides authentication)

### Implementation Details

**DH Shared Secret Computation**:
```python
# Client side
shared_secret = client_dh_private.exchange(server_dh_public)

# Server side
shared_secret = server_dh_private.exchange(client_dh_public)

# Both compute same value
assert client_shared_secret == server_shared_secret
```

**Session Key Derivation**:
```python
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

kdf = HKDF(
    algorithm=hashes.SHA256(),
    length=32,  # 256 bits for AES-256
    salt=b'',   # Empty salt for deterministic derivation
    info=b'session_key'
)
session_key = kdf.derive(shared_secret)
```

**Why Empty Salt?**:
- Ensures both parties derive identical key
- Shared secret already has high entropy
- Deterministic derivation simplifies implementation
- Security not compromised (shared secret is random)

---

## Message Encryption

### Encryption Scheme: AES-256-GCM

**Purpose**: Provide confidentiality and integrity for all messages

**Process**:

1. **Encryption** (Client → Server):
```python
# Generate random nonce
nonce = os.urandom(12)  # 96 bits

# Encrypt message
aesgcm = AESGCM(session_key)
ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext, None)

# Send: {nonce, ciphertext_with_tag}
```

2. **Decryption** (Server):
```python
# Decrypt and verify
aesgcm = AESGCM(session_key)
try:
    plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, None)
except InvalidTag:
    # Authentication failed - reject message
    return ERROR
```

### Message Format

**Plaintext Message** (before encryption):
```json
{
  "type": "EXPENSE_SUBMIT",
  "timestamp": "2024-12-08T12:34:56.789Z",
  "payload": {
    "payer": "alice",
    "amount": 50.00,
    "description": "Lunch",
    "counter": 5,
    "signature": "base64_encoded_signature",
    "timestamp": "2024-12-08T12:34:56.789Z"
  }
}
```

**Encrypted Message** (transmitted):
```json
{
  "nonce": "base64_encoded_12_byte_nonce",
  "ciphertext": "base64_encoded_ciphertext_with_16_byte_tag"
}
```

### Security Properties

**Confidentiality**:
- Ciphertext reveals no information about plaintext
- IND-CPA secure (indistinguishability under chosen plaintext attack)
- Security level: 256-bit key → 2²⁵⁶ possible keys

**Integrity**:
- 128-bit authentication tag
- Any modification detected with probability 1 - 2⁻¹²⁸
- Forgery computationally infeasible

**Authenticity**:
- Only holder of session_key can create valid ciphertext
- Provides implicit authentication

### Nonce Management

**Requirements**:
- Must be unique for each message under same key
- Reuse catastrophic (breaks confidentiality and authenticity)

**Implementation**:
- Generate random 96-bit nonce per message
- Collision probability negligible:
  - After 2⁴⁸ messages: ~2⁻⁴⁸ collision probability
  - Acceptable for session lifetime

**Alternative** (not implemented):
- Counter-based nonces (requires state synchronization)
- Advantage: No collision risk
- Disadvantage: More complex, requires careful state management

---

## Digital Signatures

### Signature Scheme: RSA-PSS with SHA-256

**Purpose**: Authenticate expense entries and receipts

### Expense Signing

**Data to Sign**:
```json
{
  "payer": "alice",
  "amount": 50.00,
  "description": "Lunch",
  "counter": 5,
  "timestamp": "2024-12-08T12:34:56.789Z"
}
```

**Canonical Representation**:
```python
import json

# Sort keys for deterministic serialization
canonical_data = json.dumps(expense_dict, sort_keys=True).encode('utf-8')
```

**Signing Process**:
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

signature = user_private_key.sign(
    canonical_data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**Verification Process**:
```python
try:
    user_public_key.verify(
        signature,
        canonical_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    # Signature valid
except InvalidSignature:
    # Signature invalid - reject
```

### Receipt Signing

**Data to Sign**:
```json
{
  "entry_id": 42,
  "entry_hash": "abc123...",
  "user_id": "alice",
  "timestamp": "2024-12-08T12:34:57.000Z"
}
```

**Signing** (by server):
```python
receipt_signature = server_private_key.sign(
    canonical_receipt_data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

**Verification** (by client):
```python
server_public_key.verify(
    receipt_signature,
    canonical_receipt_data,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
```

### Security Properties

**Unforgeability**:
- UF-CMA: Unforgeable under chosen message attack
- Attacker cannot create valid signature without private key
- Security reduction to RSA problem

**Non-Repudiation**:
- Signer cannot deny creating signature
- Provides proof of origin
- Legally binding (in principle)

**Integrity**:
- Any modification to signed data invalidates signature
- Detects tampering

---

## Hash Chain

### Purpose
Provide tamper-evident history of ledger entries

### Structure

```
Genesis Block:
  H₀ = SHA256("SplitSmart Genesis Block")

Entry 1:
  data₁ = {id, user_id, payer, amount, description, timestamp, counter, signature}
  H₁ = SHA256(H₀ || data₁)

Entry 2:
  data₂ = {id, user_id, payer, amount, description, timestamp, counter, signature}
  H₂ = SHA256(H₁ || data₂)

...

Entry n:
  dataₙ = {id, user_id, payer, amount, description, timestamp, counter, signature}
  Hₙ = SHA256(Hₙ₋₁ || dataₙ)
```

### Hash Computation

**Entry Data Serialization**:
```python
entry_data = {
    "id": entry_id,
    "user_id": user_id,
    "payer": payer,
    "amount": amount,
    "description": description,
    "timestamp": timestamp,
    "counter": counter,
    "signature": signature
}

# Canonical representation
canonical = json.dumps(entry_data, sort_keys=True).encode('utf-8')
```

**Hash Calculation**:
```python
from cryptography.hazmat.primitives import hashes

# Concatenate previous hash and entry data
combined = prev_hash_bytes + canonical_entry_data

# Compute hash
digest = hashes.Hash(hashes.SHA256())
digest.update(combined)
entry_hash = digest.finalize()
```

### Integrity Verification

**On Server Startup**:
```python
def verify_chain_integrity():
    entries = get_all_ledger_entries()
    
    # Start with genesis hash
    expected_hash = genesis_hash
    
    for entry in entries:
        # Recompute hash
        computed_hash = SHA256(expected_hash || entry_data)
        
        # Compare with stored hash
        if computed_hash != entry.stored_hash:
            return False, f"Hash mismatch at entry {entry.id}"
        
        # Update for next iteration
        expected_hash = computed_hash
    
    return True, "Chain integrity verified"
```

**By Client**:
```python
def verify_ledger(ledger, genesis_hash):
    expected_hash = genesis_hash
    
    for entry in ledger:
        computed_hash = SHA256(expected_hash || entry_data)
        
        if computed_hash != entry.hash:
            return False
        
        expected_hash = computed_hash
    
    return True
```

### Security Properties

**Tamper Evidence**:
- Any modification to entry breaks chain
- Modification detected with probability 1
- Cannot be hidden (chain break is obvious)

**Append-Only**:
- Cannot insert entries in middle (breaks chain)
- Cannot delete entries (breaks chain)
- Can only append to end

**Collision Resistance**:
- Finding two entries with same hash: ~2¹²⁸ operations
- Computationally infeasible

**Preimage Resistance**:
- Given hash, finding entry: ~2²⁵⁶ operations
- Computationally infeasible

---

## Replay Protection

### Mechanism: Monotonic Counters

**Purpose**: Prevent replay of old valid messages

### Implementation

**Per-User Counter**:
- Each user has counter starting at 0
- Stored in database: `users.counter`
- Incremented on each successful operation

**Client Side**:
```python
class ClientCrypto:
    def __init__(self, user_id):
        self.counter = 0  # Initialize
    
    def sign_expense(self, payer, amount, description, timestamp):
        self.counter += 1  # Increment before use
        
        expense_data = create_expense_data(
            payer, amount, description, 
            self.counter, timestamp
        )
        
        signature = sign(self.private_key, expense_data)
        
        return signature, self.counter
```

**Server Side**:
```python
def handle_expense_submit(user_id, counter, ...):
    # Get stored counter
    stored_counter = storage.get_user_counter(user_id)
    
    # Verify strictly increasing
    if counter <= stored_counter:
        return ERROR_REPLAY_DETECTED
    
    # Process expense...
    
    # Update counter
    storage.update_user_counter(user_id, counter)
    
    return SUCCESS
```

### Security Properties

**Replay Prevention**:
- Old messages have counter ≤ stored_counter
- Rejected deterministically
- No false positives (legitimate messages never rejected)

**Freshness**:
- Counter proves message is "new"
- Provides ordering of messages

**Limitations**:
- Requires state (stored counter)
- Counter can overflow (after 2⁶⁴ messages)
- Lost messages create gap (acceptable)

### Alternative: Timestamps

**Not Used** (but considered):
- Timestamp-based freshness
- Accept if: `|timestamp - server_time| < threshold`

**Problems**:
- Requires clock synchronization
- Vulnerable to clock manipulation
- Replay window (threshold period)

**Why Counters Better**:
- No clock synchronization needed
- Deterministic (no threshold)
- Perfect replay prevention

---

## Cryptographic Receipts

### Purpose
Provide non-repudiation proof that server accepted expense

### Receipt Structure

**Data**:
```json
{
  "entry_id": 42,
  "entry_hash": "abc123...",
  "user_id": "alice",
  "timestamp": "2024-12-08T12:34:57.000Z"
}
```

**Signature**: Server signs receipt data with private key

**Receipt**:
```json
{
  "entry_id": 42,
  "entry_hash": "abc123...",
  "user_id": "alice",
  "timestamp": "2024-12-08T12:34:57.000Z",
  "signature": "base64_encoded_server_signature"
}
```

### Generation (Server)

```python
def generate_receipt(entry_id, entry_hash, user_id):
    # Create receipt data
    receipt_timestamp = datetime.utcnow().isoformat()
    receipt_data = create_receipt_data(
        entry_id, entry_hash, user_id, receipt_timestamp
    )
    
    # Sign with server private key
    signature = server_private_key.sign(
        receipt_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    
    return {
        "entry_id": entry_id,
        "entry_hash": entry_hash,
        "user_id": user_id,
        "timestamp": receipt_timestamp,
        "signature": base64.b64encode(signature).decode()
    }
```

### Verification (Client)

```python
def verify_receipt(receipt, server_public_key):
    # Reconstruct receipt data
    receipt_data = create_receipt_data(
        receipt["entry_id"],
        receipt["entry_hash"],
        receipt["user_id"],
        receipt["timestamp"]
    )
    
    # Verify server signature
    signature = base64.b64decode(receipt["signature"])
    
    try:
        server_public_key.verify(
            signature,
            receipt_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
```

### Security Properties

**Non-Repudiation**:
- Server cannot deny issuing receipt
- Cryptographic proof of acceptance
- Legally binding (in principle)

**Proof of Inclusion**:
- Receipt includes entry_hash
- Proves entry was added to ledger
- Can verify against ledger

**Dispute Resolution**:
- User can prove expense was recorded
- Server cannot claim expense was never submitted
- Third party can verify receipt

---

## Security Analysis

### Threat Model

**Attacker Capabilities**:
1. Full control over network (MITM position)
2. Can capture, modify, replay messages
3. Read/write access to backend storage
4. Computational power: polynomial time

**Assumptions**:
1. Client devices secure (no malware)
2. Private keys not compromised
3. Cryptographic primitives secure
4. Random number generator secure

### Attack Resistance

#### 1. Eavesdropping Attack

**Attack**: Passive monitoring of network traffic

**Defense**: AES-256-GCM encryption

**Analysis**:
- All messages encrypted with session key
- Session key derived from DH shared secret
- Attacker doesn't have DH private keys
- Cannot compute shared secret or session key
- Ciphertext is IND-CPA secure

**Security Level**: 256-bit key → 2²⁵⁶ possible keys

**Conclusion**: ✓ Confidentiality preserved

#### 2. Modification Attack

**Attack**: Active MITM modifies messages

**Defense**: AES-GCM authentication tag

**Analysis**:
- GCM computes 128-bit authentication tag
- Tag cryptographically bound to ciphertext and key
- Any modification changes ciphertext
- Modified ciphertext produces different tag
- Server verifies tag before accepting
- Mismatch → reject message

**Security Level**: 128-bit tag → forgery probability 2⁻¹²⁸

**Conclusion**: ✓ Integrity violation detected

#### 3. Spoofing Attack

**Attack**: Impersonate another user

**Defense**: RSA-PSS digital signatures

**Analysis**:
- Each expense signed with user's private key
- Server verifies signature with user's public key
- Attacker doesn't have user's private key
- Cannot forge valid signature
- RSA-PSS is UF-CMA secure

**Security Level**: 2048-bit RSA → ~2¹¹² operations to forge

**Conclusion**: ✓ Origin authentication works

#### 4. Replay Attack

**Attack**: Capture and replay old valid message

**Defense**: Monotonic counters

**Analysis**:
- Each message includes counter
- Server tracks highest counter per user
- Replayed message has counter ≤ stored_counter
- Server rejects non-increasing counters
- Deterministic rejection

**Security Level**: Perfect (no false negatives)

**Conclusion**: ✓ Replay protection works

#### 5. Ledger Tampering

**Attack**: Modify database entries directly

**Defense**: SHA-256 hash chain

**Analysis**:
- Each entry linked to previous via hash
- Modification changes entry data
- Recomputed hash differs from stored hash
- Chain break detected on verification
- Cannot hide modification

**Security Level**: 256-bit hash → 2²⁵⁶ preimage resistance

**Conclusion**: ✓ Tamper evidence works

---

## Implementation Details

### Code Organization

```
shared/crypto_primitives.py  - Core cryptographic functions
client/crypto_client.py      - Client-side crypto operations
server/crypto_server.py      - Server-side crypto operations
server/ledger.py             - Hash chain implementation
```

---

## Cryptographic Scheme Usage in Codebase

This section maps each cryptographic primitive to its specific usage in the codebase with file locations and code examples.

### 1. RSA Key Generation

**File**: `shared/crypto_primitives.py`

**Function**: `generate_rsa_keypair()`

**Code**:
```python
@staticmethod
def generate_rsa_keypair() -> tuple:
    """Generate RSA-2048 key pair."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    return private_key, private_key.public_key()
```

**Used In**:
- `client/crypto_client.py` - `generate_keys()` - User key generation during registration
- `server/crypto_server.py` - `__init__()` - Server key generation on first run

**Why**: Generate long-term identity keys for digital signatures and authentication

---

### 2. RSA-PSS Digital Signatures

#### Signing

**File**: `shared/crypto_primitives.py`

**Function**: `sign_data()`

**Code**:
```python
@staticmethod
def sign_data(private_key, data: bytes) -> bytes:
    """Sign data with RSA-PSS."""
    signature = private_key.sign(
        data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature
```

**Used In**:
1. `client/crypto_client.py` - `initiate_key_exchange()` - Sign DH public key
   ```python
   # Sign DH public key for authentication
   signature = CryptoPrimitives.sign_data(
       self.private_key,
       dh_public_bytes + self.user_id.encode()
   )
   ```

2. `client/crypto_client.py` - `sign_expense()` - Sign expense records
   ```python
   # Sign expense for non-repudiation
   signature = CryptoPrimitives.sign_data(
       self.private_key,
       expense_data_bytes
   )
   ```

3. `server/crypto_server.py` - `respond_to_key_exchange()` - Sign server DH public key
   ```python
   # Server signs its DH public key
   signature = CryptoPrimitives.sign_data(
       self.private_key,
       dh_public_bytes
   )
   ```

4. `server/server.py` - `handle_expense_submit()` - Sign cryptographic receipts
   ```python
   # Server signs receipt for non-repudiation
   receipt_signature = CryptoPrimitives.sign_data(
       self.crypto.private_key,
       receipt_data_bytes
   )
   ```

**Why**: Provide authentication, non-repudiation, and origin verification

#### Verification

**File**: `shared/crypto_primitives.py`

**Function**: `verify_signature()`

**Code**:
```python
@staticmethod
def verify_signature(public_key, data: bytes, signature: bytes) -> bool:
    """Verify RSA-PSS signature."""
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except InvalidSignature:
        return False
```

**Used In**:
1. `server/server.py` - `process_message()` - Verify client signature in key exchange
   ```python
   # Verify client signed their DH public key
   if not CryptoPrimitives.verify_signature(
       user_public_key,
       dh_public_bytes + user_id.encode(),
       signature
   ):
       return error_response("Invalid signature")
   ```

2. `client/crypto_client.py` - `complete_key_exchange()` - Verify server signature
   ```python
   # Verify server signed their DH public key
   if not CryptoPrimitives.verify_signature(
       server_public_key,
       server_dh_public_bytes,
       server_signature
   ):
       return False
   ```

3. `server/server.py` - `handle_expense_submit()` - Verify expense signature
   ```python
   # Verify user signed the expense
   if not CryptoPrimitives.verify_signature(
       user_public_key,
       expense_data_bytes,
       expense_signature
   ):
       return error_response("Invalid expense signature")
   ```

**Why**: Authenticate message origin and detect forgeries

---

### 3. Diffie-Hellman Key Exchange

#### Parameter Generation

**File**: `server/crypto_server.py`

**Function**: `__init__()`

**Code**:
```python
# Generate DH parameters (2048-bit, generator=2)
self.dh_parameters = dh.generate_parameters(
    generator=2,
    key_size=2048
)
```

**Why**: Create group parameters for DH key exchange (done once, takes 2-5 seconds)

#### Ephemeral Key Generation

**File**: `client/crypto_client.py`

**Function**: `initiate_key_exchange()`

**Code**:
```python
# Generate ephemeral DH key pair
self.dh_private_key = dh_parameters.generate_private_key()
dh_public_key = self.dh_private_key.public_key()
```

**Used In**:
- Client: `client/crypto_client.py` - `initiate_key_exchange()`
- Server: `server/crypto_server.py` - `respond_to_key_exchange()`

**Why**: Generate ephemeral keys for forward secrecy

#### Shared Secret Computation

**File**: `client/crypto_client.py` and `server/crypto_server.py`

**Code**:
```python
# Client computes shared secret
shared_secret = self.dh_private_key.exchange(server_dh_public_key)

# Server computes shared secret
shared_secret = dh_private_key.exchange(client_dh_public_key)
```

**Why**: Both parties compute same shared secret without transmitting it

---

### 4. HKDF Key Derivation

**File**: `shared/crypto_primitives.py`

**Function**: `derive_session_key()`

**Code**:
```python
@staticmethod
def derive_session_key(shared_secret: bytes) -> bytes:
    """Derive AES-256 session key from DH shared secret."""
    kdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256
        salt=b'',
        info=b'session_key'
    )
    return kdf.derive(shared_secret)
```

**Used In**:
1. `client/crypto_client.py` - `complete_key_exchange()`
   ```python
   # Derive session key from shared secret
   self.session_key = CryptoPrimitives.derive_session_key(shared_secret)
   ```

2. `server/crypto_server.py` - `respond_to_key_exchange()`
   ```python
   # Derive session key from shared secret
   session_key = CryptoPrimitives.derive_session_key(shared_secret)
   ```

**Why**: Extract uniform randomness from DH shared secret and derive AES key

---

### 5. AES-256-GCM Encryption

**File**: `shared/crypto_primitives.py`

**Function**: `encrypt_aes_gcm()`

**Code**:
```python
@staticmethod
def encrypt_aes_gcm(key: bytes, plaintext: bytes) -> tuple:
    """Encrypt with AES-256-GCM."""
    nonce = os.urandom(12)  # 96-bit random nonce
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext  # ciphertext includes 16-byte auth tag
```

**Used In**:
1. `client/crypto_client.py` - `encrypt_message()`
   ```python
   # Encrypt expense message with session key
   nonce, ciphertext = CryptoPrimitives.encrypt_aes_gcm(
       self.session_key,
       message_bytes
   )
   ```

2. `server/server.py` - `process_message()` - Encrypt responses
   ```python
   # Encrypt response message
   nonce, ciphertext = CryptoPrimitives.encrypt_aes_gcm(
       session_key,
       response_bytes
   )
   ```

**Why**: Provide confidentiality and authenticity for all messages

---

### 6. AES-256-GCM Decryption

**File**: `shared/crypto_primitives.py`

**Function**: `decrypt_aes_gcm()`

**Code**:
```python
@staticmethod
def decrypt_aes_gcm(key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt with AES-256-GCM."""
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext
    except Exception:
        return None  # Authentication failed
```

**Used In**:
1. `server/server.py` - `process_message()` - Decrypt client messages
   ```python
   # Decrypt and verify message
   plaintext = CryptoPrimitives.decrypt_aes_gcm(
       session_key,
       nonce,
       ciphertext
   )
   if plaintext is None:
       return error_response("Decryption failed")
   ```

2. `client/crypto_client.py` - `decrypt_message()` - Decrypt server responses
   ```python
   # Decrypt server response
   plaintext = CryptoPrimitives.decrypt_aes_gcm(
       self.session_key,
       nonce,
       ciphertext
   )
   ```

**Why**: Decrypt messages and verify authentication tag

---

### 7. SHA-256 Hashing

#### Simple Hash

**File**: `shared/crypto_primitives.py`

**Function**: `hash_data()`

**Code**:
```python
@staticmethod
def hash_data(data: bytes) -> bytes:
    """Compute SHA-256 hash."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(data)
    return digest.finalize()
```

**Used In**:
1. `server/ledger.py` - `__init__()` - Genesis hash
   ```python
   # Create genesis hash
   self.genesis_hash = CryptoPrimitives.hash_data(
       b"SplitSmart Genesis Block"
   )
   ```

**Why**: Create initial hash for hash chain

#### Hash Chain Link

**File**: `shared/crypto_primitives.py`

**Function**: `hash_chain_link()`

**Code**:
```python
@staticmethod
def hash_chain_link(prev_hash: bytes, data: bytes) -> bytes:
    """Compute hash chain link: H(prev_hash || data)."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(prev_hash)
    digest.update(data)
    return digest.finalize()
```

**Used In**:
1. `server/ledger.py` - `append_entry()` - Add entry to chain
   ```python
   # Compute entry hash linking to previous
   entry_hash = CryptoPrimitives.hash_chain_link(
       prev_hash_bytes,
       entry_data_bytes
   )
   ```

2. `server/ledger.py` - `verify_integrity()` - Verify chain
   ```python
   # Recompute hash for verification
   computed_hash = CryptoPrimitives.hash_chain_link(
       expected_prev_hash,
       entry_data_bytes
   )
   if computed_hash != stored_hash:
       return False, "Hash mismatch"
   ```

3. `client/client.py` - `_verify_ledger_chain()` - Client-side verification
   ```python
   # Client verifies hash chain
   computed_hash = CryptoPrimitives.hash_chain_link(
       prev_hash_bytes,
       entry_data_bytes
   )
   ```

**Why**: Create tamper-evident ledger with cryptographic linking

---

### 8. Monotonic Counters (Replay Protection)

#### Counter Increment

**File**: `client/crypto_client.py`

**Function**: `sign_expense()` and `increment_counter()`

**Code**:
```python
def sign_expense(self, payer, amount, description, timestamp):
    """Sign expense and increment counter."""
    self.counter += 1  # Increment before use
    
    expense_data = {
        "payer": payer,
        "amount": amount,
        "description": description,
        "counter": self.counter,
        "timestamp": timestamp
    }
    
    signature = CryptoPrimitives.sign_data(
        self.private_key,
        MessageEncoder.encode_message(expense_data)
    )
    
    return signature, self.counter
```

**Why**: Ensure each message has strictly increasing counter

#### Counter Validation

**File**: `server/server.py`

**Function**: `handle_expense_submit()`

**Code**:
```python
def handle_expense_submit(self, session_id, expense_msg):
    """Handle expense submission with replay protection."""
    user_id = expense_msg.payload["user_id"]
    counter = expense_msg.payload["counter"]
    
    # Get stored counter
    stored_counter = self.storage.get_user_counter(user_id)
    
    # Verify strictly increasing
    if counter <= stored_counter:
        return self._create_error_response("Replay detected")
    
    # Process expense...
    
    # Update counter
    self.storage.update_user_counter(user_id, counter)
```

**Why**: Reject replayed messages with old counters

---

### 9. Message Encoding/Decoding

**File**: `shared/crypto_primitives.py`

**Class**: `MessageEncoder`

**Code**:
```python
class MessageEncoder:
    """Canonical message encoding for signatures."""
    
    @staticmethod
    def encode_message(data: dict) -> bytes:
        """Encode message deterministically."""
        return json.dumps(data, sort_keys=True).encode('utf-8')
    
    @staticmethod
    def decode_message(data: bytes) -> dict:
        """Decode message."""
        return json.loads(data.decode('utf-8'))
```

**Used In**:
- All signature operations (ensures canonical representation)
- Hash chain computations
- Message serialization

**Why**: Ensure deterministic serialization for signatures and hashes

---

### 10. Key Serialization

**File**: `shared/crypto_primitives.py`

**Functions**: `serialize_private_key()`, `serialize_public_key()`, `load_private_key()`, `load_public_key()`

**Code**:
```python
@staticmethod
def serialize_private_key(private_key) -> bytes:
    """Serialize private key to PEM format."""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

@staticmethod
def load_private_key(pem_data: bytes):
    """Load private key from PEM format."""
    return serialization.load_pem_private_key(
        pem_data,
        password=None
    )
```

**Used In**:
1. `client/crypto_client.py` - `generate_keys()` and `load_keys()`
   ```python
   # Save private key
   pem = CryptoPrimitives.serialize_private_key(private_key)
   with open(f"keys/{self.user_id}_private.pem", "wb") as f:
       f.write(pem)
   
   # Load private key
   with open(f"keys/{self.user_id}_private.pem", "rb") as f:
       pem = f.read()
   self.private_key = CryptoPrimitives.load_private_key(pem)
   ```

2. `server/crypto_server.py` - Key persistence

**Why**: Store and load keys from filesystem

---

## Summary of Cryptographic Usage

| Primitive | Primary File | Key Functions | Purpose |
|-----------|-------------|---------------|---------|
| RSA-2048 | `crypto_primitives.py` | `generate_rsa_keypair()` | Identity keys |
| RSA-PSS | `crypto_primitives.py` | `sign_data()`, `verify_signature()` | Digital signatures |
| DH-2048 | `crypto_client.py`, `crypto_server.py` | `generate_private_key()`, `exchange()` | Key exchange |
| HKDF | `crypto_primitives.py` | `derive_session_key()` | Key derivation |
| AES-GCM | `crypto_primitives.py` | `encrypt_aes_gcm()`, `decrypt_aes_gcm()` | Message encryption |
| SHA-256 | `crypto_primitives.py` | `hash_data()`, `hash_chain_link()` | Hash chain |
| Counters | `crypto_client.py`, `server.py` | `increment_counter()`, counter validation | Replay protection |

---

## Security Parameters Summary

| Parameter | Value | Security Level | Standard |
|-----------|-------|----------------|----------|
| RSA modulus | 2048 bits | ~112 bits | NIST SP 800-57 |
| DH modulus | 2048 bits | ~112 bits | RFC 3526 |
| AES key | 256 bits | 128 bits | FIPS 197 |
| GCM nonce | 96 bits | N/A | NIST SP 800-38D |
| GCM tag | 128 bits | 128 bits | NIST SP 800-38D |
| SHA-256 output | 256 bits | 128 bits (collision) | FIPS 180-4 |
| HKDF output | 256 bits | 128 bits | RFC 5869 |

All parameters meet or exceed current NIST recommendations for 112-bit security level.

---

## Implementation Notes

### Why These Choices?

1. **RSA-2048 over Ed25519**: 
   - More widely understood
   - Compatible with standard tools
   - Sufficient security for academic project

2. **AES-GCM over Encrypt-then-MAC**:
   - Single primitive (simpler)
   - AEAD provides both confidentiality and authenticity
   - Hardware acceleration available

3. **Counters over Timestamps**:
   - No clock synchronization needed
   - Deterministic (no threshold)
   - Perfect replay prevention

4. **SHA-256 over SHA-3**:
   - More widely deployed
   - Sufficient security
   - Better tool support

### Production Considerations

For production deployment, consider:

1. **Key Management**:
   - Use HSM for server keys
   - Encrypt private keys at rest
   - Implement key rotation

2. **Performance**:
   - Cache DH parameters
   - Use connection pooling
   - Consider Ed25519 for faster signatures

3. **Monitoring**:
   - Log all crypto operations
   - Monitor for replay attempts
   - Alert on integrity failures

4. **Compliance**:
   - FIPS 140-2 validated modules
   - Regular security audits
   - Penetration testing

---

**End of Cryptographic Specification**
