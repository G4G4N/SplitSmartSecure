# SplitSmart - Architecture Documentation

## Table of Contents
1. [System Overview](#system-overview)
2. [Component Architecture](#component-architecture)
3. [Security Architecture](#security-architecture)
4. [Data Flow](#data-flow)
5. [Cryptographic Design](#cryptographic-design)
6. [Storage Architecture](#storage-architecture)
7. [Protocol Specifications](#protocol-specifications)

---

## System Overview

### Purpose
SplitSmart is a cryptographically secure expense-splitting application designed for small groups (roommates, friends) that maintains an append-only, tamper-evident ledger of shared expenses while protecting against network attacks.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Client Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   CLI UI     │  │    Crypto    │  │   Session    │          │
│  │  Interface   │──│  Operations  │──│  Management  │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    Encrypted Channel
                    (AES-256-GCM + Signatures)
                             │
┌────────────────────────────┴────────────────────────────────────┐
│                         Server Layer                             │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │   Message    │  │    Ledger    │  │   Storage    │          │
│  │  Processing  │──│  Management  │──│   (SQLite)   │          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
│                                                                  │
│  Hash Chain: Genesis → H₁ → H₂ → ... → Hₙ                      │
└─────────────────────────────────────────────────────────────────┘
```

### Key Design Principles

1. **Defense in Depth**: Multiple layers of security
2. **Separation of Concerns**: Clear boundaries between components
3. **Cryptographic Correctness**: Use proven primitives correctly
4. **Tamper Evidence**: Any modification is detectable
5. **Simplicity**: Avoid unnecessary complexity

---

## Component Architecture

### Client Components

#### 1. Client Application (`client/client.py`)
**Responsibilities:**
- User interface (CLI)
- Coordinate operations (register, login, add expense, view ledger)
- Manage client-side state
- Store cryptographic receipts

**Key Methods:**
- `register()`: Register user with server
- `login()`: Establish secure session
- `add_expense()`: Submit signed expense
- `view_ledger()`: Retrieve and verify ledger
- `view_balances()`: Get balance calculations

**Dependencies:**
- `ClientCrypto` for cryptographic operations
- `Server` for communication

#### 2. Client Crypto (`client/crypto_client.py`)
**Responsibilities:**
- Key generation and management
- Signed Diffie-Hellman key exchange (client side)
- Message encryption/decryption
- Expense signing
- Receipt verification

**Key Methods:**
- `generate_keys()`: Create RSA key pair
- `initiate_key_exchange()`: Start DH exchange
- `complete_key_exchange()`: Finish DH and derive session key
- `sign_expense()`: Sign expense with private key
- `encrypt_message()`: Encrypt with AES-GCM
- `decrypt_message()`: Decrypt and verify auth tag

**State:**
- Private key (RSA-2048)
- Public key (RSA-2048)
- Session ID
- Session key (AES-256)
- Counter (for replay protection)

### Server Components

#### 1. Server Application (`server/server.py`)
**Responsibilities:**
- Handle client connections
- Route messages to appropriate handlers
- Coordinate between crypto, ledger, and storage
- Generate cryptographic receipts

**Key Methods:**
- `register_user()`: Register new user
- `handle_client_hello()`: Process key exchange initiation
- `handle_expense_submit()`: Process expense submission
- `handle_ledger_request()`: Send ledger to client
- `handle_balance_request()`: Calculate and send balances
- `process_message()`: Main message routing

**Message Handlers:**
- CLIENT_HELLO → Signed DH key exchange
- EXPENSE_SUBMIT → Verify, add to ledger, generate receipt
- LEDGER_REQUEST → Send ledger with integrity proof
- BALANCE_REQUEST → Calculate and send balances

#### 2. Server Crypto (`server/crypto_server.py`)
**Responsibilities:**
- Server-side key management
- DH parameter generation
- Signed Diffie-Hellman key exchange (server side)
- Session management
- Message encryption/decryption

**Key Methods:**
- `generate_keys()`: Create server RSA key pair
- `generate_dh_parameters()`: Create DH parameters (2048-bit)
- `handle_client_hello()`: Process client DH and respond
- `create_session()`: Establish new session
- `encrypt_message()`: Encrypt response
- `decrypt_message()`: Decrypt client message

**State:**
- Server private key (RSA-2048)
- Server public key (RSA-2048)
- DH parameters (2048-bit)
- Active sessions (in-memory dictionary)

#### 3. Ledger Manager (`server/ledger.py`)
**Responsibilities:**
- Maintain hash-chained ledger
- Verify chain integrity
- Calculate balances
- Simplify debts

**Key Methods:**
- `add_entry()`: Append entry to chain
- `verify_chain_integrity()`: Check all hashes
- `get_all_entries()`: Retrieve ledger
- `calculate_balances()`: Compute who owes whom
- `get_simplified_balances()`: Minimize transactions

**Hash Chain Structure:**
```
Genesis: H₀ = SHA256("SplitSmart Genesis Block")
Entry 1: H₁ = SHA256(H₀ || entry₁_data)
Entry 2: H₂ = SHA256(H₁ || entry₂_data)
...
Entry n: Hₙ = SHA256(Hₙ₋₁ || entryₙ_data)
```

#### 4. Storage Layer (`server/storage.py`)
**Responsibilities:**
- SQLite database operations
- User management
- Ledger persistence
- Counter tracking

**Key Methods:**
- `register_user()`: Store user and public key
- `get_user_public_key()`: Retrieve user's public key
- `get_user_counter()`: Get current counter
- `update_user_counter()`: Update counter
- `add_ledger_entry()`: Persist entry
- `get_all_ledger_entries()`: Retrieve all entries

**Database Schema:**
```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    counter INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE ledger (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id TEXT NOT NULL,
    payer TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT,
    timestamp TEXT NOT NULL,
    counter INTEGER NOT NULL,
    signature TEXT NOT NULL,
    prev_hash TEXT NOT NULL,
    entry_hash TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id)
);
```

### Shared Components

#### 1. Crypto Primitives (`shared/crypto_primitives.py`)
**Responsibilities:**
- Core cryptographic operations
- Key generation utilities
- Encryption/decryption
- Signing/verification
- Hashing
- Key derivation

**Key Functions:**
- `generate_rsa_keypair()`: Create RSA-2048 keys
- `generate_dh_parameters()`: Create DH params
- `generate_dh_keypair()`: Create ephemeral DH keys
- `compute_dh_shared_secret()`: Compute shared secret
- `derive_session_key()`: HKDF-SHA256 key derivation
- `encrypt_aes_gcm()`: AES-256-GCM encryption
- `decrypt_aes_gcm()`: AES-256-GCM decryption
- `sign_data()`: RSA-PSS signature
- `verify_signature()`: RSA-PSS verification
- `hash_data()`: SHA-256 hashing

#### 2. Protocol Messages (`shared/protocols.py`)
**Responsibilities:**
- Define message structures
- Serialization/deserialization
- Message type constants

**Message Types:**
- `ClientHelloMessage`: Initiate key exchange
- `ServerHelloMessage`: Respond to key exchange
- `ExpenseSubmitMessage`: Submit expense
- `ExpenseResponseMessage`: Acknowledge expense (with receipt)
- `LedgerRequestMessage`: Request ledger
- `LedgerResponseMessage`: Send ledger
- `BalanceRequestMessage`: Request balances
- `BalanceResponseMessage`: Send balances
- `ErrorMessage`: Error response

#### 3. Constants (`shared/constants.py`)
**Responsibilities:**
- Cryptographic parameters
- Message type constants
- Error codes

---

## Security Architecture

### Three-Layer Authentication

#### Layer 1: Handshake-Level Authentication
**Purpose**: Establish secure channel with mutual authentication

**Mechanism**: Signed Diffie-Hellman Key Exchange (STS-style)

**Process:**
1. Client generates ephemeral DH key pair
2. Client signs DH public key with long-term private key
3. Client sends: ClientHello + DH_public + signature
4. Server verifies client signature using client's public key
5. Server generates ephemeral DH key pair
6. Server signs DH public key with server private key
7. Server sends: ServerHello + DH_public + signature
8. Client verifies server signature using server's public key
9. Both compute shared secret: `secret = DH(client_private, server_public)`
10. Both derive session key: `K_session = HKDF(secret, salt=b'', info=b'session_key')`

**Security Properties:**
- Mutual authentication (both parties verified)
- Forward secrecy (ephemeral keys)
- MITM protection (signatures prevent impersonation)

#### Layer 2: Per-Entry Authentication
**Purpose**: Non-repudiation and origin verification for each expense

**Mechanism**: RSA-PSS Digital Signatures

**Process:**
1. Client creates expense record: `{payer, amount, description, counter, timestamp}`
2. Client computes canonical representation (JSON sorted keys)
3. Client signs: `signature = Sign(private_key, expense_data)`
4. Server verifies: `Verify(public_key, expense_data, signature)`

**Security Properties:**
- Non-repudiation (user cannot deny creating expense)
- Origin authentication (proves who created expense)
- Integrity (any modification invalidates signature)

#### Layer 3: Per-Message Protection
**Purpose**: Confidentiality and integrity for all messages

**Mechanism**: AES-256-GCM AEAD

**Process:**
1. Client encrypts message: `(ciphertext, tag) = AES-GCM-Encrypt(K_session, nonce, plaintext)`
2. Server decrypts: `plaintext = AES-GCM-Decrypt(K_session, nonce, ciphertext, tag)`
3. If tag verification fails, reject message

**Security Properties:**
- Confidentiality (ciphertext unintelligible without key)
- Integrity (auth tag detects modifications)
- Authenticity (only holder of K_session can create valid messages)

### Attack Defenses

#### 1. Eavesdropping Defense
**Threat**: Passive attacker monitors network traffic

**Defense**: AES-256-GCM encryption

**How It Works:**
- All messages encrypted with session key
- Session key derived from DH shared secret
- Attacker doesn't have DH private keys
- Cannot compute shared secret or session key
- Ciphertext is cryptographically secure random data

**Security Level**: 256-bit key → 2²⁵⁶ possible keys (computationally infeasible)

#### 2. Modification Defense
**Threat**: Active attacker modifies messages in transit

**Defense**: AES-GCM authentication tag

**How It Works:**
- GCM mode computes authentication tag over ciphertext
- Tag is cryptographically bound to ciphertext and key
- Any modification changes ciphertext
- Modified ciphertext produces different tag
- Server verifies tag before accepting message
- Mismatch → reject message

**Security Level**: 128-bit tag → forgery probability 2⁻¹²⁸ (negligible)

#### 3. Spoofing Defense
**Threat**: Attacker impersonates another user

**Defense**: RSA-PSS digital signatures

**How It Works:**
- Each expense signed with user's private key
- Private key never leaves user's device
- Server verifies signature with user's public key
- Attacker doesn't have victim's private key
- Cannot create valid signature
- Server rejects invalid signatures

**Security Level**: 2048-bit RSA → ~2¹¹² operations to forge (computationally infeasible)

#### 4. Replay Defense
**Threat**: Attacker captures and replays old valid messages

**Defense**: Monotonic counters

**How It Works:**
- Each user has counter starting at 0
- Client includes counter in each message
- Server stores current counter for each user
- Server checks: `received_counter > stored_counter`
- If not, reject as replay
- On success, update stored counter

**Security Level**: Perfect (deterministic check, no false negatives)

#### 5. Ledger Tampering Defense
**Threat**: Attacker modifies database entries

**Defense**: SHA-256 hash chain

**How It Works:**
- Each entry includes hash of previous entry
- Entry hash: `Hₙ = SHA256(Hₙ₋₁ || entryₙ_data)`
- On startup, server recomputes all hashes
- Compares computed vs stored hashes
- Any mismatch indicates tampering
- Chain break is immediately detectable

**Security Level**: 256-bit hash → collision resistance ~2¹²⁸ (computationally infeasible)

---

## Data Flow

### User Registration Flow
```
Client                                    Server
  │                                         │
  │ 1. Generate RSA key pair                │
  │                                         │
  │ 2. Send: user_id + public_key ─────────→│
  │                                         │ 3. Store in database
  │                                         │ 4. Initialize counter = 0
  │                                         │
  │←──── 5. Success ────────────────────────│
```

### Session Establishment Flow
```
Client                                    Server
  │                                         │
  │ 1. Generate ephemeral DH key pair       │
  │ 2. Sign DH public key                   │
  │                                         │
  │ 3. ClientHello ─────────────────────────→│
  │    + DH_public                          │ 4. Verify signature
  │    + Sign(DH_public)                    │ 5. Generate DH key pair
  │                                         │ 6. Sign DH public key
  │                                         │ 7. Compute shared secret
  │                                         │ 8. Derive K_session
  │←─── 9. ServerHello ─────────────────────│
  │    + DH_public                          │
  │    + Sign(DH_public)                    │
  │    + session_id                         │
  │                                         │
  │ 10. Verify signature                    │
  │ 11. Compute shared secret               │
  │ 12. Derive K_session                    │
```

### Expense Submission Flow
```
Client                                    Server
  │                                         │
  │ 1. Create expense record                │
  │ 2. Sign(expense || counter || ts)       │
  │ 3. Encrypt with K_session               │
  │                                         │
  │ 4. Encrypted message ───────────────────→│
  │                                         │ 5. Decrypt with K_session
  │                                         │ 6. Verify auth tag
  │                                         │ 7. Verify signature
  │                                         │ 8. Check counter
  │                                         │ 9. Add to hash chain
  │                                         │ 10. Store in database
  │                                         │ 11. Update counter
  │                                         │ 12. Generate receipt
  │                                         │ 13. Sign receipt
  │                                         │ 14. Encrypt response
  │←─── 15. Encrypted response ─────────────│
  │    (includes receipt)                   │
  │                                         │
  │ 16. Decrypt response                    │
  │ 17. Store receipt                       │
```

### Ledger Retrieval Flow
```
Client                                    Server
  │                                         │
  │ 1. Create ledger request                │
  │ 2. Encrypt with K_session               │
  │                                         │
  │ 3. Encrypted request ───────────────────→│
  │                                         │ 4. Decrypt
  │                                         │ 5. Check counter
  │                                         │ 6. Get all entries
  │                                         │ 7. Encrypt response
  │←─── 8. Encrypted ledger ────────────────│
  │    (all entries + genesis hash)         │
  │                                         │
  │ 9. Decrypt ledger                       │
  │ 10. Verify hash chain                   │
  │     - Recompute all hashes              │
  │     - Compare with stored hashes        │
  │ 11. Display if valid                    │
```

---

## Cryptographic Design

### Key Hierarchy

```
┌─────────────────────────────────────────────────────────────┐
│                    Long-Term Keys                            │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  User Private    │         │  Server Private  │         │
│  │  Key (RSA-2048)  │         │  Key (RSA-2048)  │         │
│  └────────┬─────────┘         └────────┬─────────┘         │
│           │                            │                    │
│           │ Signs                      │ Signs              │
│           ↓                            ↓                    │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  Expense         │         │  Receipt         │         │
│  │  Signatures      │         │  Signatures      │         │
│  └──────────────────┘         └──────────────────┘         │
└─────────────────────────────────────────────────────────────┘
                              │
                              │ DH Key Exchange
                              ↓
┌─────────────────────────────────────────────────────────────┐
│                    Ephemeral Keys                            │
│  ┌──────────────────┐         ┌──────────────────┐         │
│  │  Client DH       │         │  Server DH       │         │
│  │  Private (2048)  │         │  Private (2048)  │         │
│  └────────┬─────────┘         └────────┬─────────┘         │
│           │                            │                    │
│           └────────────┬───────────────┘                    │
│                        │ Compute                            │
│                        ↓                                    │
│              ┌──────────────────┐                           │
│              │  Shared Secret   │                           │
│              └────────┬─────────┘                           │
│                       │ HKDF                                │
│                       ↓                                     │
│              ┌──────────────────┐                           │
│              │  K_session       │                           │
│              │  (AES-256)       │                           │
│              └────────┬─────────┘                           │
│                       │                                     │
│                       │ Encrypts                            │
│                       ↓                                     │
│              ┌──────────────────┐                           │
│              │  All Messages    │                           │
│              └──────────────────┘                           │
└─────────────────────────────────────────────────────────────┘
```

### Cryptographic Parameters

| Parameter | Value | Justification |
|-----------|-------|---------------|
| RSA Key Size | 2048-bit | NIST recommended, ~112-bit security |
| DH Modulus | 2048-bit | Matches RSA security level |
| AES Key Size | 256-bit | 128-bit security, future-proof |
| GCM Nonce | 96-bit | Standard for GCM mode |
| GCM Tag | 128-bit | Standard, 2⁻¹²⁸ forgery probability |
| Hash Function | SHA-256 | 128-bit collision resistance |
| Signature Scheme | RSA-PSS | Provably secure, randomized |
| KDF | HKDF-SHA256 | RFC 5869 standard |

### Security Levels

All choices provide ≥112-bit security:
- RSA-2048: ~112-bit security
- DH-2048: ~112-bit security
- AES-256: 128-bit security
- SHA-256: 128-bit collision resistance

This exceeds the 80-bit minimum for academic purposes and meets NIST recommendations for near-term security (valid until ~2030).

---

## Storage Architecture

### Database Design

**File**: `data/splitsmart.db` (SQLite3)

**Tables:**

1. **users**
   - Stores user information and public keys
   - Counter for replay protection
   - Primary key: user_id

2. **ledger**
   - Stores all expense entries
   - Includes hash chain data
   - Foreign key to users table

**Indexes:**
- Primary key on users(user_id)
- Primary key on ledger(id)
- Index on ledger(user_id) for fast lookups

**Integrity Constraints:**
- Foreign key: ledger.user_id → users.user_id
- NOT NULL on critical fields
- AUTOINCREMENT on ledger.id

### Key Storage

**Directory**: `keys/`

**Files:**
- `server_private.pem`: Server's RSA private key
- `server_public.pem`: Server's RSA public key
- `dh_parameters.pem`: DH parameters (2048-bit)
- `{user}_private.pem`: User's RSA private key
- `{user}_public.pem`: User's RSA public key

**Format**: PEM (Privacy-Enhanced Mail)

**Permissions**: Private keys should be readable only by owner (chmod 600)

---

## Protocol Specifications

### Message Format

All messages use JSON encoding:

```json
{
  "type": "MESSAGE_TYPE",
  "timestamp": "2024-12-08T12:34:56.789Z",
  "payload": {
    // Message-specific data
  }
}
```

### Encrypted Message Format

```json
{
  "nonce": "base64_encoded_nonce",
  "ciphertext": "base64_encoded_ciphertext_with_tag"
}
```

### Protocol State Machine

```
[START] ──register──→ [REGISTERED]
                           │
                           │ login (CLIENT_HELLO)
                           ↓
                      [KEY_EXCHANGE]
                           │
                           │ (SERVER_HELLO)
                           ↓
                      [AUTHENTICATED]
                           │
                           ├──add_expense──→ [AUTHENTICATED]
                           ├──view_ledger──→ [AUTHENTICATED]
                           ├──view_balances─→ [AUTHENTICATED]
                           │
                           │ logout / timeout
                           ↓
                      [REGISTERED]
```

### Error Handling

**Error Codes:**
- `INVALID_SIGNATURE`: Signature verification failed
- `REPLAY_DETECTED`: Counter check failed
- `INVALID_COUNTER`: Counter not strictly increasing
- `DECRYPTION_FAILED`: GCM auth tag verification failed
- `USER_NOT_FOUND`: User not registered
- `INVALID_MESSAGE`: Malformed or unknown message type

**Error Response Format:**
```json
{
  "type": "ERROR",
  "timestamp": "...",
  "payload": {
    "error_code": "ERROR_CODE",
    "message": "Human-readable description"
  }
}
```

---

## Performance Considerations

### Bottlenecks

1. **DH Parameter Generation**: 2-5 seconds
   - Solution: Generate once, persist to disk
   - Only needed on first server startup

2. **RSA Key Generation**: ~100ms per user
   - Solution: Generate during registration (one-time cost)
   - Acceptable for small groups

3. **Hash Chain Verification**: O(n) on startup
   - Solution: Acceptable for thousands of entries
   - Could optimize with checkpoints for larger scale

### Optimization Opportunities

1. **Session Key Caching**: Keep sessions in memory
2. **Batch Operations**: Process multiple expenses in one transaction
3. **Lazy Loading**: Load ledger entries on demand
4. **Parallel Verification**: Verify signatures in parallel

### Scalability Limits

- **Users**: 10-50 (small group design)
- **Expenses**: Thousands (linear scaling)
- **Sessions**: Limited by memory (dozens concurrent)
- **Storage**: SQLite suitable up to GB scale

---

## Security Considerations

### Assumptions

1. **Client Security**: Client devices are not compromised
2. **Key Security**: Private keys are securely stored
3. **Random Number Generation**: System RNG is cryptographically secure
4. **Library Correctness**: `cryptography` library is correctly implemented
5. **Small Group**: Fixed, known set of users

### Limitations

1. **No Key Revocation**: Cannot remove compromised users
2. **No Key Rotation**: Long-term keys never change
3. **In-Memory Sessions**: Lost on server restart
4. **Single Server**: No distributed architecture
5. **No Backup**: No automatic backup mechanism

### Threat Model Boundaries

**In Scope:**
- Network attacker (MITM)
- Storage attacker (database access)
- Malicious users (within protocol)

**Out of Scope:**
- Client compromise
- Key theft
- Side-channel attacks
- Denial of service
- Social engineering

---

## Testing Strategy

### Unit Tests
- Crypto primitives (encryption, signing, hashing)
- Key exchange protocol
- Hash chain operations
- Counter validation

### Integration Tests
- Full client-server workflow
- Multi-user scenarios
- Error handling
- Edge cases

### Security Tests
- All 5 attack demonstrations
- Invalid input handling
- Boundary conditions

### Performance Tests
- Operation timing
- Scalability limits
- Resource usage

---

## Deployment Considerations

### Requirements
- Python 3.8+
- `cryptography` library
- SQLite3
- ~10MB disk space
- Minimal CPU/memory

### Installation
1. Install Python dependencies
2. Generate server keys (automatic on first run)
3. Initialize database (automatic)
4. Register users

### Maintenance
- Monitor ledger integrity
- Backup database regularly
- Rotate server keys periodically (manual)
- Clean up old sessions

### Monitoring
- Log all security events
- Track failed authentication attempts
- Monitor ledger integrity checks
- Alert on anomalies

---

## Future Enhancements

### Planned
- Key evolution/rotation
- Cryptographic receipts (implemented)
- Merkle tree for efficient proofs
- Multi-device support

### Potential
- Web-based UI
- Mobile clients
- Distributed ledger
- Zero-knowledge proofs
- Threshold signatures

---

## References

### Standards
- NIST SP 800-38D: AES-GCM
- PKCS #1 v2.2: RSA-PSS
- RFC 2631: Diffie-Hellman
- RFC 5869: HKDF
- FIPS 180-4: SHA-256

### Libraries
- Python `cryptography`: https://cryptography.io/
- SQLite: https://www.sqlite.org/

### Academic
- NYU CS6903/4783 Course Materials
- Lectures 1-7: Cryptographic Primitives

---

## Glossary

- **AEAD**: Authenticated Encryption with Associated Data
- **DH**: Diffie-Hellman
- **GCM**: Galois/Counter Mode
- **HKDF**: HMAC-based Key Derivation Function
- **MITM**: Man-in-the-Middle
- **PSS**: Probabilistic Signature Scheme
- **RSA**: Rivest-Shamir-Adleman
- **STS**: Station-to-Station (protocol)
