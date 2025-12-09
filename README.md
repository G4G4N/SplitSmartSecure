# SplitSmart - Secure Expense Splitting Application

A cryptographically secure expense-splitting service demonstrating end-to-end encryption, digital signatures, tamper-evident ledger, and protection against common network attacks.

## 🎯 Project Overview

**Course**: NYU CS6903/4783 - Applied Cryptography  
**Project**: 2.7 - Designing an end-to-end cryptography solution  
**Team**: Gagan Yalamuri and Yathish Naraganahalli Veerabhadraiah

SplitSmart is a networked expense-splitting service for a fixed group of users (e.g., roommates, friends) that maintains a cryptographically secure, tamper-evident ledger of shared expenses.

## 🔒 Security Features

### Three-Layer Cryptographic Architecture

1. **Layer 1: Handshake-Level Authentication**
   - Signed Diffie-Hellman key exchange (STS-style)
   - Mutual authentication using RSA-PSS signatures
   - Establishes secure session with forward secrecy

2. **Layer 2: Per-Entry Authentication**
   - Digital signatures on each expense record
   - Non-repudiation and origin verification
   - Prevents spoofing attacks

3. **Layer 3: Per-Message Protection**
   - AES-256-GCM AEAD encryption
   - Confidentiality and integrity for all messages
   - Protects against eavesdropping and modification

### Attack Defenses

| Attack Type | Defense Mechanism | Implementation |
|------------|-------------------|----------------|
| **Eavesdropping** | AES-256-GCM encryption | All messages encrypted end-to-end |
| **Modification** | AES-GCM auth tags + signatures | Tampering detected immediately |
| **Spoofing** | RSA-PSS digital signatures | Each entry signed by user |
| **Replay** | Monotonic counters | Old messages rejected |
| **Ledger Tampering** | SHA-256 hash chain | Breaks detected on startup |

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                         Client                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  CLI/UI      │  │  Crypto      │  │  Session     │      │
│  │  Interface   │──│  Operations  │──│  Management  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────────┬────────────────────────────────┘
                             │
                    Encrypted Channel
                    (AES-256-GCM)
                             │
┌────────────────────────────┴────────────────────────────────┐
│                         Server                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Message     │  │  Ledger      │  │  Storage     │      │
│  │  Processing  │──│  Management  │──│  (SQLite)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│                                                              │
│  Hash Chain: H₀ → H₁ → H₂ → ... → Hₙ                       │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Cryptographic Specifications

### Algorithms & Parameters

- **Key Exchange**: Diffie-Hellman (2048-bit) + RSA-PSS signatures
- **Symmetric Encryption**: AES-256-GCM (provides encryption + authentication)
- **Digital Signatures**: RSA-PSS (2048-bit)
- **Hash Function**: SHA-256
- **Key Derivation**: HKDF-SHA256

### Security Level

All cryptographic choices provide ≥128-bit security, aligned with NIST recommendations.

## 📁 Project Structure

```
Crypto-Project-2/
├── client/
│   ├── client.py              # Main client application
│   └── crypto_client.py       # Client-side crypto operations
├── server/
│   ├── server.py              # Main server application
│   ├── crypto_server.py       # Server-side crypto operations
│   ├── ledger.py              # Hash-chained ledger management
│   ├── storage.py             # SQLite database operations
│   └── user_manager.py        # User registration & keys
├── shared/
│   ├── crypto_primitives.py   # Core crypto functions
│   ├── protocols.py           # Protocol message formats
│   └── constants.py           # Cryptographic constants
├── demos/
│   ├── demo_eavesdropping.py  # Eavesdropping attack demo
│   ├── demo_replay.py         # Replay attack demo
│   └── demo_tampering.py      # Ledger tampering demo
├── tests/
│   ├── test_crypto.py         # Crypto primitives tests
│   ├── test_key_exchange.py   # Key exchange tests
│   └── test_signature.py      # Signature verification tests
├── keys/                      # Key storage directory
├── data/                      # Database storage
├── main.py                    # Main demo application
├── run_all_demos.py           # Run all attack demos
└── requirements.txt           # Python dependencies
```

## 🚀 Installation & Setup

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Installation Steps

1. **Clone the repository**
   ```bash
   cd Crypto-Project-2
   ```

2. **Create virtual environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

4. **Verify installation**
   ```bash
   python -c "from cryptography.hazmat.primitives import hashes; print('✓ Installation successful')"
   ```

## 💻 Usage

### Quick Start Demo

Run the complete demonstration showing all features:

```bash
python main.py demo
```

This will:
1. Register three users (alice, bob, charlie)
2. Establish secure sessions
3. Record multiple expenses
4. Display the ledger with hash chain verification
5. Calculate and show balances

### Individual Attack Demonstrations

#### 1. Eavesdropping Attack
```bash
python demos/demo_eavesdropping.py
```
Shows how AES-256-GCM encryption protects message confidentiality.

#### 2. Replay Attack
```bash
python demos/demo_replay.py
```
Demonstrates how monotonic counters prevent message replay.

#### 3. Ledger Tampering
```bash
python demos/demo_tampering.py
```
Shows how hash chain detects any modification to stored entries.

### Run All Demos
```bash
python run_all_demos.py
```

## 🔬 Testing

### Run All Tests
```bash
pytest tests/ -v
```

### Run Specific Test Suites
```bash
# Crypto primitives
pytest tests/test_crypto.py -v

# Key exchange
pytest tests/test_key_exchange.py -v

# Signature verification
pytest tests/test_signature.py -v
```

### Test Coverage
```bash
pytest tests/ --cov=. --cov-report=html
```

## 📊 Protocol Flow

### 1. User Registration
```
Client                                Server
  │                                     │
  │──── Register(user_id, pub_key) ───→│
  │                                     │ Store user & initialize counter
  │←──── Success ─────────────────────│
```

### 2. Session Establishment (Signed DH)
```
Client                                Server
  │                                     │
  │──── ClientHello + DH_pub + Sig ───→│
  │                                     │ Verify signature
  │                                     │ Generate DH_pub
  │←─── ServerHello + DH_pub + Sig ───│
  │                                     │
  │ Verify signature                    │
  │ Compute shared secret               │ Compute shared secret
  │ K_session = HKDF(secret)            │ K_session = HKDF(secret)
```

### 3. Expense Submission
```
Client                                Server
  │                                     │
  │ Create expense record               │
  │ Sign(expense || counter || ts)      │
  │ Encrypt with K_session              │
  │                                     │
  │──── Encrypted(expense + sig) ─────→│
  │                                     │ Decrypt with K_session
  │                                     │ Verify signature
  │                                     │ Check counter > stored
  │                                     │ Add to hash chain
  │                                     │ Store in database
  │←──── Encrypted(success) ───────────│
```

## 🔍 Security Analysis

### Threat Model

**Attacker Capabilities:**
- Full control over network (MITM position)
- Can capture, modify, replay messages
- Read/write access to backend storage

**Assumptions:**
- Client devices are secure
- Private keys are not compromised
- Users are authenticated to their client

### Security Properties

✅ **Confidentiality**: All expense data encrypted with AES-256-GCM  
✅ **Integrity**: Modifications detected via GCM tags and signatures  
✅ **Authentication**: Each entry signed by user's private key  
✅ **Non-repudiation**: Digital signatures provide proof of origin  
✅ **Replay Protection**: Monotonic counters prevent replay  
✅ **Tamper Evidence**: Hash chain detects ledger modifications  
✅ **Forward Secrecy**: Ephemeral DH keys protect past sessions  

### Attack Resistance

| Attack | Mechanism | Result |
|--------|-----------|--------|
| Passive eavesdropping | Capture encrypted traffic | ✗ Cannot decrypt without K_session |
| Active MITM | Modify ciphertext | ✗ GCM auth tag verification fails |
| Impersonation | Submit expense as another user | ✗ Signature verification fails |
| Replay | Resend old valid message | ✗ Counter check rejects |
| Ledger tampering | Modify database entry | ✗ Hash chain breaks |
| Key compromise (future) | Steal current session key | ✗ Past sessions protected (forward secrecy) |

## 📈 Performance Considerations

### Cryptographic Operations

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| Key Generation (RSA-2048) | ~100ms | One-time per user |
| DH Parameter Generation | ~2-5s | One-time per server |
| DH Key Exchange | ~10ms | Per session |
| AES-GCM Encrypt/Decrypt | <1ms | Per message |
| RSA-PSS Sign/Verify | ~1-2ms | Per expense |
| SHA-256 Hash | <1ms | Per ledger entry |

### Scalability

- **Users**: Designed for small groups (10-50 users)
- **Expenses**: Hash chain scales linearly O(n)
- **Sessions**: Multiple concurrent sessions supported
- **Storage**: SQLite suitable for thousands of entries

## 🛠️ Development

### Adding New Features

1. **New Message Type**: Add to `shared/protocols.py`
2. **New Crypto Primitive**: Add to `shared/crypto_primitives.py`
3. **New Attack Demo**: Create in `demos/` directory
4. **New Test**: Add to `tests/` directory

### Code Style

- Follow PEP 8 guidelines
- Use type hints where applicable
- Document all cryptographic operations
- Include security considerations in comments

## 📚 References

### Cryptographic Primitives

- **AES-GCM**: NIST SP 800-38D
- **RSA-PSS**: PKCS #1 v2.2
- **Diffie-Hellman**: RFC 2631
- **HKDF**: RFC 5869
- **SHA-256**: FIPS 180-4

### Libraries

- **cryptography**: https://cryptography.io/
- **Python**: https://www.python.org/

### Course Materials

- NYU CS6903/4783 - Applied Cryptography
- Lectures 1-7: Symmetric encryption, public-key crypto, signatures, key exchange

## 🐛 Known Limitations

1. **Small Group Size**: Designed for fixed, small groups
2. **No User Revocation**: Cannot remove users once registered
3. **Simple Balance Calculation**: Basic debt simplification algorithm
4. **No Persistence of Sessions**: Sessions lost on server restart
5. **CLI Only**: No graphical user interface (by design)

## 🔮 Future Enhancements

### Implemented (Core)
- ✅ Authenticated key exchange
- ✅ End-to-end encryption
- ✅ Digital signatures
- ✅ Hash-chained ledger
- ✅ Replay protection
- ✅ Attack demonstrations

### Potential Additions
- ⏳ Cryptographic receipts (server-signed acknowledgments)
- ⏳ Key evolution/rotation
- ⏳ Merkle tree for efficient proofs
- ⏳ Web-based UI
- ⏳ Multi-device support per user
- ⏳ Backup and recovery mechanisms

## 📝 License

This is an academic project for NYU CS6903/4783. All rights reserved.

## 👥 Authors

- **Gagan Yalamuri**
- **Yathish Naraganahalli Veerabhadraiah**

## 🙏 Acknowledgments

- NYU CS6903/4783 course staff
- Python cryptography library maintainers
- OpenSSL project

---

**Note**: This is an educational project demonstrating cryptographic concepts. It is not intended for production use without further security auditing and hardening.
