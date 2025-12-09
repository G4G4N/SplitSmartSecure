# SplitSmart Testing Guide

Complete guide for testing and demonstrating the SplitSmart cryptographic expense-splitting application.

---

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run all attack demonstrations
python demos/run_all_demos.py

# Run CLI demo
python cli.py demo

# Show attack defenses
python cli.py attacks
```

---

## CLI Commands

### Basic Usage

```bash
# Show help
python cli.py --help

# Register a user
python cli.py register alice

# Register with verbose mode (shows crypto operations)
python cli.py -v register alice

# Login user (establish secure session)
python cli.py login alice

# Login with verbose mode (shows key exchange)
python cli.py -v login alice
```

### Expense Operations

```bash
# Add an expense (requires login first)
python cli.py add alice alice 50.00 "Dinner"

# Add with verbose mode (shows signing and encryption)
python cli.py -v add alice alice 50.00 "Dinner"

# View ledger
python cli.py ledger alice

# View balances
python cli.py balances alice
```

### Security Operations

```bash
# List all registered users
python cli.py users

# Verify ledger integrity
python cli.py verify

# Verify with verbose mode (shows hash chain verification)
python cli.py -v verify

# Check user counter (for replay protection)
python cli.py counter alice

# Show attack defense summary
python cli.py attacks
```

### Demo and Reset

```bash
# Run quick demo (complete workflow)
python cli.py demo

# Reset application (delete all data)
python cli.py reset --confirm
```

---

## Verbose Mode

The `-v` or `--verbose` flag shows detailed cryptographic operations:

### Registration (Verbose)
```bash
python cli.py -v register alice
```
**Shows:**
- RSA-2048 key pair generation
- Public key storage
- Counter initialization

### Login (Verbose)
```bash
python cli.py -v login alice
```
**Shows:**
- Diffie-Hellman key exchange
- Signature creation and verification
- Shared secret computation
- Session key derivation (HKDF)
- Mutual authentication

### Add Expense (Verbose)
```bash
python cli.py -v add alice alice 50.00 "Dinner"
```
**Shows:**
- Expense record signing
- Counter incrementation
- AES-GCM encryption
- Message authentication

### Verify (Verbose)
```bash
python cli.py -v verify
```
**Shows:**
- Hash chain recomputation
- Entry-by-entry verification
- Tamper detection

---

## Attack Demonstrations

### Run All Demos
```bash
python demos/run_all_demos.py
```

### Individual Attack Demos

#### 1. Eavesdropping Attack
```bash
python demos/demo_eavesdropping.py
```
**Demonstrates:**
- Message interception
- Ciphertext capture
- Failed decryption attempt
- **Defense**: AES-256-GCM encryption

#### 2. Modification Attack
```bash
python demos/demo_modification.py
```
**Demonstrates:**
- Message tampering
- Ciphertext modification
- Authentication tag verification failure
- **Defense**: GCM authentication tag

#### 3. Spoofing Attack
```bash
python demos/demo_spoofing.py
```
**Demonstrates:**
- Identity impersonation attempt
- Forged signature
- Signature verification failure
- **Defense**: RSA-PSS digital signatures

#### 4. Replay Attack
```bash
python demos/demo_replay.py
```
**Demonstrates:**
- Message capture and replay
- Old counter detection
- Replay rejection
- **Defense**: Monotonic counters

#### 5. Ledger Tampering
```bash
python demos/demo_tampering.py
```
**Demonstrates:**
- Direct database modification
- Hash chain break
- Tamper detection
- **Defense**: SHA-256 hash chain

---

## Concurrent Users Testing

Test multiple users and race conditions:

```bash
python test_concurrent_users.py
```

**Tests:**
1. Concurrent expense submissions
2. Race conditions in counter validation
3. Replay attacks during concurrent operations
4. Spoofing attacks during concurrent operations

---

## Unit Tests

Run all unit tests:

```bash
# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_crypto.py -v

# Run with coverage
python -m pytest tests/ --cov=. --cov-report=html
```

**Test Files:**
- `test_crypto.py` - Cryptographic primitives
- `test_key_exchange.py` - Key exchange protocol
- `test_signature.py` - Digital signatures
- `test_basic.py` - Basic workflow

---

## Python Interactive Mode

For step-by-step testing:

```bash
python main.py
```

**Interactive Commands:**
```python
# The script will guide you through:
# 1. User registration
# 2. Secure login
# 3. Expense submission
# 4. Ledger viewing
# 5. Balance calculation
```

---

## Testing Checklist

### ✅ Core Functionality
- [ ] User registration
- [ ] Key generation
- [ ] Secure login (key exchange)
- [ ] Expense submission
- [ ] Ledger retrieval
- [ ] Balance calculation

### ✅ Security Features
- [ ] Confidentiality (encryption)
- [ ] Integrity (authentication tags)
- [ ] Authentication (signatures)
- [ ] Replay protection (counters)
- [ ] Tamper evidence (hash chain)

### ✅ Attack Defenses
- [ ] Eavesdropping blocked
- [ ] Modification detected
- [ ] Spoofing prevented
- [ ] Replay rejected
- [ ] Tampering detected

### ✅ Concurrent Operations
- [ ] Multiple users
- [ ] Race conditions handled
- [ ] Counter validation
- [ ] Ledger integrity maintained

---

## Presentation Demonstrations

### Demo 1: Basic Workflow (5 minutes)
```bash
# 1. Show attack defenses
python cli.py attacks

# 2. Run quick demo
python cli.py demo

# 3. Verify integrity
python cli.py -v verify
```

### Demo 2: Cryptographic Operations (5 minutes)
```bash
# 1. Register with verbose
python cli.py -v register demo_user

# 2. Login with verbose (shows key exchange)
python cli.py -v login demo_user

# 3. Verify with verbose (shows hash chain)
python cli.py -v verify
```

### Demo 3: Attack Demonstrations (5 minutes)
```bash
# Run all attack demos
python demos/run_all_demos.py
```

### Demo 4: Concurrent Users (3 minutes)
```bash
# Test concurrent operations
python test_concurrent_users.py
```

---

## Troubleshooting

### Database Locked Error
```bash
# Reset the application
python cli.py reset --confirm
```

### Session Not Found
```bash
# Login again
python cli.py login <username>
```

### Keys Not Found
```bash
# Register the user
python cli.py register <username>
```

### Ledger Integrity Failed
```bash
# Check for tampering
python cli.py verify

# If tampered, reset
python cli.py reset --confirm
```

---

## Performance Testing

### Large Ledger Test
```python
# In Python interactive mode
from client.client import SplitSmartClient
from server.server import SplitSmartServer

server = SplitSmartServer()
client = SplitSmartClient('test_user', server)
client.register()
client.login()

# Submit many expenses
for i in range(100):
    client.add_expense('test_user', 10.0, f'Expense {i}')

# Verify integrity
client.view_ledger()
```

### Concurrent Load Test
```bash
# Run concurrent users test
python test_concurrent_users.py
```

---

## Security Analysis

### Cryptographic Strength
- **RSA**: 2048-bit (112-bit security)
- **DH**: 2048-bit (112-bit security)
- **AES**: 256-bit (128-bit security)
- **SHA-256**: 256-bit (128-bit security)

### Attack Resistance
- **Eavesdropping**: ✅ AES-256-GCM encryption
- **Modification**: ✅ GCM authentication tag
- **Spoofing**: ✅ RSA-PSS signatures
- **Replay**: ✅ Monotonic counters
- **Tampering**: ✅ SHA-256 hash chain

### Forward Secrecy
- ✅ Ephemeral DH keys
- ✅ Session keys derived per session
- ✅ Keys not stored long-term

---

## Additional Resources

- **README.md** - Project overview and setup
- **docs/ARCHITECTURE.md** - System architecture
- **docs/CRYPTO_SPEC.md** - Cryptographic specifications
- **docs/PROJECT_SUMMARY.md** - Project summary
- **IMPLEMENTATION_PLAN.md** - Development plan

---

## Quick Reference

| Command | Purpose |
|---------|---------|
| `python cli.py demo` | Quick demonstration |
| `python cli.py attacks` | Show defenses |
| `python cli.py -v register <user>` | Register with crypto details |
| `python cli.py -v login <user>` | Login with key exchange details |
| `python cli.py -v verify` | Verify with hash chain details |
| `python demos/run_all_demos.py` | All attack demos |
| `python test_concurrent_users.py` | Concurrent testing |
| `python -m pytest tests/` | Unit tests |

---

**For questions or issues, refer to README.md or the documentation in the `docs/` folder.**
