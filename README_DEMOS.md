# SplitSmart Demo Instructions

## Quick Start

### Basic Functionality Demo

Run the main demo to see the complete system in action:

```bash
python main.py demo
```

**What it does:**
- ✅ Registers three users (alice, bob, charlie)
- ✅ Establishes secure sessions with authenticated key exchange
- ✅ Records multiple expenses with digital signatures
- ✅ Displays the blockchain ledger with hash chain verification
- ✅ Shows blockchain information (blocks, hashes, chain validity)
- ✅ Calculates and shows balances

**Output includes:**
- User registration and login
- Expense submissions
- Blockchain ledger with block heights and hashes
- Chain integrity verification
- Balance calculations

## Individual Attack Demonstrations

### 1. Eavesdropping Attack

**Run:**
```bash
python demos/demo_eavesdropping.py
```

**Demonstrates:**
- How attackers intercept encrypted messages
- Why they cannot decrypt without the session key
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305, AES-CBC-HMAC)

### 2. Modification Attack

**Run:**
```bash
python demos/demo_modification.py
```

**Demonstrates:**
- How attackers try to modify encrypted messages
- How authentication tags detect modifications
- Why modified messages are rejected

### 3. Spoofing Attack

**Run:**
```bash
python demos/demo_spoofing.py
```

**Demonstrates:**
- How attackers try to impersonate users
- How digital signatures prevent spoofing
- Why invalid signatures are rejected

### 4. Replay Attack

**Run:**
```bash
python demos/demo_replay.py
```

**Demonstrates:**
- How attackers capture and replay old messages
- How monotonic counters prevent replay
- Why old messages are rejected

### 5. Ledger Tampering

**Run:**
```bash
python demos/demo_tampering.py
```

**Demonstrates:**
- How attackers modify database directly
- How blockchain hash chain detects tampering
- Why tampered entries break the chain

## Run All Demos

Run all attack demonstrations sequentially:

```bash
python run_all_demos.py
```

This will:
1. Run each demo individually
2. Clean up between demos
3. Show results for each attack scenario
4. Demonstrate all security features

## Interactive Mode

Run the interactive CLI:

```bash
python main.py interactive
```

**Available commands:**
- `register <username>` - Register a new user
- `login <username>` - Login as user
- `add <payer> <amount> <desc>` - Add expense
- `ledger` - View blockchain ledger
- `balances` - View balances
- `users` - List registered users
- `logout` - Logout current user
- `exit` - Exit program

## Testing

### Run All Tests

```bash
pytest tests/ -v
```

### Run Specific Test Suites

**Crypto primitives:**
```bash
pytest tests/test_crypto.py -v
```

**Key exchange:**
```bash
pytest tests/test_key_exchange.py -v
```

**Signature verification:**
```bash
pytest tests/test_signature.py -v
```

### Test Coverage

```bash
pytest tests/ --cov=. --cov-report=html
```

## Understanding the Output

### Blockchain Information

When viewing the ledger, you'll see:
- **Block Height**: Sequential block number (0, 1, 2, ...)
- **Block Hash**: Cryptographic hash of the block
- **Previous Hash**: Link to previous block
- **Merkle Root**: Hash of block contents
- **Chain Validity**: Whether the chain is intact

### Encryption Algorithms

The system automatically selects encryption algorithms:
- **AES-256-GCM**: For large messages (>10KB), hardware-accelerated
- **ChaCha20-Poly1305**: For small messages (<1KB), fast software implementation
- **AES-256-CBC-HMAC**: For compatibility requirements

### Security Features Demonstrated

| Feature | Protection | Demo |
|---------|-----------|------|
| **Encryption** | Confidentiality | `demo_eavesdropping.py` |
| **Authentication Tags** | Integrity | `demo_modification.py` |
| **Digital Signatures** | Authentication | `demo_spoofing.py` |
| **Monotonic Counters** | Replay Protection | `demo_replay.py` |
| **Hash Chain** | Tamper Evidence | `demo_tampering.py` |

## Example Output

### Main Demo Output

```
================================================================================
                    SplitSmart - Secure Expense Splitting Demo
================================================================================

ℹ Initializing server...
✓ Server initialized

================================================================================
                        Phase 1: User Registration
================================================================================

Registering alice...
✓ alice registered

Registering bob...
✓ bob registered

Registering charlie...
✓ charlie registered

================================================================================
              Phase 2: Secure Session Establishment
================================================================================

alice logging in...
✓ alice established secure session

bob logging in...
✓ bob established secure session

charlie logging in...
✓ charlie established secure session

================================================================================
                        Phase 3: Recording Expenses
================================================================================

Alice pays for dinner...
✓ Expense added: Entry ID 1

Bob pays for groceries...
✓ Expense added: Entry ID 2

Charlie pays for movie tickets...
✓ Expense added: Entry ID 3

Alice pays for coffee...
✓ Expense added: Entry ID 4

================================================================================
                    Phase 4: Viewing Blockchain Ledger
================================================================================

Alice viewing blockchain ledger...
✓ Ledger retrieved successfully

Blockchain Information:
  Total Blocks: 4
  Chain Length: 4
  Chain Valid: ✓ Yes
  Genesis Hash: 5f4dcc3b5aa765d61d8327deb882cf99...
  Latest Block Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...

Block Details:
  Block #2: bob paid $45.50
    Hash: a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6...
    Prev Hash: 1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7...

================================================================================
                      Phase 5: Calculating Balances
================================================================================

Bob viewing balances...
✓ Balances calculated successfully

================================================================================
                          Demo Complete
================================================================================

✓ All operations completed successfully!
ℹ The blockchain ledger is cryptographically secured with:
  • Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305, AES-CBC-HMAC)
  • Digital signatures (RSA-PSS)
  • Blockchain hash chain for tamper evidence
  • Merkle roots for efficient verification
  • Replay protection via monotonic counters
  • Authenticated key exchange (Signed Diffie-Hellman)
  • Three-layer cryptographic architecture
```

## Troubleshooting

### Database Locked Error

If you see "database is locked":
- Wait a few seconds and try again
- Close any other instances of the application
- The demos clean up between runs automatically

### Import Errors

If you see import errors:
- Make sure you're in the project root directory
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Check that Python can find the modules

### Demo Fails

If a demo fails:
- Check the error message
- Ensure previous demos completed successfully
- Try running the demo individually
- Check that the database file exists and is accessible

## Next Steps

After running the demos:
1. Explore the web UI: `python web_app.py`
2. Read the security documentation: `BLOCKCHAIN_SECURITY_README.md`
3. Review the encryption algorithms: `ENCRYPTION_ALGORITHMS_README.md`
4. Check the main README: `README.md`
5. Read the demo guide: `DEMO_GUIDE.md`

