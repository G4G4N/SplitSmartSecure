# SplitSmart Demo Guide

This guide explains how to run all demonstrations individually to see how SplitSmart's security features work.

## Quick Start

### Basic Functionality Demo

Run the main demo to see the complete system in action:

```bash
python main.py demo
```

This will:
- Register three users (alice, bob, charlie)
- Establish secure sessions with authenticated key exchange
- Record multiple expenses with digital signatures
- Display the blockchain ledger with hash chain verification
- Show blockchain information (blocks, hashes, chain validity)
- Calculate and show balances

## Individual Attack Demonstrations

### 1. Eavesdropping Attack

**File**: `demos/demo_eavesdropping.py`

**What it demonstrates:**
- How attackers intercept encrypted messages
- Why they cannot decrypt without the session key
- How multiple encryption algorithms protect confidentiality

**Run:**
```bash
python demos/demo_eavesdropping.py
```

**What you'll see:**
- Attacker intercepts encrypted message
- Ciphertext appears as random data
- Server successfully decrypts with session key
- Multiple encryption algorithms explained (AES-256-GCM, ChaCha20-Poly1305, AES-CBC-HMAC)

### 2. Modification Attack

**File**: `demos/demo_modification.py`

**What it demonstrates:**
- How attackers try to modify encrypted messages
- How authentication tags detect modifications
- Why modified messages are rejected

**Run:**
```bash
python demos/demo_modification.py
```

**What you'll see:**
- Attacker intercepts and modifies encrypted message
- Server attempts to decrypt modified message
- Authentication tag verification fails
- Modified message is rejected

### 3. Spoofing Attack

**File**: `demos/demo_spoofing.py`

**What it demonstrates:**
- How attackers try to impersonate users
- How digital signatures prevent spoofing
- Why invalid signatures are rejected

**Run:**
```bash
python demos/demo_spoofing.py
```

**What you'll see:**
- Attacker tries to create expense as another user
- Signature verification fails
- Spoofed message is rejected
- Only valid signatures are accepted

### 4. Replay Attack

**File**: `demos/demo_replay.py`

**What it demonstrates:**
- How attackers capture and replay old messages
- How monotonic counters prevent replay
- Why old messages are rejected

**Run:**
```bash
python demos/demo_replay.py
```

**What you'll see:**
- Attacker captures valid message
- Attacker replays message later
- Counter check detects replay
- Replayed message is rejected
- Ledger remains intact

### 5. Ledger Tampering

**File**: `demos/demo_tampering.py`

**What it demonstrates:**
- How attackers modify database directly
- How blockchain hash chain detects tampering
- Why tampered entries break the chain

**Run:**
```bash
python demos/demo_tampering.py
```

**What you'll see:**
- Legitimate expenses added to blockchain
- Attacker modifies database directly
- Server detects tampering on restart
- Hash chain verification fails
- Blockchain structure explained

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

Available commands:
- `register <username>` - Register a new user
- `login <username>` - Login as user
- `add <payer> <amount> <desc>` - Add expense
- `ledger` - View blockchain ledger
- `balances` - View balances
- `users` - List registered users
- `logout` - Logout current user
- `exit` - Exit program

## Understanding the Output

### Blockchain Information

When viewing the ledger, you'll see:
- **Block Height**: Sequential block number
- **Block Hash**: Cryptographic hash of the block
- **Previous Hash**: Link to previous block
- **Merkle Root**: Hash of block contents
- **Chain Validity**: Whether the chain is intact

### Encryption Algorithms

The system automatically selects encryption algorithms:
- **AES-256-GCM**: For large messages (>10KB)
- **ChaCha20-Poly1305**: For small messages (<1KB)
- **AES-256-CBC-HMAC**: For compatibility

### Security Features Demonstrated

1. **Confidentiality**: Messages encrypted end-to-end
2. **Integrity**: Authentication tags detect modifications
3. **Authentication**: Digital signatures verify identity
4. **Non-repudiation**: Signatures provide proof
5. **Replay Protection**: Counters prevent replay
6. **Tamper Evidence**: Hash chain detects tampering

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

## Advanced Usage

### Custom Demo Scripts

You can create your own demo scripts by importing:

```python
from server.server import SplitSmartServer
from client.client import SplitSmartClient

# Initialize server
server = SplitSmartServer()

# Create client
client = SplitSmartClient("username", server)

# Register and login
client.register()
client.login()

# Add expense
client.add_expense("payer", 100.00, "Description")

# View ledger
client.view_ledger()

# View balances
client.view_balances()
```

### Testing Blockchain Integrity

Check blockchain integrity:

```python
from server.server import SplitSmartServer

server = SplitSmartServer()
is_valid, error = server.ledger.verify_chain_integrity()

if is_valid:
    print("✓ Blockchain is valid")
else:
    print(f"✗ Blockchain tampered: {error}")
```

### Getting Blockchain Info

Get blockchain statistics:

```python
from server.server import SplitSmartServer

server = SplitSmartServer()
info = server.ledger.get_blockchain_info()

print(f"Total Blocks: {info['total_blocks']}")
print(f"Chain Length: {info['chain_length']}")
print(f"Chain Valid: {info['is_valid']}")
print(f"Genesis Hash: {info['genesis_hash']}")
print(f"Latest Block Hash: {info['latest_block_hash']}")
```

## Security Features Summary

| Feature | Protection | Demo |
|---------|-----------|------|
| **Encryption** | Confidentiality | `demo_eavesdropping.py` |
| **Authentication Tags** | Integrity | `demo_modification.py` |
| **Digital Signatures** | Authentication | `demo_spoofing.py` |
| **Monotonic Counters** | Replay Protection | `demo_replay.py` |
| **Hash Chain** | Tamper Evidence | `demo_tampering.py` |

## Next Steps

After running the demos:
1. Explore the web UI: `python web_app.py`
2. Read the security documentation: `BLOCKCHAIN_SECURITY_README.md`
3. Review the encryption algorithms: `ENCRYPTION_ALGORITHMS_README.md`
4. Check the main README: `README.md`

## Support

For issues or questions:
- Check the error messages in the demos
- Review the documentation files
- Examine the source code comments
- Run individual demos to isolate issues

