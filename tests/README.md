# Test Suite

This directory contains test scripts that verify the correctness and security of SplitSmart's cryptographic implementations.

## Available Tests

### 1. `test_basic.py`

**Purpose**: Basic functionality test to verify core operations work correctly.

**What it tests**:
- Server initialization
- User registration
- User login (key exchange)
- Expense submission
- Ledger viewing
- Balance calculation

**How to run**:
```bash
python tests/test_basic.py
```

**Expected output**: All operations complete successfully with ✓ checkmarks.

---

### 2. `test_crypto.py`

**Purpose**: Tests cryptographic primitives in isolation.

**What it tests**:
- AES-GCM encryption/decryption
- ChaCha20-Poly1305 encryption/decryption
- AES-CBC-HMAC encryption/decryption
- RSA key generation
- RSA-PSS signature creation and verification
- SHA-256 hashing
- HKDF key derivation

**How to run**:
```bash
python tests/test_crypto.py
```

**Expected output**: All cryptographic operations pass verification.

---

### 3. `test_key_exchange.py`

**Purpose**: Tests the Diffie-Hellman key exchange protocol.

**What it tests**:
- Server crypto initialization
- Client crypto initialization
- DH parameter generation
- Client hello message creation
- Server hello message creation
- Shared secret computation (both sides)
- Session key derivation
- Signature verification during key exchange

**How to run**:
```bash
python tests/test_key_exchange.py
```

**Expected output**: Key exchange completes successfully, both parties derive the same session key.

---

### 4. `test_signature.py`

**Purpose**: Tests expense signing and verification.

**What it tests**:
- Expense data creation
- Client-side expense signing
- Server-side signature verification
- Signature validation with correct data
- Signature rejection with modified data

**How to run**:
```bash
python tests/test_signature.py
```

**Expected output**: Valid signatures are accepted, invalid signatures are rejected.

---

### 5. `test_concurrent_users.py`

**Purpose**: Tests concurrent operations and race conditions.

**What it tests**:
- Multiple users registering simultaneously
- Multiple users logging in simultaneously
- Multiple users submitting expenses concurrently
- Counter management under concurrent access
- Ledger integrity with concurrent writes
- Thread safety of cryptographic operations

**How to run**:
```bash
python tests/test_concurrent_users.py
```

**Expected output**: All concurrent operations complete successfully, no race conditions detected.

---

### 6. `test_debug.py`

**Purpose**: Debug test to diagnose encryption/decryption issues.

**What it tests**:
- End-to-end message encryption/decryption
- Message serialization
- Protocol message creation
- Error handling

**How to run**:
```bash
python tests/test_debug.py
```

**Expected output**: Detailed output showing each step of the encryption/decryption process.

---

### 7. `test_ai_security.py`

**Purpose**: Tests the AI security layer (`ai_security/` package).

**What it tests**:
- Threat classifier: injection payloads detected, benign descriptions accepted, model-only verdicts never block
- Anomaly detector: baselines, z-score / ratio / absolute outliers, velocity and duplicate bursts, unknown payers, training from ledger rows
- Intrusion detector: allow -> challenge -> throttle -> block escalation, credential stuffing, decay and unblock
- Engine: block / flag decisions, event persistence, dashboard, rule-based explanations, LLM payload isolation
- End-to-end: the protocol server rejects injections, blocks CRITICAL anomalies, blocks a repeatedly attacking identity, and re-learns baselines after restart

**How to run**:
```bash
python tests/test_ai_security.py
```

---

### 8. `test_web_ai_security.py`

**Purpose**: Tests the AI security layer through the Flask web API.

**What it tests**:
- `/api/add_expense` rejects injection payloads (400) and CRITICAL anomalies (403) with a `security` report
- Clean expenses succeed with a LOW risk report
- Four failed logins block a client; the fifth attempt returns 403 with `Retry-After`
- HMAC mismatches are recorded as `hmac_mismatch` events
- `/api/ai_security/status`, `/events`, `/analyze` (dry run) and `/explain/<id>` behave as documented

**How to run**:
```bash
python tests/test_web_ai_security.py
```

---

## Running All Tests

To run all tests using pytest:

```bash
pytest tests/ -v
```

To run with coverage:

```bash
pytest tests/ --cov=. --cov-report=html
```

---

## Test Structure

Each test script:
1. **Imports required modules** (server, client, crypto primitives)
2. **Sets up test environment** (creates server, registers users)
3. **Performs operations** (login, add expenses, etc.)
4. **Verifies results** (checks signatures, counters, ledger integrity)
5. **Prints results** (✓ for pass, ✗ for fail)

---

## Understanding Test Output

- **✓ (checkmark)**: Test passed
- **✗ (cross)**: Test failed
- **Error messages**: Indicate what went wrong
- **Debug output**: Shows intermediate steps (in verbose tests)

---

## Requirements

All test scripts require:
- Python 3.8+
- SplitSmart dependencies installed (`pip install -r requirements.txt`)
- Access to `server/`, `client/`, and `shared/` modules
- (Optional) pytest for running all tests: `pip install pytest pytest-cov`

---

## Writing New Tests

To add a new test:

1. Create a new file: `tests/test_<feature>.py`
2. Import required modules
3. Write test functions
4. Use print statements to show progress
5. Use assertions or manual checks to verify correctness

Example:
```python
#!/usr/bin/env python3
"""
Test <feature name>.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient

def test_feature():
    print("Testing <feature>...")
    # Setup
    server = SplitSmartServer()
    client = SplitSmartClient("test_user", server)
    
    # Test operation
    result = client.some_operation()
    
    # Verify
    if result:
        print("✓ Test passed!")
    else:
        print("✗ Test failed!")
```

---

## Note

These tests verify **correctness** and **security properties**. They do not test performance or scalability. For performance testing, use the demo scripts or create dedicated benchmarks.

