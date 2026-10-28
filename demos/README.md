# Demo Scripts

This directory contains demonstration scripts that showcase how SplitSmart protects against various attacks.

## Available Demos

### 1. `demo_eavesdropping.py`

**Purpose**: Demonstrates protection against eavesdropping attacks.

**What it does**:
- Sets up a client-server connection
- Shows that intercepted network traffic is encrypted (unintelligible ciphertext)
- Demonstrates that only the intended recipient can decrypt messages

**How to run**:
```bash
python demos/demo_eavesdropping.py
```

**Key demonstration**:
- Shows encrypted ciphertext that an attacker would see
- Shows that decryption requires the session key
- Proves confidentiality protection

---

### 2. `demo_modification.py`

**Purpose**: Demonstrates protection against message modification attacks.

**What it does**:
- Sends a legitimate expense message
- Attempts to modify the encrypted message
- Shows that modification is detected via authentication tag verification

**How to run**:
```bash
python demos/demo_modification.py
```

**Key demonstration**:
- Shows that any modification to ciphertext invalidates the authentication tag
- Demonstrates that modified messages are rejected
- Proves integrity protection

---

### 3. `demo_replay.py`

**Purpose**: Demonstrates protection against replay attacks.

**What it does**:
- Sends a legitimate expense
- Attempts to replay the same message
- Shows that replay is detected via monotonic counter verification

**How to run**:
```bash
python demos/demo_replay.py
```

**Key demonstration**:
- Shows that each message includes an incrementing counter
- Demonstrates that replayed messages are rejected (counter not increasing)
- Proves replay protection

---

### 4. `demo_spoofing.py`

**Purpose**: Demonstrates protection against user impersonation (spoofing) attacks.

**What it does**:
- Registers two users (Alice and Bob)
- Attempts to submit an expense as Bob using Alice's credentials
- Shows that spoofing is detected via signature verification

**How to run**:
```bash
python demos/demo_spoofing.py
```

**Key demonstration**:
- Shows that each expense is signed with the user's private key
- Demonstrates that signature verification fails for impersonated expenses
- Proves authentication and non-repudiation

---

### 5. `demo_tampering.py`

**Purpose**: Demonstrates protection against ledger tampering attacks.

**What it does**:
- Adds legitimate expenses to the ledger
- Directly modifies the database to tamper with entries
- Shows that tampering is detected via hash chain verification

**How to run**:
```bash
python demos/demo_tampering.py
```

**Key demonstration**:
- Shows the hash chain structure (each entry linked to previous)
- Demonstrates that any database modification breaks the chain
- Proves tamper evidence

---

### 6. `demo_ai_security.py`

**Purpose**: Demonstrates the AI security layer that sits on top of the cryptography.

**What it does**:
- Trains a spending baseline for a user from normal expenses
- Submits SQL injection, XSS, command injection, path traversal and prompt injection payloads as expense descriptions
- Submits an unusual expense (flagged) and an extreme one (blocked)
- Simulates password guessing and credential stuffing against the intrusion detector
- Prints the resulting security event log and an analyst explanation

**How to run**:
```bash
python demos/demo_ai_security.py
```

**Key demonstration**:
- Shows the Naive Bayes + signature classifier rejecting malicious payloads
- Shows behavioural anomaly scores (z-score, ratio, absolute limits, unknown payer)
- Shows the adaptive response escalating allow -> challenge -> throttle -> block
- Proves detections are logged and explainable

---

## Running All Demos

To run all attack demonstrations in sequence:

```bash
python run_all_demos.py
```

This script will execute all demo scripts and show a comprehensive security demonstration.

---

## Understanding the Output

Each demo script:
1. **Prints a header** explaining the attack scenario
2. **Shows the defense mechanism** being tested
3. **Demonstrates the attack attempt** (what an attacker would try)
4. **Shows the protection** (how the system prevents the attack)
5. **Confirms security** (verifies the defense worked)

---

## Requirements

All demo scripts require:
- Python 3.8+
- SplitSmart dependencies installed (`pip install -r requirements.txt`)
- Access to `server/` and `client/` modules
- Access to `shared/crypto_primitives.py`

---

## Note

These are **demonstration scripts** for educational purposes. They show how the cryptographic protections work, but they simulate attacks in a controlled environment. In a real attack scenario, the protections would work the same way, but the attack vectors might be more sophisticated.

