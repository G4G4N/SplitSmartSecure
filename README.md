# SplitSmart - Secure Expense Splitting Application

A cryptographically secure expense-splitting service demonstrating end-to-end encryption, digital signatures, tamper-evident blockchain ledger, protection against common network attacks, and an AI security layer that detects anomalous and malicious activity the cryptography alone cannot see.

## 🎯 Project Overview

**Course**: NYU CS6903/4783 - Applied Cryptography  
**Project**: 2.7 - Designing an end-to-end cryptography solution  
**Team**: Gagan Yalamuri and Yathish Naraganahalli Veerabhadraiah

SplitSmart is a networked expense-splitting service for a fixed group of users (e.g., roommates, friends) that maintains a cryptographically secure, tamper-evident blockchain ledger of shared expenses.

## ✨ What's New - Latest Updates

### 🆕 Major Features Added

1. **🌐 Web Application (Flask)**
   - Beautiful, modern web UI with animations
   - Real-time expense tracking
   - Interactive blockchain ledger visualization
   - Analytics dashboard with charts
   - Security explanation page

2. **🔐 Multiple Encryption Algorithms**
   - **AES-256-GCM**: Hardware-accelerated, best for large messages
   - **ChaCha20-Poly1305**: Fast software implementation, best for small messages
   - **AES-256-CBC-HMAC**: Compatibility option
   - Automatic algorithm selection based on message size

3. **🛡️ Web API Security Enhancements (NEW)**
   - **HMAC-SHA256 Request Integrity**: All web API requests protected with HMAC
   - **Replay Attack Protection**: Request hash deduplication (5-minute window)
   - **Modification Attack Protection**: HMAC verification detects tampered requests
   - **Session-based Integrity Keys**: Unique key per user session
   - **Client-side HMAC Computation**: Web Crypto API for browser-based protection

4. **⛓️ Blockchain Ledger**
   - Block structure with heights and hashes
   - Merkle root computation
   - Tamper-evident hash chain
   - Chain integrity verification

5. **🔑 Password Authentication**
   - Username/password login
   - Secure password hashing (bcrypt)
   - Session management

6. **📊 Analytics Dashboard**
   - Expense summaries
   - Charts and visualizations
   - Detailed analysis
   - Balance calculations

7. **🚀 Deployment Ready**
   - Railway, Render, Heroku configurations
   - Production-ready setup
   - Environment variable support

8. **📽️ Presentation**
   - Complete PowerPoint presentation
   - 17 slides covering all features
   - Attack demonstrations

9. **🧪 Burp Suite Testing Guide**
   - Comprehensive guide for testing attacks with Burp Suite
   - Step-by-step instructions for eavesdropping, modification, replay, and tampering tests
   - Expected results and verification steps

10. **🤖 AI Security Layer (NEW)**
   - **Injection payload classifier**: Naive Bayes model + signature rules reject SQL, XSS, command, path-traversal and prompt-injection payloads
   - **Behavioural anomaly detection**: per-user spending baselines learned from the ledger; unusual expenses are flagged, extreme ones blocked
   - **Adaptive intrusion response**: decaying per-client risk score escalates allow → challenge → throttle → block (brute force, credential stuffing, tampering)
   - **Security event log** persisted in SQLite, live **AI Security Monitor** dashboard with a dry-run "Test the AI" panel
   - **Optional Claude analyst** explains incidents in plain language, with prompt-injection-safe handling of user text
   - Design details in [AI_SECURITY.md](AI_SECURITY.md)

## 🔒 Security Features

### Three-Layer Cryptographic Architecture

1. **Layer 1: Handshake-Level Authentication**
   - Signed Diffie-Hellman key exchange (STS-style)
   - Mutual authentication using RSA-PSS signatures
   - Establishes secure session with forward secrecy
   - Supports multiple encryption algorithms

2. **Layer 2: Per-Entry Authentication**
   - Digital signatures on each expense record (RSA-PSS)
   - Non-repudiation and origin verification
   - Prevents spoofing attacks

3. **Layer 3: Per-Message Protection**
   - Multiple AEAD encryption algorithms
   - Automatic algorithm selection
   - Confidentiality and integrity for all messages
   - Protects against eavesdropping and modification

4. **Layer 4: AI Security (NEW)**
   - Runs after the cryptographic checks on every authenticated submission
   - Threat classifier rejects injection payloads in free-text fields
   - Anomaly detector scores each expense against learned behaviour (z-score, velocity, payer graph, absolute limits)
   - Intrusion detector turns failed logins, HMAC mismatches, replays and bad signatures into a graduated response
   - Protects against misuse of *valid* credentials and sessions

### Attack Defenses

| Attack Type | Defense Mechanism | Implementation | Status |
|------------|-------------------|----------------|--------|
| **Eavesdropping** | Multiple encryption algorithms | AES-256-GCM, ChaCha20-Poly1305, AES-CBC-HMAC | ✅ Protected |
| **Modification** | Authentication tags + HMAC-SHA256 | GCM tags, Poly1305 MAC, HMAC-SHA256 (Web API) | ✅ Protected |
| **Spoofing** | RSA-PSS digital signatures | Each entry signed by user | ✅ Protected |
| **Replay** | Monotonic counters + Request deduplication | Protocol-level counters + Web API hash tracking | ✅ Protected |
| **Ledger Tampering** | Blockchain hash chain | Breaks detected on startup | ✅ Protected |
| **Brute Force** | Rate limiting | API rate limits | ✅ Protected |
| **Injection** | Input validation + AI payload classifier | Sanitization, Naive Bayes model, 19 signature rules | ✅ Protected |
| **Anomalous Transactions** | AI behavioural baselines | z-score / ratio / velocity / payer signals, CRITICAL blocked | ✅ Protected |
| **Credential Stuffing** | AI intrusion response | Decaying per-client score, tarpit + 5-minute block | ✅ Protected |
| **Prompt Injection (LLM)** | Untrusted-data isolation | User text quarantined in the analyst prompt, schema-validated output | ✅ Protected |

### Web API Security Layers

The web application implements **additional security layers** on top of the cryptographic protocol:

1. **Request Integrity (HMAC-SHA256)**
   - Each request includes `X-Request-HMAC` header
   - HMAC computed over request body using session-based integrity key
   - Server verifies HMAC before processing
   - Detects any modification to request payload

2. **Replay Protection (Request Hash Deduplication)**
   - Tracks processed request hashes in memory
   - 5-minute protection window
   - Rejects duplicate requests within window
   - Prevents replay attacks at web API level

3. **Protocol-Level Protection**
   - Underlying cryptographic protocol still active
   - AES-256-GCM encryption for protocol messages
   - RSA-PSS signatures for expense records
   - Monotonic counters for protocol-level replay protection

4. **AI Security Screening (NEW)**
   - Blocked clients receive `403` + `Retry-After` on login, register and expense endpoints
   - Failed logins, HMAC mismatches and replays feed the intrusion score; throttled clients are tarpitted
   - Every expense is screened before signing; responses carry a `security` block (risk score, level, reasons)
   - `/api/ai_security/status`, `/events`, `/analyze` (dry run) and `/explain/<id>` power the dashboard

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Web Client (Browser)                      │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  HTML/CSS    │  │  JavaScript  │  │  API Calls   │      │
│  │  Interface   │──│  Frontend    │──│  (AJAX)      │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────────┬────────────────────────────────┘
                             │ HTTPS
                             │
┌────────────────────────────┴────────────────────────────────┐
│                    Flask Web Server                          │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Flask App   │  │  API Routes   │  │  Session     │      │
│  │  (web_app.py)│──│  & Security   │──│  Management  │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
└────────────────────────────┬────────────────────────────────┘
                             │
                    Encrypted Channel
                    (AES-256-GCM/ChaCha20-Poly1305)
                             │
┌────────────────────────────┴────────────────────────────────┐
│                    SplitSmart Server                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │  Message     │  │  Blockchain   │  │  Storage     │      │
│  │  Processing  │──│  Ledger       │──│  (SQLite)    │      │
│  └──────────────┘  └──────────────┘  └──────────────┘      │
│  ┌──────────────────────────────────────────────────────┐   │
│  │  AI Security Engine: threat classifier · anomaly     │   │
│  │  detection · intrusion response · LLM analyst        │   │
│  └──────────────────────────────────────────────────────┘   │
│                                                              │
│  Blockchain: Genesis → Block 0 → Block 1 → ... → Block N   │
│  Hash Chain: H₀ → H₁ → H₂ → ... → Hₙ                       │
└─────────────────────────────────────────────────────────────┘
```

## 🔐 Cryptographic Specifications

### Algorithms & Parameters

- **Key Exchange**: Diffie-Hellman (2048-bit) + RSA-PSS signatures
- **Symmetric Encryption**: 
  - AES-256-GCM (hardware-accelerated)
  - ChaCha20-Poly1305 (software-optimized)
  - AES-256-CBC-HMAC (compatibility)
- **Digital Signatures**: RSA-PSS (2048-bit)
- **Hash Function**: SHA-256
- **Key Derivation**: HKDF-SHA256
- **Password Hashing**: bcrypt
- **Request Integrity (Web API)**: HMAC-SHA256 (256-bit keys)
- **Replay Protection (Web API)**: SHA-256 request hashing with time-windowed deduplication

### Security Level

All cryptographic choices provide ≥128-bit security, aligned with NIST recommendations.

## 📁 Project Structure

```
SplitSmartSecure/
├── client/                      # Client-side code
│   ├── client.py               # Main client application
│   └── crypto_client.py        # Client-side crypto operations
├── server/                      # Server-side code
│   ├── server.py               # Main server application
│   ├── crypto_server.py        # Server-side crypto operations
│   ├── ledger.py               # Blockchain ledger management
│   └── storage.py              # SQLite database operations
├── shared/                      # Shared utilities
│   ├── crypto_primitives.py    # Core crypto functions
│   ├── protocols.py            # Protocol message formats
│   └── constants.py             # Cryptographic constants
├── ai_security/                 # AI security layer (NEW)
│   ├── engine.py               # Facade: assess / commit / record / dashboard / explain
│   ├── threat_classifier.py    # Naive Bayes + signature injection classifier
│   ├── anomaly_detector.py     # Behavioural baselines and anomaly scoring
│   ├── intrusion_detector.py   # Decaying per-client risk score, adaptive response
│   ├── llm_analyst.py          # Optional Claude-backed incident explanations
│   └── config.py               # Thresholds (overridable via AI_SECURITY_* env vars)
├── demos/                       # Attack demonstrations
│   ├── demo_eavesdropping.py   # Eavesdropping attack demo
│   ├── demo_modification.py    # Modification attack demo
│   ├── demo_spoofing.py        # Spoofing attack demo
│   ├── demo_replay.py          # Replay attack demo
│   ├── demo_tampering.py       # Ledger tampering demo
│   └── demo_ai_security.py     # AI security layer demo (NEW)
├── tests/                       # Test suites
│   ├── test_crypto.py          # Crypto primitives tests
│   ├── test_key_exchange.py     # Key exchange tests
│   ├── test_signature.py       # Signature verification tests
│   ├── test_ai_security.py     # AI security unit + protocol tests (NEW)
│   └── test_web_ai_security.py # AI security web API tests (NEW)
├── static/                      # Web static files
│   ├── css/
│   │   └── style.css           # Web UI styles
│   └── js/
│       └── app.js              # Web UI JavaScript
├── templates/                   # Web templates
│   └── index.html              # Main web page
├── keys/                        # Key storage directory
├── data/                        # Database storage
├── main.py                      # Main demo application
├── web_app.py                   # Flask web application
├── run_all_demos.py             # Run all attack demos
├── requirements.txt             # Python dependencies
├── Procfile                     # Deployment configuration
├── runtime.txt                  # Python version
├── AI_SECURITY.md               # AI security layer design document (NEW)
└── README.md                    # This file
```

## 🚀 Installation & Setup

### Prerequisites

- **Python 3.8 or higher** (Python 3.11 recommended)
- **pip** (Python package manager)
- **Git** (for cloning repository)

### Step-by-Step Installation

#### 1. Clone the Repository

```bash
git clone https://github.com/G4G4N/SplitSmartSecure.git
cd SplitSmartSecure
```

#### 2. Create Virtual Environment

**Windows:**
```powershell
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

**Expected output:**
```
Successfully installed cryptography-41.0.0 flask-3.0.0 flask-cors-4.0.0 bcrypt-4.0.0 ...
```

#### 4. Verify Installation

```bash
python -c "from cryptography.hazmat.primitives import hashes; print('✓ Installation successful')"
```

**Expected output:**
```
✓ Installation successful
```

#### 5. Verify All Components

```bash
# Check Python version
python --version
# Should show: Python 3.8+ or 3.11+

# Check Flask
python -c "import flask; print(f'Flask {flask.__version__}')"

# Check cryptography
python -c "from cryptography.hazmat.primitives import hashes; print('✓ Cryptography OK')"
```

## 💻 Usage

### Option 1: Web Application (Recommended)

#### Start the Web Server

```bash
python web_app.py
```

**Expected output:**
```
================================================================================
                        SplitSmart Web Application
================================================================================

Starting Flask server...
Open your browser to: http://localhost:5000

Press Ctrl+C to stop the server
================================================================================
```

#### Access the Web UI

1. Open your browser
2. Navigate to: `http://localhost:5000`
3. You'll see the SplitSmart web interface

#### Web UI Features

- **Registration**: Create new user account
- **Login**: Secure password-based authentication
- **Add Expenses**: Submit expenses with payer, amount, description
- **View Ledger**: See blockchain ledger with all expenses
- **Analytics**: View charts and statistics
- **Blockchain Info**: See block heights, hashes, chain validity
- **Security Explanation**: Learn how encryption works
- **AI Security Monitor**: Live threat level, detection counters, model details, learned baselines, event log with "Explain", and a dry-run "Test the AI" panel with attack presets

#### Test the Web Application

1. **Register a User:**
   - Click "Register"
   - Enter username and password
   - Click "Register"

2. **Login:**
   - Enter username and password
   - Click "Login"

3. **Add Expenses:**
   - Enter payer name
   - Enter amount (e.g., 50.00)
   - Enter description (e.g., "Dinner")
   - Click "Add Expense"

4. **View Blockchain:**
   - Click "Dashboard"
   - See blockchain ledger
   - View block heights and hashes

5. **View Analytics:**
   - See expense summaries
   - View charts
   - Check balances

### Option 2: Command Line Interface

#### Quick Start Demo

```bash
python main.py demo
```

**This will:**
1. Register three users (alice, bob, charlie)
2. Establish secure sessions
3. Record multiple expenses
4. Display the blockchain ledger with hash chain verification
5. Show blockchain information (blocks, hashes, chain validity)
6. Calculate and show balances

**Expected output:**
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
...
```

#### Interactive Mode

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

### Option 3: Individual Attack Demonstrations

#### 1. Eavesdropping Attack

```bash
python demos/demo_eavesdropping.py
```

**What it demonstrates:**
- How attackers intercept encrypted messages
- Why they cannot decrypt without the session key
- Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305)

**Expected output:**
```
================================================================================
                        ATTACK DEMO: Eavesdropping
================================================================================

Scenario: An attacker intercepts network traffic between client and server
Defense: All messages are encrypted with AES-256-GCM

1. Setting up server and client...
2. Alice registers and logs in...
...
4. ATTACKER INTERCEPTS THE MESSAGE:
   Nonce: a3f9b2c1d4e5f6a7b8c9d0e1f2a3b4c5...
   Ciphertext: x7y8z9a0b1c2d3e4f5g6h7i8j9k0l1m2...
...
✓ AES-256-GCM encryption protects against eavesdropping
```

#### 2. Modification Attack

```bash
python demos/demo_modification.py
```

**What it demonstrates:**
- How attackers try to modify encrypted messages
- How authentication tags detect modifications
- Why modified messages are rejected

#### 3. Spoofing Attack

```bash
python demos/demo_spoofing.py
```

**What it demonstrates:**
- How attackers try to impersonate users
- How digital signatures prevent spoofing
- Why invalid signatures are rejected

#### 4. Replay Attack

```bash
python demos/demo_replay.py
```

**What it demonstrates:**
- How attackers capture and replay old messages
- How monotonic counters prevent replay
- Why old messages are rejected

#### 5. Ledger Tampering

```bash
python demos/demo_tampering.py
```

**What it demonstrates:**
- How attackers modify database directly
- How blockchain hash chain detects tampering
- Why tampered entries break the chain

#### 6. AI Security Layer

```bash
python demos/demo_ai_security.py
```

**Demonstrates:**
- Five injection payloads classified and rejected, then the attacking identity blocked
- A $250 hotel flagged (MEDIUM) but accepted; a $90,000 "yacht" rejected (CRITICAL)
- Password guessing escalating allow → challenge → throttle → block, and credential stuffing
- The persisted security event log and an analyst explanation

### Run All Demos

```bash
python run_all_demos.py
```

**This runs all attack demonstrations sequentially:**
1. Eavesdropping Attack
2. Modification Attack
3. Spoofing Attack
4. Replay Attack
5. Ledger Tampering

## 🤖 AI Security Layer

The AI layer answers a question the cryptography cannot: *is this authentic request also legitimate?* Full design in [AI_SECURITY.md](AI_SECURITY.md).

| Component | Technique | Decides |
|-----------|-----------|---------|
| `ThreatClassifier` | Multinomial Naive Bayes (word, punctuation and char-trigram features, ~250 built-in labelled samples) corroborated by 19 signature rules | Reject SQL / XSS / command / path-traversal / prompt-injection payloads. Only signature-backed verdicts block; the model alone can only raise suspicion |
| `ExpenseAnomalyDetector` | Online per-user and group baselines (Welford mean/variance, velocity, hour-of-day, payer graph), rebuilt from the ledger at start-up | Risk score 0-100 → LOW / MEDIUM / HIGH (flagged) / CRITICAL (blocked) |
| `IntrusionDetector` | Weighted security signals with exponential decay per client (IP or user identity), credential-stuffing detection | allow → challenge → throttle (tarpit) → block (5 min, `Retry-After`) |
| `LLMSecurityAnalyst` | Claude (`claude-opus-5-5`) with structured JSON output; user text isolated as untrusted data | Explains events for the operator; never makes allow/block decisions |

**Try it from the terminal:**

```bash
python cli.py analyze alice 20 "'; DROP TABLE ledger; --"   # dry-run any payload / amount
python cli.py security                                       # dashboard: threat level, models, events
```

**Enable the Claude analyst (optional):**

```bash
pip install anthropic            # already in requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
python web_app.py                # the "Explain" buttons now use Claude
```

Without a key the engine falls back to rule-based explanations, so every other feature works offline. The request opts into Anthropic's server-side refusal fallback (`fallbacks="default"`) so a safety-classifier refusal is retried on a suitable fallback model automatically.

**Tuning:** every threshold is an environment variable (`AI_SECURITY_Z_WARN`, `AI_SECURITY_AMOUNT_CRITICAL`, `AI_SECURITY_BLOCK_SCORE`, `AI_SECURITY_BLOCK_CRITICAL`, `AI_SECURITY_THROTTLE_DELAY`, ...); see `ai_security/config.py` and the table in [AI_SECURITY.md](AI_SECURITY.md#configuration).

## 🔬 Testing

### Run All Tests

```bash
pytest tests/ -v
```

**Expected output:**
```
tests/test_crypto.py::test_aes_gcm_encryption ... PASSED
tests/test_crypto.py::test_rsa_signature ... PASSED
tests/test_key_exchange.py::test_dh_key_exchange ... PASSED
...
```

### Run Specific Test Suites

```bash
# Crypto primitives
pytest tests/test_crypto.py -v

# Key exchange
pytest tests/test_key_exchange.py -v

# Signature verification
pytest tests/test_signature.py -v

# AI security layer (unit + protocol integration)
pytest tests/test_ai_security.py -v

# AI security via the Flask web API
pytest tests/test_web_ai_security.py -v
```

### Test Coverage

```bash
pytest tests/ --cov=. --cov-report=html
```

**This generates:**
- Coverage report in terminal
- HTML report in `htmlcov/index.html`

### Verify Security Features

#### Test 1: Encryption Algorithms

```bash
python -c "
from shared.crypto_primitives import CryptoPrimitives
key = b'0' * 32
plaintext = b'Test message'
nonce, ciphertext = CryptoPrimitives.aes_gcm_encrypt(key, plaintext)
decrypted = CryptoPrimitives.aes_gcm_decrypt(key, nonce, ciphertext)
print('✓ AES-256-GCM works:', decrypted == plaintext)
"
```

#### Test 2: Digital Signatures

```bash
python -c "
from shared.crypto_primitives import CryptoPrimitives
private_key, public_key = CryptoPrimitives.generate_rsa_keypair()
message = b'Test message'
signature = CryptoPrimitives.rsa_pss_sign(private_key, message)
is_valid = CryptoPrimitives.rsa_pss_verify(public_key, signature, message)
print('✓ RSA-PSS signatures work:', is_valid)
"
```

#### Test 3: Blockchain Ledger

```bash
python -c "
from server.server import SplitSmartServer
server = SplitSmartServer()
info = server.ledger.get_blockchain_info()
print('✓ Blockchain initialized')
print(f'  Genesis hash: {info[\"genesis_hash\"][:32]}...')
print(f'  Chain valid: {info[\"is_valid\"]}')
"
```

## ✅ Verification Checklist

### Basic Functionality

- [ ] **Installation**: All dependencies installed successfully
- [ ] **Web Server**: Flask app starts without errors
- [ ] **Registration**: Can register new users
- [ ] **Login**: Can login with username/password
- [ ] **Add Expense**: Can submit expenses
- [ ] **View Ledger**: Can see blockchain ledger
- [ ] **Analytics**: Dashboard shows data

### Security Features

- [ ] **Encryption**: Messages are encrypted (check network tab)
- [ ] **Signatures**: Expenses are signed (check ledger)
- [ ] **Hash Chain**: Blockchain integrity verified
- [ ] **Replay Protection**: Old messages rejected
- [ ] **Tamper Detection**: Database tampering detected

### Attack Demonstrations

- [ ] **Eavesdropping Demo**: Shows ciphertext is unreadable
- [ ] **Modification Demo**: Shows modified messages rejected
- [ ] **Spoofing Demo**: Shows invalid signatures rejected
- [ ] **Replay Demo**: Shows old messages rejected
- [ ] **Tampering Demo**: Shows hash chain breaks

### Web Application

- [ ] **UI Loads**: Web page displays correctly
- [ ] **Registration Form**: Can register users
- [ ] **Login Form**: Can login
- [ ] **Expense Form**: Can add expenses
- [ ] **Dashboard**: Shows analytics
- [ ] **Blockchain**: Shows block information
- [ ] **Security Page**: Explains encryption

## 📊 Protocol Flow

### 1. User Registration

```
Client                                Server
  │                                     │
  │──── Register(user_id, pub_key) ───→│
  │     password_hash                   │ Store user & initialize counter
  │                                     │
  │←──── Success ─────────────────────│
```

### 2. Login & Session Establishment (Signed DH)

```
Client                                Server
  │                                     │
  │──── Login(user_id, password) ─────→│
  │                                     │ Verify password
  │                                     │
  │──── ClientHello + DH_pub + Sig ───→│
  │                                     │ Verify signature
  │                                     │ Generate DH_pub
  │←─── ServerHello + DH_pub + Sig ───│
  │     encryption_algo                 │
  │                                     │
  │ Verify signature                    │
  │ Compute shared secret               │ Compute shared secret
  │ K_session = HKDF(secret)            │ K_session = HKDF(secret)
  │ Select encryption algorithm         │ Store algorithm in session
```

### 3. Expense Submission

```
Client                                Server
  │                                     │
  │ Create expense record               │
  │ Sign(expense || counter || ts)      │
  │ Encrypt with K_session              │
  │ (using selected algorithm)          │
  │                                     │
  │──── Encrypted(expense + sig) ─────→│
  │     algorithm, nonce, ciphertext     │
  │                                     │ Decrypt with K_session
  │                                     │ Verify signature
  │                                     │ Check counter > stored
  │                                     │ Add to blockchain
  │                                     │ Compute block hash
  │                                     │ Store in database
  │←──── Encrypted(success) ───────────│
  │     block_height, block_hash        │
```

## 🔍 Security Analysis

### Threat Model

**Attacker Capabilities:**
- Full control over network (MITM position)
- Can capture, modify, replay messages
- Read/write access to backend storage
- Can attempt brute force attacks

**Assumptions:**
- Client devices are secure
- Private keys are not compromised
- Users are authenticated to their client
- Server is trusted (centralized model)

### Security Properties

✅ **Confidentiality**: All expense data encrypted with multiple algorithms  
✅ **Integrity**: Modifications detected via authentication tags, signatures, and HMAC-SHA256  
✅ **Authentication**: Each entry signed by user's private key  
✅ **Non-repudiation**: Digital signatures provide proof of origin  
✅ **Replay Protection**: Monotonic counters (protocol) + Request deduplication (web API)  
✅ **Tamper Evidence**: Blockchain hash chain detects ledger modifications  
✅ **Forward Secrecy**: Ephemeral DH keys protect past sessions  
✅ **Rate Limiting**: Prevents brute force attacks  
✅ **Input Validation**: Prevents injection attacks  
✅ **Request Integrity**: HMAC-SHA256 protects web API requests from modification  

### Attack Resistance

| Attack | Mechanism | Result |
|--------|-----------|--------|
| Passive eavesdropping | Capture encrypted traffic | ✗ Cannot decrypt without K_session (protocol level) |
| Active MITM | Modify ciphertext | ✗ Authentication tag verification fails (protocol) |
| Active MITM (Web API) | Modify JSON request | ✗ HMAC verification fails (web API level) |
| Impersonation | Submit expense as another user | ✗ Signature verification fails |
| Replay (Protocol) | Resend old valid message | ✗ Counter check rejects |
| Replay (Web API) | Resend same HTTP request | ✗ Request hash deduplication rejects |
| Ledger tampering | Modify database entry | ✗ Hash chain breaks |
| Brute force | Multiple login attempts | ✗ Rate limiting prevents |
| SQL injection | Malicious input | ✗ Input validation prevents |

## 📈 Performance Considerations

### Cryptographic Operations

| Operation | Time Complexity | Notes |
|-----------|----------------|-------|
| Key Generation (RSA-2048) | ~100ms | One-time per user |
| DH Parameter Generation | ~2-5s | One-time per server |
| DH Key Exchange | ~10ms | Per session |
| AES-GCM Encrypt/Decrypt | <1ms | Per message |
| ChaCha20-Poly1305 | <1ms | Per message (small) |
| RSA-PSS Sign/Verify | ~1-2ms | Per expense |
| SHA-256 Hash | <1ms | Per ledger entry |
| HMAC-SHA256 (Web API) | <1ms | Per web API request |
| Blockchain Verification | O(n) | Linear with entries |

### Scalability

- **Users**: Designed for small groups (10-50 users)
- **Expenses**: Hash chain scales linearly O(n)
- **Sessions**: Multiple concurrent sessions supported
- **Storage**: SQLite suitable for thousands of entries
- **Web**: Flask handles concurrent requests

## 🚀 Deployment

### Quick Deploy to Railway

1. **Push to GitHub:**
   ```bash
   git push origin main
   ```

2. **Deploy on Railway:**
   - Go to [railway.app](https://railway.app)
   - Sign up with GitHub
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository

3. **Set Environment Variables:**
   - `SECRET_KEY`: Generate random string
   - `FLASK_DEBUG`: `false`

4. **Get Public URL:**
   - Railway provides URL automatically
   - Share to showcase your project!

See `DEPLOYMENT_GUIDE.md` for detailed instructions.

## 📚 Documentation

### Main Documentation Files

- **README.md** (this file) - Main project documentation
- **AI_SECURITY.md** - AI security layer: models, signals, thresholds, prompt-injection defences (NEW)
- **BURP_SUITE_TESTING_GUIDE.md** - Comprehensive Burp Suite attack testing guide
- **WEB_APP_README.md** - Web application guide
- **BLOCKCHAIN_SECURITY_README.md** - Security documentation
- **ENCRYPTION_ALGORITHMS_README.md** - Encryption algorithms guide
- **DEMO_GUIDE.md** - Demo instructions
- **DEPLOYMENT_GUIDE.md** - Deployment instructions
- **TESTING_GUIDE.md** - Testing guide

### Presentation

- **PRESENTATION.md** - Presentation content
- **SplitSmart_Presentation.pptx** - PowerPoint presentation
- **create_presentation.py** - Script to generate PPT

## 🛠️ Development

### Adding New Features

1. **New Message Type**: Add to `shared/protocols.py`
2. **New Crypto Primitive**: Add to `shared/crypto_primitives.py`
3. **New Attack Demo**: Create in `demos/` directory
4. **New Test**: Add to `tests/` directory
5. **Web Feature**: Update `web_app.py`, `templates/index.html`, `static/js/app.js`

### Code Style

- Follow PEP 8 guidelines
- Use type hints where applicable
- Document all cryptographic operations
- Include security considerations in comments

## 📝 Changelog

### Version 3.0 (Latest - AI Security Layer)

- ✅ New `ai_security/` package: threat classifier, behavioural anomaly detector, intrusion detector, optional Claude analyst
- ✅ Protocol server screens every signed submission; CRITICAL anomalies and injection payloads return `SECURITY_POLICY_VIOLATION`
- ✅ Web API: adaptive client blocking, login tarpit, HMAC/replay signals, `security` block in expense responses
- ✅ `/api/ai_security/{status,events,analyze,explain}` endpoints and the AI Security Monitor dashboard card
- ✅ `security_events` table, `cli.py security` / `cli.py analyze`, `demos/demo_ai_security.py`
- ✅ 21 new tests (`tests/test_ai_security.py`, `tests/test_web_ai_security.py`)

### Version 2.1 (December 2024)

**Added:**
- ✅ **Web API Security Enhancements**:
  - HMAC-SHA256 request integrity verification
  - Replay attack protection with request hash deduplication
  - Modification attack detection at web API level
  - Session-based integrity keys
  - Client-side HMAC computation using Web Crypto API
- ✅ Burp Suite testing guide for all attack types
- ✅ Enhanced error logging and debugging

**Improved:**
- ✅ Web API now protected against replay and modification attacks
- ✅ Better error messages for security failures
- ✅ Comprehensive attack testing documentation

### Version 2.0

**Added:**
- ✅ Web application with Flask
- ✅ Multiple encryption algorithms (AES-GCM, ChaCha20-Poly1305, AES-CBC-HMAC)
- ✅ Blockchain ledger with block structure
- ✅ Password authentication
- ✅ Analytics dashboard
- ✅ Deployment configurations
- ✅ PowerPoint presentation
- ✅ Comprehensive documentation

**Improved:**
- ✅ Algorithm selection based on message size
- ✅ Enhanced security features
- ✅ Better error handling
- ✅ Production-ready configuration

### Version 1.0 (Initial)

**Features:**
- ✅ Basic CLI application
- ✅ AES-256-GCM encryption
- ✅ RSA-PSS signatures
- ✅ Hash chain ledger
- ✅ Attack demonstrations

## 🐛 Known Limitations

1. **Small Group Size**: Designed for fixed, small groups
2. **No User Revocation**: Cannot remove users once registered
3. **Simple Balance Calculation**: Basic debt simplification algorithm
4. **SQLite Database**: File-based, not ideal for high concurrency
5. **Centralized Server**: Single point of trust
6. **AI Baselines Need History**: z-score checks start after 5 entries; before that only absolute, velocity and payer checks apply
7. **Process-Local Intrusion Scores**: with several web workers each process keeps its own live scores (persisted events are shared)

## 🔮 Future Enhancements

### Potential Additions

- ⏳ PostgreSQL database support
- ⏳ Key rotation/evolution
- ⏳ Merkle tree for efficient proofs
- ⏳ Mobile app (iOS/Android)
- ⏳ Multi-device support per user
- ⏳ Backup and recovery mechanisms
- ⏳ Post-quantum cryptography
- ⏳ Distributed ledger

## 📚 References

### Cryptographic Primitives

- **AES-GCM**: NIST SP 800-38D
- **ChaCha20-Poly1305**: RFC 8439
- **RSA-PSS**: PKCS #1 v2.2
- **Diffie-Hellman**: RFC 2631
- **HKDF**: RFC 5869
- **SHA-256**: FIPS 180-4
- **bcrypt**: OpenBSD

### Libraries

- **cryptography**: https://cryptography.io/
- **Flask**: https://flask.palletsprojects.com/
- **Python**: https://www.python.org/

### Course Materials

- NYU CS6903/4783 - Applied Cryptography
- Lectures 1-7: Symmetric encryption, public-key crypto, signatures, key exchange

## 📝 License

This is an academic project for NYU CS6903/4783. All rights reserved.

## 👥 Authors

- **Gagan Yalamuri**
- **Yathish Naraganahalli Veerabhadraiah**

## 🙏 Acknowledgments

- NYU CS6903/4783 course staff
- Python cryptography library maintainers
- Flask framework developers
- OpenSSL project

---

## 🎓 Quick Start Summary

1. **Install**: `pip install -r requirements.txt`
2. **Run Web App**: `python web_app.py` → Open `http://localhost:5000` (or `http://localhost:5001` if port 5000 is in use)
3. **Run Demo**: `python main.py demo`
4. **Test Attacks**: 
   - CLI: `python demos/demo_eavesdropping.py`
   - Burp Suite: See `BURP_SUITE_TESTING_GUIDE.md`
5. **Run Tests**: `pytest tests/ -v`

**For detailed instructions, see sections above.**

## 🧪 Testing with Burp Suite

The application now includes comprehensive Burp Suite testing capabilities:

- **Eavesdropping**: Capture and examine intercepted requests
- **Modification**: Test HMAC-based request integrity protection
- **Replay**: Verify request deduplication prevents duplicate submissions
- **Tampering**: Test database tampering detection (requires direct DB access)

See **BURP_SUITE_TESTING_GUIDE.md** for complete step-by-step instructions.

---

**Note**: This is an educational project demonstrating cryptographic concepts. It is not intended for production use without further security auditing and hardening.
