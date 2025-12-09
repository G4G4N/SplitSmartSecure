# SplitSmart: End-to-End Cryptography Solution
## Project 2.7 - Presentation Outline

---

## Slide 1: Title Slide

**Title:** SplitSmart: End-to-End Cryptography Solution for Secure Expense Splitting

**Subtitle:** Protecting Data Against Eavesdropping, Modification, Spoofing, and Replay Attacks

**Presented by:** [Your Name]

**Course:** [Course Name/Number]

**Date:** [Date]

---

## Slide 2: Project Overview

### Objective
Design and implement an end-to-end cryptography solution to protect a real-life data processing application from security attacks.

### Application: SplitSmart
- **Purpose:** Secure expense splitting application
- **Use Case:** Groups of users splitting expenses (e.g., roommates, friends, colleagues)
- **Challenge:** Protect financial data from various attacks

### Key Requirements
- ✅ Protect against 4 core attacks
- ✅ Use state-of-the-art cryptographic algorithms
- ✅ Implement using available cryptography libraries
- ✅ Demonstrate effectiveness through working demos

---

## Slide 3: Application Architecture

### SplitSmart Components

**Client-Side:**
- User registration and authentication
- Expense submission interface
- Cryptographic operations (encryption, signing)
- Session management

**Server-Side:**
- User management
- Blockchain ledger storage
- Message processing and verification
- Balance calculations

**Security Layer:**
- End-to-end encryption
- Digital signatures
- Hash chain (blockchain-inspired)
- Replay protection

---

## Slide 4: Threat Model - Four Core Attacks

### 1. Data Eavesdropping
- **Threat:** Attacker intercepts network traffic
- **Risk:** Unauthorized access to expense data
- **Impact:** Privacy violation, financial information exposure

### 2. Data Modification
- **Threat:** Attacker modifies messages in transit
- **Risk:** Unauthorized changes to expense amounts/descriptions
- **Impact:** Financial fraud, incorrect balances

### 3. Data Originator Spoofing
- **Threat:** Attacker impersonates legitimate users
- **Risk:** Unauthorized expense submissions
- **Impact:** Fraudulent charges, incorrect accounting

### 4. Data Replay
- **Threat:** Attacker captures and replays old messages
- **Risk:** Duplicate expense entries
- **Impact:** Double-charging, incorrect balances

---

## Slide 5: Cryptographic Architecture - Three Layers

### Layer 1: Handshake-Level Authentication
**Technology:** Signed Diffie-Hellman Key Exchange
- Mutual authentication between client and server
- Establishes secure session with forward secrecy
- Prevents man-in-the-middle attacks

### Layer 2: Per-Entry Authentication
**Technology:** RSA-PSS Digital Signatures
- Each expense signed by user's private key
- Server verifies signature using public key
- Provides non-repudiation

### Layer 3: Per-Message Protection
**Technology:** Multiple AEAD Encryption Algorithms
- AES-256-GCM (hardware-accelerated)
- ChaCha20-Poly1305 (software-optimized)
- AES-256-CBC-HMAC (compatibility)

---

## Slide 6: Defense Against Attack #1: Eavesdropping

### Attack Scenario
- Attacker intercepts network traffic
- Attempts to read expense data

### Defense Mechanism
**End-to-End Encryption:**
- All messages encrypted with AES-256-GCM or ChaCha20-Poly1305
- Session keys derived from Diffie-Hellman key exchange
- 256-bit key strength provides confidentiality

### Implementation
```python
# Automatic algorithm selection based on message size
if message_size < 1KB:
    algorithm = "ChaCha20-Poly1305"
else:
    algorithm = "AES-256-GCM"

encrypted = encrypt_message(plaintext, algorithm)
```

### Result
✅ Attacker sees only ciphertext (cryptographically secure random data)
✅ Cannot decrypt without session key
✅ Confidentiality preserved

---

## Slide 7: Defense Against Attack #2: Modification

### Attack Scenario
- Attacker intercepts and modifies encrypted messages
- Attempts to change expense amounts or descriptions

### Defense Mechanism
**Authenticated Encryption:**
- AES-256-GCM includes authentication tag
- ChaCha20-Poly1305 includes Poly1305 MAC
- Any modification breaks authentication tag

### Implementation
```python
# Encryption includes authentication tag
ciphertext, tag = aes_gcm_encrypt(key, plaintext)

# Decryption verifies tag
plaintext = aes_gcm_decrypt(key, ciphertext, tag)
# Raises exception if tag invalid
```

### Result
✅ Modified messages detected immediately
✅ Authentication tag verification fails
✅ Modified messages rejected by server
✅ Integrity preserved

---

## Slide 8: Defense Against Attack #3: Spoofing

### Attack Scenario
- Attacker tries to submit expenses as another user
- Attempts to impersonate legitimate users

### Defense Mechanism
**Digital Signatures (RSA-PSS):**
- Each expense signed with user's private key
- Server verifies signature using user's public key
- 2048-bit RSA provides ~112-bit security

### Implementation
```python
# User signs expense
signature = sign_expense(payer, amount, description, timestamp)

# Server verifies signature
is_valid = verify_signature(signature, user_public_key, data)
if not is_valid:
    reject_message()
```

### Result
✅ Invalid signatures detected
✅ Spoofed messages rejected
✅ Only legitimate users can create expenses
✅ Authentication and non-repudiation provided

---

## Slide 9: Defense Against Attack #4: Replay

### Attack Scenario
- Attacker captures valid messages
- Replays them later to create duplicate entries

### Defense Mechanism
**Monotonic Counters:**
- Each user has a counter that increments with each message
- Server checks counter is strictly increasing
- Old messages have lower counters and are rejected

### Implementation
```python
# Client increments counter
counter = get_next_counter()  # e.g., 1, 2, 3, ...

# Server verifies
if counter <= stored_counter:
    reject_message("Replay detected")
else:
    accept_message()
    update_counter(counter)
```

### Result
✅ Replayed messages detected
✅ Counter check prevents replay
✅ Old messages cannot be reused
✅ Replay protection achieved

---

## Slide 10: Blockchain Ledger - Tamper Evidence

### Additional Security: Hash Chain

**Blockchain Structure:**
- Each expense stored as a block
- Blocks linked via cryptographic hashes
- Genesis block starts the chain

**Block Components:**
- Block height (sequential number)
- Previous block hash
- Merkle root
- Block hash
- Entry data with signature

### Tamper Detection
```python
# Each block contains hash of previous block
block_hash = hash(prev_hash || block_data)

# Tampering breaks the chain
if verify_chain_integrity() == False:
    alert("Tampering detected!")
```

### Result
✅ Any database modification detected
✅ Hash chain breaks on tampering
✅ Provides tamper-evident history
✅ Blockchain-inspired security

---

## Slide 11: Cryptographic Algorithms Used

### Key Exchange
- **Diffie-Hellman (2048-bit):** Secure key exchange
- **HKDF-SHA256:** Key derivation from shared secret
- **RSA-2048:** Digital signatures and key exchange signatures

### Encryption
- **AES-256-GCM:** Authenticated encryption, hardware-accelerated
- **ChaCha20-Poly1305:** Authenticated encryption, software-optimized
- **AES-256-CBC-HMAC:** Encrypt-then-MAC for compatibility

### Hashing
- **SHA-256:** Hash chain and key derivation
- **HMAC-SHA256:** Message authentication (for CBC mode)

### Digital Signatures
- **RSA-PSS:** Probabilistic signature scheme
- **2048-bit keys:** ~112-bit security level

---

## Slide 12: Implementation Details

### Technology Stack
- **Language:** Python 3.x
- **Cryptography Library:** `cryptography` (Python)
- **Web Framework:** Flask
- **Database:** SQLite with blockchain structure
- **Frontend:** HTML, CSS, JavaScript

### Key Components
1. **Client Crypto (`client/crypto_client.py`):** Encryption, signing, key exchange
2. **Server Crypto (`server/crypto_server.py`):** Decryption, verification, session management
3. **Ledger (`server/ledger.py`):** Blockchain hash chain implementation
4. **Storage (`server/storage.py`):** Database with blockchain schema
5. **Protocols (`shared/protocols.py`):** Message format definitions

### Code Statistics
- ~3,000+ lines of Python code
- Comprehensive error handling
- Extensive documentation

---

## Slide 13: Demonstration - Attack Scenarios

### Demo 1: Eavesdropping Attack
```bash
python demos/demo_eavesdropping.py
```
- Shows intercepted ciphertext
- Demonstrates inability to decrypt
- Confirms confidentiality

### Demo 2: Modification Attack
```bash
python demos/demo_modification.py
```
- Shows message modification attempt
- Demonstrates tag verification failure
- Confirms integrity protection

### Demo 3: Spoofing Attack
```bash
python demos/demo_spoofing.py
```
- Shows impersonation attempt
- Demonstrates signature verification failure
- Confirms authentication

### Demo 4: Replay Attack
```bash
python demos/demo_replay.py
```
- Shows message replay attempt
- Demonstrates counter check failure
- Confirms replay protection

---

## Slide 14: Demonstration - Blockchain Tampering

### Demo 5: Ledger Tampering
```bash
python demos/demo_tampering.py
```

**Process:**
1. Legitimate expenses added to blockchain
2. Attacker modifies database directly
3. Server detects tampering on restart
4. Hash chain verification fails
5. Tampering alert generated

**Result:**
✅ Any modification to ledger detected
✅ Blockchain structure prevents undetected tampering
✅ Provides audit trail

---

## Slide 15: Security Properties Achieved

### Confidentiality ✅
- All messages encrypted end-to-end
- Multiple encryption algorithms
- 256-bit key strength

### Integrity ✅
- Authentication tags detect modifications
- Hash chain detects tampering
- Digital signatures verify authenticity

### Authentication ✅
- Mutual authentication during key exchange
- Per-entry signatures verify origin
- Cannot impersonate without private key

### Non-Repudiation ✅
- Digital signatures provide proof
- Users cannot deny their expenses
- Cryptographic evidence of actions

### Replay Protection ✅
- Monotonic counters prevent replay
- Old messages rejected
- Each message must be unique

---

## Slide 16: Performance & Scalability

### Algorithm Selection
- **Automatic selection** based on message size
- **AES-256-GCM:** Best for large messages (>10KB)
- **ChaCha20-Poly1305:** Best for small messages (<1KB)

### Performance Metrics
- **Key Exchange:** ~100-200ms (one-time per session)
- **Encryption:** <1ms per message
- **Signature:** ~5-10ms per expense
- **Verification:** ~5-10ms per expense

### Scalability
- Supports multiple concurrent users
- Efficient blockchain verification
- Database optimized for read operations

---

## Slide 17: Comparison with Traditional Approaches

### Traditional Expense Apps
- ❌ Data stored in plaintext
- ❌ No end-to-end encryption
- ❌ No tamper detection
- ❌ Vulnerable to database attacks

### SplitSmart Approach
- ✅ End-to-end encryption
- ✅ Blockchain tamper detection
- ✅ Digital signatures
- ✅ Replay protection
- ✅ Multiple encryption algorithms

### Security Level
- **Traditional:** Basic authentication only
- **SplitSmart:** Military-grade cryptography
- **Protection:** Against all 4 attack types

---

## Slide 18: Real-World Applications

### Use Cases
1. **Roommates:** Splitting rent, utilities, groceries
2. **Friends:** Splitting restaurant bills, travel expenses
3. **Colleagues:** Business trip expenses, team lunches
4. **Families:** Shared household expenses

### Security Benefits
- **Privacy:** Financial data encrypted
- **Integrity:** No unauthorized modifications
- **Accountability:** Digital signatures provide proof
- **Audit Trail:** Blockchain provides history

### Compliance
- Suitable for sensitive financial data
- Meets cryptographic best practices
- Provides non-repudiation for disputes

---

## Slide 19: Lessons Learned & Best Practices

### Cryptographic Best Practices Implemented
1. ✅ **Defense in Depth:** Multiple layers of security
2. ✅ **Strong Algorithms:** State-of-the-art cryptography
3. ✅ **Key Management:** Secure key storage and derivation
4. ✅ **Forward Secrecy:** Ephemeral keys protect past sessions
5. ✅ **Input Validation:** Prevents injection attacks
6. ✅ **Rate Limiting:** Prevents brute force attacks

### Design Principles
- **Security by Default:** Secure by design
- **Fail Secure:** Errors don't compromise security
- **Minimal Trust:** Verify everything
- **Transparency:** Open cryptographic protocols

---

## Slide 20: Future Enhancements

### Potential Improvements
1. **Post-Quantum Cryptography:** CRYSTALS-Kyber for key exchange
2. **Perfect Forward Secrecy:** Key rotation for long sessions
3. **Distributed Ledger:** Multiple servers for decentralization
4. **Mobile Apps:** Native iOS/Android applications
5. **Advanced Analytics:** Privacy-preserving analytics

### Research Directions
- Performance optimization
- Additional encryption algorithms
- Enhanced blockchain features
- Zero-knowledge proofs for privacy

---

## Slide 21: Conclusion

### Project Achievements
✅ **Complete Implementation:** Working end-to-end cryptography solution
✅ **Attack Protection:** All 4 attacks defended against
✅ **State-of-the-Art:** Modern cryptographic algorithms
✅ **Demonstrations:** Working attack demos
✅ **Documentation:** Comprehensive documentation

### Key Takeaways
- End-to-end encryption is essential for data protection
- Multiple layers provide defense in depth
- Blockchain provides tamper evidence
- Proper implementation requires careful design

### Impact
- Demonstrates practical application of cryptography
- Shows real-world security implementation
- Provides template for secure applications

---

## Slide 22: Q&A

### Questions & Discussion

**Contact Information:**
- GitHub: [Repository URL]
- Documentation: See README.md files
- Demos: Run `python main.py demo`

**Thank You!**

---

## Appendix: Code Snippets

### Key Exchange
```python
# Client initiates key exchange
client_dh_public = generate_dh_key()
signature = sign(client_dh_public, client_private_key)
send_client_hello(client_dh_public, signature)

# Server responds
server_dh_public = generate_dh_key()
shared_secret = compute_dh_shared_secret(client_dh_public)
session_key = derive_key(shared_secret)
```

### Encryption
```python
# Encrypt message
algorithm = select_algorithm(message_size)
nonce, ciphertext = encrypt(plaintext, session_key, algorithm)

# Decrypt message
plaintext = decrypt(nonce, ciphertext, session_key, algorithm)
```

### Signing
```python
# Sign expense
data = encode(payer, amount, description, timestamp, counter)
signature = rsa_pss_sign(data, user_private_key)

# Verify signature
is_valid = rsa_pss_verify(signature, data, user_public_key)
```

---

## Presentation Tips

### Slide Design
- Use consistent color scheme
- Include diagrams for architecture
- Show code snippets for implementation
- Use screenshots for demos

### Delivery
- Explain each attack clearly
- Show live demos if possible
- Highlight security properties
- Discuss real-world implications

### Visual Aids
- Architecture diagrams
- Attack flow diagrams
- Security property diagrams
- Demo screenshots/videos


