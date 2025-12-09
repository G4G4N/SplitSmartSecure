# SplitSmart Web Application

A modern, secure web interface for the SplitSmart expense splitting system with real-time tampering detection.

## Features

- 🔐 **Secure Authentication** - User registration and login with cryptographic key exchange
- 💰 **Expense Management** - Add expenses with payer, amount, and description
- 📊 **Ledger View** - View all expense entries with cryptographic hashes
- ⚖️ **Balance Calculation** - See who owes whom
- 🛡️ **Tampering Detection** - Real-time verification of ledger integrity using hash chains
- 🎨 **Modern UI** - Beautiful, responsive design with animations
- 🔒 **Security Features**:
  - AES-256-GCM encryption for all messages
  - RSA-PSS digital signatures
  - Hash chain for tamper evidence
  - Replay protection via monotonic counters

## Installation

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Run the web application:
```bash
python web_app.py
```

3. Open your browser to:
```
http://localhost:5000
```

## Usage

### 1. Register/Login
- Enter a username and click "Register" to create a new account
- Or click "Login" if you already have an account
- The system will automatically generate cryptographic keys for you

### 2. Add Expenses
- Fill in the expense form:
  - **Who Paid?**: Enter the username of the person who paid
  - **Amount**: Enter the amount in dollars
  - **Description**: Describe what the expense was for
- Click "Submit Expense" to add it to the ledger

### 3. View Ledger
- The ledger automatically displays all expense entries
- Each entry shows:
  - Entry ID
  - Payer and amount
  - Description and timestamp
  - Cryptographic hash (for verification)
- Click the refresh button to reload the ledger

### 4. View Balances
- See who owes money to whom
- Positive amounts = person is owed money
- Negative amounts = person owes money
- Click refresh to recalculate balances

### 5. Verify Tampering
- Click "Verify Ledger Integrity" to check for any tampering
- The system will verify the hash chain
- Green = No tampering detected
- Red = Tampering detected (hash chain broken)

## Security Features Explained

### Encryption (AES-256-GCM)
All messages between client and server are encrypted using AES-256-GCM, providing:
- **Confidentiality**: Only authorized parties can read messages
- **Integrity**: Any modification is detected via authentication tags

### Digital Signatures (RSA-PSS)
Each expense is signed with the user's private key:
- **Authentication**: Proves who created the expense
- **Non-repudiation**: Users cannot deny their expenses

### Hash Chain
Each ledger entry is cryptographically linked to the previous one:
- **Tamper Evidence**: Any modification breaks the chain
- **Verification**: Can detect tampering even if database is modified directly

### Replay Protection
Monotonic counters prevent replay attacks:
- Each message must have a counter higher than the previous one
- Old messages cannot be replayed

## Architecture

```
┌─────────────┐
│  Web UI     │  (HTML/CSS/JavaScript)
│  (Browser)  │
└──────┬──────┘
       │ HTTP/JSON
       │
┌──────▼──────┐
│ Flask API   │  (web_app.py)
│  Endpoints  │
└──────┬──────┘
       │
┌──────▼──────┐
│   Client    │  (client/client.py)
│   Crypto    │
└──────┬──────┘
       │ Encrypted Messages
       │
┌──────▼──────┐
│   Server    │  (server/server.py)
│   Ledger    │
└─────────────┘
```

## API Endpoints

- `POST /api/register` - Register a new user
- `POST /api/login` - Login and establish secure session
- `POST /api/logout` - Logout current user
- `POST /api/add_expense` - Add an expense to the ledger
- `GET /api/ledger` - Get all ledger entries
- `GET /api/balances` - Get balance calculations
- `GET /api/verify_tampering` - Verify ledger integrity
- `GET /api/status` - Get current session status

## Troubleshooting

### Port Already in Use
If port 5000 is already in use, modify `web_app.py`:
```python
app.run(debug=True, host='0.0.0.0', port=5001)  # Change port
```

### Database Locked
If you see database locking errors:
- Make sure only one instance of the web app is running
- Close any other applications using the database

### Session Expired
If you see "Session expired" errors:
- Logout and login again
- The system will establish a new secure session

## Development

The web application uses:
- **Backend**: Flask (Python)
- **Frontend**: Vanilla JavaScript (no frameworks)
- **Styling**: Custom CSS with animations
- **Icons**: Font Awesome

## Notes

- The web app uses Flask sessions for user management
- Each user session maintains a client instance with cryptographic keys
- The server instance is shared across all requests (thread-safe)
- All cryptographic operations happen server-side using the existing Python code

