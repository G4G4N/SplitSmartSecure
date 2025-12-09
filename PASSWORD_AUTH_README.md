# Password Authentication Implementation

## Overview

Password-based authentication has been added to SplitSmart with secure password hashing using bcrypt. Passwords are never stored in plain text - only secure hashes are stored in the database.

## Security Features

### Password Hashing
- **Algorithm**: bcrypt (adaptive hashing)
- **Salt**: Automatically generated unique salt per password
- **Rounds**: Default bcrypt cost factor (10 rounds = 2^10 iterations)
- **Storage**: Only password hashes stored, never plain text passwords

### Security Properties
- ✅ **One-way hashing**: Passwords cannot be recovered from hashes
- ✅ **Unique salts**: Each password has a unique salt, preventing rainbow table attacks
- ✅ **Timing-safe comparison**: bcrypt uses constant-time comparison
- ✅ **Adaptive**: Can increase cost factor as hardware improves

## Database Changes

### Schema Update
The `users` table now includes a `password_hash` column:

```sql
CREATE TABLE users (
    user_id TEXT PRIMARY KEY,
    public_key TEXT NOT NULL,
    password_hash TEXT,  -- NEW: Stores bcrypt hash
    counter INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
```

### Migration
- Existing databases are automatically migrated
- Old users without passwords can still use key-based authentication
- New users must provide passwords during registration

## API Changes

### Registration Endpoint
**POST `/api/register`**

**Request:**
```json
{
    "username": "alice",
    "password": "securepassword123"
}
```

**Response:**
```json
{
    "success": true,
    "message": "User alice registered successfully"
}
```

**Password Requirements:**
- Minimum 6 characters
- Stored as bcrypt hash

### Login Endpoint
**POST `/api/login`**

**Request:**
```json
{
    "username": "alice",
    "password": "securepassword123"
}
```

**Response:**
```json
{
    "success": true,
    "message": "Logged in as alice",
    "session_id": "session-uuid"
}
```

**Authentication Flow:**
1. Verify password hash matches
2. If valid, establish secure cryptographic session (key exchange)
3. Return session ID for subsequent requests

## Implementation Details

### Backend Changes

#### `server/storage.py`
- Added `password_hash` column to users table
- `register_user()` now accepts optional `password_hash` parameter
- Added `get_user_password_hash()` method
- Added `verify_user_password()` method using bcrypt

#### `server/server.py`
- `register_user()` now accepts optional `password_hash` parameter
- Added `verify_user_password()` method

#### `web_app.py`
- Registration endpoint hashes passwords using bcrypt before storage
- Login endpoint verifies passwords before establishing session
- Password validation (minimum 6 characters)

### Frontend Changes

#### HTML Forms
- Login form now includes password field
- Registration form includes password and confirm password fields
- Password fields use appropriate `autocomplete` attributes
- Password confirmation validation

#### JavaScript (`static/js/app.js`)
- `register()` function now accepts and sends password
- `login()` function now accepts and sends password
- Password validation on client side
- Password confirmation matching

## Usage

### Registration
1. Enter username
2. Enter password (minimum 6 characters)
3. Confirm password
4. Click "Register"
5. System automatically logs you in after registration

### Login
1. Enter username
2. Enter password
3. Click "Login"
4. System verifies password and establishes secure session

## Security Best Practices

### Password Storage
- ✅ Passwords are hashed with bcrypt before storage
- ✅ Each password has a unique salt
- ✅ Plain text passwords never stored in database
- ✅ Passwords never logged or printed

### Password Transmission
- ⚠️ **Note**: Currently passwords are sent over HTTPS in production
- ⚠️ **Development**: Use HTTPS in production (Flask debug mode is HTTP only)
- ✅ Passwords are hashed immediately upon receipt
- ✅ Password hashes are never sent back to client

### Password Verification
- ✅ Uses bcrypt's `checkpw()` for constant-time comparison
- ✅ Prevents timing attacks
- ✅ Returns generic error message to prevent user enumeration

## Dependencies

Added to `requirements.txt`:
```
bcrypt>=4.0.0
```

Install with:
```bash
pip install bcrypt
```

## Backward Compatibility

- Existing users without passwords can still use the system
- Old registration flow (without password) still works for CLI/demos
- New web UI requires passwords for all new registrations
- Database migration is automatic and non-destructive

## Testing

### Manual Testing
1. Register a new user with password
2. Logout
3. Login with correct password (should succeed)
4. Try login with wrong password (should fail)
5. Verify password hash in database (should be bcrypt hash, not plain text)

### Example Test Flow
```bash
# Start web app
python web_app.py

# Register user via API
curl -X POST http://localhost:5000/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'

# Login via API
curl -X POST http://localhost:5000/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"testpass123"}'
```

## Security Considerations

### Current Implementation
- ✅ Secure password hashing (bcrypt)
- ✅ Password validation (minimum length)
- ✅ Password confirmation on registration
- ✅ Generic error messages (prevents user enumeration)

### Recommendations for Production
- 🔒 Use HTTPS/TLS for all connections
- 🔒 Implement rate limiting on login attempts
- 🔒 Add password complexity requirements (optional)
- 🔒 Consider password reset functionality
- 🔒 Add account lockout after failed attempts
- 🔒 Implement session timeout
- 🔒 Use secure session cookies (HttpOnly, Secure flags)

## Code Examples

### Password Hashing (Registration)
```python
import bcrypt

password = "userpassword123"
password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
# Store password_hash in database
```

### Password Verification (Login)
```python
import bcrypt

stored_hash = get_password_hash_from_db(username)
password = "userpassword123"
is_valid = bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
```

## Troubleshooting

### "Password must be at least 6 characters"
- Ensure password is at least 6 characters long
- Check password field validation

### "Invalid username or password"
- Verify username exists
- Check password is correct
- Ensure password was hashed correctly during registration

### Database Migration Issues
- The password_hash column is added automatically
- If migration fails, manually run: `ALTER TABLE users ADD COLUMN password_hash TEXT`

## Future Enhancements

Potential improvements:
- Password strength meter
- Password reset via email
- Two-factor authentication (2FA)
- Password expiration policies
- Account lockout after failed attempts
- Password history (prevent reuse)


