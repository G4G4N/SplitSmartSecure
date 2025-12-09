# How to Change GitHub Login to Different User

## Quick Method: Change Git Credentials

### Windows (Git Credential Manager)

**Method 1: Clear Credentials and Re-authenticate**

1. **Open Windows Credential Manager:**
   - Press `Win + R`
   - Type: `control /name Microsoft.CredentialManager`
   - Press Enter

2. **Find GitHub credentials:**
   - Go to "Windows Credentials"
   - Look for entries like:
     - `git:https://github.com`
     - `github.com`

3. **Remove old credentials:**
   - Click on the credential
   - Click "Remove" or "Edit"
   - Delete the entry

4. **Next time you push/pull:**
   - Git will prompt for credentials
   - Enter your new GitHub username and password/token

**Method 2: Using Git Command**

```powershell
# Remove cached credentials
git credential-manager erase https://github.com

# Or remove all GitHub credentials
git credential-manager erase https://github.com
```

### Using Personal Access Token (Recommended)

1. **Create Personal Access Token:**
   - Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
   - Click "Generate new token (classic)"
   - Give it a name (e.g., "SplitSmart Project")
   - Select scopes: `repo`, `workflow` (if needed)
   - Click "Generate token"
   - **Copy the token** (you won't see it again!)

2. **Use token instead of password:**
   - When Git prompts for password, paste the token instead
   - Username: your GitHub username

### Change Git Config

**Change user name and email:**

```bash
# Change globally (all repositories)
git config --global user.name "Your New Username"
git config --global user.email "your.new.email@example.com"

# Change for this repository only
git config user.name "Your New Username"
git config user.email "your.new.email@example.com"
```

**Check current config:**
```bash
git config --global user.name
git config --global user.email
```

---

## Method 2: Use SSH Instead of HTTPS

### Generate SSH Key for New Account

```bash
# Generate new SSH key
ssh-keygen -t ed25519 -C "your.new.email@example.com"

# When prompted, save to different file:
# Enter file: C:/Users/YourName/.ssh/id_ed25519_new

# Start ssh-agent
eval "$(ssh-agent -s)"

# Add key to ssh-agent
ssh-add ~/.ssh/id_ed25519_new
```

### Add SSH Key to GitHub

1. **Copy public key:**
   ```bash
   cat ~/.ssh/id_ed25519_new.pub
   ```

2. **Add to GitHub:**
   - Go to GitHub → Settings → SSH and GPG keys
   - Click "New SSH key"
   - Paste the public key
   - Save

### Update Remote URL to SSH

```bash
# Check current remote
git remote -v

# Change to SSH
git remote set-url origin git@github.com:username/repository.git

# Verify
git remote -v
```

---

## Method 3: Use GitHub CLI

### Install GitHub CLI

**Windows:**
```powershell
# Using winget
winget install GitHub.cli

# Or download from: https://cli.github.com/
```

### Login with Different Account

```bash
# Logout current user
gh auth logout

# Login with new account
gh auth login

# Follow prompts:
# - Choose GitHub.com
# - Choose HTTPS or SSH
# - Authenticate via browser or token
```

---

## Method 4: Multiple Accounts (Advanced)

### Use Different Credentials Per Repository

**For HTTPS:**

1. **Create credential helper script:**
   ```bash
   # Windows: Create .gitconfig-helper
   [credential "https://github.com"]
       helper = manager-core
   ```

2. **Use different credentials per repo:**
   ```bash
   # In repository directory
   git config credential.https://github.com.username "new-username"
   ```

**For SSH:**

1. **Create SSH config:**
   ```bash
   # Edit ~/.ssh/config
   # Account 1 (default)
   Host github.com
       HostName github.com
       User git
       IdentityFile ~/.ssh/id_ed25519
   
   # Account 2
   Host github-work
       HostName github.com
       User git
       IdentityFile ~/.ssh/id_ed25519_work
   ```

2. **Use different host for different repos:**
   ```bash
   git remote set-url origin git@github-work:username/repo.git
   ```

---

## Step-by-Step: Complete Switch

### 1. Clear Old Credentials

**Windows:**
```powershell
# Open Credential Manager
control /name Microsoft.CredentialManager

# Remove GitHub entries
```

**Or use command:**
```bash
git credential-manager erase https://github.com
```

### 2. Update Git Config

```bash
git config --global user.name "New Username"
git config --global user.email "new.email@example.com"
```

### 3. Update Remote URL (if needed)

```bash
# Check current remote
git remote -v

# Update if needed
git remote set-url origin https://github.com/newusername/repository.git
```

### 4. Test Connection

```bash
# Test with HTTPS
git ls-remote https://github.com/newusername/repository.git

# Or test with SSH
ssh -T git@github.com
```

### 5. Push/Pull

```bash
# Next push will prompt for credentials
git push origin main

# Enter:
# Username: your-new-username
# Password: your-personal-access-token (not password!)
```

---

## Troubleshooting

### Still Using Old Credentials?

**Clear all Git credentials:**
```bash
# Windows
git credential-manager erase https://github.com
git credential-manager erase https://github.com

# Or manually delete from Credential Manager
```

### Authentication Failed?

1. **Check username:**
   ```bash
   git config user.name
   ```

2. **Use Personal Access Token:**
   - Don't use password
   - Use token instead
   - Create token: GitHub → Settings → Developer settings → Personal access tokens

3. **Check remote URL:**
   ```bash
   git remote -v
   ```

### Multiple Accounts?

- Use SSH with different keys
- Use different credential helpers
- Use GitHub CLI for easy switching

---

## Quick Reference

### Check Current Settings
```bash
# Git config
git config --global user.name
git config --global user.email

# Remote URL
git remote -v

# Credentials (Windows)
control /name Microsoft.CredentialManager
```

### Change Settings
```bash
# Change user
git config --global user.name "New Name"
git config --global user.email "new@email.com"

# Change remote
git remote set-url origin https://github.com/newuser/repo.git

# Clear credentials
git credential-manager erase https://github.com
```

---

## Recommended Approach

**For most users:**

1. ✅ Clear old credentials from Credential Manager
2. ✅ Update Git config (name/email)
3. ✅ Create Personal Access Token on GitHub
4. ✅ Use token when prompted (not password)
5. ✅ Done!

**For multiple accounts:**

1. ✅ Use SSH keys with different hosts
2. ✅ Configure SSH config file
3. ✅ Use different remote URLs per repository

---

## Security Note

- **Never commit passwords or tokens**
- **Use Personal Access Tokens instead of passwords**
- **Use SSH keys for better security**
- **Rotate tokens regularly**


