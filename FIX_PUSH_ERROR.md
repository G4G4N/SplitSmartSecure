# Fix Git Push Permission Error

## Error Message
```
ERROR: Permission to G4G4N/SplitSmartSecure.git denied to yathish-ship-it.
```

This means Git is trying to authenticate with the wrong GitHub account.

## Solutions

### Option 1: Fix SSH Authentication (Recommended)

**Check which SSH key is being used:**
```powershell
ssh -T git@github.com
```

**If it shows the wrong account:**
1. Make sure your SSH key is added to the correct GitHub account
2. Or update SSH config to use correct key

**Test with verbose output:**
```powershell
ssh -T git@github.com -v
```

### Option 2: Switch to HTTPS with Personal Access Token

**Change remote to HTTPS:**
```powershell
git remote set-url origin https://github.com/G4G4N/SplitSmartSecure.git
```

**Clear old credentials:**
```powershell
# Open Credential Manager
control /name Microsoft.CredentialManager

# Delete GitHub entries under "Windows Credentials"
```

**Create Personal Access Token:**
1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Generate new token
3. Copy the token

**Push again:**
```powershell
git push -u origin dev
# When prompted:
# Username: G4G4N (or your GitHub username)
# Password: paste your Personal Access Token (not password!)
```

### Option 3: Use GitHub CLI

**Install GitHub CLI:**
```powershell
winget install GitHub.cli
```

**Login:**
```powershell
gh auth login
# Follow prompts to authenticate
```

**Then push:**
```powershell
git push -u origin dev
```

### Option 4: Check Repository Access

Make sure:
- You have write access to the repository
- The repository exists
- You're using the correct GitHub account

---

## Quick Fix: Use HTTPS

**Simplest solution:**

```powershell
# 1. Change to HTTPS
git remote set-url origin https://github.com/G4G4N/SplitSmartSecure.git

# 2. Clear credentials
control /name Microsoft.CredentialManager
# Delete GitHub entries

# 3. Push (will prompt for credentials)
git push -u origin dev
# Enter: GitHub username and Personal Access Token
```

---

## Verify Current Setup

```powershell
# Check remote URL
git remote -v

# Check current branch
git branch

# Check Git config
git config user.name
git config user.email

# Test SSH connection
ssh -T git@github.com
```

---

## After Fixing

Once authentication is fixed, push again:

```powershell
git push -u origin dev
```

The `-u` flag sets up tracking so future pushes can just use `git push`.

