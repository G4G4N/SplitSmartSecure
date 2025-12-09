# Generate SSH Key for New GitHub Account

## Step-by-Step Instructions

### Step 1: Generate SSH Key

**Windows PowerShell:**
```powershell
# Generate new SSH key
ssh-keygen -t ed25519 -C "your.new.email@example.com" -f "$HOME\.ssh\id_ed25519_new"

# When prompted:
# - Press Enter for no passphrase (or set one if you want)
# - Key will be saved to: C:\Users\yathi\.ssh\id_ed25519_new
```

**Or interactively:**
```powershell
ssh-keygen -t ed25519 -C "your.new.email@example.com"
# When asked for file location, enter: C:\Users\yathi\.ssh\id_ed25519_new
```

### Step 2: View Public Key

**Windows PowerShell:**
```powershell
# View the public key
Get-Content "$HOME\.ssh\id_ed25519_new.pub"

# Or
cat ~/.ssh/id_ed25519_new.pub
```

**Copy the entire output** - it starts with `ssh-ed25519` and ends with your email.

### Step 3: Add to GitHub

1. **Copy the public key** (from Step 2)

2. **Go to GitHub:**
   - Sign in to your **new** GitHub account
   - Go to: Settings → SSH and GPG keys
   - Click "New SSH key"

3. **Add the key:**
   - Title: Give it a name (e.g., "Windows PC - New Account")
   - Key: Paste the public key you copied
   - Click "Add SSH key"

### Step 4: Configure SSH Config

Create/edit `C:\Users\yathi\.ssh\config`:

```ssh-config
# Default GitHub account (old)
Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519

# New GitHub account
Host github-new
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519_new
```

### Step 5: Test Connection

```powershell
# Test old account
ssh -T git@github.com

# Test new account
ssh -T git@github-new
```

You should see: `Hi username! You've successfully authenticated...`

### Step 6: Update Git Remote (if using new account)

```powershell
# If you want to use new account for this repo:
git remote set-url origin git@github-new:newusername/repository.git

# Or keep same repo but authenticate with new account:
# Just make sure the new SSH key is added to the account that owns the repo
```

### Step 7: Update Git Config

```powershell
# Update Git username and email
git config --global user.name "New GitHub Username"
git config --global user.email "your.new.email@example.com"

# Verify
git config --global user.name
git config --global user.email
```

---

## Quick Commands Summary

```powershell
# 1. Generate key
ssh-keygen -t ed25519 -C "your.email@example.com" -f "$HOME\.ssh\id_ed25519_new"

# 2. View public key
Get-Content "$HOME\.ssh\id_ed25519_new.pub"

# 3. Add to GitHub (manually via web)

# 4. Test
ssh -T git@github-new

# 5. Update Git config
git config --global user.name "New Username"
git config --global user.email "new@email.com"
```

---

## Troubleshooting

### Key Already Exists?
If you get "file already exists" error:
- Use a different filename: `id_ed25519_new2`
- Or overwrite: `ssh-keygen -t ed25519 -f "$HOME\.ssh\id_ed25519_new" -y`

### Permission Denied?
```powershell
# Fix SSH directory permissions
icacls "$HOME\.ssh" /inheritance:r
icacls "$HOME\.ssh" /grant:r "$env:USERNAME:(OI)(CI)F"
```

### Still Using Old Key?
- Check SSH config: `cat ~/.ssh/config`
- Make sure IdentityFile points to correct key
- Test with: `ssh -T git@github-new -v` (verbose mode)

---

## Alternative: Use HTTPS Instead

If SSH is too complicated, use HTTPS:

```powershell
# Change remote to HTTPS
git remote set-url origin https://github.com/username/repository.git

# Clear old credentials
control /name Microsoft.CredentialManager

# Next push will prompt for:
# Username: your GitHub username
# Password: your Personal Access Token (not password!)
```

