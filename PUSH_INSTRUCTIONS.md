# Push Dev Branch Instructions

## Current Status
✅ Branch `dev` created
✅ All changes committed (43 files, 9227 insertions)
❌ Push failed due to authentication

## Next Steps to Push

### Step 1: Clear Old Credentials

**Open Windows Credential Manager:**
```powershell
control /name Microsoft.CredentialManager
```

**Delete GitHub entries:**
- Go to "Windows Credentials"
- Find entries like:
  - `git:https://github.com`
  - `github.com`
- Click and delete them

### Step 2: Create Personal Access Token

1. **Go to GitHub:**
   - Sign in to your GitHub account (the one that owns G4G4N/SplitSmartSecure)
   - Go to: Settings → Developer settings → Personal access tokens → Tokens (classic)

2. **Generate new token:**
   - Click "Generate new token (classic)"
   - Name: "SplitSmart Dev Branch"
   - Select scopes: `repo` (full control of private repositories)
   - Click "Generate token"
   - **Copy the token** (you won't see it again!)

### Step 3: Push the Branch

```powershell
git push -u origin dev
```

**When prompted:**
- **Username:** Your GitHub username (G4G4N or your account)
- **Password:** Paste your Personal Access Token (NOT your GitHub password!)

### Step 4: Verify

After successful push:
- Go to GitHub repository
- You should see the `dev` branch
- All your files should be there

---

## Alternative: Use GitHub CLI

If you have GitHub CLI installed:

```powershell
# Login
gh auth login

# Push
git push -u origin dev
```

---

## Summary

**What was done:**
1. ✅ Created `dev` branch
2. ✅ Switched to `dev` branch
3. ✅ Added all changes (43 files)
4. ✅ Committed changes
5. ✅ Changed remote to HTTPS
6. ⏳ **Need to:** Clear credentials and push with token

**What you need to do:**
1. Clear old credentials from Credential Manager
2. Create Personal Access Token on GitHub
3. Run: `git push -u origin dev`
4. Enter username and token when prompted

---

## Quick Command Reference

```powershell
# Check status
git status
git branch

# Push (after fixing auth)
git push -u origin dev

# Verify remote
git remote -v
```


