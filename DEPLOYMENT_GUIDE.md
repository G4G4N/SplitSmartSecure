# Deployment Guide for SplitSmart

This guide covers deploying the SplitSmart Flask application to various cloud platforms.

## Quick Deploy Options

### Option 1: Railway (Recommended - Easiest)

**Railway** is the easiest platform for deploying Flask apps.

1. **Sign up:** Go to [railway.app](https://railway.app) and sign up with GitHub

2. **Create New Project:**
   - Click "New Project"
   - Select "Deploy from GitHub repo"
   - Connect your repository

3. **Configure:**
   - Railway auto-detects Python
   - Uses `Procfile` for start command
   - Automatically sets PORT environment variable

4. **Set Environment Variables:**
   - Go to Variables tab
   - Add: `SECRET_KEY` (generate a random string)
   - Add: `FLASK_DEBUG=false`

5. **Deploy:**
   - Railway automatically deploys on git push
   - Get your public URL from the dashboard

**Cost:** Free tier available, then pay-as-you-go

---

### Option 2: Render (Free Tier Available)

**Render** offers a free tier perfect for demos.

1. **Sign up:** Go to [render.com](https://render.com) and sign up

2. **Create New Web Service:**
   - Click "New +" → "Web Service"
   - Connect your GitHub repository

3. **Configure:**
   - **Name:** splitsmart (or your choice)
   - **Environment:** Python 3
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python web_app.py`
   - **Plan:** Free (or paid)

4. **Set Environment Variables:**
   - `SECRET_KEY`: Generate random string
   - `FLASK_DEBUG`: false
   - `PORT`: 5000 (auto-set by Render)

5. **Deploy:**
   - Click "Create Web Service"
   - Wait for build to complete
   - Get your public URL

**Cost:** Free tier available (spins down after inactivity)

---

### Option 3: Heroku (Classic Platform)

**Heroku** is a well-established platform.

1. **Install Heroku CLI:**
   ```bash
   # Windows: Download from heroku.com
   # Mac: brew install heroku/brew/heroku
   ```

2. **Login:**
   ```bash
   heroku login
   ```

3. **Create App:**
   ```bash
   heroku create splitsmart-app
   ```

4. **Set Environment Variables:**
   ```bash
   heroku config:set SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
   heroku config:set FLASK_DEBUG=false
   ```

5. **Deploy:**
   ```bash
   git push heroku main
   ```

6. **Open:**
   ```bash
   heroku open
   ```

**Cost:** No free tier (paid plans only)

---

### Option 4: PythonAnywhere (Free Tier)

**PythonAnywhere** is great for Python apps.

1. **Sign up:** Go to [pythonanywhere.com](https://www.pythonanywhere.com)

2. **Upload Files:**
   - Go to Files tab
   - Upload all project files
   - Or use git: `git clone <your-repo-url>`

3. **Create Web App:**
   - Go to Web tab
   - Click "Add a new web app"
   - Select Flask
   - Choose Python version

4. **Configure WSGI:**
   - Edit WSGI file:
   ```python
   import sys
   path = '/home/yourusername/splitsmart'
   if path not in sys.path:
       sys.path.append(path)
   
   from web_app import app as application
   ```

5. **Set Environment Variables:**
   - In Web tab → Environment variables
   - Add: `SECRET_KEY`, `FLASK_DEBUG=false`

6. **Reload:**
   - Click "Reload" button

**Cost:** Free tier available (limited)

---

### Option 5: Fly.io (Modern Alternative)

**Fly.io** offers global deployment.

1. **Install Fly CLI:**
   ```bash
   # Windows: Download from fly.io
   # Mac/Linux: curl -L https://fly.io/install.sh | sh
   ```

2. **Login:**
   ```bash
   fly auth login
   ```

3. **Create App:**
   ```bash
   fly launch
   ```

4. **Configure:**
   - Follow prompts
   - Creates `fly.toml` automatically

5. **Deploy:**
   ```bash
   fly deploy
   ```

**Cost:** Free tier available

---

## Pre-Deployment Checklist

### 1. Update Secret Key
- Generate a secure random key:
  ```python
  import secrets
  print(secrets.token_hex(32))
  ```
- Set as environment variable: `SECRET_KEY`

### 2. Disable Debug Mode
- Set `FLASK_DEBUG=false` in production
- Already handled in `web_app.py`

### 3. Database Considerations
- Current setup uses SQLite (file-based)
- For production, consider PostgreSQL
- SQLite works for demos but has limitations

### 4. Static Files
- Ensure `static/` and `templates/` folders are included
- Check `.gitignore` doesn't exclude them

### 5. Dependencies
- Verify `requirements.txt` is complete
- Test locally: `pip install -r requirements.txt`

---

## Environment Variables

Set these in your deployment platform:

| Variable | Description | Example |
|----------|-------------|---------|
| `SECRET_KEY` | Flask secret key | `your-random-key-here` |
| `FLASK_DEBUG` | Debug mode | `false` |
| `PORT` | Server port | `5000` (auto-set by platforms) |

---

## Testing Deployment

### Local Testing (Production Mode)
```bash
# Set environment variables
export SECRET_KEY="test-key-123"
export FLASK_DEBUG="false"
export PORT=5000

# Run
python web_app.py
```

### Verify:
1. App starts without errors
2. No debug output
3. Accessible at `http://localhost:5000`
4. All features work

---

## Post-Deployment

### 1. Test Public URL
- Register a new user
- Add expenses
- View ledger
- Check blockchain

### 2. Monitor Logs
- Check platform logs for errors
- Monitor performance
- Watch for security issues

### 3. Update Documentation
- Update README with public URL
- Add deployment instructions
- Document any platform-specific notes

---

## Troubleshooting

### Common Issues

**1. App won't start:**
- Check logs for errors
- Verify all dependencies installed
- Check PORT environment variable

**2. Database errors:**
- Ensure database file is writable
- Check file permissions
- Consider using PostgreSQL for production

**3. Static files not loading:**
- Verify `static/` folder included
- Check Flask static folder configuration
- Clear browser cache

**4. Import errors:**
- Verify all Python files included
- Check `requirements.txt` complete
- Ensure Python version compatible

**5. Port binding errors:**
- Use PORT environment variable
- Don't hardcode port numbers
- Check platform port requirements

---

## Production Recommendations

### Security
- ✅ Use strong SECRET_KEY
- ✅ Disable debug mode
- ✅ Use HTTPS (most platforms provide)
- ✅ Enable rate limiting (already implemented)
- ✅ Validate all inputs (already implemented)

### Performance
- Consider using gunicorn instead of Flask dev server:
  ```bash
  pip install gunicorn
  # Update Procfile:
  web: gunicorn web_app:app --bind 0.0.0.0:$PORT
  ```

### Database
- For production, migrate to PostgreSQL:
  - More robust
  - Better concurrency
  - Supports multiple connections

### Monitoring
- Set up error tracking (Sentry, etc.)
- Monitor performance metrics
- Track user activity

---

## Quick Start Commands

### Railway
```bash
# Install Railway CLI
npm i -g @railway/cli

# Login
railway login

# Deploy
railway up
```

### Render
- Use web interface (no CLI needed)
- Connect GitHub repo
- Configure and deploy

### Heroku
```bash
heroku create splitsmart-app
git push heroku main
heroku open
```

---

## Support

For deployment issues:
1. Check platform documentation
2. Review error logs
3. Test locally first
4. Verify environment variables

---

## Recommended Platform for Demo

**For showcasing the project, I recommend Railway or Render:**

- ✅ Easy setup
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Good performance
- ✅ Easy to update

Both platforms make it easy to deploy and share your project!

