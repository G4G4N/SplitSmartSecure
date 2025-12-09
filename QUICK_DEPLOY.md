# Quick Deployment Guide

## Fastest Way: Railway (5 minutes)

### Step 1: Push to GitHub
```bash
git add .
git commit -m "Ready for deployment"
git push origin main
```

### Step 2: Deploy on Railway
1. Go to [railway.app](https://railway.app)
2. Sign up with GitHub
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your repository
5. Railway auto-detects and deploys!

### Step 3: Set Environment Variables
In Railway dashboard:
- Go to Variables tab
- Add: `SECRET_KEY` = (generate random string)
- Add: `FLASK_DEBUG` = `false`

### Step 4: Get Your URL
- Railway provides a public URL automatically
- Share it to showcase your project!

---

## Alternative: Render (Also 5 minutes)

### Step 1: Push to GitHub
(Same as above)

### Step 2: Deploy on Render
1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Click "New +" → "Web Service"
4. Connect your repository
5. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python web_app.py`
   - **Plan:** Free

### Step 3: Set Environment Variables
- `SECRET_KEY`: Generate random string
- `FLASK_DEBUG`: false

### Step 4: Deploy
- Click "Create Web Service"
- Wait for build (~2-3 minutes)
- Get your public URL!

---

## Generate Secret Key

Run this Python command:
```python
import secrets
print(secrets.token_hex(32))
```

Copy the output and use it as `SECRET_KEY` environment variable.

---

## Test Locally First

Before deploying, test production mode locally:

```bash
# Windows PowerShell
$env:SECRET_KEY="test-key-123"
$env:FLASK_DEBUG="false"
$env:PORT=5000
python web_app.py

# Linux/Mac
export SECRET_KEY="test-key-123"
export FLASK_DEBUG="false"
export PORT=5000
python web_app.py
```

Visit `http://localhost:5000` and verify everything works!

---

## Troubleshooting

**Build fails?**
- Check `requirements.txt` is complete
- Verify Python version compatibility
- Check platform logs for errors

**App won't start?**
- Verify PORT environment variable is set
- Check that all files are committed to git
- Review error logs in platform dashboard

**Database errors?**
- SQLite works for demos
- For production, consider PostgreSQL
- Check file permissions

---

## Recommended: Railway

Railway is the easiest:
- ✅ Auto-detects Python
- ✅ Auto-configures everything
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Easy updates (just git push)

**Just push to GitHub and connect to Railway!**

