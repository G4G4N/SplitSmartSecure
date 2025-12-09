# 🚀 Deploy SplitSmart to Public Website

## Quick Start - Deploy in 5 Minutes!

### Recommended: Railway (Easiest)

1. **Push your code to GitHub:**
   ```bash
   git add .
   git commit -m "Ready for deployment"
   git push origin main
   ```

2. **Deploy on Railway:**
   - Go to [railway.app](https://railway.app)
   - Sign up with GitHub
   - Click "New Project" → "Deploy from GitHub repo"
   - Select your repository
   - Railway auto-detects Python and deploys!

3. **Set Environment Variables:**
   - In Railway dashboard → Variables tab
   - Add: `SECRET_KEY` = `147760becb9989434f2cb3f3af1feaf0a284df137a045da0c39c161fe6b4346f`
   - Add: `FLASK_DEBUG` = `false`

4. **Get Your Public URL:**
   - Railway provides a public URL automatically
   - Share it to showcase your project!

**That's it! Your app is live! 🎉**

---

## Alternative: Render (Free Tier)

1. **Push to GitHub** (same as above)

2. **Deploy on Render:**
   - Go to [render.com](https://render.com)
   - Sign up with GitHub
   - Click "New +" → "Web Service"
   - Connect your repository
   - Configure:
     - **Build Command:** `pip install -r requirements.txt`
     - **Start Command:** `python web_app.py`
     - **Plan:** Free

3. **Set Environment Variables:**
   - `SECRET_KEY`: `147760becb9989434f2cb3f3af1feaf0a284df137a045da0c39c161fe6b4346f`
   - `FLASK_DEBUG`: `false`

4. **Deploy:**
   - Click "Create Web Service"
   - Wait ~2-3 minutes for build
   - Get your public URL!

---

## Files Created for Deployment

✅ **Procfile** - Tells platform how to run your app
✅ **runtime.txt** - Specifies Python version
✅ **railway.json** - Railway configuration
✅ **render.yaml** - Render configuration
✅ **.gitignore** - Excludes unnecessary files
✅ **gunicorn_config.py** - Production server config (optional)

---

## Environment Variables

Set these in your deployment platform:

| Variable | Value | Description |
|----------|-------|-------------|
| `SECRET_KEY` | `147760becb9989434f2cb3f3af1feaf0a284df137a045da0c39c161fe6b4346f` | Flask secret key |
| `FLASK_DEBUG` | `false` | Disable debug mode |
| `PORT` | `5000` | Server port (auto-set by platforms) |

---

## Test Locally Before Deploying

Test production mode locally:

**Windows PowerShell:**
```powershell
$env:SECRET_KEY="147760becb9989434f2cb3f3af1feaf0a284df137a045da0c39c161fe6b4346f"
$env:FLASK_DEBUG="false"
$env:PORT=5000
python web_app.py
```

**Linux/Mac:**
```bash
export SECRET_KEY="147760becb9989434f2cb3f3af1feaf0a284df137a045da0c39c161fe6b4346f"
export FLASK_DEBUG="false"
export PORT=5000
python web_app.py
```

Visit `http://localhost:5000` and verify everything works!

---

## What's Included

Your deployment includes:
- ✅ Flask web application
- ✅ Blockchain ledger visualization
- ✅ Security explanation page
- ✅ Analytics dashboard
- ✅ Multiple encryption algorithms
- ✅ Attack demonstrations
- ✅ Complete UI/UX

---

## Troubleshooting

### Build Fails?
- Check `requirements.txt` is complete
- Verify Python version (3.11 recommended)
- Check platform logs for errors

### App Won't Start?
- Verify PORT environment variable is set
- Check that all files are committed to git
- Review error logs in platform dashboard

### Database Errors?
- SQLite works for demos
- For production, consider PostgreSQL
- Check file permissions

---

## Post-Deployment Checklist

- [ ] Test registration and login
- [ ] Add test expenses
- [ ] View blockchain ledger
- [ ] Check analytics dashboard
- [ ] Test security features
- [ ] Share your public URL!

---

## Need Help?

See detailed guides:
- **DEPLOYMENT_GUIDE.md** - Complete deployment guide
- **QUICK_DEPLOY.md** - Quick reference

---

## Recommended Platform

**Railway** is recommended because:
- ✅ Easiest setup (just connect GitHub)
- ✅ Auto-detects Python
- ✅ Free tier available
- ✅ Automatic HTTPS
- ✅ Easy updates (just git push)

**Just push to GitHub and connect to Railway!**

