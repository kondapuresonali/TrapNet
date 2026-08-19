# TrapNet Security & Deployment Runbook

## 🚨 Critical Security Issue - Action Required

**Issue:** Gemini API key was exposed in the repository (Issue #1)  
**Status:** 🔧 FIXING  
**Timeline:** Urgent - Complete within 24 hours

---

## ⚡ Quick Start (5 minutes)

### 1️⃣ Rotate Your API Keys

**Google Gemini:**
```bash
# Go to: https://aistudio.google.com/apikey
# Delete old key ending in: x14
# Generate new API key
# Copy it
```

**VirusTotal:**
```bash
# Go to: https://virustotal.com → Avatar → API Key
# Regenerate the key
# Copy it
```

### 2️⃣ Create Local .env File
```bash
cd TrapNet
cp .env.example .env

# Edit with your NEW keys
nano .env  # or: code .env
```

**Content:**
```env
FLASK_ENV=development
VT_API_KEY=your_new_virustotal_key
GEMINI_API_KEY=your_new_gemini_key
DATABASE_URL=sqlite:///trapnet.db
```

### 3️⃣ Clean Git History
```bash
bash scripts/cleanup-secrets.sh
```

This will:
- ✅ Backup your repo
- ✅ Remove secrets from git history
- ✅ Setup .env properly
- ✅ Verify cleanup
- ✅ Prompt for force push

### 4️⃣ Update Render Deployment
```
https://dashboard.render.com
→ TrapNet service
→ Environment
→ Update: VT_API_KEY, GEMINI_API_KEY
→ Redeploy
```

### 5️⃣ Mark GitScan as Resolved
```
https://gitscan.ai/resolve?finding=gs_4345f33d0aeb3c6a
```

---

## 📋 Detailed Steps

### Step 1: Rotate API Keys

#### Google Gemini API
1. Go to https://aistudio.google.com/apikey
2. Sign in with your Google account
3. Find your current API key (ending in `x14`)
4. Click **Delete** or **Regenerate**
5. Create a **new API key**
6. Copy it (save securely)

#### VirusTotal API
1. Go to https://virustotal.com
2. Sign in → Avatar → **API Key**
3. Click **Regenerate API key**
4. Copy the new key
5. Save it securely

**Pro Tip:** Use a password manager (1Password, Bitwarden) to store keys securely.

---

### Step 2: Setup Local Environment

```bash
# Clone repo (if not already done)
git clone https://github.com/kondapuresonali/TrapNet.git
cd TrapNet
git checkout upgrade/modernize-architecture

# Copy template
cp .env.example .env

# Edit with your new keys
nano .env
```

**Expected .env content:**
```env
# Flask
FLASK_ENV=development
SECRET_KEY=your-random-key-here

# API Keys (from step 1)
VT_API_KEY=your_new_virustotal_key_here
GEMINI_API_KEY=your_new_gemini_key_here

# Database
DATABASE_URL=sqlite:///trapnet.db

# Logging
LOG_LEVEL=INFO
```

**Verify .env is ignored:**
```bash
git check-ignore .env  # Should return: .env
git status  # .env should NOT appear in changes
```

---

### Step 3: Remove Secrets from Git History

**⚠️ Important:** Only do this if you own the repo and no one else is working on it.

```bash
# Make the script executable
chmod +x scripts/cleanup-secrets.sh

# Run the cleanup
bash scripts/cleanup-secrets.sh
```

**What it does:**
1. Creates a backup (`../trapnet-backup.bundle`)
2. Installs `git-filter-repo` if needed
3. Removes all occurrences of the leaked key
4. Verifies no secrets remain
5. Prompts you to force push

**Manual verification:**
```bash
# Check if any secrets remain
git log -p | grep -i "AIza"  # Should be empty

# Check git history doesn't contain keys
git log --all -S "GEMINI_API_KEY=" -- app.py
```

---

### Step 4: Update Deployment Secrets

#### For Render.com (Current)
```
1. Go to: https://dashboard.render.com
2. Select: TrapNet service
3. Go to: Environment
4. Update/Add:
   - Name: VT_API_KEY
     Value: your_new_virustotal_key
   
   - Name: GEMINI_API_KEY
     Value: your_new_gemini_key

5. Click: Redeploy
```

#### For Docker (Local Development)
```bash
# .env file is automatically loaded
docker-compose up --build

# Verify keys are loaded
docker logs trapnet-app | grep "API"
```

#### For GitHub Actions (CI/CD)
```
1. Go to: Repository → Settings
2. → Secrets and variables → Actions
3. New repository secret:
   - Name: VT_API_KEY
   - Value: your_new_key
   
   - Name: GEMINI_API_KEY
   - Value: your_new_key

4. Use in workflows: ${{ secrets.VT_API_KEY }}
```

---

### Step 5: Verify Everything Works

```bash
# Install dependencies
pip install -r requirements.txt

# Start the app
python app.py

# Test endpoint
curl http://localhost:5000/

# Try a scan
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

Expected response:
```json
{
  "url": "https://example.com",
  "status": "safe",
  "risk": 2,
  "threat_level": "SAFE",
  ...
}
```

---

## 🔐 Security Checklist

- [ ] Old Gemini key deleted from Google AI Studio
- [ ] Old VirusTotal key regenerated
- [ ] New keys stored in `.env` locally
- [ ] `.env` file is in `.gitignore` (verified)
- [ ] Git history cleaned (leaked key removed)
- [ ] Changes force-pushed to origin
- [ ] Render environment variables updated
- [ ] New deployment tested at https://trapnet.onrender.com
- [ ] GitScan finding marked as resolved
- [ ] No secrets in `git log -p`

---

## 🚀 Deployment Checklist

### Before Going Live
```bash
# Test locally
export FLASK_ENV=production
python app.py

# Run tests
pytest tests/ -v

# Check for remaining secrets
git log -p | grep -i "api_key\|secret\|aiza"
```

### Deploy to Render
```bash
# Push to main branch (after security fixes)
git checkout main
git merge upgrade/modernize-architecture
git push origin main

# Render auto-deploys on push
# Monitor: https://dashboard.render.com → Logs
```

### Verify Deployment
```bash
curl https://trapnet.onrender.com/
curl -X POST https://trapnet.onrender.com/analyze \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

---

## 📚 Reference Files

| File | Purpose |
|------|---------|
| `.env.example` | Template for local environment variables |
| `.env` | **LOCAL ONLY** - Never commit |
| `.gitignore` | Prevents `.env` from being committed |
| `SECURITY.md` | Detailed security policy |
| `config.py` | Environment-based configuration |
| `scripts/cleanup-secrets.sh` | Automated secret cleanup |
| `logger.py` | Structured logging |

---

## 🆘 Troubleshooting

### Issue: "Module 'services' not found"
```bash
# Make sure you're on the upgrade branch
git checkout upgrade/modernize-architecture

# Install dependencies
pip install -r requirements.txt
```

### Issue: "GEMINI_API_KEY not configured"
```bash
# Check .env exists
ls -la .env

# Check it has the key
grep GEMINI_API_KEY .env

# Verify it's loaded
python -c "import os; print(os.environ.get('GEMINI_API_KEY'))"
```

### Issue: "Permission denied" on cleanup script
```bash
# Make it executable
chmod +x scripts/cleanup-secrets.sh

# Then run
bash scripts/cleanup-secrets.sh
```

### Issue: Force push fails
```bash
# Pull latest
git fetch origin
git pull origin upgrade/modernize-architecture

# Try again
git push -f origin upgrade/modernize-architecture
```

---

## 🔗 Useful Links

- **Google Gemini API:** https://ai.google.dev/gemini-api/docs/api-key
- **VirusTotal API:** https://developers.virustotal.com/reference
- **Render Dashboard:** https://dashboard.render.com
- **GitScan:** https://gitscan.ai
- **Git Filter Repo:** https://github.com/newren/git-filter-repo
- **OWASP Secrets Management:** https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html

---

## 📞 Support

If you encounter issues:

1. **Check SECURITY.md** for detailed information
2. **Review .env.example** for correct format
3. **Check logs:** `tail -f logs/trapnet.log`
4. **Verify git history:** `git log --all -S "AIza"`

---

**Last Updated:** 2026-04-26  
**Status:** 🟢 Ready for Deployment  
**Branch:** `upgrade/modernize-architecture`
