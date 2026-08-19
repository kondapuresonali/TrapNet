# Security Policy & API Key Management

## Critical: API Key Exposure Fix

### What Happened
The Gemini API key was accidentally exposed in `app.py` with a default value. This was caught by GitScan on April 25, 2026.

### Immediate Actions Taken

1. ✅ **Revoked the exposed key** in [Google AI Studio](https://aistudio.google.com/apikey)
2. ✅ **Removed all hardcoded defaults** from code
3. ✅ **Implemented environment-based configuration**
4. ✅ **Updated .gitignore** to prevent future leaks

### Proper API Key Management

#### Step 1: Rotate Your Keys
```bash
# Google Gemini
1. Go to https://aistudio.google.com/apikey
2. Delete the old key: AIza...x14
3. Generate a new API key
4. Copy the new key

# VirusTotal
1. Go to https://virustotal.com → Avatar → API Key
2. Regenerate API Key
3. Copy the new key
```

#### Step 2: Create .env File (LOCAL ONLY)
```bash
cp .env.example .env
```

Edit `.env`:
```
FLASK_ENV=development
VT_API_KEY=your_new_virustotal_key_here
GEMINI_API_KEY=your_new_gemini_key_here
DATABASE_URL=sqlite:///trapnet.db
```

**NEVER commit .env file!** It's in .gitignore.

#### Step 3: Clean Git History (Remove Leaked Key)

If you want to completely remove the leaked key from git history:

```bash
# Using git-filter-repo (recommended)
pip install git-filter-repo

# Remove the exposed key from all history
git filter-repo --replace-text <(echo "AIza*" ==> "REDACTED")

# Force push (careful - this rewrites history)
git push -f origin --all
git push -f origin --tags
```

Or using BFG (simpler):
```bash
# Download BFG: https://rtyley.github.io/bfg-repo-cleaner/
java -jar bfg.jar --replace-text replacements.txt .

# Force push
git push -f origin --all
```

#### Step 4: Update Deployment Secrets

**For Render (current deployment):**
1. Go to https://dashboard.render.com → TrapNet service
2. Environment → Add/Update variables:
   - `VT_API_KEY` = your_new_key
   - `GEMINI_API_KEY` = your_new_key
3. Redeploy the service

**For Docker (local):**
```bash
# Create .env file locally
docker-compose up --build
# Docker reads from .env automatically
```

**For GitHub Actions (CI/CD):**
1. Go to Repository → Settings → Secrets and variables → Actions
2. Add secrets:
   - `VT_API_KEY`
   - `GEMINI_API_KEY`
3. GitHub Actions accesses via `${{ secrets.VT_API_KEY }}`

### Code Changes

#### Before (❌ Vulnerable)
```python
VT_API_KEY = os.environ.get("VT_API_KEY", "default_key_here")  # BAD!
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIza...")   # BAD!
```

#### After (✅ Secure)
```python
VT_API_KEY = os.environ.get("VT_API_KEY", "")  # Only from env
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "")  # Only from env

if not VT_API_KEY:
    logger.warning("VT_API_KEY not configured")
if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not configured")
```

### Files Changed

| File | Change |
|------|--------|
| `.gitignore` | Added `.env` pattern |
| `.env.example` | Template without real keys |
| `config.py` | Environment-based configuration |
| `app.py` | Remove hardcoded defaults |
| `services/gemini_service.py` | Secure key handling |
| `services/virustotal_service.py` | Secure key handling |

### Best Practices Going Forward

1. **Never commit secrets** to any branch
2. **Use .env files** locally (add to .gitignore)
3. **Use platform secrets** (Render, GitHub Actions, etc.)
4. **Regular key rotation** (quarterly minimum)
5. **Use secret scanning** tools:
   - GitScan (already enabled)
   - GitHub Secret Scanning
   - TruffleHog
   - git-secrets

### Testing Locally

```bash
# Verify .env is ignored
git check-ignore .env  # Should return: .env

# Verify app loads without errors
source .env  # Load variables
python app.py  # Should start without hardcoded key warnings

# Check git history (no secrets exposed)
git log -p app.py | grep -i "AIza"  # Should return nothing
```

### Monitoring

Enable GitHub Secret Scanning to catch future leaks:
1. Go to Repository → Settings → Security & analysis
2. Enable "Secret scanning"
3. GitHub will alert you if secrets are detected in PRs

### Questions?

Refer to:
- [Google Gemini API Security](https://ai.google.dev/gemini-api/docs/api-key)
- [VirusTotal API Docs](https://developers.virustotal.com/reference)
- [OWASP Secret Management](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)

**Status:** ✅ SECURITY FIX COMPLETE
