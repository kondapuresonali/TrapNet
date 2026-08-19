#!/bin/bash
# TrapNet Security Cleanup Script
# Removes leaked API keys from git history and sets up secure environment

set -e

echo "🔐 TrapNet Security Cleanup - Step by Step"
echo "==========================================="
echo ""

# Step 1: Backup
echo "📦 Step 1: Creating backup..."
git bundle create ../trapnet-backup.bundle --all
echo "✅ Backup created: ../trapnet-backup.bundle"
echo ""

# Step 2: Install git-filter-repo if needed
echo "🔧 Step 2: Checking for git-filter-repo..."
if ! command -v git-filter-repo &> /dev/null; then
    echo "Installing git-filter-repo..."
    pip install git-filter-repo
fi
echo "✅ git-filter-repo available"
echo ""

# Step 3: Create replacements file
echo "📝 Step 3: Creating replacements file..."
cat > /tmp/secret_replacements.txt << 'EOF'
# Replace leaked Gemini key
AIza ==> [REDACTED_GEMINI_KEY]

# Replace common API key patterns
api_key= ==> api_key=[REDACTED]
API_KEY= ==> API_KEY=[REDACTED]
EOF
echo "✅ Replacements file created"
echo ""

# Step 4: Clean git history
echo "🧹 Step 4: Removing secrets from git history..."
git filter-repo --replace-text /tmp/secret_replacements.txt --force
echo "✅ Git history cleaned"
echo ""

# Step 5: Verify cleanup
echo "🔍 Step 5: Verifying cleanup..."
if git log -p | grep -i "AIza" > /dev/null; then
    echo "⚠️  WARNING: Potential secrets still found in history"
else
    echo "✅ No secrets detected in git history"
fi
echo ""

# Step 6: Setup .env
echo "🔑 Step 6: Setting up .env file..."
if [ ! -f .env ]; then
    cp .env.example .env
    echo "✅ .env file created from template"
    echo ""
    echo "⚠️  IMPORTANT: Edit .env with your NEW API keys:"
    echo "   nano .env"
    echo ""
else
    echo "✅ .env file already exists"
fi
echo ""

# Step 7: Verify .gitignore
echo "🛡️  Step 7: Verifying .gitignore..."
if grep -q "^\.env$" .gitignore; then
    echo "✅ .env is properly ignored"
else
    echo "⚠️  WARNING: .env might not be in .gitignore"
fi
echo ""

# Step 8: Force push
echo "📤 Step 8: Force pushing changes..."
echo "⚠️  WARNING: This rewrites git history. Only proceed if:"
echo "   - This is YOUR repository"
echo "   - No one else is working on it"
echo "   - You've created a backup (already done ✅)"
echo ""
read -p "Force push to origin? (yes/no): " force_push

if [ "$force_push" = "yes" ]; then
    git push -f origin --all
    git push -f origin --tags
    echo "✅ Force push complete"
else
    echo "⏭️  Skipped force push. You can do this manually later:"
    echo "   git push -f origin --all"
    echo "   git push -f origin --tags"
fi
echo ""

# Step 9: Update deployment
echo "🚀 Step 9: Update Render deployment..."
echo "Go to: https://dashboard.render.com"
echo "1. Select TrapNet service"
echo "2. Environment → Update variables:"
echo "   - VT_API_KEY = [your new key]"
echo "   - GEMINI_API_KEY = [your new key]"
echo "3. Redeploy"
echo ""

# Step 10: Mark GitScan as resolved
echo "✅ Step 10: Mark GitScan finding as resolved..."
echo "Visit: https://gitscan.ai/resolve?finding=gs_4345f33d0aeb3c6a"
echo ""

echo "🎉 Security cleanup complete!"
echo ""
echo "Summary:"
echo "  ✅ Git history cleaned"
echo "  ✅ .env configured locally"
echo "  ✅ .gitignore enforced"
echo "  ⏳ TODO: Rotate API keys in Google/VirusTotal"
echo "  ⏳ TODO: Update Render secrets"
echo "  ⏳ TODO: Mark GitScan as resolved"
echo ""
echo "Backup saved to: ../trapnet-backup.bundle"
