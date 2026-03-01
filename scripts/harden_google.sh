#!/usr/bin/env bash
# =============================================================================
# Google Workspace & Chrome Hardening Guide
# Checks and recommends security settings for Google services.
# Some settings must be changed in browser — this script guides you through.
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[FAIL]${NC}  $*"; }

PASS=0; FAIL=0; WARN_COUNT=0; CHANGED=0
pass() { ((PASS++)); ok "$*"; }
fail() { ((FAIL++)); err "$*"; }
flag() { ((WARN_COUNT++)); warn "$*"; }

echo ""
echo "=============================================="
echo "  Google Workspace & Chrome Hardening"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. CHROME SECURITY SETTINGS (via defaults/preferences)
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 1: Chrome Browser Security ==="

CHROME_PREFS="$HOME/Library/Application Support/Google/Chrome/Default/Preferences"

if [[ -f "$CHROME_PREFS" ]]; then
    pass "Chrome profile found"

    # Safe Browsing
    SB=$(python3 -c "import json; d=json.load(open('$CHROME_PREFS')); print(d.get('safebrowsing',{}).get('enabled','not set'))" 2>/dev/null || echo "not set")
    if [[ "$SB" == "True" ]] || [[ "$SB" == "true" ]]; then
        pass "Safe Browsing is enabled"
    else
        flag "Safe Browsing may not be enabled"
        echo "    → Chrome → Settings → Privacy & Security → Safe Browsing → Enhanced protection"
    fi

    # DNS over HTTPS
    DOH=$(python3 -c "import json; d=json.load(open('$CHROME_PREFS')); print(d.get('dns_over_https',{}).get('mode','not set'))" 2>/dev/null || echo "not set")
    if [[ "$DOH" == "secure" ]]; then
        pass "DNS over HTTPS is enabled (secure mode)"
    elif [[ "$DOH" == "automatic" ]]; then
        pass "DNS over HTTPS is enabled (automatic mode)"
    else
        flag "DNS over HTTPS may not be enabled"
        echo "    → Chrome → Settings → Privacy & Security → Use secure DNS → Enabled"
    fi
else
    info "Chrome preferences not found — Chrome may not be installed or not yet configured"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 2. CHROME EXTENSIONS AUDIT
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 2: Chrome Extensions Audit ==="

EXT_DIR="$HOME/Library/Application Support/Google/Chrome/Default/Extensions"
if [[ -d "$EXT_DIR" ]]; then
    EXT_COUNT=$(ls -d "$EXT_DIR"/*/ 2>/dev/null | wc -l | tr -d ' ')
    info "Installed extensions: $EXT_COUNT"

    # List extensions with their names
    echo ""
    info "Installed Chrome extensions:"
    for ext_id_dir in "$EXT_DIR"/*/; do
        ext_id=$(basename "$ext_id_dir")
        # Try to get extension name from manifest
        manifest=$(find "$ext_id_dir" -name "manifest.json" -maxdepth 2 2>/dev/null | head -1)
        if [[ -n "$manifest" ]]; then
            name=$(python3 -c "import json; print(json.load(open('$manifest')).get('name','Unknown'))" 2>/dev/null || echo "Unknown")
            # Skip Chrome internals
            if [[ "$name" != "__MSG_"* ]] && [[ "$name" != "Unknown" ]]; then
                info "  • $name ($ext_id)"
            fi
        fi
    done
    echo ""
    info "Review extensions above. Remove any you don't recognize."
    echo "    → Chrome → chrome://extensions/"
else
    info "No Chrome extensions directory found"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 3. GOOGLE DRIVE DESKTOP SECURITY
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 3: Google Drive Desktop ==="

GDRIVE_APP="/Applications/Google Drive.app"
if [[ -d "$GDRIVE_APP" ]]; then
    pass "Google Drive Desktop is installed"

    # Check if Google Drive is running
    GDRIVE_RUNNING=$(ps aux 2>/dev/null | awk '$11 ~ /Google Drive/ {found=1} END {print found+0}')
    if [[ "$GDRIVE_RUNNING" -gt 0 ]]; then
        pass "Google Drive is running"
    else
        info "Google Drive is not currently running"
    fi

    # Check Drive FS crash reporting (telemetry)
    GDRIVE_CRASHPAD=$(ps aux 2>/dev/null | grep -c "crashpad_handler.*DriveFS" || true)
    GDRIVE_CRASHPAD=$(echo "$GDRIVE_CRASHPAD" | tr -d '[:space:]')
    if [[ "$GDRIVE_CRASHPAD" -gt 0 ]]; then
        flag "Google Drive crash reporting (crashpad) is active"
        echo "    → This sends crash data to Google. Consider if you want this."
    fi

    # Check Drive cache location and size
    DRIVE_CACHE="$HOME/Library/Application Support/Google/DriveFS"
    if [[ -d "$DRIVE_CACHE" ]]; then
        CACHE_SIZE=$(du -sh "$DRIVE_CACHE" 2>/dev/null | awk '{print $1}')
        info "Drive cache size: $CACHE_SIZE"
        info "Cache location: $DRIVE_CACHE"
    fi
else
    info "Google Drive Desktop not installed"
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 4. CHROME SECURITY RECOMMENDATIONS
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 4: Manual Chrome Hardening Checklist ==="
echo ""
echo "    Open each URL in Chrome and verify these settings:"
echo ""
echo "    1. SAFE BROWSING (Enhanced Protection):"
echo "       → chrome://settings/security"
echo "       → Select 'Enhanced protection'"
echo ""
echo "    2. SECURE DNS:"
echo "       → chrome://settings/security"
echo "       → 'Use secure DNS' → ON → 'Cloudflare (1.1.1.1)'"
echo ""
echo "    3. ALWAYS USE HTTPS:"
echo "       → chrome://settings/security"
echo "       → 'Always use secure connections' → ON"
echo ""
echo "    4. BLOCK THIRD-PARTY COOKIES:"
echo "       → chrome://settings/cookies"
echo "       → 'Block third-party cookies'"
echo ""
echo "    5. DO NOT TRACK:"
echo "       → chrome://settings/cookies"
echo "       → 'Send a Do Not Track request' → ON"
echo ""
echo "    6. DISABLE PASSWORD SAVING IN CHROME:"
echo "       → chrome://settings/passwords"
echo "       → 'Offer to save passwords' → OFF"
echo "       → Use a dedicated password manager instead"
echo ""
echo "    7. REVIEW SITE PERMISSIONS:"
echo "       → chrome://settings/content"
echo "       → Review: Camera, Microphone, Location, Notifications"
echo "       → Set defaults to 'Ask' or 'Block'"
echo ""
echo "    8. DISABLE CHROME SIGN-IN SYNC (if not needed):"
echo "       → chrome://settings/syncSetup"
echo "       → Consider disabling sync of passwords, payment methods"
echo ""
echo "    9. REVIEW EXTENSIONS:"
echo "       → chrome://extensions/"
echo "       → Remove anything you don't recognize or use"
echo "       → Check permissions on remaining extensions"
echo ""
echo "    10. SITE ISOLATION:"
echo "        → chrome://flags/#enable-site-per-process"
echo "        → Should be 'Enabled' (default on modern Chrome)"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 5. GOOGLE ACCOUNT SECURITY CHECKLIST
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 5: Google Account Security Checklist ==="
echo ""
echo "    Visit these pages in your browser:"
echo ""
echo "    1. SECURITY CHECKUP:"
echo "       → https://myaccount.google.com/security-checkup"
echo "       → Review all recommendations"
echo ""
echo "    2. 2-STEP VERIFICATION:"
echo "       → https://myaccount.google.com/signinoptions/two-step-verification"
echo "       → Enable if not already (use Security Key or Google Prompts)"
echo ""
echo "    3. APP PASSWORDS:"
echo "       → https://myaccount.google.com/apppasswords"
echo "       → Revoke any you don't recognize"
echo ""
echo "    4. THIRD-PARTY ACCESS:"
echo "       → https://myaccount.google.com/permissions"
echo "       → Remove apps you no longer use"
echo ""
echo "    5. RECENT SECURITY ACTIVITY:"
echo "       → https://myaccount.google.com/notifications"
echo "       → Review for any suspicious sign-ins"
echo ""
echo "    6. DEVICE ACTIVITY:"
echo "       → https://myaccount.google.com/device-activity"
echo "       → Remove devices you don't recognize"
echo ""
echo "    7. ADVANCED PROTECTION (optional):"
echo "       → https://landing.google.com/advancedprotection/"
echo "       → Strongest protection — requires security keys"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 6. APPLY CHROME SETTINGS VIA DEFAULTS (where possible)
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 6: Applying Chrome Hardening ==="

# Disable Chrome metrics/crash reporting
CHROME_METRICS=$(defaults read com.google.Chrome MetricsReportingEnabled 2>/dev/null || echo "not set")
if [[ "$CHROME_METRICS" == "0" ]]; then
    pass "Chrome metrics reporting is disabled"
else
    flag "Chrome metrics reporting may be enabled"
    read -rp "    → Disable Chrome metrics/crash reporting? [y/N] " answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        defaults write com.google.Chrome MetricsReportingEnabled -bool false
        pass "Chrome metrics disabled"
        ((CHANGED++))
    fi
fi

# Disable Chrome background apps
CHROME_BG=$(defaults read com.google.Chrome BackgroundModeEnabled 2>/dev/null || echo "not set")
if [[ "$CHROME_BG" == "0" ]] || [[ "$CHROME_BG" == "false" ]]; then
    pass "Chrome background mode is disabled"
else
    flag "Chrome may run background apps when closed"
    read -rp "    → Disable Chrome background apps? [y/N] " answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        defaults write com.google.Chrome BackgroundModeEnabled -bool false
        pass "Chrome background mode disabled"
        ((CHANGED++))
    fi
fi

# Block auto-fill of payment methods
CHROME_AUTOPAY=$(defaults read com.google.Chrome AutofillCreditCardEnabled 2>/dev/null || echo "not set")
if [[ "$CHROME_AUTOPAY" == "0" ]] || [[ "$CHROME_AUTOPAY" == "false" ]]; then
    pass "Chrome credit card autofill is disabled"
else
    flag "Chrome may autofill credit card info"
    read -rp "    → Disable Chrome credit card autofill? [y/N] " answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        defaults write com.google.Chrome AutofillCreditCardEnabled -bool false
        pass "Chrome credit card autofill disabled"
        ((CHANGED++))
    fi
fi

# Disable Chrome password manager (recommend dedicated password manager)
CHROME_PWSAVE=$(defaults read com.google.Chrome PasswordManagerEnabled 2>/dev/null || echo "not set")
if [[ "$CHROME_PWSAVE" == "0" ]] || [[ "$CHROME_PWSAVE" == "false" ]]; then
    pass "Chrome built-in password manager is disabled"
else
    flag "Chrome built-in password manager is enabled"
    echo "    → Consider using a dedicated password manager (1Password, Bitwarden)"
    read -rp "    → Disable Chrome password saving? [y/N] " answer
    if [[ "$answer" =~ ^[Yy] ]]; then
        defaults write com.google.Chrome PasswordManagerEnabled -bool false
        pass "Chrome password manager disabled"
        ((CHANGED++))
    fi
fi

echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo "=============================================="
echo "  Google Hardening Summary"
echo "=============================================="
echo ""
echo -e "  ${GREEN}Passed:${NC}   $PASS checks"
echo -e "  ${RED}Failed:${NC}   $FAIL checks"
echo -e "  ${YELLOW}Warnings:${NC} $WARN_COUNT items"
echo -e "  ${BLUE}Changed:${NC}  $CHANGED settings"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Some checks failed. Review the output above.${NC}"
elif [[ $WARN_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}Some warnings found. Follow the manual steps above.${NC}"
else
    echo -e "${GREEN}Chrome hardening complete! Follow the manual checklists above for full coverage.${NC}"
fi
echo ""
