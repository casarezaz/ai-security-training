#!/usr/bin/env bash
# =============================================================================
# macOS System Hardening
# Verifies and hardens macOS security settings.
# Non-destructive: reports status first, asks before making changes.
# Run once after initial setup, then periodically to verify.
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

ask_fix() {
    local prompt="$1"
    if [[ "${AUTO_FIX:-}" == "true" ]]; then
        return 0
    fi
    echo ""
    read -rp "    → $prompt [y/N] " answer
    [[ "$answer" =~ ^[Yy] ]]
}

echo ""
echo "=============================================="
echo "  macOS System Hardening"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo ""

# Usage
if [[ "${1:-}" == "--auto" ]]; then
    AUTO_FIX=true
    info "Auto-fix mode enabled (will apply all recommended changes)"
fi

info "System: $(sw_vers -productName) $(sw_vers -productVersion) ($(uname -m))"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. SYSTEM INTEGRITY PROTECTION (SIP)
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 1: System Integrity Protection ==="

SIP_STATUS=$(csrutil status 2>/dev/null || echo "unknown")
if echo "$SIP_STATUS" | grep -q "enabled"; then
    pass "SIP is enabled"
elif echo "$SIP_STATUS" | grep -q "unknown"; then
    flag "Could not determine SIP status (normal in some VMs)"
else
    fail "SIP is DISABLED — re-enable via Recovery Mode (csrutil enable)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. GATEKEEPER
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 2: Gatekeeper ==="

GK_STATUS=$(spctl --status 2>/dev/null || echo "unknown")
if echo "$GK_STATUS" | grep -q "assessments enabled"; then
    pass "Gatekeeper is enabled"
else
    fail "Gatekeeper is disabled"
    if ask_fix "Enable Gatekeeper?"; then
        sudo spctl --master-enable
        pass "Gatekeeper enabled"
        ((CHANGED++))
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. FILEVAULT (DISK ENCRYPTION)
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 3: FileVault Disk Encryption ==="

FV_STATUS=$(fdesetup status 2>/dev/null || echo "unknown")
if echo "$FV_STATUS" | grep -q "FileVault is On"; then
    pass "FileVault is enabled — disk is encrypted"
elif echo "$FV_STATUS" | grep -q "FileVault is Off"; then
    fail "FileVault is OFF — your disk is NOT encrypted"
    echo "    → Enable in: System Settings → Privacy & Security → FileVault"
    echo "    → IMPORTANT: Save your recovery key somewhere safe"
else
    flag "Could not determine FileVault status"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. MACOS APPLICATION FIREWALL
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 4: macOS Firewall ==="

FW_PATH="/usr/libexec/ApplicationFirewall/socketfilterfw"

FW_STATE=$($FW_PATH --getglobalstate 2>/dev/null || echo "unknown")
if echo "$FW_STATE" | grep -q "enabled"; then
    pass "Firewall is enabled"
else
    fail "Firewall is DISABLED"
    if ask_fix "Enable macOS firewall?"; then
        sudo $FW_PATH --setglobalstate on
        pass "Firewall enabled"
        ((CHANGED++))
    fi
fi

# Stealth mode (don't respond to pings/probes)
FW_STEALTH=$($FW_PATH --getstealthmode 2>/dev/null || echo "unknown")
if echo "$FW_STEALTH" | grep -q "enabled"; then
    pass "Stealth mode is enabled"
else
    flag "Stealth mode is disabled (your Mac responds to network probes)"
    if ask_fix "Enable stealth mode?"; then
        sudo $FW_PATH --setstealthmode on
        pass "Stealth mode enabled"
        ((CHANGED++))
    fi
fi

# Block all incoming (except essential)
FW_BLOCK=$($FW_PATH --getblockall 2>/dev/null || echo "unknown")
if echo "$FW_BLOCK" | grep -q "DISABLED"; then
    info "Block-all-incoming is off (allowing signed apps — this is normal)"
else
    pass "Block-all-incoming is enabled (strict mode)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. REMOTE ACCESS SERVICES
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 5: Remote Access ==="

# Remote Login (SSH server)
RL_STATUS=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "unknown")
if echo "$RL_STATUS" | grep -qi "off"; then
    pass "Remote Login (SSH server) is disabled"
elif echo "$RL_STATUS" | grep -qi "on"; then
    flag "Remote Login (SSH server) is ENABLED — others can SSH into your Mac"
    if ask_fix "Disable Remote Login?"; then
        sudo systemsetup -setremotelogin off
        pass "Remote Login disabled"
        ((CHANGED++))
    fi
else
    flag "Could not check Remote Login status"
fi

# Remote Apple Events
RAE=$(sudo systemsetup -getremoteappleevents 2>/dev/null || echo "unknown")
if echo "$RAE" | grep -qi "off"; then
    pass "Remote Apple Events is disabled"
elif echo "$RAE" | grep -qi "on"; then
    fail "Remote Apple Events is ENABLED"
    if ask_fix "Disable Remote Apple Events?"; then
        sudo systemsetup -setremoteappleevents off
        pass "Remote Apple Events disabled"
        ((CHANGED++))
    fi
fi

# Screen Sharing
SS_STATUS=$(launchctl list 2>/dev/null | grep -c "com.apple.screensharing" || true)
if [[ "$SS_STATUS" -eq 0 ]]; then
    pass "Screen Sharing is not running"
else
    flag "Screen Sharing appears to be running"
    echo "    → Disable in: System Settings → General → Sharing → Screen Sharing"
fi

# File Sharing
FS_STATUS=$(launchctl list 2>/dev/null | grep -c "com.apple.smbd" || true)
if [[ "$FS_STATUS" -eq 0 ]]; then
    pass "File Sharing (SMB) is not running"
else
    flag "File Sharing (SMB) appears to be running"
    echo "    → Disable in: System Settings → General → Sharing → File Sharing"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. WIRELESS SHARING
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 6: Wireless & Sharing ==="

# AirDrop
AIRDROP=$(defaults read com.apple.NetworkBrowser DisableAirDrop 2>/dev/null || echo "not set")
if [[ "$AIRDROP" == "1" ]]; then
    pass "AirDrop is disabled"
elif [[ "$AIRDROP" == "0" ]] || [[ "$AIRDROP" == "not set" ]]; then
    flag "AirDrop is enabled (can receive files from nearby devices)"
    if ask_fix "Disable AirDrop?"; then
        defaults write com.apple.NetworkBrowser DisableAirDrop -bool true
        pass "AirDrop disabled"
        ((CHANGED++))
    fi
fi

# Bluetooth Sharing
BT_SHARE=$(defaults read com.apple.Bluetooth PrefKeyServicesEnabled 2>/dev/null || echo "not set")
if [[ "$BT_SHARE" == "0" ]] || [[ "$BT_SHARE" == "not set" ]]; then
    pass "Bluetooth Sharing is disabled"
else
    flag "Bluetooth Sharing is enabled"
    if ask_fix "Disable Bluetooth Sharing?"; then
        defaults write com.apple.Bluetooth PrefKeyServicesEnabled -bool false
        pass "Bluetooth Sharing disabled"
        ((CHANGED++))
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. AUTOMATIC UPDATES
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 7: Automatic Updates ==="

AUTO_CHECK=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled 2>/dev/null || echo "not set")
AUTO_DOWNLOAD=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload 2>/dev/null || echo "not set")
AUTO_INSTALL=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates 2>/dev/null || echo "not set")

if [[ "$AUTO_CHECK" == "1" ]]; then
    pass "Automatic update checking is enabled"
else
    flag "Automatic update checking is disabled"
    if ask_fix "Enable automatic update checking?"; then
        sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -bool true
        pass "Automatic update checking enabled"
        ((CHANGED++))
    fi
fi

if [[ "$AUTO_DOWNLOAD" == "1" ]]; then
    pass "Automatic update download is enabled"
else
    flag "Automatic update download is disabled"
    if ask_fix "Enable automatic update downloads?"; then
        sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticDownload -bool true
        pass "Automatic update downloads enabled"
        ((CHANGED++))
    fi
fi

if [[ "$AUTO_INSTALL" == "1" ]]; then
    pass "Automatic macOS update installation is enabled"
else
    flag "Automatic macOS update installation is disabled"
    if ask_fix "Enable automatic macOS update installation?"; then
        sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticallyInstallMacOSUpdates -bool true
        pass "Automatic installation enabled"
        ((CHANGED++))
    fi
fi

# XProtect / MRT (malware removal) updates
XP_UPDATE=$(defaults read /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall 2>/dev/null || echo "not set")
if [[ "$XP_UPDATE" == "1" ]]; then
    pass "XProtect/security data updates are enabled"
else
    flag "XProtect/security data auto-updates may be disabled"
    if ask_fix "Enable XProtect auto-updates?"; then
        sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate ConfigDataInstall -bool true
        sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate CriticalUpdateInstall -bool true
        pass "XProtect auto-updates enabled"
        ((CHANGED++))
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 8. SCREEN LOCK & LOGIN SECURITY
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 8: Screen Lock & Login Security ==="

# Require password after sleep/screensaver
SCREEN_LOCK=$(sysadminctl -screenLock status 2>/dev/null || echo "unknown")
if echo "$SCREEN_LOCK" | grep -qi "immediate\|screenLock is on"; then
    pass "Screen lock requires password"
else
    flag "Screen lock delay may be too long"
    if ask_fix "Set screen lock to require password immediately?"; then
        sysadminctl -screenLock immediate 2>/dev/null || \
        defaults write com.apple.screensaver askForPassword -int 1
        defaults write com.apple.screensaver askForPasswordDelay -int 0
        pass "Screen lock set to immediate"
        ((CHANGED++))
    fi
fi

# Guest account
GUEST=$(sudo defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "not set")
if [[ "$GUEST" == "0" ]]; then
    pass "Guest account is disabled"
elif [[ "$GUEST" == "1" ]]; then
    flag "Guest account is ENABLED"
    if ask_fix "Disable guest account?"; then
        sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false
        pass "Guest account disabled"
        ((CHANGED++))
    fi
else
    info "Guest account status: could not determine (likely disabled by default)"
fi

# Show password hints
HINTS=$(defaults read com.apple.loginwindow RetriesUntilHint 2>/dev/null || echo "not set")
if [[ "$HINTS" == "0" ]] || [[ "$HINTS" == "not set" ]]; then
    pass "Login password hints are disabled"
else
    flag "Password hints are shown after $HINTS failed attempts"
    if ask_fix "Disable password hints?"; then
        sudo defaults write /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0
        pass "Password hints disabled"
        ((CHANGED++))
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 9. PRIVACY & SECURITY SETTINGS
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 9: Privacy & Security ==="

# Safari safe downloads
SAFARI_OPEN=$(defaults read com.apple.Safari AutoOpenSafeDownloads 2>/dev/null || echo "not set")
if [[ "$SAFARI_OPEN" == "0" ]]; then
    pass "Safari auto-open safe downloads is disabled"
elif [[ "$SAFARI_OPEN" == "1" ]]; then
    flag "Safari auto-opens 'safe' downloads"
    if ask_fix "Disable Safari auto-open downloads?"; then
        defaults write com.apple.Safari AutoOpenSafeDownloads -bool false
        pass "Safari auto-open disabled"
        ((CHANGED++))
    fi
else
    info "Safari auto-open setting: default (you may not use Safari)"
fi

# Show file extensions
SHOW_EXT=$(defaults read NSGlobalDomain AppleShowAllExtensions 2>/dev/null || echo "not set")
if [[ "$SHOW_EXT" == "1" ]]; then
    pass "File extensions are visible in Finder"
else
    flag "File extensions are hidden (malware can disguise itself)"
    if ask_fix "Show all file extensions in Finder?"; then
        defaults write NSGlobalDomain AppleShowAllExtensions -bool true
        pass "File extensions now visible"
        ((CHANGED++))
    fi
fi

# Disable Handoff (prevents data leaking between devices)
HANDOFF=$(defaults read ~/Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist ActivityAdvertisingAllowed 2>/dev/null || echo "not set")
if [[ "$HANDOFF" == "0" ]]; then
    pass "Handoff is disabled"
else
    info "Handoff is enabled (shares activity between your Apple devices)"
    echo "    → Disable in: System Settings → General → AirDrop & Handoff if desired"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 10. LOGIN ITEMS AUDIT
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 10: Login Items & Launch Agents ==="

echo ""
info "User Launch Agents (~/Library/LaunchAgents/):"
if ls ~/Library/LaunchAgents/*.plist 2>/dev/null | head -20; then
    echo ""
else
    ok "  No user launch agents found"
fi

info "System Launch Agents (/Library/LaunchAgents/):"
if ls /Library/LaunchAgents/*.plist 2>/dev/null | head -20; then
    echo ""
else
    ok "  No third-party system launch agents"
fi

info "System Launch Daemons (/Library/LaunchDaemons/):"
if ls /Library/LaunchDaemons/*.plist 2>/dev/null | head -20; then
    echo ""
else
    ok "  No third-party system launch daemons"
fi

echo ""
info "Review the above items. Anything unexpected should be investigated."
info "Use: launchctl list | grep <name> to check if running"

# ─────────────────────────────────────────────────────────────────────────────
# 11. NETWORK SECURITY
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 11: Network Security ==="

# Check for open listening ports
info "Currently listening ports:"
echo ""
lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{printf "    %-20s %-10s %s\n", $1, $9, $10}' | sort -u
echo ""

# DNS settings
info "DNS servers:"
networksetup -getdnsservers Wi-Fi 2>/dev/null | head -5 | while read line; do
    echo "    $line"
done
echo ""

# Wi-Fi security
WIFI_SECURITY=$(networksetup -getairportnetwork en0 2>/dev/null || echo "unknown")
info "Wi-Fi: $WIFI_SECURITY"

# ─────────────────────────────────────────────────────────────────────────────
# 12. DEVELOPER TOOL SECURITY
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 12: Developer Tool Security ==="

# Check Homebrew
if command -v brew &>/dev/null; then
    pass "Homebrew installed: $(brew --version | head -1)"
    BREW_ANALYTICS=$(brew analytics 2>/dev/null || echo "unknown")
    if echo "$BREW_ANALYTICS" | grep -qi "disabled"; then
        pass "Homebrew analytics is disabled"
    else
        flag "Homebrew analytics is enabled (sends usage data)"
        if ask_fix "Disable Homebrew analytics?"; then
            brew analytics off
            pass "Homebrew analytics disabled"
            ((CHANGED++))
        fi
    fi
else
    info "Homebrew not installed"
fi

# Check npm audit settings
if command -v npm &>/dev/null; then
    info "npm installed: $(npm --version)"
fi

# Check Python/pip
if command -v python3 &>/dev/null; then
    info "Python: $(python3 --version)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  Hardening Summary"
echo "=============================================="
echo ""
echo -e "  ${GREEN}Passed:${NC}   $PASS checks"
echo -e "  ${RED}Failed:${NC}   $FAIL checks"
echo -e "  ${YELLOW}Warnings:${NC} $WARN_COUNT items"
echo -e "  ${BLUE}Changed:${NC}  $CHANGED settings"
echo ""

if [[ $FAIL -gt 0 ]]; then
    echo -e "${RED}Some checks failed. Review the output above and fix issues.${NC}"
elif [[ $WARN_COUNT -gt 0 ]]; then
    echo -e "${YELLOW}Some warnings found. Consider addressing them.${NC}"
else
    echo -e "${GREEN}All checks passed! Your Mac is well-hardened.${NC}"
fi

# Save report
REPORT_DIR="$HOME/aiml-cybersecurity/reports/security"
mkdir -p "$REPORT_DIR"
REPORT="$REPORT_DIR/macos_hardening_$(date +%Y%m%d_%H%M%S).txt"
{
    echo "macOS Hardening Report - $(date)"
    echo "System: $(sw_vers -productName) $(sw_vers -productVersion) ($(uname -m))"
    echo ""
    echo "Passed: $PASS | Failed: $FAIL | Warnings: $WARN_COUNT | Changed: $CHANGED"
} > "$REPORT"
echo ""
ok "Report saved: $REPORT"
echo ""
