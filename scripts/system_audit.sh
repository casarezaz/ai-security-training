#!/usr/bin/env bash
# =============================================================================
# On-Demand System Security Audit
# Comprehensive security audit for manual investigation.
# Usage:
#   ./system_audit.sh --quick          Essential checks (3-5 min)
#   ./system_audit.sh --full           Everything (10-15 min)
#   ./system_audit.sh --save-baseline  Save current state as trusted baseline
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[FAIL]${NC}  $*"; }
hdr()   { echo ""; echo -e "${BLUE}═══ $* ═══${NC}"; echo ""; }

PROJECT_DIR="$HOME/aiml-cybersecurity"
REPORT_DIR="$PROJECT_DIR/reports/security"
CONFIGS_DIR="$PROJECT_DIR/configs/hardening"
REPORT_FILE="$REPORT_DIR/audit_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$REPORT_DIR" "$CONFIGS_DIR"

MODE="${1:---quick}"

report() { echo "$*" | tee -a "$REPORT_FILE"; }

{
    echo "=============================================="
    echo "System Security Audit — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Mode: $MODE"
    echo "Host: $(hostname)"
    echo "macOS: $(sw_vers -productVersion) ($(uname -m))"
    echo "=============================================="
    echo ""
} > "$REPORT_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# SAVE BASELINE MODE
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--save-baseline" ]]; then
    hdr "Saving Trusted Baselines"

    # Save trusted listening ports
    info "Saving current listening ports as trusted baseline..."
    lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{print $1 ":" $9}' | sort -u > "$CONFIGS_DIR/trusted_ports.txt"
    ok "Saved: $CONFIGS_DIR/trusted_ports.txt ($(wc -l < "$CONFIGS_DIR/trusted_ports.txt") entries)"

    # Save trusted processes
    info "Saving current process list as trusted baseline..."
    ps -eo comm= 2>/dev/null | sort -u > "$CONFIGS_DIR/trusted_processes.txt"
    ok "Saved: $CONFIGS_DIR/trusted_processes.txt ($(wc -l < "$CONFIGS_DIR/trusted_processes.txt") entries)"

    # Save launch agents baseline
    info "Saving launch agents baseline..."
    {
        ls ~/Library/LaunchAgents/*.plist 2>/dev/null
        ls /Library/LaunchAgents/*.plist 2>/dev/null
        ls /Library/LaunchDaemons/*.plist 2>/dev/null
    } > "$CONFIGS_DIR/launch_agents_baseline.txt" 2>/dev/null
    ok "Saved: $CONFIGS_DIR/launch_agents_baseline.txt"

    # Create file integrity baseline
    if [[ -x "$PROJECT_DIR/scripts/file_integrity.sh" ]]; then
        info "Creating file integrity baseline..."
        "$PROJECT_DIR/scripts/file_integrity.sh" --baseline
    fi

    echo ""
    ok "All baselines saved to $CONFIGS_DIR/"
    echo ""
    exit 0
fi

# ─────────────────────────────────────────────────────────────────────────────
# 1. SYSTEM OVERVIEW
# ─────────────────────────────────────────────────────────────────────────────
hdr "System Overview"

report "Hostname: $(hostname)"
report "macOS: $(sw_vers -productVersion) (Build $(sw_vers -buildVersion))"
report "Kernel: $(uname -r)"
report "Arch: $(uname -m)"
report "Uptime: $(uptime | sed 's/.*up //' | sed 's/,.*//')"
report "Current User: $(whoami)"
report "Admin Group: $(dscl . -read /Groups/admin GroupMembership 2>/dev/null | cut -d: -f2 || echo 'unknown')"

# ─────────────────────────────────────────────────────────────────────────────
# 2. SECURITY FEATURES
# ─────────────────────────────────────────────────────────────────────────────
hdr "Security Features"

# SIP
SIP=$(csrutil status 2>/dev/null || echo "unknown")
echo "$SIP" | grep -q "enabled" && ok "SIP: Enabled" || err "SIP: $SIP"
report "SIP: $SIP"

# Gatekeeper
GK=$(spctl --status 2>/dev/null || echo "unknown")
echo "$GK" | grep -q "assessments enabled" && ok "Gatekeeper: Enabled" || err "Gatekeeper: $GK"
report "Gatekeeper: $GK"

# FileVault
FV=$(fdesetup status 2>/dev/null || echo "unknown")
echo "$FV" | grep -q "On" && ok "FileVault: $FV" || warn "FileVault: $FV"
report "FileVault: $FV"

# Firewall
FW=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate 2>/dev/null || echo "unknown")
echo "$FW" | grep -q "enabled" && ok "Firewall: Enabled" || err "Firewall: $FW"
report "Firewall: $FW"

# Stealth mode
SM=$(/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode 2>/dev/null || echo "unknown")
echo "$SM" | grep -q "enabled" && ok "Stealth Mode: Enabled" || warn "Stealth Mode: $SM"
report "Stealth Mode: $SM"

# XProtect version
XP_VER=$(system_profiler SPInstallHistoryDataType 2>/dev/null | grep -A2 "XProtect" | tail -1 | awk '{print $NF}' || echo "unknown")
info "XProtect version: $XP_VER"

# ─────────────────────────────────────────────────────────────────────────────
# 3. LISTENING PORTS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Listening Ports & Services"

report "--- Listening Services ---"
lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{printf "  %-20s %-8s %s\n", $1, $3, $9}' | sort -u | tee -a "$REPORT_FILE"

# ─────────────────────────────────────────────────────────────────────────────
# 4. NETWORK CONNECTIONS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Active Network Connections"

report "--- Established Connections ---"
CONN_COUNT=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
info "Total established connections: $CONN_COUNT"
report "Total: $CONN_COUNT"

lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{printf "  %-20s %-8s %s\n", $1, $3, $9}' | sort -u | head -30 | tee -a "$REPORT_FILE"

if [[ $CONN_COUNT -gt 30 ]]; then
    info "... and $(($CONN_COUNT - 30)) more (see full report)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. USER ACCOUNTS
# ─────────────────────────────────────────────────────────────────────────────
hdr "User Accounts"

report "--- User Accounts ---"
dscl . list /Users | grep -v '^_' | grep -v "^daemon$\|^nobody$\|^root$" | while read user; do
    info "User: $user"
    report "  $user"
done

# Guest account
GUEST=$(sudo defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled 2>/dev/null || echo "not set")
[[ "$GUEST" == "0" ]] && ok "Guest account: Disabled" || warn "Guest account: Enabled or unknown"

# ─────────────────────────────────────────────────────────────────────────────
# 6. SSH CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
hdr "SSH Security"

report "--- SSH ---"

# Check authorized_keys
if [[ -f "$HOME/.ssh/authorized_keys" ]]; then
    KEYS=$(wc -l < "$HOME/.ssh/authorized_keys" | tr -d ' ')
    warn "authorized_keys has $KEYS key(s) — verify these are all yours"
    report "authorized_keys: $KEYS keys"
else
    ok "No authorized_keys file (no remote SSH access configured)"
fi

# SSH key permissions
if [[ -f "$HOME/.ssh/id_ed25519" ]]; then
    PERMS=$(stat -f "%Lp" "$HOME/.ssh/id_ed25519" 2>/dev/null)
    if [[ "$PERMS" == "600" ]]; then
        ok "SSH private key permissions: 600"
    else
        err "SSH private key permissions: $PERMS (should be 600)"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 7. PROCESS ANALYSIS (full mode only)
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--full" ]]; then
    hdr "Deep Process Analysis"

    report "--- Process Analysis ---"

    # Top CPU consumers
    info "Top 10 CPU consumers:"
    ps aux --sort=-%cpu 2>/dev/null | head -11 | tee -a "$REPORT_FILE" || \
    ps -eo pid,pcpu,pmem,comm -r 2>/dev/null | head -11 | tee -a "$REPORT_FILE"
    echo ""

    # Top memory consumers
    info "Top 10 memory consumers:"
    ps -eo pid,pmem,rss,comm 2>/dev/null | sort -k2 -rn | head -11 | tee -a "$REPORT_FILE"
    echo ""

    # Processes running as root (non-system)
    info "Non-Apple root processes:"
    ps aux 2>/dev/null | awk '$1 == "root" && $11 !~ /^\/usr\/|^\/System\/|^\/sbin\// {print $11}' | sort -u | head -20 | while read p; do
        warn "  Root: $p"
        report "  Root process: $p"
    done
fi

# ─────────────────────────────────────────────────────────────────────────────
# 8. FILE PERMISSIONS
# ─────────────────────────────────────────────────────────────────────────────
hdr "Critical File Permissions"

report "--- File Permissions ---"

check_perms() {
    local file="$1" expected="$2" label="$3"
    if [[ -e "$file" ]]; then
        actual=$(stat -f "%Lp" "$file" 2>/dev/null)
        if [[ "$actual" == "$expected" ]]; then
            ok "$label: $actual"
        else
            err "$label: $actual (expected $expected)"
        fi
        report "$label: $actual (expected $expected)"
    fi
}

check_perms "$HOME/.ssh" "700" "~/.ssh directory"
check_perms "$HOME/.ssh/id_ed25519" "600" "SSH private key"
check_perms "$HOME/.ssh/config" "600" "SSH config"
check_perms "$PROJECT_DIR/.env" "600" ".env file"
check_perms "$HOME/.docker/daemon.json" "600" "Docker daemon.json"
check_perms "$HOME/.gnupg" "700" "GPG directory"

# ─────────────────────────────────────────────────────────────────────────────
# 9. DOCKER DEEP DIVE (full mode only)
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--full" ]] && command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    hdr "Docker Deep Dive"

    report "--- Docker ---"

    # Docker version
    info "Docker: $(docker --version)"
    report "Docker: $(docker --version)"

    # All containers
    info "All containers:"
    docker ps -a --format 'table {{.Names}}\t{{.Status}}\t{{.Image}}' 2>/dev/null | tee -a "$REPORT_FILE"
    echo ""

    # Container security details
    docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
        info "Container: $c"
        PRIV=$(docker inspect --format='Privileged={{.HostConfig.Privileged}} ReadOnly={{.HostConfig.ReadonlyRootfs}} NoNewPriv={{.HostConfig.SecurityOpt}}' "$c" 2>/dev/null)
        info "  $PRIV"
        report "  $c: $PRIV"

        CAPS=$(docker inspect --format='CapDrop={{.HostConfig.CapDrop}} CapAdd={{.HostConfig.CapAdd}}' "$c" 2>/dev/null)
        info "  $CAPS"
        report "  $c: $CAPS"
    done

    # Docker networks
    info "Docker networks:"
    docker network ls --format 'table {{.Name}}\t{{.Driver}}\t{{.Scope}}' 2>/dev/null | tee -a "$REPORT_FILE"

    # Dangling images
    DANGLING=$(docker images -f "dangling=true" -q 2>/dev/null | wc -l | tr -d ' ')
    if [[ "$DANGLING" -gt 0 ]]; then
        warn "$DANGLING dangling images (run docker image prune to clean)"
    else
        ok "No dangling images"
    fi
fi

# ─────────────────────────────────────────────────────────────────────────────
# 10. RECENT SECURITY EVENTS (full mode)
# ─────────────────────────────────────────────────────────────────────────────
if [[ "$MODE" == "--full" ]]; then
    hdr "Recent Security Events (last 24h)"

    report "--- Security Events ---"

    # Sudo usage
    SUDO_COUNT=$(log show --predicate 'process == "sudo"' --last 24h --style compact 2>/dev/null | wc -l | tr -d ' ')
    info "Sudo events in last 24h: $SUDO_COUNT"
    report "Sudo events: $SUDO_COUNT"

    # Keychain access
    KC_COUNT=$(log show --predicate 'subsystem == "com.apple.securityd"' --last 24h --style compact 2>/dev/null | wc -l | tr -d ' ')
    info "Keychain/security events: $KC_COUNT"
    report "Keychain events: $KC_COUNT"

    # Software installations
    info "Recent software changes:"
    log show --predicate 'process == "installd" OR process == "softwareupdated"' --last 24h --style compact 2>/dev/null | tail -5 | tee -a "$REPORT_FILE"
fi

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo "  Audit Complete"
echo "=============================================="
echo ""
ok "Report saved: $REPORT_FILE"
echo ""
echo "  Quick review:  grep -E 'FAIL|ALERT|WARN' $REPORT_FILE"
echo "  Full report:   cat $REPORT_FILE"
echo ""
