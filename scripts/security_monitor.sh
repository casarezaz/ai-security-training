#!/usr/bin/env bash
# =============================================================================
# Daily Security Monitor
# Automated daily security scan — run manually or via launchd.
# Usage:
#   ./security_monitor.sh            Full scan with output
#   ./security_monitor.sh --quiet    Only output alerts (for launchd)
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'

QUIET="false"
[[ "${1:-}" == "--quiet" ]] && QUIET="true"

log()   { echo -e "$*"; }
info()  { [[ "$QUIET" != "true" ]] && log "${BLUE}[INFO]${NC}  $*"; }
ok()    { [[ "$QUIET" != "true" ]] && log "${GREEN}[ OK ]${NC}  $*"; }
warn()  { log "${YELLOW}[WARN]${NC}  $*"; }
err()   { log "${RED}[ALERT]${NC} $*"; }

PROJECT_DIR="$HOME/aiml-cybersecurity"
REPORT_DIR="$PROJECT_DIR/reports/security"
REPORT_FILE="$REPORT_DIR/daily_scan_$(date +%Y%m%d).txt"
SCRIPTS_DIR="$PROJECT_DIR/scripts"
TRUSTED_PORTS="$PROJECT_DIR/configs/hardening/trusted_ports.txt"
TRUSTED_PROCS="$PROJECT_DIR/configs/hardening/trusted_processes.txt"

ALERTS=0
CHECKS=0
PASSED=0
ALERT_MESSAGES=()

# macOS native notification
notify() {
    local title="$1"
    local message="$2"
    osascript -e "display notification \"$message\" with title \"$title\"" 2>/dev/null || true
}

# Email alert via iCloud (password stored in Keychain)
EMAIL_TO="angie.agee@icloud.com"
EMAIL_FROM="angie.agee@icloud.com"

send_email_alert() {
    local subject="$1"
    local body="$2"

    # Retrieve app password from Keychain
    local app_pw
    app_pw=$(security find-generic-password -a "$EMAIL_FROM" -s "aiml-security-alerts" -w 2>/dev/null)

    if [[ -z "$app_pw" ]]; then
        warn "Could not retrieve email password from Keychain — skipping email alert"
        return 1
    fi

    # Send via iCloud SMTP (port 587 with STARTTLS)
    local email_result
    email_result=$(curl --silent --show-error \
        --url "smtp://smtp.mail.me.com:587" \
        --ssl-reqd \
        --user "${EMAIL_FROM}:${app_pw}" \
        --mail-from "$EMAIL_FROM" \
        --mail-rcpt "$EMAIL_TO" \
        --upload-file - 2>&1 <<EOF
From: Security Monitor <${EMAIL_FROM}>
To: ${EMAIL_TO}
Subject: ${subject}
Date: $(date -R 2>/dev/null || date)
Content-Type: text/plain; charset=UTF-8

${body}

---
Report: ${REPORT_FILE}
Host: $(hostname)
Time: $(date '+%Y-%m-%d %H:%M:%S')
EOF
)
    local email_exit=$?

    if [[ $email_exit -eq 0 ]]; then
        info "Email alert sent to $EMAIL_TO"
    else
        warn "Failed to send email alert: $email_result"
    fi
}

mkdir -p "$REPORT_DIR"

report() { echo "$*" >> "$REPORT_FILE"; }
alert()  { ((ALERTS++)); err "$*"; report "ALERT: $*"; ALERT_MESSAGES+=("$*"); }
check_pass() { ((PASSED++)); ok "$*"; report "OK: $*"; }

# Initialize report
{
    echo "=============================================="
    echo "Daily Security Scan — $(date '+%Y-%m-%d %H:%M:%S')"
    echo "Host: $(hostname)"
    echo "macOS: $(sw_vers -productVersion) ($(uname -m))"
    echo "=============================================="
    echo ""
} > "$REPORT_FILE"

[[ "$QUIET" != "true" ]] && {
    echo ""
    echo "=============================================="
    echo "  Daily Security Monitor"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=============================================="
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# 1. OPEN PORTS & LISTENING SERVICES
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 1: Open Ports & Listening Services ==="
((CHECKS++))

LISTENING=$(lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{print $1 ":" $9}' | sort -u)
report "--- Listening Services ---"

if [[ -f "$TRUSTED_PORTS" ]]; then
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        proc_port=$(echo "$line" | awk -F: '{print $1 ":" $NF}')
        if ! grep -qF "$proc_port" "$TRUSTED_PORTS" 2>/dev/null; then
            alert "Unexpected listener: $line"
        fi
    done <<< "$LISTENING"
    [[ $ALERTS -eq 0 ]] && check_pass "All listening ports match trusted baseline"
else
    info "No trusted ports baseline — listing current listeners:"
    echo "$LISTENING" | while read line; do
        info "  $line"
        report "  $line"
    done
    check_pass "Port scan completed (create baseline with system_audit.sh --save-baseline)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 2. SUSPICIOUS PROCESS DETECTION
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 2: Process Audit ==="
((CHECKS++))

report "--- Process Audit ---"

# CRITICAL: Detect unauthorized nmap activity
# Nmap should ONLY run when you explicitly launch it for red team work.
# Any other nmap process is a potential indicator of compromise.
# Use awk to match the actual command (field 11) not the full argument string
NMAP_PROCS=$(ps aux 2>/dev/null | awk '$11 ~ /\/nmap$/ || $11 == "nmap" {print}')
if [[ -n "$NMAP_PROCS" ]]; then
    alert "⚠️  NMAP DETECTED — unauthorized network scanning in progress!"
    alert "If you did NOT start this, assume compromise. Investigate immediately."
    echo "$NMAP_PROCS" | while read p; do alert "  $p"; done
    report "CRITICAL: Nmap process detected"
else
    check_pass "No unauthorized nmap activity"
fi

# Detect other recon/attack tools that shouldn't be running
# Match on command name (field 11) only to avoid false positives from arguments
# Excludes legitimate macOS processes like mDNSResponder
RECON_TOOLS="masscan|zmap|mimikatz|metasploit|msfconsole|msfvenom|cobalt|empire|crackmapexec|evil-winrm|hashcat|john|hydra|sqlmap"
RECON_PROCS=$(ps aux 2>/dev/null | awk -v tools="$RECON_TOOLS" '$11 ~ tools {print}' | grep -v "mDNSResponder")
if [[ -n "$RECON_PROCS" ]]; then
    alert "⚠️  OFFENSIVE TOOL DETECTED — possible compromise!"
    echo "$RECON_PROCS" | while read p; do alert "  $p"; done
    report "CRITICAL: Offensive tool process detected"
else
    check_pass "No unauthorized offensive tools running"
fi

# Processes running from /tmp or /var/tmp (suspicious)
TMP_PROCS=$(ps aux 2>/dev/null | awk '$11 ~ /^\/(tmp|var\/tmp)/ {print $11}' | sort -u)
if [[ -n "$TMP_PROCS" ]]; then
    alert "Processes running from temporary directories:"
    echo "$TMP_PROCS" | while read p; do alert "  $p"; done
else
    check_pass "No processes running from /tmp"
fi

# Processes with deleted binaries
DELETED_PROCS=$(ls -la /proc/*/exe 2>/dev/null | grep deleted | awk '{print $NF}' || true)
if [[ -n "$DELETED_PROCS" ]]; then
    alert "Processes with deleted binaries found"
fi

# Check for unsigned code (sample of running processes)
UNSIGNED=0
for pid in $(ps -eo pid= 2>/dev/null | head -30); do
    binary=$(ps -p "$pid" -o comm= 2>/dev/null || continue)
    path=$(which "$binary" 2>/dev/null || continue)
    if [[ -n "$path" ]] && ! codesign -v "$path" 2>/dev/null; then
        ((UNSIGNED++))
    fi
done
if [[ $UNSIGNED -gt 5 ]]; then
    warn "Found $UNSIGNED unsigned processes (some may be expected for dev tools)"
    report "WARN: $UNSIGNED unsigned processes detected"
else
    check_pass "Process signature check OK"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 2b. SHARING & REMOTE ACCESS SERVICES
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 2b: Sharing & Remote Access Services ==="
((CHECKS++))

report "--- Sharing Services ---"

# AirPlay Receiver (someone casting TO your Mac)
AIRPLAY_RX=$(launchctl list 2>/dev/null | grep -c "com.apple.AirPlayXPCHelper" || true)
AIRPLAY_RX=$(echo "$AIRPLAY_RX" | tr -d '[:space:]')
if [[ "$AIRPLAY_RX" -gt 0 ]]; then
    # Check if AirPlay Receiver is actually enabled in settings
    AIRPLAY_ENABLED=$(defaults read com.apple.controlcenter "NSStatusItem Visible AirplayReceiver" 2>/dev/null || echo "unknown")
    if [[ "$AIRPLAY_ENABLED" == "1" ]]; then
        alert "AirPlay Receiver is ENABLED — others can cast to your Mac"
        report "ALERT: AirPlay Receiver enabled"
    else
        check_pass "AirPlay Receiver service loaded but not actively receiving"
    fi
else
    check_pass "AirPlay Receiver not active"
fi

# Screen Mirroring / AirPlay sending (your screen going OUT to TV, AppleTV, etc.)
# AirPlayUIAgent runs as an idle background process on macOS — only alert
# if there's an actual active connection (ESTABLISHED on AirPlay ports 7000, 7100, 49152-65535)
# Also check for AirPlay sender daemon connections
MIRROR_ACTIVE=$(lsof -i -n -P 2>/dev/null | grep -iE "airplay|AirPlayXPC" | grep "ESTABLISHED" || true)
AIRPLAY_OUT=$(lsof -i -n -P 2>/dev/null | grep -E ":(7000|7100|47000)" | grep "ESTABLISHED" | grep -v "LISTEN" || true)
if [[ -n "$MIRROR_ACTIVE" ]] || [[ -n "$AIRPLAY_OUT" ]]; then
    alert "AirPlay/Screen Mirroring ACTIVE — your screen is being sent to another device!"
    [[ -n "$MIRROR_ACTIVE" ]] && echo "$MIRROR_ACTIVE" | while read p; do alert "  $p"; done
    [[ -n "$AIRPLAY_OUT" ]] && echo "$AIRPLAY_OUT" | while read p; do alert "  $p"; done
    report "ALERT: AirPlay sending active"
else
    check_pass "No active AirPlay/screen mirroring connections"
fi

# Screen Sharing (VNC/ARD)
# Check if the service is actually accepting connections, not just loaded
SCREEN_SHARE_LISTEN=$(lsof -i -n -P 2>/dev/null | grep -i "screensharingd\|vnc" | grep "LISTEN" || true)
if [[ -n "$SCREEN_SHARE_LISTEN" ]]; then
    alert "Screen Sharing (VNC) is LISTENING for connections — remote access possible"
    report "ALERT: Screen Sharing listening"
else
    check_pass "Screen Sharing not listening"
fi

# Remote Management (Apple Remote Desktop)
# Check for actual ARDAgent process actively running, not just launchctl entry
ARD_ACTIVE=$(ps aux 2>/dev/null | awk '$11 ~ /ARDAgent/ {print}')
if [[ -n "$ARD_ACTIVE" ]]; then
    alert "Apple Remote Desktop agent is actively RUNNING"
    report "ALERT: ARD agent running"
else
    check_pass "Remote Desktop not active"
fi

# Remote Login (SSH server)
SSHD_RUNNING=$(launchctl list 2>/dev/null | grep -c "com.openssh.sshd" || true)
SSHD_RUNNING=$(echo "$SSHD_RUNNING" | tr -d '[:space:]')
if [[ "$SSHD_RUNNING" -gt 0 ]]; then
    alert "SSH server (Remote Login) is ENABLED — remote access possible"
    report "ALERT: SSH server running"
else
    check_pass "SSH server not running"
fi

# Internet Sharing (turns Mac into router/hotspot)
NATD=$(ps aux 2>/dev/null | awk '$11 ~ /natd|InternetSharing/ {print $11}' | sort -u)
if [[ -n "$NATD" ]]; then
    alert "Internet Sharing is ACTIVE — your Mac is acting as a router!"
    report "ALERT: Internet Sharing active"
else
    check_pass "Internet Sharing not active"
fi

# Printer Sharing
CUPS_SHARE=$(cupsctl 2>/dev/null | grep -c "_share_printers=1" || true)
CUPS_SHARE=$(echo "$CUPS_SHARE" | tr -d '[:space:]')
if [[ "$CUPS_SHARE" -gt 0 ]]; then
    warn "Printer Sharing is enabled"
    report "WARN: Printer sharing enabled"
else
    check_pass "Printer Sharing disabled"
fi

# Bluetooth PAN
BT_PAN=$(ps aux 2>/dev/null | awk '$11 ~ /BluetoothSharing|BTPan/ {print $11}' | sort -u)
if [[ -n "$BT_PAN" ]]; then
    warn "Bluetooth PAN/sharing process detected"
    report "WARN: Bluetooth PAN active"
else
    check_pass "Bluetooth PAN not active"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 2c. MALICIOUS SERVICE & PERSISTENCE DETECTION
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 2c: Malicious Service Detection ==="
((CHECKS++))

report "--- Malicious Service Detection ---"

# Reverse shell indicators — outbound connections on common backdoor ports
BACKDOOR_PORTS="4444|1337|31337|5555|6666|9999|8888|1234|4443|4445"
REVERSE_SHELLS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1 ":" $9}' | grep -E ":($BACKDOOR_PORTS)$" | sort -u)
if [[ -n "$REVERSE_SHELLS" ]]; then
    alert "⚠️  POSSIBLE REVERSE SHELL — connections on known backdoor ports!"
    echo "$REVERSE_SHELLS" | while read p; do alert "  $p"; done
    report "CRITICAL: Possible reverse shell connections"
else
    check_pass "No connections on known backdoor ports"
fi

# Crypto miner detection — high CPU from unexpected processes
HIGH_CPU=$(ps aux 2>/dev/null | awk 'NR>1 && $3 > 80.0 {print $11 " (CPU: " $3 "%)"}' | grep -v -E "WindowServer|kernel_task|mdworker|mds_stores|Finder|Safari|Chrome|firefox|Docker|python|node|duetexpertd|suggestd|photoanalysisd|mediaanalysisd|siriknowledged|triald|intelligenceplatformd|coreduetd|backupd|softwareupdated|trustd|nsurlsessiond" | head -5)
if [[ -n "$HIGH_CPU" ]]; then
    alert "⚠️  HIGH CPU — possible crypto miner or malicious process!"
    echo "$HIGH_CPU" | while read p; do alert "  $p"; done
    report "ALERT: High CPU suspicious process"
else
    check_pass "No suspicious high-CPU processes"
fi

# Keylogger / input monitoring detection
# Check for processes with accessibility/input monitoring access
INPUT_PROCS=$(sqlite3 "/Library/Application Support/com.apple.TCC/TCC.db" \
    "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND allowed=1;" 2>/dev/null | \
    grep -v -E "com.apple|com.docker|com.obdev.littlesnitch|com.google" || true)
if [[ -n "$INPUT_PROCS" ]]; then
    warn "Non-standard apps with accessibility/input access:"
    echo "$INPUT_PROCS" | while read p; do
        warn "  $p"
        report "WARN: Accessibility access: $p"
    done
else
    check_pass "No unexpected accessibility access grants"
fi

# New cron jobs (persistence mechanism)
CRON_JOBS=$(crontab -l 2>/dev/null | grep -v "^#" | grep -v "^$")
if [[ -n "$CRON_JOBS" ]]; then
    warn "Active cron jobs found (verify these are yours):"
    echo "$CRON_JOBS" | while read j; do
        warn "  $j"
        report "WARN: Cron job: $j"
    done
else
    check_pass "No user cron jobs"
fi

# Suspicious network binaries — processes binding to ports that shouldn't
BIND_PROCS=$(lsof -i -n -P 2>/dev/null | grep LISTEN | awk '{print $1}' | sort -u | \
    grep -v -E "rapportd|Google|Docker|com\.apple|mDNSResponder|Nessus|socketfilterfw|cupsd|launchd|node|Python|java" || true)
if [[ -n "$BIND_PROCS" ]]; then
    warn "Unexpected processes binding to network ports:"
    echo "$BIND_PROCS" | while read p; do
        warn "  Listener: $p"
        report "WARN: Unexpected listener process: $p"
    done
else
    check_pass "No unexpected network-binding processes"
fi

# Detect processes spawned by unexpected parents (orphaned/injected)
ORPHAN_PROCS=$(ps -eo ppid,pid,comm 2>/dev/null | awk '$1 == 1 {print $3}' | \
    grep -v -E "launchd|kernel|WindowServer|loginwindow|Finder|Dock|SystemUI|Spotlight|AirPort|coreautha|cfprefsd|distnoted|trustd|secd" | \
    sort -u | head -10)
# This is informational — many legitimate processes have ppid 1
report "Processes with launchd as parent (informational): $(echo "$ORPHAN_PROCS" | wc -l | tr -d ' ')"

# Check for suspicious LaunchAgent/LaunchDaemon names
SUSPICIOUS_AGENTS=""
for dir in ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons; do
    if [[ -d "$dir" ]]; then
        while IFS= read -r -d '' plist; do
            name=$(basename "$plist")
            # Flag agents that don't match common vendor patterns
            if ! echo "$name" | grep -qE "^(com\.apple\.|com\.google\.|com\.docker\.|at\.obdev\.|com\.aiml-)"; then
                SUSPICIOUS_AGENTS+="  $plist\n"
            fi
        done < <(find "$dir" -name "*.plist" -maxdepth 1 -print0 2>/dev/null)
    fi
done
if [[ -n "$SUSPICIOUS_AGENTS" ]]; then
    warn "Non-standard launch agents/daemons (verify these are legitimate):"
    echo -e "$SUSPICIOUS_AGENTS" | while read p; do
        [[ -n "$p" ]] && warn "$p"
    done
    report "WARN: Non-standard launch agents found"
else
    check_pass "All launch agents match known vendors"
fi

# Check for hidden files in common persistence locations
HIDDEN_PERSIST=$(find /tmp /var/tmp "$HOME/Library/LaunchAgents" -name ".*" -not -name ".DS_Store" -not -name ".localized" 2>/dev/null | head -5)
if [[ -n "$HIDDEN_PERSIST" ]]; then
    warn "Hidden files in persistence/temp locations:"
    echo "$HIDDEN_PERSIST" | while read f; do
        warn "  $f"
        report "WARN: Hidden file: $f"
    done
else
    check_pass "No suspicious hidden files in temp/persistence locations"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 3. FILE INTEGRITY
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 3: File Integrity ==="
((CHECKS++))

report "--- File Integrity ---"

if [[ -f "$SCRIPTS_DIR/file_integrity.sh" ]]; then
    FIM_OUTPUT=$("$SCRIPTS_DIR/file_integrity.sh" --quiet 2>&1)
    FIM_EXIT=$?
    if [[ $FIM_EXIT -ne 0 ]]; then
        alert "File integrity check FAILED — files have changed"
        report "$FIM_OUTPUT"
        echo "$FIM_OUTPUT"
    else
        check_pass "File integrity check passed"
    fi
else
    warn "file_integrity.sh not found — skipping"
    report "WARN: file_integrity.sh missing"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 4. DOCKER SECURITY AUDIT
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 4: Docker Security ==="
((CHECKS++))

report "--- Docker Security ---"

if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    # Check for privileged containers
    PRIV=$(docker ps --format '{{.Names}}' 2>/dev/null | while read c; do
        docker inspect --format='{{.HostConfig.Privileged}}' "$c" 2>/dev/null | grep -q "true" && echo "$c"
    done)
    if [[ -n "$PRIV" ]]; then
        alert "Privileged containers found: $PRIV"
    else
        check_pass "No privileged containers running"
    fi

    # Check container count
    RUNNING=$(docker ps -q 2>/dev/null | wc -l | tr -d ' ')
    info "Running containers: $RUNNING"
    report "Running containers: $RUNNING"

    # Run docker_audit.sh if available
    if [[ -x "$SCRIPTS_DIR/docker_audit.sh" ]]; then
        AUDIT_OUT=$("$SCRIPTS_DIR/docker_audit.sh" 2>&1 | tail -5)
        report "Docker audit: $AUDIT_OUT"
    fi
else
    info "Docker not running — skipping container checks"
    report "Docker not running"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 5. DEPENDENCY VULNERABILITIES
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 5: Dependency Vulnerabilities ==="
((CHECKS++))

report "--- Dependency Scan ---"

# Use pip-audit directly with JSON output for reliable parsing
if command -v pip-audit &>/dev/null; then
    VULN_COUNT=$(pip-audit --format json 2>/dev/null | python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    vulns = [v for v in data if v.get('fix_versions')]
    print(len(vulns))
except:
    print(0)
" 2>/dev/null || echo "0")
    VULN_COUNT=$(echo "$VULN_COUNT" | tr -d '[:space:]')
    VULN_COUNT="${VULN_COUNT:-0}"

    if [[ "$VULN_COUNT" -gt 0 ]]; then
        alert "$VULN_COUNT dependency vulnerabilities with available fixes found"
        report "Dependency vulnerabilities: $VULN_COUNT"
    else
        check_pass "No dependency vulnerabilities with available fixes"
    fi
else
    info "pip-audit not available — skipping dependency scan"
    report "Dependency scan skipped (pip-audit not installed)"
    check_pass "Dependency scan skipped"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 6. LOGIN ITEMS & LAUNCH AGENTS
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 6: Login Items Audit ==="
((CHECKS++))

report "--- Login Items ---"

# Count current launch agents
USER_AGENTS=$(ls ~/Library/LaunchAgents/*.plist 2>/dev/null | wc -l | tr -d ' ')
SYS_AGENTS=$(ls /Library/LaunchAgents/*.plist 2>/dev/null | wc -l | tr -d ' ')
SYS_DAEMONS=$(ls /Library/LaunchDaemons/*.plist 2>/dev/null | wc -l | tr -d ' ')

info "User agents: $USER_AGENTS | System agents: $SYS_AGENTS | System daemons: $SYS_DAEMONS"
report "User agents: $USER_AGENTS | System agents: $SYS_AGENTS | System daemons: $SYS_DAEMONS"

# Check for new user agents (compare against baseline if available)
AGENT_BASELINE="$PROJECT_DIR/configs/hardening/launch_agents_baseline.txt"
if [[ -f "$AGENT_BASELINE" ]]; then
    ls ~/Library/LaunchAgents/*.plist 2>/dev/null | while read agent; do
        if ! grep -qF "$agent" "$AGENT_BASELINE"; then
            alert "NEW launch agent: $agent"
        fi
    done
fi
check_pass "Login items audit completed"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 7. FIREWALL STATUS
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 7: Firewall Status ==="
((CHECKS++))

report "--- Firewall ---"

FW_PATH="/usr/libexec/ApplicationFirewall/socketfilterfw"
FW_STATE=$($FW_PATH --getglobalstate 2>/dev/null || echo "unknown")
if echo "$FW_STATE" | grep -q "enabled"; then
    check_pass "macOS firewall is enabled"
else
    alert "macOS firewall is DISABLED"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 8. NETWORK CONNECTIONS
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 8: Network Connections ==="
((CHECKS++))

report "--- Network Connections ---"

# Count established connections
ESTABLISHED=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | wc -l | tr -d ' ')
info "Established connections: $ESTABLISHED"
report "Established connections: $ESTABLISHED"

# Check for connections to unusual ports
UNUSUAL_PORTS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $9}' | \
    grep -vE ':(443|80|22|53|993|587|465|8080|8443|5432|3306|6379)$' | sort -u)
if [[ -n "$UNUSUAL_PORTS" ]]; then
    warn "Connections on non-standard ports:"
    echo "$UNUSUAL_PORTS" | head -10 | while read p; do
        warn "  $p"
        report "UNUSUAL PORT: $p"
    done
else
    check_pass "No connections on unusual ports"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 9. FAILED LOGIN ATTEMPTS
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 9: Failed Login Attempts ==="
((CHECKS++))

report "--- Login Attempts ---"

FAILED_LOGINS=$(log show --predicate 'process == "loginwindow" AND eventMessage CONTAINS "authentication"' \
    --last 24h --style compact 2>/dev/null | grep -ci "fail" || true)
FAILED_LOGINS="${FAILED_LOGINS:-0}"
FAILED_LOGINS=$(echo "$FAILED_LOGINS" | tr -d '[:space:]')

if [[ "$FAILED_LOGINS" -gt 5 ]]; then
    alert "$FAILED_LOGINS failed login attempts in the last 24 hours"
elif [[ "$FAILED_LOGINS" -gt 0 ]]; then
    warn "$FAILED_LOGINS failed login attempt(s) in the last 24 hours"
    report "WARN: $FAILED_LOGINS failed logins"
else
    check_pass "No failed login attempts in last 24 hours"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 10. DOCKER IMAGE SCAN (if Trivy available)
# ─────────────────────────────────────────────────────────────────────────────
info "=== Check 10: Container Image Vulnerabilities ==="
((CHECKS++))

report "--- Image Scan ---"

if command -v trivy &>/dev/null && command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -v "<none>" | head -5)
    if [[ -n "$IMAGES" ]]; then
        while IFS= read -r img; do
            CRIT=$(trivy image --severity CRITICAL --quiet "$img" 2>/dev/null | grep -c "CRITICAL" || true)
            CRIT="${CRIT:-0}"
            CRIT=$(echo "$CRIT" | tr -d '[:space:]')
            if [[ "$CRIT" -gt 0 ]]; then
                alert "Image $img has $CRIT CRITICAL vulnerabilities"
            else
                check_pass "Image $img — no critical vulnerabilities"
            fi
        done <<< "$IMAGES"
    else
        info "No Docker images to scan"
    fi
else
    info "Trivy or Docker not available — skipping image scan"
    info "Install Trivy: brew install trivy"
    report "Image scan skipped (trivy not installed)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
{
    echo ""
    echo "=============================================="
    echo "  Summary: $CHECKS checks | $PASSED passed | $ALERTS alerts"
    echo "=============================================="
} | tee -a "$REPORT_FILE"

echo ""
if [[ $ALERTS -gt 0 ]]; then
    err "$ALERTS alert(s) require attention — review: $REPORT_FILE"

    # Send macOS notification
    SUMMARY="${ALERT_MESSAGES[0]}"
    if [[ $ALERTS -gt 1 ]]; then
        SUMMARY="$SUMMARY (+$((ALERTS - 1)) more)"
    fi
    notify "🔴 Security Alert — $ALERTS issue(s)" "$SUMMARY"

    # Send email for critical alerts
    EMAIL_BODY="Security Monitor detected $ALERTS alert(s):\n\n"
    for msg in "${ALERT_MESSAGES[@]}"; do
        EMAIL_BODY+="  • $msg\n"
    done
    EMAIL_BODY+="\nReview full report at: $REPORT_FILE"
    send_email_alert "[ALERT] Security Monitor — $ALERTS issue(s) on $(hostname)" "$(echo -e "$EMAIL_BODY")"

    exit 1
else
    ok "All checks passed — system looks good"
    notify "✅ Daily Security Scan" "All $CHECKS checks passed — no issues found"
fi

ok "Full report: $REPORT_FILE"
echo ""
