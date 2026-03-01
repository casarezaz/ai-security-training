#!/usr/bin/env bash
# =============================================================================
# Network Bypass Detection & Deep Audit
# Detects network connections that may be bypassing Little Snitch rules.
# Checks for proxy abuse, DNS leaks, and hidden tunnels.
# Usage:
#   ./network_audit.sh              Full network audit
#   ./network_audit.sh --live       Continuous monitoring mode (Ctrl+C to stop)
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ALERT]${NC} $*"; }

PROJECT_DIR="$HOME/aiml-cybersecurity"
REPORT_DIR="$PROJECT_DIR/reports/security"
REPORT_FILE="$REPORT_DIR/network_audit_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$REPORT_DIR"

report() { echo "$*" >> "$REPORT_FILE"; }

echo ""
echo "=============================================="
echo "  Network Bypass Detection & Deep Audit"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo ""

{
    echo "Network Audit — $(date)"
    echo "=============================================="
    echo ""
} > "$REPORT_FILE"

ALERTS=0

# ─────────────────────────────────────────────────────────────────────────────
# 1. ALL ACTIVE CONNECTIONS — The Ground Truth
# ─────────────────────────────────────────────────────────────────────────────
info "=== 1. All Active Outbound Connections ==="
echo ""

report "--- All Outbound Connections ---"

# Get every established outbound connection with process info
# This is what's ACTUALLY happening regardless of what Little Snitch shows
CONNECTIONS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{printf "%-25s %-8s %-8s %s\n", $1, $2, $3, $9}' | sort -u)

if [[ -n "$CONNECTIONS" ]]; then
    echo "    PROCESS                  PID      USER     CONNECTION"
    echo "    ─────────────────────────────────────────────────────────"
    echo "$CONNECTIONS" | while read line; do
        echo "    $line"
        report "$line"
    done
else
    ok "No established connections"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 2. PROXY BYPASS DETECTION
# Apps can route traffic through allowed system processes
# ─────────────────────────────────────────────────────────────────────────────
info "=== 2. Proxy/Tunnel Bypass Detection ==="

report "--- Proxy Bypass Check ---"

# Check if any process is using system processes as network proxies
# mDNSResponder, nsurlsessiond, and trustd are commonly abused
SYSTEM_PROXY_PROCS="nsurlsessiond|com.apple.WebKit|cfnetwork|networkserviceproxy"
PROXY_CONNECTIONS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep -iE "$SYSTEM_PROXY_PROCS" | awk '{print $1 " -> " $9}' | sort -u)

if [[ -n "$PROXY_CONNECTIONS" ]]; then
    warn "System proxy processes with active connections (may be normal, verify):"
    echo "$PROXY_CONNECTIONS" | while read line; do
        warn "  $line"
        report "PROXY: $line"
    done
    echo ""
    info "These system processes can carry traffic for OTHER apps."
    info "If an app is blocked in Little Snitch, it can sometimes route through these."
else
    ok "No system proxy abuse detected"
fi
echo ""

# Check for SOCKS/HTTP proxy listeners
PROXY_LISTEN=$(lsof -i -n -P 2>/dev/null | grep LISTEN | grep -iE ":1080|:3128|:8080|:9050|:9150" | awk '{print $1 " listening on " $9}' | sort -u)
if [[ -n "$PROXY_LISTEN" ]]; then
    err "⚠️  LOCAL PROXY DETECTED — could be used to bypass firewall rules!"
    echo "$PROXY_LISTEN" | while read line; do
        err "  $line"
        report "ALERT: Local proxy: $line"
    done
    ((ALERTS++))
else
    ok "No local proxy listeners (SOCKS/HTTP)"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 3. DNS LEAK DETECTION
# Even with Little Snitch blocking, DNS can leak through system resolver
# ─────────────────────────────────────────────────────────────────────────────
info "=== 3. DNS Configuration & Leak Check ==="

report "--- DNS Check ---"

# Current DNS servers
info "Configured DNS servers:"
DNS_SERVERS=$(scutil --dns 2>/dev/null | grep "nameserver\[" | awk '{print $3}' | sort -u)
if [[ -n "$DNS_SERVERS" ]]; then
    echo "$DNS_SERVERS" | while read dns; do
        # Check if it's a known safe DNS
        case "$dns" in
            1.1.1.2|1.0.0.2|1.1.1.3|1.0.0.3)
                ok "  $dns (Cloudflare malware filter)"
                ;;
            1.1.1.1|1.0.0.1)
                ok "  $dns (Cloudflare)"
                ;;
            8.8.8.8|8.8.4.4)
                info "  $dns (Google DNS)"
                ;;
            9.9.9.9|149.112.112.112)
                ok "  $dns (Quad9 — blocks malware)"
                ;;
            127.0.0.1|::1)
                info "  $dns (localhost — local DNS resolver)"
                ;;
            *)
                warn "  $dns (unknown — verify this is your ISP or intended DNS)"
                report "WARN: Unknown DNS server: $dns"
                ;;
        esac
    done
else
    warn "No DNS servers found — DNS may not be working"
fi
echo ""

# Check for DNS-over-HTTPS/TLS bypasses
# Some apps bundle their own DNS resolver to bypass system DNS
DOH_CONNECTIONS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep ":443" | awk '{print $1}' | sort | uniq -c | sort -rn | head -10)
info "Top processes with HTTPS connections (potential DoH bypass):"
echo "$DOH_CONNECTIONS" | while read count proc; do
    if [[ "$count" -gt 20 ]]; then
        warn "  $proc: $count connections (unusually high — possible DNS tunneling)"
        report "WARN: High HTTPS connections: $proc ($count)"
    else
        info "  $proc: $count connections"
    fi
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 4. HIDDEN TUNNEL DETECTION
# SSH tunnels, VPN connections, or encrypted tunnels
# ─────────────────────────────────────────────────────────────────────────────
info "=== 4. Hidden Tunnel Detection ==="

report "--- Tunnel Detection ---"

# SSH tunnels (port forwarding)
SSH_TUNNELS=$(ps aux 2>/dev/null | awk '$11 ~ /ssh$/ || $11 ~ /\/ssh$/' | grep -E "\-[LRD]" || true)
if [[ -n "$SSH_TUNNELS" ]]; then
    err "⚠️  SSH TUNNEL DETECTED — data may be exfiltrating through SSH!"
    echo "$SSH_TUNNELS" | while read line; do
        err "  $line"
        report "ALERT: SSH tunnel: $line"
    done
    ((ALERTS++))
else
    ok "No SSH tunnels detected"
fi

# VPN processes (unexpected)
VPN_PROCS=$(ps aux 2>/dev/null | awk '$11 ~ /openvpn|wireguard|wg-quick|vpn/ {print $11}' | sort -u)
if [[ -n "$VPN_PROCS" ]]; then
    warn "VPN processes detected (verify these are intentional):"
    echo "$VPN_PROCS" | while read p; do
        warn "  $p"
        report "WARN: VPN process: $p"
    done
else
    ok "No unexpected VPN processes"
fi

# TUN/TAP interfaces (used by VPNs and tunnels)
TUNNEL_IFS=$(ifconfig 2>/dev/null | grep -E "^(utun|tun|tap)" | awk -F: '{print $1}')
if [[ -n "$TUNNEL_IFS" ]]; then
    info "Tunnel interfaces (utun is normal for macOS system VPN):"
    echo "$TUNNEL_IFS" | while read iface; do
        info "  $iface"
        report "Tunnel interface: $iface"
    done
else
    ok "No tunnel interfaces"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 5. HIGH PORT BYPASS CHECK
# Apps blocked on standard ports may try high ports
# ─────────────────────────────────────────────────────────────────────────────
info "=== 5. High Port & Non-Standard Port Connections ==="

report "--- High Port Check ---"

# Connections on non-standard ports (not 80, 443, 53, 22, etc.)
STANDARD_PORTS="80|443|53|22|993|587|465|143|25|8080|8443"
HIGH_PORT_CONNS=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1 " " $9}' | \
    grep -vE ":($STANDARD_PORTS)$" | sort -u)

if [[ -n "$HIGH_PORT_CONNS" ]]; then
    info "Connections on non-standard ports (verify these are expected):"
    echo "$HIGH_PORT_CONNS" | while read proc dest; do
        # Extract port
        port=$(echo "$dest" | awk -F: '{print $NF}')
        if [[ "$port" -gt 49152 ]]; then
            warn "  $proc → $dest (ephemeral port — likely return traffic, but verify)"
        elif [[ "$port" -gt 10000 ]]; then
            warn "  $proc → $dest (high port — unusual)"
        else
            info "  $proc → $dest"
        fi
        report "Non-standard port: $proc → $dest"
    done
else
    ok "No connections on non-standard ports"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 6. PROCESS-TO-CONNECTION MAP
# Full view of which processes are talking to which destinations
# ─────────────────────────────────────────────────────────────────────────────
info "=== 6. Process → Destination Map ==="

report "--- Process Destination Map ---"

# Group connections by process
PROC_MAP=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1}' | sort | uniq -c | sort -rn)
echo ""
echo "    CONNECTIONS  PROCESS"
echo "    ──────────────────────────"
echo "$PROC_MAP" | head -15 | while read count proc; do
    printf "    %-12s %s\n" "$count" "$proc"
    report "  $count connections: $proc"

    # Show destinations for top talkers
    if [[ "$count" -gt 5 ]]; then
        lsof -i -n -P 2>/dev/null | grep ESTABLISHED | grep "^$proc " | awk '{print $9}' | \
            awk -F'>' '{print $2}' | awk -F: '{print $1}' | sort | uniq -c | sort -rn | head -5 | \
            while read dcount dest; do
                printf "    %12s   → %s (%s connections)\n" "" "$dest" "$dcount"
            done
    fi
done
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 7. LITTLE SNITCH VERIFICATION
# Check if Little Snitch is actually running and intercepting
# ─────────────────────────────────────────────────────────────────────────────
info "=== 7. Little Snitch Status Verification ==="

report "--- Little Snitch ---"

# Is Little Snitch running?
LS_RUNNING=$(ps aux 2>/dev/null | awk '$11 ~ /LittleSnitch/ || $11 ~ /at.obdev.littlesnitch/' | wc -l | tr -d ' ')
if [[ "$LS_RUNNING" -gt 0 ]]; then
    ok "Little Snitch is running ($LS_RUNNING processes)"
else
    err "⚠️  LITTLE SNITCH IS NOT RUNNING — no network filtering active!"
    ((ALERTS++))
fi

# Check if the network filter is loaded
LS_FILTER=$(kextstat 2>/dev/null | grep -c "obdev" || true)
LS_FILTER=$(echo "$LS_FILTER" | tr -d '[:space:]')
if [[ "$LS_FILTER" -gt 0 ]]; then
    ok "Little Snitch network extension is loaded"
else
    # Modern macOS uses Network Extension, not kext
    LS_SYSEXT=$(systemextensionsctl list 2>/dev/null | grep -c "obdev" || true)
    LS_SYSEXT=$(echo "$LS_SYSEXT" | tr -d '[:space:]')
    if [[ "$LS_SYSEXT" -gt 0 ]]; then
        ok "Little Snitch system extension is active"
    else
        warn "Could not verify Little Snitch network filter — may use Network Extension"
    fi
fi

# Check Little Snitch operation mode
LS_MODE=$(defaults read at.obdev.LittleSnitchConfiguration OperationMode 2>/dev/null || echo "unknown")
case "$LS_MODE" in
    0) ok "Little Snitch mode: Alert Mode (prompts for new connections)" ;;
    1) ok "Little Snitch mode: Silent Allow — ⚠️ WARNING: allowing all!" ;
       err "Little Snitch is in SILENT ALLOW mode — this bypasses all rules!"
       ((ALERTS++)) ;;
    2) ok "Little Snitch mode: Silent Deny (blocks unapproved connections)" ;;
    *) info "Little Snitch mode: $LS_MODE (could not determine)" ;;
esac
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 8. NETWORK INTERFACE AUDIT
# Check for unexpected network interfaces that could bypass filtering
# ─────────────────────────────────────────────────────────────────────────────
info "=== 8. Network Interface Audit ==="

report "--- Network Interfaces ---"

# List all active network interfaces
ACTIVE_IFS=$(ifconfig 2>/dev/null | grep -E "^[a-z]" | awk -F: '{print $1}' | while read iface; do
    status=$(ifconfig "$iface" 2>/dev/null | grep "status:" | awk '{print $2}')
    inet=$(ifconfig "$iface" 2>/dev/null | grep "inet " | awk '{print $2}')
    if [[ -n "$inet" ]]; then
        echo "$iface: $inet ($status)"
    fi
done)

if [[ -n "$ACTIVE_IFS" ]]; then
    info "Active network interfaces:"
    echo "$ACTIVE_IFS" | while read line; do
        iface_name=$(echo "$line" | awk -F: '{print $1}')
        case "$iface_name" in
            en0|en1) ok "  $line (Wi-Fi/Ethernet — expected)" ;;
            lo0)     ok "  $line (loopback — expected)" ;;
            bridge*) warn "  $line (bridge — verify this is expected)" ;;
            utun*)   info "  $line (system tunnel — usually VPN/iCloud)" ;;
            *)       warn "  $line (unexpected interface — investigate)" ;;
        esac
        report "Interface: $line"
    done
else
    ok "No unexpected active interfaces"
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 9. DATA EXFILTRATION INDICATORS
# Large outbound transfers, unusual patterns
# ─────────────────────────────────────────────────────────────────────────────
info "=== 9. Data Exfiltration Indicators ==="

report "--- Exfiltration Check ---"

# Check network stats for unusual outbound traffic
NETSTATS=$(nettop -x -t wifi -l 1 -J bytes_out 2>/dev/null | tail -n +2 | awk '$NF > 10000000 {print $1 " sent " $NF " bytes"}' | head -10 || true)
if [[ -n "$NETSTATS" ]]; then
    warn "Processes with high outbound traffic (>10MB):"
    echo "$NETSTATS" | while read line; do
        warn "  $line"
        report "HIGH OUTBOUND: $line"
    done
else
    ok "No unusually high outbound traffic detected"
fi

# Check for processes connecting to IP addresses (not domains)
# Legitimate traffic usually goes through DNS first
DIRECT_IP=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1 " " $9}' | \
    grep -v "localhost\|127.0.0.1\|::1\|\*:" | \
    grep -E ">[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+:" | sort -u | head -10)
if [[ -n "$DIRECT_IP" ]]; then
    info "Connections to direct IP addresses (no DNS — verify these):"
    echo "$DIRECT_IP" | while read proc dest; do
        info "  $proc → $dest"
        report "Direct IP: $proc → $dest"
    done
fi
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo "=============================================="
echo "  Network Audit Complete"
echo "=============================================="
echo ""

if [[ $ALERTS -gt 0 ]]; then
    err "$ALERTS critical issue(s) found — investigate immediately"
else
    ok "No critical network bypass issues detected"
fi
echo ""
ok "Full report: $REPORT_FILE"
echo ""
echo "  Tips:"
echo "  • Run periodically to catch intermittent bypasses"
echo "  • Compare reports over time for changes"
echo "  • Use --live mode to watch connections in real-time"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# LIVE MONITORING MODE
# ─────────────────────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--live" ]]; then
    echo ""
    info "Live monitoring mode — watching for new connections (Ctrl+C to stop)"
    info "Any new connection will be shown below:"
    echo ""

    # Capture initial state
    INITIAL=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1 ":" $9}' | sort -u)

    while true; do
        sleep 5
        CURRENT=$(lsof -i -n -P 2>/dev/null | grep ESTABLISHED | awk '{print $1 ":" $9}' | sort -u)

        # Find new connections
        NEW=$(comm -13 <(echo "$INITIAL") <(echo "$CURRENT"))
        if [[ -n "$NEW" ]]; then
            echo -e "${RED}[$(date '+%H:%M:%S')] NEW CONNECTION:${NC}"
            echo "$NEW" | while read conn; do
                echo -e "  ${RED}→ $conn${NC}"
            done
        fi

        # Find closed connections
        CLOSED=$(comm -23 <(echo "$INITIAL") <(echo "$CURRENT"))
        if [[ -n "$CLOSED" ]]; then
            echo -e "${GREEN}[$(date '+%H:%M:%S')] CLOSED:${NC}"
            echo "$CLOSED" | while read conn; do
                echo -e "  ${GREEN}← $conn${NC}"
            done
        fi

        INITIAL="$CURRENT"
    done
fi
