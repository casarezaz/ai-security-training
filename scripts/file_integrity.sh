#!/usr/bin/env bash
# =============================================================================
# File Integrity Monitoring (FIM)
# Creates SHA256 baselines of critical files and detects changes.
# Usage:
#   ./file_integrity.sh --baseline    Create/update baseline
#   ./file_integrity.sh --check       Check files against baseline
#   ./file_integrity.sh --quiet       Check mode, only output alerts (for cron)
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { [[ "$QUIET" != "true" ]] && echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { [[ "$QUIET" != "true" ]] && echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ALERT]${NC} $*"; }

PROJECT_DIR="$HOME/aiml-cybersecurity"
REPORT_DIR="$PROJECT_DIR/reports/security"
BASELINE_FILE="$REPORT_DIR/file_integrity_baseline.txt"
ALERT_FILE="$REPORT_DIR/fim_alerts_$(date +%Y%m%d_%H%M%S).txt"
QUIET="false"

mkdir -p "$REPORT_DIR"

# Files to monitor — add or remove paths as needed
MONITORED_FILES=(
    # System files
    "/etc/hosts"
    "/etc/shells"
    "/etc/ssh/sshd_config"
    "/etc/pam.d/sudo"
    # SSH
    "$HOME/.ssh/config"
    "$HOME/.ssh/authorized_keys"
    "$HOME/.ssh/id_ed25519.pub"
    # Shell config
    "$HOME/.zshrc"
    "$HOME/.zprofile"
    "$HOME/.bash_profile"
    # Docker
    "$HOME/.docker/daemon.json"
    # Project security config
    "$PROJECT_DIR/.pre-commit-config.yaml"
    "$PROJECT_DIR/.gitignore"
    "$PROJECT_DIR/.gitattributes"
    "$PROJECT_DIR/.env.template"
    "$PROJECT_DIR/.secrets.baseline"
    "$PROJECT_DIR/pyproject.toml"
    "$PROJECT_DIR/docker/Dockerfile.sectools"
    "$PROJECT_DIR/docker/docker-compose.yml"
)

# Directories to monitor (all .plist files within)
MONITORED_DIRS=(
    "$HOME/Library/LaunchAgents"
    "/Library/LaunchAgents"
    "/Library/LaunchDaemons"
)

compute_hash() {
    local file="$1"
    if [[ -f "$file" ]]; then
        shasum -a 256 "$file" 2>/dev/null | awk '{print $1}'
    else
        echo "MISSING"
    fi
}

create_baseline() {
    echo ""
    echo "=============================================="
    echo "  File Integrity Monitoring — Create Baseline"
    echo "  $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=============================================="
    echo ""

    local count=0
    local temp_baseline=$(mktemp)

    # Individual files
    for file in "${MONITORED_FILES[@]}"; do
        if [[ -f "$file" ]]; then
            hash=$(compute_hash "$file")
            echo "$hash  $file" >> "$temp_baseline"
            ok "Baselined: $file"
            ((count++))
        else
            info "Skipped (not found): $file"
        fi
    done

    # Plist files in monitored directories
    for dir in "${MONITORED_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' plist; do
                hash=$(compute_hash "$plist")
                echo "$hash  $plist" >> "$temp_baseline"
                ok "Baselined: $plist"
                ((count++))
            done < <(find "$dir" -name "*.plist" -maxdepth 1 -print0 2>/dev/null)
        fi
    done

    # Store baseline with restricted permissions
    mv "$temp_baseline" "$BASELINE_FILE"
    chmod 600 "$BASELINE_FILE"

    echo ""
    ok "Baseline created: $BASELINE_FILE ($count files)"
    echo ""
}

check_integrity() {
    if [[ ! -f "$BASELINE_FILE" ]]; then
        err "No baseline found! Run with --baseline first."
        exit 1
    fi

    [[ "$QUIET" != "true" ]] && {
        echo ""
        echo "=============================================="
        echo "  File Integrity Check"
        echo "  $(date '+%Y-%m-%d %H:%M:%S')"
        echo "=============================================="
        echo ""
    }

    local alerts=0
    local ok_count=0
    local missing=0
    local alert_lines=()

    # Check each baselined file
    while IFS='  ' read -r expected_hash filepath; do
        [[ -z "$filepath" ]] && continue

        if [[ ! -f "$filepath" ]]; then
            err "DELETED: $filepath"
            alert_lines+=("DELETED: $filepath (was: ${expected_hash:0:16}...)")
            ((missing++))
            ((alerts++))
            continue
        fi

        current_hash=$(compute_hash "$filepath")
        if [[ "$current_hash" == "$expected_hash" ]]; then
            ok "Unchanged: $filepath"
            ((ok_count++))
        else
            err "MODIFIED: $filepath"
            echo "    Expected: ${expected_hash:0:16}..."
            echo "    Current:  ${current_hash:0:16}..."
            alert_lines+=("MODIFIED: $filepath (expected: ${expected_hash:0:16}..., got: ${current_hash:0:16}...)")
            ((alerts++))
        fi
    done < "$BASELINE_FILE"

    # Check for NEW files in monitored directories
    for dir in "${MONITORED_DIRS[@]}"; do
        if [[ -d "$dir" ]]; then
            while IFS= read -r -d '' plist; do
                if ! grep -q "$plist" "$BASELINE_FILE" 2>/dev/null; then
                    warn "NEW FILE: $plist (not in baseline)"
                    alert_lines+=("NEW FILE: $plist")
                    ((alerts++))
                fi
            done < <(find "$dir" -name "*.plist" -maxdepth 1 -print0 2>/dev/null)
        fi
    done

    # Summary
    echo ""
    if [[ $alerts -gt 0 ]]; then
        err "INTEGRITY ALERT: $alerts issue(s) detected ($ok_count files OK, $missing missing)"

        # Write alert file
        {
            echo "File Integrity Alert — $(date)"
            echo "========================="
            echo ""
            for line in "${alert_lines[@]}"; do
                echo "  $line"
            done
        } > "$ALERT_FILE"
        chmod 600 "$ALERT_FILE"
        echo ""
        warn "Alert details saved: $ALERT_FILE"
        return 1
    else
        ok "All $ok_count files match baseline — no changes detected"
        return 0
    fi
    echo ""
}

# ─────────────────────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
    --baseline)
        create_baseline
        ;;
    --check)
        check_integrity
        ;;
    --quiet)
        QUIET="true"
        check_integrity
        ;;
    *)
        echo "Usage: $0 {--baseline|--check|--quiet}"
        echo ""
        echo "  --baseline   Create/update file integrity baseline"
        echo "  --check      Compare current files against baseline"
        echo "  --quiet      Check mode, only output alerts (for scheduled scans)"
        exit 1
        ;;
esac
