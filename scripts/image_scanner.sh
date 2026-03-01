#!/usr/bin/env bash
# =============================================================================
# Docker Image Vulnerability Scanner
# Scans Docker images using Trivy for known vulnerabilities.
# Usage:
#   ./image_scanner.sh                Scan all project images
#   ./image_scanner.sh <image:tag>    Scan specific image
#   ./image_scanner.sh --install      Install Trivy via Homebrew
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[FAIL]${NC}  $*"; }

PROJECT_DIR="$HOME/aiml-cybersecurity"
REPORT_DIR="$PROJECT_DIR/reports/security"
REPORT_FILE="$REPORT_DIR/image_scan_$(date +%Y%m%d_%H%M%S).txt"

mkdir -p "$REPORT_DIR"

# Install mode
if [[ "${1:-}" == "--install" ]]; then
    info "Installing Trivy..."
    if command -v brew &>/dev/null; then
        brew install trivy
        ok "Trivy installed: $(trivy --version)"
    else
        err "Homebrew not found. Install Homebrew first."
        exit 1
    fi
    exit 0
fi

# Check prerequisites
if ! command -v trivy &>/dev/null; then
    err "Trivy not installed. Run: ./image_scanner.sh --install"
    exit 1
fi

if ! command -v docker &>/dev/null || ! docker info &>/dev/null 2>&1; then
    err "Docker is not running. Start Docker Desktop first."
    exit 1
fi

echo ""
echo "=============================================="
echo "  Docker Image Vulnerability Scanner"
echo "  $(date '+%Y-%m-%d %H:%M:%S')"
echo "=============================================="
echo ""

{
    echo "Image Vulnerability Scan — $(date)"
    echo "Trivy version: $(trivy --version 2>/dev/null | head -1)"
    echo ""
} > "$REPORT_FILE"

TOTAL_CRIT=0
TOTAL_HIGH=0
IMAGES_SCANNED=0

scan_image() {
    local image="$1"
    info "Scanning: $image"

    # Run Trivy scan
    local output
    output=$(trivy image --severity HIGH,CRITICAL --format table "$image" 2>&1)
    local exit_code=$?

    # Count vulnerabilities
    local crit=$(echo "$output" | grep -c "CRITICAL" || echo "0")
    local high=$(echo "$output" | grep -c "HIGH" || echo "0")

    TOTAL_CRIT=$((TOTAL_CRIT + crit))
    TOTAL_HIGH=$((TOTAL_HIGH + high))
    ((IMAGES_SCANNED++))

    if [[ $crit -gt 0 ]]; then
        err "$image: $crit CRITICAL, $high HIGH vulnerabilities"
    elif [[ $high -gt 0 ]]; then
        warn "$image: $high HIGH vulnerabilities"
    else
        ok "$image: No HIGH/CRITICAL vulnerabilities"
    fi

    # Save to report
    {
        echo "=== $image ==="
        echo "$output"
        echo ""
    } >> "$REPORT_FILE"
}

# Determine what to scan
if [[ -n "${1:-}" ]]; then
    # Scan specific image
    scan_image "$1"
else
    # Scan all project images
    info "Scanning all Docker images..."
    echo ""

    IMAGES=$(docker images --format "{{.Repository}}:{{.Tag}}" 2>/dev/null | grep -v "<none>")

    if [[ -z "$IMAGES" ]]; then
        warn "No Docker images found to scan"
        exit 0
    fi

    while IFS= read -r img; do
        scan_image "$img"
        echo ""
    done <<< "$IMAGES"
fi

# Summary
echo "=============================================="
echo "  Scan Summary"
echo "=============================================="
echo ""
echo "  Images scanned: $IMAGES_SCANNED"

if [[ $TOTAL_CRIT -gt 0 ]]; then
    err "  CRITICAL: $TOTAL_CRIT"
else
    ok "  CRITICAL: 0"
fi

if [[ $TOTAL_HIGH -gt 0 ]]; then
    warn "  HIGH: $TOTAL_HIGH"
else
    ok "  HIGH: 0"
fi

{
    echo ""
    echo "Summary: $IMAGES_SCANNED images | $TOTAL_CRIT CRITICAL | $TOTAL_HIGH HIGH"
} >> "$REPORT_FILE"

echo ""
ok "Full report: $REPORT_FILE"
echo ""

[[ $TOTAL_CRIT -gt 0 ]] && exit 2
[[ $TOTAL_HIGH -gt 0 ]] && exit 1
exit 0
