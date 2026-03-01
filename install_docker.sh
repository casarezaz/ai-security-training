#!/usr/bin/env bash
# =============================================================================
# Docker Desktop Installer for macOS
# Downloads and installs Docker Desktop, then verifies it's running.
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo ""
echo "=============================================="
echo "  Docker Desktop Installation"
echo "=============================================="
echo ""

# Check if already installed
if command -v docker &>/dev/null; then
    ok "Docker is already installed: $(docker --version)"
    echo ""

    # Check if running
    if docker info &>/dev/null 2>&1; then
        ok "Docker daemon is running"
    else
        warn "Docker is installed but not running."
        echo "    Open Docker Desktop from Applications and wait for it to start."
        echo "    Then re-run this script to verify."
    fi
    exit 0
fi

# Detect architecture
ARCH=$(uname -m)
info "Detected architecture: $ARCH"

if [[ "$ARCH" == "arm64" ]]; then
    DOCKER_URL="https://desktop.docker.com/mac/main/arm64/Docker.dmg"
    info "Downloading Docker Desktop for Apple Silicon..."
else
    DOCKER_URL="https://desktop.docker.com/mac/main/amd64/Docker.dmg"
    info "Downloading Docker Desktop for Intel..."
fi

# Download
DMG_PATH="/tmp/Docker.dmg"
curl -L -o "$DMG_PATH" "$DOCKER_URL"

if [ ! -f "$DMG_PATH" ]; then
    echo ""
    warn "Download failed. Install manually from:"
    echo "    https://www.docker.com/products/docker-desktop/"
    exit 1
fi

ok "Download complete"

# Mount and install
info "Installing Docker Desktop..."
hdiutil attach "$DMG_PATH" -quiet
cp -R "/Volumes/Docker/Docker.app" "/Applications/" 2>/dev/null

# Unmount
hdiutil detach "/Volumes/Docker" -quiet 2>/dev/null
rm -f "$DMG_PATH"

ok "Docker Desktop installed to /Applications"

# Launch Docker
info "Launching Docker Desktop (first launch takes 1-2 minutes)..."
open /Applications/Docker.app

echo ""
echo "=============================================="
echo -e "  ${GREEN}Docker Desktop Installed${NC}"
echo "=============================================="
echo ""
echo "  Docker Desktop is starting up. You'll see the whale icon"
echo "  in your menu bar. Wait until it says 'Docker Desktop is running'"
echo "  before continuing."
echo ""
echo "  You may need to:"
echo "    1. Accept the Docker license agreement"
echo "    2. Grant system permissions when prompted"
echo "    3. Choose 'Use recommended settings' at the setup screen"
echo ""
echo "  Once Docker is running, verify with:"
echo "    docker --version"
echo "    docker run hello-world"
echo ""
echo "  Then continue with:"
echo "    cd ~/aiml-cybersecurity"
echo "    ./install_security_tools.sh"
echo ""
