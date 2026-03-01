#!/usr/bin/env bash
# =============================================================================
# Docker Desktop Hardening
# Secures the Docker daemon and default container behavior.
# Run BEFORE building any containers.
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo ""
echo "=============================================="
echo "  Docker Desktop Hardening"
echo "=============================================="
echo ""

# Check Docker is running
if ! docker info &>/dev/null 2>&1; then
    echo "Docker is not running. Start Docker Desktop first."
    exit 1
fi

ok "Docker is running: $(docker --version)"

# ─────────────────────────────────────────────────────────────────────────────
# 1. DAEMON CONFIGURATION
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 1: Daemon Security Configuration ==="

DAEMON_JSON="$HOME/.docker/daemon.json"
cp "$DAEMON_JSON" "${DAEMON_JSON}.backup" 2>/dev/null

cat > "$DAEMON_JSON" << 'DAEMON'
{
  "builder": {
    "gc": {
      "defaultKeepStorage": "20GB",
      "enabled": true
    }
  },
  "experimental": false,
  "no-new-privileges": true,
  "icc": false,
  "live-restore": true,
  "userland-proxy": false,
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  },
  "default-ulimits": {
    "nofile": {
      "Name": "nofile",
      "Hard": 65536,
      "Soft": 32768
    },
    "nproc": {
      "Name": "nproc",
      "Hard": 4096,
      "Soft": 2048
    }
  }
}
DAEMON

ok "Daemon config hardened:"
echo "    no-new-privileges: true  — containers can't gain extra privileges"
echo "    icc: false               — containers can't talk to each other by default"
echo "    live-restore: true       — containers keep running if daemon restarts"
echo "    userland-proxy: false    — uses iptables instead (more secure)"
echo "    log limits: 10MB x 3    — prevents log files from filling disk"
echo "    ulimits set              — caps file descriptors and processes"

# ─────────────────────────────────────────────────────────────────────────────
# 2. DISABLE DOCKER AI / TELEMETRY
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 2: Disable Telemetry & AI Features ==="

SETTINGS_FILE="$HOME/Library/Group Containers/group.com.docker/settings-store.json"
if [ -f "$SETTINGS_FILE" ]; then
    # Use python to safely modify JSON
    python3 -c "
import json, sys
with open('$SETTINGS_FILE', 'r') as f:
    settings = json.load(f)
settings['EnableDockerAI'] = False
settings['AnalyticsEnabled'] = False
settings['AutoStart'] = False
settings['SendUsageStatistics'] = False
with open('$SETTINGS_FILE', 'w') as f:
    json.dump(settings, f, indent=4)
print('Settings updated')
" 2>/dev/null && ok "Disabled Docker AI, analytics, telemetry, and auto-start" || \
    warn "Could not modify Docker Desktop settings — do this manually in Docker Desktop > Settings > General"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. DOCKER CONTENT TRUST (image signing verification)
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 3: Content Trust ==="

# Enable Docker Content Trust (only pull signed images)
ZSHRC="$HOME/.zshrc"
if ! grep -q "DOCKER_CONTENT_TRUST" "$ZSHRC" 2>/dev/null; then
    echo "" >> "$ZSHRC"
    echo "# Docker: only pull signed/verified images" >> "$ZSHRC"
    echo "export DOCKER_CONTENT_TRUST=1" >> "$ZSHRC"
fi
export DOCKER_CONTENT_TRUST=1
ok "Docker Content Trust enabled (only signed images will be pulled)"
echo "    Note: Set DOCKER_CONTENT_TRUST=0 temporarily if you need unsigned images"

# ─────────────────────────────────────────────────────────────────────────────
# 4. RESOURCE LIMITS
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 4: Resource Limits ==="

echo "    Docker Desktop resource limits should be configured in the GUI:"
echo "    Docker Desktop > Settings > Resources"
echo ""
echo "    Recommended limits for this project:"
echo "    - CPUs: 4 (or half your total cores)"
echo "    - Memory: 4 GB (or half your total RAM)"
echo "    - Swap: 1 GB"
echo "    - Disk image size: 32 GB"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 5. NETWORK ISOLATION
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 5: Network Hardening ==="

# Create a dedicated isolated network for our security tools
docker network create \
    --driver bridge \
    --internal \
    --subnet=172.28.0.0/16 \
    aiml-isolated 2>/dev/null && \
    ok "Created isolated Docker network: aiml-isolated (no internet access)" || \
    ok "Isolated network already exists"

# Also create a network that allows outbound (for tools that need API access)
docker network create \
    --driver bridge \
    --subnet=172.29.0.0/16 \
    aiml-controlled 2>/dev/null && \
    ok "Created controlled Docker network: aiml-controlled (outbound allowed)" || \
    ok "Controlled network already exists"

echo "    aiml-isolated   — no internet, for malware analysis and offline tools"
echo "    aiml-controlled — outbound only, for threat intel API queries"

# ─────────────────────────────────────────────────────────────────────────────
# 6. CLEANUP POLICY
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 6: Cleanup Scripts ==="

PROJECT_ROOT="$HOME/aiml-cybersecurity"
mkdir -p "$PROJECT_ROOT/scripts"

cat > "$PROJECT_ROOT/scripts/docker_cleanup.sh" << 'CLEANUP'
#!/usr/bin/env bash
# Clean up Docker resources to free disk space
echo "=== Removing stopped containers ==="
docker container prune -f
echo ""
echo "=== Removing unused images ==="
docker image prune -f
echo ""
echo "=== Removing unused volumes ==="
docker volume prune -f
echo ""
echo "=== Removing unused networks ==="
docker network prune -f
echo ""
echo "=== Disk usage ==="
docker system df
CLEANUP
chmod +x "$PROJECT_ROOT/scripts/docker_cleanup.sh"

cat > "$PROJECT_ROOT/scripts/docker_audit.sh" << 'AUDIT'
#!/usr/bin/env bash
# Audit running Docker containers for security
echo "=============================================="
echo "  Docker Security Audit"
echo "=============================================="
echo ""

echo "=== Running Containers ==="
docker ps --format "table {{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}"
echo ""

echo "=== Container Security Settings ==="
for container in $(docker ps -q); do
    name=$(docker inspect --format '{{.Name}}' $container | tr -d '/')
    echo "--- $name ---"
    echo "  Privileged:        $(docker inspect --format '{{.HostConfig.Privileged}}' $container)"
    echo "  No New Privileges: $(docker inspect --format '{{.HostConfig.SecurityOpt}}' $container)"
    echo "  Capabilities Add:  $(docker inspect --format '{{.HostConfig.CapAdd}}' $container)"
    echo "  Capabilities Drop: $(docker inspect --format '{{.HostConfig.CapDrop}}' $container)"
    echo "  Network Mode:      $(docker inspect --format '{{.HostConfig.NetworkMode}}' $container)"
    echo "  Memory Limit:      $(docker inspect --format '{{.HostConfig.Memory}}' $container)"
    echo "  CPU Limit:         $(docker inspect --format '{{.HostConfig.NanoCpus}}' $container)"
    echo "  Read-only Root:    $(docker inspect --format '{{.HostConfig.ReadonlyRootfs}}' $container)"
    echo "  User:              $(docker inspect --format '{{.Config.User}}' $container)"
    echo ""
done

echo "=== Exposed Ports ==="
docker ps --format "{{.Names}}: {{.Ports}}" | grep -v "^$"
echo ""

echo "=== Volumes Mounted ==="
for container in $(docker ps -q); do
    name=$(docker inspect --format '{{.Name}}' $container | tr -d '/')
    mounts=$(docker inspect --format '{{range .Mounts}}{{.Source}} -> {{.Destination}} ({{.Mode}}){{"\n"}}{{end}}' $container)
    if [ -n "$mounts" ]; then
        echo "--- $name ---"
        echo "$mounts"
    fi
done

echo ""
echo "=== Docker Daemon Settings ==="
echo "  Content Trust: ${DOCKER_CONTENT_TRUST:-not set}"
cat ~/.docker/daemon.json 2>/dev/null | python3 -m json.tool 2>/dev/null
AUDIT
chmod +x "$PROJECT_ROOT/scripts/docker_audit.sh"

ok "Created docker_cleanup.sh and docker_audit.sh"

# ─────────────────────────────────────────────────────────────────────────────
# 7. LITTLE SNITCH RULE REMINDER
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 7: Firewall (Little Snitch) ==="
echo ""
echo "    Docker Desktop needs these Little Snitch rules:"
echo ""
echo "    1. Allow: com.docker.backend → any (TCP, ports 443, 80)"
echo "       Purpose: Pull container images from Docker Hub / registries"
echo ""
echo "    2. Allow: vpnkit-bridge → any (TCP)"
echo "       Purpose: Container networking"
echo ""
echo "    3. BLOCK: com.docker.backend → any (TCP, all other ports)"
echo "       Purpose: Deny everything else by default"
echo ""
echo "    Create these rules in Little Snitch Configuration if prompted."

# ─────────────────────────────────────────────────────────────────────────────
# RESTART NOTICE
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "  ${GREEN}Docker Hardening Complete${NC}"
echo "=============================================="
echo ""
echo "  What's configured:"
echo "    [x] Daemon: no-new-privileges, no inter-container comms, log limits"
echo "    [x] Telemetry: Docker AI, analytics, usage stats disabled"
echo "    [x] Content Trust: only signed images pulled by default"
echo "    [x] Networks: aiml-isolated (no internet) + aiml-controlled (outbound)"
echo "    [x] Audit script: ./scripts/docker_audit.sh"
echo "    [x] Cleanup script: ./scripts/docker_cleanup.sh"
echo ""
echo -e "  ${YELLOW}IMPORTANT: Restart Docker Desktop for daemon changes to take effect.${NC}"
echo "    Click the whale icon > Restart"
echo ""
echo "  After restart, continue with:"
echo "    cd ~/aiml-cybersecurity"
echo "    ./install_security_tools.sh"
echo ""
