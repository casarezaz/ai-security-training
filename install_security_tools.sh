#!/usr/bin/env bash
# =============================================================================
# Security Tools — Master Install Script
# Orchestrates the full isolated security setup:
#   1. Docker container for CLI tools (nmap, tshark, Zeek, YARA, etc.)
#   2. Separate conda env for Python security packages
#   3. Wrapper scripts for seamless access
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR ]${NC}  $*"; }

PROJECT_ROOT="$HOME/aiml-cybersecurity"
cd "$PROJECT_ROOT" || { err "Project directory not found"; exit 1; }

echo ""
echo "=============================================="
echo "  Security Tools — Isolated Installation"
echo "=============================================="
echo ""
echo "  Architecture:"
echo "    ┌─────────────────────────────────────────┐"
echo "    │  Your Mac (host)                        │"
echo "    │                                         │"
echo "    │  ┌───────────────┐  ┌────────────────┐  │"
echo "    │  │ conda:        │  │ conda:         │  │"
echo "    │  │ aiml-cyber    │  │ aiml-sectools  │  │"
echo "    │  │ (ML/DL/NLP)   │  │ (adversarial,  │  │"
echo "    │  │               │  │  threat intel,  │  │"
echo "    │  │               │  │  privacy)       │  │"
echo "    │  └───────────────┘  └────────────────┘  │"
echo "    │                                         │"
echo "    │  ┌─────────────────────────────────────┐│"
echo "    │  │ Docker: aiml-sectools               ││"
echo "    │  │ (nmap, tshark, Zeek, YARA, tcpdump, ││"
echo "    │  │  ssdeep, oletools, volatility)       ││"
echo "    │  │ — no-new-privileges, caps dropped   ││"
echo "    │  └─────────────────────────────────────┘│"
echo "    └─────────────────────────────────────────┘"
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# STEP 1: Check Docker
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 1: Docker ==="

if ! command -v docker &>/dev/null; then
    warn "Docker not found."
    echo ""
    echo "  Install Docker Desktop for Mac:"
    echo "  https://www.docker.com/products/docker-desktop/"
    echo ""
    echo "  After installing, re-run this script."
    echo ""
    read -rp "Continue with conda setup only? (y/n): " CONTINUE
    if [[ ! "$CONTINUE" =~ ^[Yy] ]]; then
        exit 0
    fi
    DOCKER_AVAILABLE=false
else
    ok "Docker found: $(docker --version)"
    DOCKER_AVAILABLE=true
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 2: Build Docker container
# ─────────────────────────────────────────────────────────────────────────────
if [ "$DOCKER_AVAILABLE" = true ]; then
    info "=== Step 2: Building Security Tools Container ==="
    info "This may take 5-10 minutes on first build..."

    cd "$PROJECT_ROOT/docker"
    docker compose build sectools 2>&1 | tail -20

    if [ $? -eq 0 ]; then
        ok "Docker container built: aiml-sectools"

        # Start it
        docker compose up -d sectools
        ok "Container running"

        # Verify tools inside container
        info "Verifying containerized tools..."
        docker compose exec -T sectools bash -c '
            echo "  nmap:    $(nmap --version 2>&1 | head -1)"
            echo "  tshark:  $(tshark --version 2>&1 | head -1)"
            echo "  tcpdump: $(tcpdump --version 2>&1 | head -1)"
            echo "  yara:    $(yara --version 2>&1)"
            echo "  ssdeep:  $(ssdeep -V 2>&1)"
            echo "  python3: $(python3 --version 2>&1)"
        ' 2>/dev/null || warn "Could not verify tools — container may need manual start"

    else
        warn "Docker build failed — check docker/Dockerfile.sectools"
    fi
    cd "$PROJECT_ROOT"
else
    warn "Skipping Docker setup (not installed)"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 3: Conda security environment
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 3: Conda Security Environment ==="
bash "$PROJECT_ROOT/setup_security_env.sh"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 4: Install wrapper scripts
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 4: Creating Wrapper Scripts ==="

WRAPPER_DIR="$PROJECT_ROOT/scripts/wrappers"
mkdir -p "$WRAPPER_DIR"

# Generic wrapper template
create_wrapper() {
    local TOOL_NAME=$1
    local EXTRA_ARGS=${2:-""}
    cat > "$WRAPPER_DIR/$TOOL_NAME" << WRAPPER
#!/usr/bin/env bash
# Wrapper: runs $TOOL_NAME inside the security Docker container
# Usage: ./scripts/wrappers/$TOOL_NAME [args...]
CONTAINER="aiml-sectools"
if ! docker ps --format '{{.Names}}' | grep -q "^\$CONTAINER\$"; then
    echo "Starting security container..."
    cd "\$HOME/aiml-cybersecurity/docker" && docker compose up -d sectools
fi
docker exec -it \$CONTAINER $TOOL_NAME $EXTRA_ARGS "\$@"
WRAPPER
    chmod +x "$WRAPPER_DIR/$TOOL_NAME"
}

create_wrapper "nmap"
create_wrapper "tshark"
create_wrapper "tcpdump"
create_wrapper "yara"
create_wrapper "ssdeep"
create_wrapper "zeek"
create_wrapper "olevba"     # oletools
create_wrapper "vol3" "python3 -m volatility3"

# Special wrapper for interactive shell
cat > "$WRAPPER_DIR/secshell" << 'SHELL'
#!/usr/bin/env bash
# Open an interactive shell in the security container
CONTAINER="aiml-sectools"
if ! docker ps --format '{{.Names}}' | grep -q "^$CONTAINER$"; then
    echo "Starting security container..."
    cd "$HOME/aiml-cybersecurity/docker" && docker compose up -d sectools
fi
docker exec -it $CONTAINER bash
SHELL
chmod +x "$WRAPPER_DIR/secshell"

ok "Wrapper scripts created in scripts/wrappers/"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 5: Add wrappers to PATH (optional)
# ─────────────────────────────────────────────────────────────────────────────
info ""
WRAPPER_PATH_LINE="export PATH=\"\$HOME/aiml-cybersecurity/scripts/wrappers:\$PATH\""
if ! grep -q "aiml-cybersecurity/scripts/wrappers" "$HOME/.zshrc" 2>/dev/null; then
    read -rp "Add wrapper scripts to your PATH? (y/n): " ADD_PATH
    if [[ "$ADD_PATH" =~ ^[Yy] ]]; then
        echo "" >> "$HOME/.zshrc"
        echo "# AI/ML x Cybersecurity — containerized security tools" >> "$HOME/.zshrc"
        echo "$WRAPPER_PATH_LINE" >> "$HOME/.zshrc"
        ok "Wrappers added to PATH — restart terminal or run: source ~/.zshrc"
    else
        info "Skipped. You can run tools directly: ./scripts/wrappers/nmap [args]"
    fi
else
    ok "Wrappers already in PATH"
fi

# ─────────────────────────────────────────────────────────────────────────────
# STEP 6: Download reference data
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 6: Downloading Reference Data ==="

# MITRE ATT&CK
eval "$(conda shell.bash hook)"
conda activate aiml-sectools 2>/dev/null

mkdir -p "$PROJECT_ROOT/data/external/mitre_attack"
python3 -c "
import urllib.request, os
url = 'https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json'
dest = os.path.expanduser('~/aiml-cybersecurity/data/external/mitre_attack/enterprise-attack.json')
if not os.path.exists(dest):
    print('Downloading MITRE ATT&CK Enterprise...')
    urllib.request.urlretrieve(url, dest)
    print('Done')
else:
    print('MITRE ATT&CK data already exists')
" 2>/dev/null || warn "Could not download MITRE ATT&CK data"

ok "Reference data downloaded"

# ─────────────────────────────────────────────────────────────────────────────
# STEP 7: Create verification script
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 7: Creating Verification Scripts ==="

cat > "$PROJECT_ROOT/scripts/verify_tools.py" << 'VERIFY'
#!/usr/bin/env python3
"""
Verify that security tools are installed in the correct locations.
Run from either conda env to check its packages,
or without an env to check Docker tools.
"""
import sys
import os
import subprocess
import shutil

def check_python(module, name):
    try:
        __import__(module)
        return True, f"  \u2705  {name:<40} OK"
    except ImportError:
        return False, f"  \u274C  {name:<40} NOT FOUND"

def check_docker_tool(tool):
    try:
        result = subprocess.run(
            ["docker", "exec", "aiml-sectools", "which", tool],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            return True, f"  \u2705  {tool:<40} OK (Docker)"
        return False, f"  \u274C  {tool:<40} NOT IN CONTAINER"
    except Exception:
        return False, f"  \u274C  {tool:<40} CONTAINER NOT RUNNING"

print("=" * 60)
print("  Security Tool Verification")
print("=" * 60)

env = os.environ.get("CONDA_DEFAULT_ENV", "none")
print(f"\n  Active conda env: {env}")

passed = failed = 0

# Check based on which env is active
if env == "aiml-cyber":
    print("\n  --- ML/DL Environment (aiml-cyber) ---")
    ml_tools = {
        "numpy": "NumPy", "pandas": "Pandas", "sklearn": "scikit-learn",
        "xgboost": "XGBoost", "torch": "PyTorch", "tensorflow": "TensorFlow",
        "transformers": "Transformers", "spacy": "spaCy",
    }
    for mod, name in ml_tools.items():
        ok, msg = check_python(mod, name)
        print(msg)
        passed += ok; failed += (not ok)

elif env == "aiml-sectools":
    print("\n  --- Security Environment (aiml-sectools) ---")
    sec_tools = {
        "art": "ART (Adversarial Robustness Toolbox)",
        "foolbox": "Foolbox",
        "stix2": "STIX 2.1",
        "mitre_attack_data": "MITRE ATT&CK",
        "sigma": "pySigma",
        "OTXv2": "AlienVault OTX",
        "vt": "VirusTotal",
        "shodan": "Shodan",
        "opacus": "Opacus (DP-SGD)",
        "networkx": "NetworkX",
        "neo4j": "Neo4j driver",
        "shap": "SHAP",
    }
    for mod, name in sec_tools.items():
        ok, msg = check_python(mod, name)
        print(msg)
        passed += ok; failed += (not ok)

# Docker tools (check regardless of env)
print("\n  --- Docker Container Tools ---")
docker_tools = ["nmap", "tshark", "tcpdump", "yara", "ssdeep", "python3"]
for tool in docker_tools:
    ok, msg = check_docker_tool(tool)
    print(msg)
    passed += ok; failed += (not ok)

# Wrapper scripts
print("\n  --- Wrapper Scripts ---")
wrapper_dir = os.path.expanduser("~/aiml-cybersecurity/scripts/wrappers")
wrappers = ["nmap", "tshark", "tcpdump", "yara", "ssdeep", "secshell"]
for w in wrappers:
    path = os.path.join(wrapper_dir, w)
    if os.path.isfile(path) and os.access(path, os.X_OK):
        print(f"  \u2705  {w:<40} OK")
        passed += 1
    else:
        print(f"  \u274C  {w:<40} NOT FOUND")
        failed += 1

print(f"\n  Results: {passed} passed, {failed} failed")
print("=" * 60)
sys.exit(1 if failed > 5 else 0)
VERIFY
chmod +x "$PROJECT_ROOT/scripts/verify_tools.py"

ok "Verification script updated"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "  ${GREEN}Security Tools Installation Complete${NC}"
echo "=============================================="
echo ""
echo "  Isolation architecture:"
echo ""
echo "  ┌─ conda: aiml-cyber ──────────────────────┐"
echo "  │  ML, DL, NLP, data science                │"
echo "  │  → conda activate aiml-cyber              │"
echo "  └──────────────────────────────────────────┘"
echo ""
echo "  ┌─ conda: aiml-sectools ───────────────────┐"
echo "  │  Adversarial ML, threat intel, privacy,   │"
echo "  │  knowledge graphs, LLM security           │"
echo "  │  → conda activate aiml-sectools           │"
echo "  └──────────────────────────────────────────┘"
echo ""
echo "  ┌─ Docker: aiml-sectools ──────────────────┐"
echo "  │  nmap, tshark, Zeek, YARA, tcpdump,      │"
echo "  │  ssdeep, oletools, volatility             │"
echo "  │  → ./scripts/wrappers/nmap [args]         │"
echo "  │  → ./scripts/wrappers/secshell            │"
echo "  └──────────────────────────────────────────┘"
echo ""
echo "  Verify:  python scripts/verify_tools.py"
echo "  Cleanup: cd docker && docker compose down"
echo "  Remove:  conda env remove -n aiml-sectools"
echo ""
