#!/usr/bin/env bash
# =============================================================================
# Security Environment Setup — Separate conda env for Python security packages
# This keeps security/adversarial packages isolated from your main ML env.
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo ""
echo "=============================================="
echo "  Security Python Environment Setup"
echo "=============================================="
echo ""

# Check conda
if ! command -v conda &>/dev/null; then
    echo "Conda not found. Run: source ~/.zshrc"
    exit 1
fi

SEC_ENV="aiml-sectools"

# ── Create dedicated security conda env ──
if conda env list | grep -q "$SEC_ENV"; then
    warn "Environment '$SEC_ENV' already exists — skipping creation"
else
    info "Creating security conda environment: $SEC_ENV (Python 3.11)..."
    conda create -n "$SEC_ENV" python=3.11 -y
fi

eval "$(conda shell.bash hook)"
conda activate "$SEC_ENV"
ok "Activated $SEC_ENV"

# ── Adversarial ML Tools ──
info "Installing adversarial ML tools..."
pip install --quiet \
    adversarial-robustness-toolbox \
    foolbox \
    textattack

# ── Threat Intelligence ──
info "Installing threat intelligence tools..."
pip install --quiet \
    mitreattack-python \
    stix2 \
    taxii2-client \
    OTXv2 \
    vt-py \
    shodan \
    pySigma

# ── Privacy / Differential Privacy ──
info "Installing privacy tools..."
pip install --quiet \
    opacus \
    diffprivlib

# ── Malware Analysis (Python side) ──
info "Installing malware analysis Python packages..."
pip install --quiet \
    yara-python \
    pefile \
    oletools \
    ssdeep 2>/dev/null || warn "ssdeep may need manual install"

# ── Network Analysis (Python side) ──
info "Installing network analysis Python packages..."
pip install --quiet \
    scapy \
    dpkt \
    pyshark \
    netaddr

# ── Knowledge Graph ──
info "Installing knowledge graph tools..."
pip install --quiet \
    networkx \
    neo4j \
    pyvis

# ── Forensics ──
info "Installing forensics tools..."
pip install --quiet \
    volatility3 \
    python-evtx \
    python-registry 2>/dev/null || true

# ── LLM Security (for Project 8) ──
info "Installing LLM security tools..."
pip install --quiet \
    garak 2>/dev/null || warn "garak (LLM vulnerability scanner) may need manual install"

# ── Explainability (needed for adversarial analysis) ──
info "Installing explainability tools..."
pip install --quiet \
    shap \
    lime

# ── Dev tools for this env ──
pip install --quiet \
    jupyterlab \
    ipykernel \
    matplotlib \
    pandas \
    numpy

# Register as Jupyter kernel (so you can switch envs in notebooks)
python -m ipykernel install --user --name "$SEC_ENV" --display-name "Python (Security Tools)"
ok "Registered Jupyter kernel: Python (Security Tools)"

# ── Freeze requirements ──
pip freeze > "$HOME/aiml-cybersecurity/configs/sectools-requirements.txt"
ok "Requirements saved to configs/sectools-requirements.txt"

echo ""
echo "=============================================="
echo -e "  ${GREEN}Security Environment Ready${NC}"
echo "=============================================="
echo ""
echo "  Two environments now exist:"
echo ""
echo "    aiml-cyber    — ML/DL, NLP, data science (daily work)"
echo "    aiml-sectools — Adversarial ML, threat intel, forensics"
echo ""
echo "  Switch between them:"
echo "    conda activate aiml-cyber      # ML development"
echo "    conda activate aiml-sectools   # Security tools"
echo ""
echo "  In Jupyter, select the kernel:"
echo "    'Python (aiml-cyber)' or 'Python (Security Tools)'"
echo ""
echo "  Docker container for CLI tools:"
echo "    cd ~/aiml-cybersecurity/docker"
echo "    docker compose build"
echo "    docker compose up -d"
echo "    docker compose exec sectools bash"
echo ""
