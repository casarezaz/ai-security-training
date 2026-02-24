#!/usr/bin/env bash
# =============================================================================
# Finish Setup — Creates conda environment and installs Python packages
# Run this from ~/aiml-cybersecurity
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }

echo ""
echo "=============================================="
echo "  Finishing AI/ML x Cyber Environment Setup"
echo "=============================================="
echo ""

# ── Check conda is available ──
if ! command -v conda &>/dev/null; then
    echo "Conda not found. Try: source ~/.zshrc"
    exit 1
fi

ENV_NAME="aiml-cyber"

# ── Create environment ──
if conda env list | grep -q "$ENV_NAME"; then
    warn "Environment '$ENV_NAME' already exists — skipping creation"
else
    info "Creating conda environment: $ENV_NAME (Python 3.11)..."
    conda create -n "$ENV_NAME" python=3.11 -y
fi

# ── Activate ──
eval "$(conda shell.bash hook)"
conda activate "$ENV_NAME"
ok "Activated $ENV_NAME"

# ── Install packages (one group at a time so failures are easy to spot) ──

info "Installing core ML & data science..."
pip install numpy pandas scipy matplotlib seaborn plotly scikit-learn xgboost lightgbm imbalanced-learn

info "Installing deep learning (CPU)..."
pip install torch torchvision torchaudio tensorflow

info "Installing NLP libraries..."
pip install transformers datasets tokenizers nltk spacy
python -m spacy download en_core_web_sm 2>/dev/null || true

info "Installing explainability tools..."
pip install shap lime

info "Installing network & security tools..."
pip install scapy dpkt pyshark python-whois dnspython requests beautifulsoup4 tldextract

info "Installing Jupyter & dev tools..."
pip install jupyterlab notebook ipywidgets tqdm python-dotenv pyyaml black ruff pytest

info "Installing dashboard frameworks..."
pip install streamlit dash

# ── Init git repo if not already ──
cd "$HOME/aiml-cybersecurity" 2>/dev/null
if [ ! -d .git ]; then
    info "Initializing Git repository..."
    git init
    git add .
    git commit -m "Initial project structure for AI/ML x Cybersecurity Phase 1"
    ok "Git repo initialized"
else
    ok "Git repo already exists"
fi

# ── Done ──
echo ""
echo "=============================================="
echo -e "  ${GREEN}Setup Complete!${NC}"
echo "=============================================="
echo ""
echo "  Quick start:"
echo "    conda activate aiml-cyber"
echo "    cd ~/aiml-cybersecurity"
echo "    jupyter lab"
echo ""
echo "  When you get an NVIDIA GPU, upgrade PyTorch:"
echo "    pip install torch torchvision torchaudio --index-url https://download.pytorch.org/whl/cu124"
echo ""
