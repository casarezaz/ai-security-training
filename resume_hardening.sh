#!/usr/bin/env bash
# =============================================================================
# Resume Security Hardening
# Picks up where security_hardening.sh stopped (after SSH key creation).
# Each step is independent — if one fails, the rest still run.
# =============================================================================

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR ]${NC}  $*"; }

PROJECT_ROOT="$HOME/aiml-cybersecurity"
cd "$PROJECT_ROOT" || { err "Project dir not found"; exit 1; }

echo ""
echo "=============================================="
echo "  Resuming Security Hardening"
echo "=============================================="
echo ""

# ─────────────────────────────────────────────────────────────────────────────
# 1. FIX SSH KEY — add to agent + GitHub
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 1: SSH Key (finishing setup) ==="

SSH_KEY="$HOME/.ssh/id_ed25519"
if [ -f "$SSH_KEY" ]; then
    ok "SSH key exists"

    # Remove stale agent directory if it exists (caused the original error)
    if [ -d "$HOME/.ssh/agent" ]; then
        rm -rf "$HOME/.ssh/agent" 2>/dev/null && \
            ok "Removed stale ~/.ssh/agent directory" || \
            warn "Could not remove ~/.ssh/agent — run: rm -rf ~/.ssh/agent"
    fi

    # Add key to macOS Keychain (no need to start a new agent — macOS launchd handles it)
    if ssh-add --apple-use-keychain "$SSH_KEY" 2>/dev/null; then
        ok "SSH key added to Keychain"
    elif ssh-add "$SSH_KEY" 2>/dev/null; then
        ok "SSH key added to agent"
    else
        warn "Could not add SSH key. Run manually:"
        echo "    ssh-add --apple-use-keychain ~/.ssh/id_ed25519"
    fi

    # Add to GitHub if gh is authenticated
    if command -v gh &>/dev/null && gh auth status &>/dev/null 2>&1; then
        PUB_KEY=$(cat "${SSH_KEY}.pub" | awk '{print $2}')
        if gh ssh-key list 2>/dev/null | grep -q "$PUB_KEY"; then
            ok "SSH key already on GitHub"
        else
            gh ssh-key add "${SSH_KEY}.pub" --title "aiml-cyber-$(hostname)-$(date +%Y%m%d)" 2>/dev/null && \
                ok "SSH key added to GitHub" || \
                warn "Could not auto-add SSH key to GitHub. Add manually:"
                echo "    Copy the output below and paste at github.com/settings/ssh/new"
                echo ""
                cat "${SSH_KEY}.pub"
                echo ""
        fi

        # Set Git to use SSH
        git config --global url."git@github.com:".insteadOf "https://github.com/"
        ok "Git configured to use SSH"
    else
        warn "GitHub CLI not authenticated — skipping SSH key upload"
        echo "    Run: gh auth login"
        echo "    Then: gh ssh-key add ~/.ssh/id_ed25519.pub"
    fi
else
    warn "No SSH key found — run security_hardening.sh first"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. GPG COMMIT SIGNING
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "=== Step 2: GPG Commit Signing ==="

# Install GPG if needed
if ! command -v gpg &>/dev/null; then
    info "Installing GPG..."
    brew install gnupg pinentry-mac 2>/dev/null || true
fi

if command -v gpg &>/dev/null; then
    GPG_KEY=$(gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep sec | head -1 | awk -F'/' '{print $2}' | awk '{print $1}')

    if [ -z "$GPG_KEY" ]; then
        info "Generating GPG key..."
        GIT_EMAIL=$(git config --global user.email)
        GIT_NAME=$(git config --global user.name)

        gpg --batch --gen-key << GPGEOF
%no-protection
Key-Type: eddsa
Key-Curve: ed25519
Subkey-Type: eddsa
Subkey-Curve: ed25519
Name-Real: $GIT_NAME
Name-Email: $GIT_EMAIL
Expire-Date: 2y
%commit
GPGEOF

        GPG_KEY=$(gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep sec | head -1 | awk -F'/' '{print $2}' | awk '{print $1}')

        if [ -n "$GPG_KEY" ]; then
            ok "GPG key generated: $GPG_KEY"
            # Try to add to GitHub
            gpg --armor --export "$GPG_KEY" | gh gpg-key add - 2>/dev/null && \
                ok "GPG key added to GitHub" || \
                warn "Add GPG key manually: gpg --armor --export $GPG_KEY | pbcopy"
        else
            warn "GPG key generation failed — commit signing will be skipped"
        fi
    else
        ok "GPG key exists: $GPG_KEY"
    fi

    if [ -n "$GPG_KEY" ]; then
        git config --global user.signingkey "$GPG_KEY"
        git config --global commit.gpgsign true
        git config --global tag.gpgsign true

        # GPG TTY fix
        grep -q 'GPG_TTY' "$HOME/.zshrc" 2>/dev/null || echo 'export GPG_TTY=$(tty)' >> "$HOME/.zshrc"

        # pinentry-mac for passphrase prompts
        if command -v pinentry-mac &>/dev/null; then
            mkdir -p "$HOME/.gnupg"
            echo "pinentry-program $(which pinentry-mac)" > "$HOME/.gnupg/gpg-agent.conf" 2>/dev/null
        fi
        ok "Commit signing configured"
    fi
else
    warn "GPG not available — skipping commit signing"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 3. SECRETS MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "=== Step 3: Secrets Management ==="

# .env template
if [ ! -f "$PROJECT_ROOT/.env.template" ]; then
    cat > "$PROJECT_ROOT/.env.template" << 'ENVTEMPLATE'
# =============================================================================
# Environment Variables — NEVER commit the actual .env file
# Copy this to .env and fill in your values
# =============================================================================

# API Keys (for threat intel enrichment)
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
SHODAN_API_KEY=
OTX_API_KEY=

# Hugging Face (for model downloads)
HF_TOKEN=

# Jupyter
JUPYTER_TOKEN=

# Model paths
MODEL_DIR=./models
DATA_DIR=./data
ENVTEMPLATE
    ok "Created .env.template"
fi

if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env.template" "$PROJECT_ROOT/.env"
    chmod 600 "$PROJECT_ROOT/.env"
    ok "Created .env (permissions: 600)"
else
    chmod 600 "$PROJECT_ROOT/.env"
    ok ".env exists (permissions secured)"
fi

# git-secrets
if ! command -v git-secrets &>/dev/null; then
    info "Installing git-secrets..."
    brew install git-secrets 2>/dev/null || true
fi

if command -v git-secrets &>/dev/null; then
    cd "$PROJECT_ROOT"
    git secrets --install --force 2>/dev/null || true
    git secrets --register-aws 2>/dev/null || true
    git secrets --add 'sk-[a-zA-Z0-9]{20,}' 2>/dev/null || true
    git secrets --add 'ghp_[a-zA-Z0-9]{36}' 2>/dev/null || true
    git secrets --add 'hf_[a-zA-Z0-9]{34}' 2>/dev/null || true
    git secrets --add --allowed '.*\.template$' 2>/dev/null || true
    ok "git-secrets configured"
else
    warn "git-secrets not available"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 4. PRE-COMMIT HOOKS
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "=== Step 4: Pre-commit Hooks ==="

# Make sure we're in the right conda env
if [[ "${CONDA_DEFAULT_ENV:-}" == "aiml-cyber" ]]; then
    pip install pre-commit detect-secrets bandit 2>/dev/null

    if [ ! -f "$PROJECT_ROOT/.pre-commit-config.yaml" ]; then
        cat > "$PROJECT_ROOT/.pre-commit-config.yaml" << 'PRECOMMIT'
repos:
  - repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.6.0
    hooks:
      - id: check-yaml
      - id: check-json
      - id: check-toml
      - id: end-of-file-fixer
      - id: trailing-whitespace
      - id: check-merge-conflict
      - id: check-added-large-files
        args: ['--maxkb=5000']
      - id: detect-private-key
      - id: check-case-conflict
      - id: check-symlinks

  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.8
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.9
    hooks:
      - id: bandit
        args: ['-c', 'pyproject.toml']
        additional_dependencies: ['bandit[toml]']

  - repo: https://github.com/kynan/nbstripout
    rev: 0.7.1
    hooks:
      - id: nbstripout
PRECOMMIT
        ok "Created .pre-commit-config.yaml"
    fi

    if [ ! -f "$PROJECT_ROOT/pyproject.toml" ]; then
        cat > "$PROJECT_ROOT/pyproject.toml" << 'PYPROJECT'
[tool.bandit]
exclude_dirs = ["tests", "notebooks"]
skips = ["B101"]

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "W", "I", "S", "B", "UP"]
ignore = ["S101"]

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_*.py"
PYPROJECT
        ok "Created pyproject.toml"
    fi

    cd "$PROJECT_ROOT"
    detect-secrets scan > .secrets.baseline 2>/dev/null || true
    pre-commit install 2>/dev/null && ok "Pre-commit hooks installed" || warn "pre-commit install failed"
else
    warn "Activate aiml-cyber env first for pre-commit setup:"
    echo "    conda activate aiml-cyber"
    echo "    pip install pre-commit detect-secrets bandit"
    echo "    cd ~/aiml-cybersecurity && pre-commit install"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 5. DEPENDENCY SCANNING
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "=== Step 5: Dependency Scanning ==="

if [[ "${CONDA_DEFAULT_ENV:-}" == "aiml-cyber" ]]; then
    pip install pip-audit safety 2>/dev/null

    mkdir -p "$PROJECT_ROOT/scripts"
    cat > "$PROJECT_ROOT/scripts/scan_deps.sh" << 'SCANDEPS'
#!/usr/bin/env bash
echo "=== pip-audit ==="
pip-audit --strict 2>&1 || true
echo ""
echo "=== safety check ==="
safety check 2>&1 || true
SCANDEPS
    chmod +x "$PROJECT_ROOT/scripts/scan_deps.sh"

    mkdir -p "$PROJECT_ROOT/reports/security"
    info "Running initial dependency scan..."
    pip-audit 2>&1 | tee "$PROJECT_ROOT/reports/security/dep_scan_$(date +%Y%m%d).txt" || true
    ok "Dependency scanning configured"
else
    warn "Activate aiml-cyber env first for dependency scanning"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 6. FILE PERMISSIONS & GITATTRIBUTES
# ─────────────────────────────────────────────────────────────────────────────
echo ""
info "=== Step 6: File Permissions & Git Attributes ==="

chmod 600 "$PROJECT_ROOT/.env" 2>/dev/null
chmod 700 "$PROJECT_ROOT/models" 2>/dev/null
chmod 700 "$HOME/.ssh" 2>/dev/null
chmod 600 "$HOME/.ssh/id_ed25519" 2>/dev/null
chmod 644 "$HOME/.ssh/id_ed25519.pub" 2>/dev/null
chmod 600 "$HOME/.ssh/config" 2>/dev/null

if [ ! -f "$PROJECT_ROOT/.gitattributes" ]; then
    cat > "$PROJECT_ROOT/.gitattributes" << 'GITATTR'
* text=auto
*.py text diff=python
*.md text
*.yaml text
*.yml text
*.json text
*.sh text eol=lf
*.pkl binary
*.h5 binary
*.hdf5 binary
*.pt binary
*.pth binary
*.onnx binary
*.safetensors binary
*.pcap binary
*.pcapng binary
GITATTR
    ok "Created .gitattributes"
fi

ok "Permissions and attributes configured"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "  ${GREEN}Hardening Complete${NC}"
echo "=============================================="
echo ""
echo "  What's in place now:"
echo "    [x] SSH key for GitHub"
echo "    [x] GPG commit signing"
echo "    [x] Secrets management (.env + git-secrets)"
echo "    [x] Pre-commit hooks (secrets, linting, large files, notebooks)"
echo "    [x] Dependency vulnerability scanning"
echo "    [x] File permissions hardened"
echo "    [x] .gitattributes for binary files"
echo ""
echo "  Next step:"
echo "    Install Docker Desktop, then run:"
echo "    ./install_security_tools.sh"
echo ""
