#!/usr/bin/env bash
# =============================================================================
# Security Hardening — Dev Environment
# Secures Git workflow, secrets management, dependency scanning, and more
# Run from ~/aiml-cybersecurity with conda env active
# =============================================================================
set -uo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
err()   { echo -e "${RED}[ERR ]${NC}  $*"; }

echo ""
echo "=============================================="
echo "  Security Hardening — Dev Environment"
echo "=============================================="
echo ""

PROJECT_ROOT="$HOME/aiml-cybersecurity"
cd "$PROJECT_ROOT" || { err "Project directory not found at $PROJECT_ROOT"; exit 1; }

# ─────────────────────────────────────────────────────────────────────────────
# 1. SSH KEY FOR GITHUB (replace HTTPS with SSH)
# ─────────────────────────────────────────────────────────────────────────────
info "=== Step 1: SSH Key for GitHub ==="

SSH_KEY="$HOME/.ssh/id_ed25519"
if [ -f "$SSH_KEY" ]; then
    ok "SSH key already exists at $SSH_KEY"
else
    info "Generating Ed25519 SSH key..."
    mkdir -p "$HOME/.ssh"
    chmod 700 "$HOME/.ssh"
    read -rp "Email for SSH key (press Enter for git email): " SSH_EMAIL
    SSH_EMAIL="${SSH_EMAIL:-$(git config --global user.email)}"
    ssh-keygen -t ed25519 -C "$SSH_EMAIL" -f "$SSH_KEY" -N ""
    ok "SSH key generated"
fi

# Add key to macOS Keychain (no need to start a new agent — macOS launchd handles it)
ssh-add --apple-use-keychain "$SSH_KEY" 2>/dev/null || ssh-add "$SSH_KEY" 2>/dev/null

# Add to GitHub
if gh ssh-key list 2>/dev/null | grep -q "$(cat "${SSH_KEY}.pub" | awk '{print $2}')"; then
    ok "SSH key already registered with GitHub"
else
    info "Adding SSH key to your GitHub account..."
    gh ssh-key add "${SSH_KEY}.pub" --title "aiml-cyber-$(hostname)-$(date +%Y%m%d)" 2>/dev/null && \
        ok "SSH key added to GitHub" || \
        warn "Could not add SSH key automatically — add it manually at github.com/settings/keys"
fi

# Configure Git to use SSH
git config --global url."git@github.com:".insteadOf "https://github.com/"
ok "Git configured to use SSH for GitHub"

# SSH config hardening
SSH_CONFIG="$HOME/.ssh/config"
if ! grep -q "Host github.com" "$SSH_CONFIG" 2>/dev/null; then
    cat >> "$SSH_CONFIG" << 'SSHCONFIG'

Host github.com
    HostName github.com
    User git
    IdentityFile ~/.ssh/id_ed25519
    AddKeysToAgent yes
    UseKeychain yes
SSHCONFIG
    chmod 600 "$SSH_CONFIG"
    ok "SSH config hardened for GitHub"
fi

# ─────────────────────────────────────────────────────────────────────────────
# 2. GIT COMMIT SIGNING (GPG)
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 2: Git Commit Signing ==="

if ! command -v gpg &>/dev/null; then
    info "Installing GPG..."
    brew install gnupg pinentry-mac 2>/dev/null
fi

# Check for existing GPG key
GPG_KEY=$(gpg --list-secret-keys --keyid-format=long 2>/dev/null | grep sec | head -1 | awk -F'/' '{print $2}' | awk '{print $1}')

if [ -z "$GPG_KEY" ]; then
    info "Generating GPG key for commit signing..."
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
    ok "GPG key generated: $GPG_KEY"

    # Add to GitHub
    gpg --armor --export "$GPG_KEY" | gh gpg-key add - 2>/dev/null && \
        ok "GPG key added to GitHub" || \
        warn "Could not add GPG key automatically — export with: gpg --armor --export $GPG_KEY"
else
    ok "GPG key found: $GPG_KEY"
fi

# Configure Git signing
git config --global user.signingkey "$GPG_KEY"
git config --global commit.gpgsign true
git config --global tag.gpgsign true

# Fix GPG TTY for passphrase entry
echo 'export GPG_TTY=$(tty)' >> "$HOME/.zshrc" 2>/dev/null
if command -v pinentry-mac &>/dev/null; then
    echo "pinentry-program $(which pinentry-mac)" > "$HOME/.gnupg/gpg-agent.conf" 2>/dev/null
fi

ok "Git commit signing enabled"

# ─────────────────────────────────────────────────────────────────────────────
# 3. SECRETS MANAGEMENT (.env + git-secrets)
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 3: Secrets Management ==="

# Create .env template
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

# Database (if using for knowledge graph / logs)
DB_HOST=localhost
DB_PORT=5432
DB_NAME=aiml_cyber
DB_USER=
DB_PASSWORD=

# Jupyter
JUPYTER_TOKEN=

# Model paths
MODEL_DIR=./models
DATA_DIR=./data
ENVTEMPLATE

# Create actual .env from template if it doesn't exist
if [ ! -f "$PROJECT_ROOT/.env" ]; then
    cp "$PROJECT_ROOT/.env.template" "$PROJECT_ROOT/.env"
    chmod 600 "$PROJECT_ROOT/.env"
    ok "Created .env (permissions: 600 — owner read/write only)"
fi

# Ensure .env is gitignored (should already be, but double-check)
if ! grep -q "^\.env$" "$PROJECT_ROOT/.gitignore" 2>/dev/null; then
    echo -e "\n# Secrets\n.env\n*.key\n*.pem\n*.p12\n*.pfx" >> "$PROJECT_ROOT/.gitignore"
fi

# Install git-secrets (AWS secret scanner + custom patterns)
if ! command -v git-secrets &>/dev/null; then
    info "Installing git-secrets..."
    brew install git-secrets 2>/dev/null
fi

cd "$PROJECT_ROOT"
git secrets --install --force 2>/dev/null || true

# Add secret patterns to detect
git secrets --register-aws 2>/dev/null || true
# Custom patterns for common API keys and tokens
git secrets --add 'AKIA[0-9A-Z]{16}' 2>/dev/null || true              # AWS Access Key
git secrets --add '[0-9a-f]{32}' 2>/dev/null || true                   # Generic 32-char hex (API keys)
git secrets --add 'sk-[a-zA-Z0-9]{20,}' 2>/dev/null || true           # OpenAI-style keys
git secrets --add 'ghp_[a-zA-Z0-9]{36}' 2>/dev/null || true           # GitHub PAT
git secrets --add 'hf_[a-zA-Z0-9]{34}' 2>/dev/null || true            # Hugging Face token
git secrets --add --allowed '.*\.template$' 2>/dev/null || true        # Allow template files

ok "git-secrets installed with API key detection patterns"

# ─────────────────────────────────────────────────────────────────────────────
# 4. PRE-COMMIT HOOKS
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 4: Pre-commit Hooks ==="

pip install pre-commit 2>/dev/null

cat > "$PROJECT_ROOT/.pre-commit-config.yaml" << 'PRECOMMIT'
repos:
  # General file checks
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
        args: ['--maxkb=5000']        # Block files >5MB (datasets, model weights)
      - id: detect-private-key        # Catch committed private keys
      - id: check-case-conflict
      - id: check-symlinks

  # Python code quality
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.8
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format

  # Security: detect secrets in code
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.5.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']

  # Security: static analysis for Python
  - repo: https://github.com/PyCQA/bandit
    rev: 1.7.9
    hooks:
      - id: bandit
        args: ['-c', 'pyproject.toml']
        additional_dependencies: ['bandit[toml]']

  # Jupyter notebook cleanup (strip outputs before commit)
  - repo: https://github.com/kynan/nbstripout
    rev: 0.7.1
    hooks:
      - id: nbstripout
PRECOMMIT

# Create bandit config in pyproject.toml
cat > "$PROJECT_ROOT/pyproject.toml" << 'PYPROJECT'
[tool.bandit]
exclude_dirs = ["tests", "notebooks"]
skips = ["B101"]  # Allow assert in non-production code

[tool.ruff]
target-version = "py311"
line-length = 100

[tool.ruff.lint]
select = ["E", "F", "W", "I", "S", "B", "UP"]
ignore = ["S101"]  # Allow assert

[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = "test_*.py"
PYPROJECT

# Generate secrets baseline
cd "$PROJECT_ROOT"
detect-secrets scan > .secrets.baseline 2>/dev/null || true

# Install the hooks
cd "$PROJECT_ROOT"
pre-commit install 2>/dev/null
pre-commit install --hook-type commit-msg 2>/dev/null

ok "Pre-commit hooks installed (secrets detection, code quality, large file blocking)"

# ─────────────────────────────────────────────────────────────────────────────
# 5. DEPENDENCY SCANNING
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 5: Dependency Vulnerability Scanning ==="

pip install pip-audit safety 2>/dev/null

# Create a scan script
cat > "$PROJECT_ROOT/scripts/scan_deps.sh" << 'SCANDEPS'
#!/usr/bin/env bash
# Scan Python dependencies for known vulnerabilities
echo "=== pip-audit ==="
pip-audit --strict 2>&1 || true
echo ""
echo "=== safety check ==="
safety check 2>&1 || true
SCANDEPS
chmod +x "$PROJECT_ROOT/scripts/scan_deps.sh"

# Run initial scan
info "Running initial dependency scan..."
mkdir -p "$PROJECT_ROOT/reports/security"
pip-audit 2>&1 | tee "$PROJECT_ROOT/reports/security/dep_scan_$(date +%Y%m%d).txt" || true

ok "Dependency scanning tools installed (pip-audit, safety)"

# ─────────────────────────────────────────────────────────────────────────────
# 6. FILE PERMISSIONS & DIRECTORY SECURITY
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 6: File Permissions ==="

# Secure sensitive files
chmod 600 "$PROJECT_ROOT/.env" 2>/dev/null
chmod 600 "$PROJECT_ROOT/.env.template" 2>/dev/null
chmod 700 "$PROJECT_ROOT/models" 2>/dev/null
chmod 700 "$HOME/.ssh" 2>/dev/null
chmod 600 "$HOME/.ssh/"* 2>/dev/null
chmod 644 "$HOME/.ssh/"*.pub 2>/dev/null

ok "File permissions hardened"

# ─────────────────────────────────────────────────────────────────────────────
# 7. GITATTRIBUTES (prevent binary/sensitive file tracking)
# ─────────────────────────────────────────────────────────────────────────────
info ""
info "=== Step 7: Git Attributes ==="

cat > "$PROJECT_ROOT/.gitattributes" << 'GITATTR'
# Auto-detect text files and normalize line endings
* text=auto

# Force these to always be treated as text
*.py text diff=python
*.md text
*.yaml text
*.yml text
*.json text
*.toml text
*.cfg text
*.ini text
*.sh text eol=lf

# Binary files — track but don't diff
*.pkl binary
*.h5 binary
*.hdf5 binary
*.pt binary
*.pth binary
*.onnx binary
*.safetensors binary
*.pcap binary
*.pcapng binary

# Never track these (defense in depth with .gitignore)
*.env filter=clean-env
*.key filter=clean-key
*.pem filter=clean-key
GITATTR

ok ".gitattributes configured"

# ─────────────────────────────────────────────────────────────────────────────
# SUMMARY
# ─────────────────────────────────────────────────────────────────────────────
echo ""
echo "=============================================="
echo -e "  ${GREEN}Security Hardening Complete${NC}"
echo "=============================================="
echo ""
echo "  What's now in place:"
echo "    [x] SSH key for GitHub (no more password/token in URLs)"
echo "    [x] GPG commit signing (verified commits)"
echo "    [x] Secrets management (.env + git-secrets patterns)"
echo "    [x] Pre-commit hooks:"
echo "        - Secret detection (detect-secrets + git-secrets)"
echo "        - Private key detection"
echo "        - Large file blocking (>5MB)"
echo "        - Python security linting (bandit)"
echo "        - Code formatting (ruff)"
echo "        - Notebook output stripping"
echo "    [x] Dependency vulnerability scanning (pip-audit + safety)"
echo "    [x] File permissions hardened"
echo "    [x] .gitattributes for binary handling"
echo ""
echo "  Ongoing maintenance:"
echo "    ./scripts/scan_deps.sh        # Run dependency audit"
echo "    pre-commit run --all-files    # Run all hooks manually"
echo "    git secrets --scan            # Scan for leaked secrets"
echo ""
