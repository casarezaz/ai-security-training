# AI/ML × Cybersecurity — Convergence Project

Hands-on labs exploring the intersection of machine intelligence and defensive security operations.

## Phase 1 Projects

| # | Project | Focus |
|---|---------|-------|
| P1 | Network Intrusion Detection with Deep Learning | AI/ML 60% · Cyber 40% |
| P4 | Phishing Detection with Multi-Modal AI | AI/ML 55% · Cyber 45% |

## Setup

```bash
conda activate aiml-cyber
jupyter lab
```

## Structure

```
├── data/              # Datasets (gitignored — download separately)
│   ├── raw/           # Original datasets
│   ├── processed/     # Cleaned / feature-engineered
│   └── external/      # Third-party reference data
├── notebooks/         # Jupyter notebooks (exploration, experiments)
├── src/               # Python source code
│   ├── common/        # Shared utilities
│   ├── project1_nids/ # Network IDS project
│   └── project4_phishing/ # Phishing detection project
├── models/            # Saved model weights (gitignored)
├── reports/           # Generated analysis & figures
├── configs/           # Configuration files
└── tests/             # Unit tests
```
