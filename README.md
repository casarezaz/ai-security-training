# AI × Cybersecurity Convergence Training

A comprehensive, hands-on training curriculum built at the intersection of artificial intelligence/machine learning and cybersecurity.

## Overview

This project addresses the critical global shortage of **3.4 million cybersecurity professionals**, specifically targeting the scarce niche of specialists who can both build intelligent defense systems and secure the AI systems organizations deploy.

**Estimated Duration:** 200–275+ hours across 16+ weeks
**Skill Levels:** Beginner → Intermediate → Advanced
**Author:** Angie Casarez-Agee, CISSP | GCIH | GSEC

## Curriculum Structure

### Three Convergence Tracks

| Track | Focus | Projects |
|-------|-------|----------|
| **Track A** | AI-Powered Security Systems | Using ML/AI to enhance threat detection, malware analysis, and security operations |
| **Track B** | Securing AI Systems | Defending against adversarial attacks, model supply chain threats, and LLM vulnerabilities |
| **Track C** | Capstone Integration | End-to-end projects combining both disciplines |

### 12 Hands-On Lab Projects

| # | Project | Difficulty | Hours |
|---|---------|-----------|-------|
| 1 | Network Intrusion Detection with Deep Learning | Intermediate | 12–16 |
| 2 | Malware Classification Engine | Intermediate | 14–18 |
| 3 | Vulnerability Prioritization with ML | Intermediate | 10–14 |
| 4 | Phishing Detection with Multi-Modal AI | Beginner | 8–12 |
| 5 | Threat Intelligence NLP Pipeline | Intermediate | 16–20 |
| 6 | Adversarial Attack & Defense Lab | Intermediate | 10–14 |
| 7 | Model Supply Chain Security | Intermediate | 12–16 |
| 8 | Privacy-Preserving ML for Security | Advanced | 10–14 |
| 9 | LLM Security Framework | Advanced | 12–16 |
| 10 | Detection Engineering with ML | Intermediate | 14–18 |
| 11 | AI-Powered SOC Analyst Assistant | Advanced | 20–25 |
| 12 | Capstone: Full Integration | Advanced | 18–22 |

### 5 Theoretical Study Guides

- Anomaly Detection Theory
- Security-Aware ML System Design
- Adversarial Machine Learning
- Privacy-Preserving Techniques
- LLM Security & Prompt Injection Defense

### 5 Real-World Scenario Exercises

Simulated organizational challenges that test decision-making across both disciplines.

## Learning Roadmap

| Phase | Weeks | Focus |
|-------|-------|-------|
| **Phase 1** | 1–4 | Foundations — Anomaly detection theory, Projects 1 & 4 |
| **Phase 2** | 5–8 | Core Skills — Malware analysis, threat intel, Projects 2 & 5 |
| **Phase 3** | 9–12 | AI Security — Adversarial ML, model security, Projects 6 & 7 |
| **Phase 4** | 13–16 | Advanced — LLM security, privacy, Projects 8, 9 & 10 |
| **Phase 5** | 17+ | Capstone & Differentiation — Projects 11 & 12 |

## Career Paths

This curriculum prepares learners for high-demand roles including:

- AI Red Team Engineer
- ML Security Engineer
- Detection Engineer
- LLM Security Specialist
- AI-Powered SOC Analyst

## Setup

```bash
conda activate aiml-cyber
jupyter lab
```

## Project Structure

```
ai-security-training/
├── README.md
├── requirements.txt
├── .gitignore
├── data/                          # Datasets (not tracked in git)
│   ├── raw/                       # Original datasets
│   ├── processed/                 # Cleaned / feature-engineered
│   └── external/                  # Third-party reference data
├── notebooks/                     # Jupyter notebooks
├── src/                           # Python source code
│   ├── common/                    # Shared utilities
│   ├── project1_nids/             # Network IDS project
│   └── project4_phishing/         # Phishing detection project
├── models/                        # Saved model weights (gitignored)
├── configs/                       # Configuration files
├── scripts/                       # Setup & hardening scripts
├── docker/                        # Docker configurations
├── docs/                          # Study guides & scenario docs
├── reports/                       # Generated analysis & figures
└── tests/                         # Unit tests
```

## Frameworks & Standards Alignment

- [MITRE ATT&CK](https://attack.mitre.org/)
- [MITRE ATLAS](https://atlas.mitre.org/)
- [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence)
- [OWASP Top 10 for LLMs](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built at the convergence of AI and cybersecurity — where the greatest professional impact meets the greatest market need.*
