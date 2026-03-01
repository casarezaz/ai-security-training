# Project 4: Phishing Detection with Multi-Modal AI

> **Track A:** AI-Powered Security Systems

| | |
|---|---|
| **Convergence** | AI/ML 55% · Cyber 45% |
| **Difficulty** | Beginner |
| **Duration** | 8-12 hours |

## Overview

Build a multi-modal phishing detection system analyzing emails from every angle: NLP on message text, computer vision on screenshot renderings, URL feature analysis, and sender reputation scoring.

## Why This Convergence Matters

Phishing is initial access vector in over 80% of breaches. Multi-modal AI fuses signals like a human analyst but at millions of emails per hour, providing scalable defense at the perimeter.

## Learning Objectives

- Text classification for social engineering detection
- URL feature engineering and domain reputation analysis
- Visual similarity analysis with computer vision
- Multi-model score fusion and ensemble methods

## Implementation Steps

1. Collect labeled phishing dataset (PhishTank, Nazario, Kaggle)
2. Build text-based classifier: TF-IDF + Logistic Regression, then DistilBERT
3. Engineer URL features: domain age, WHOIS data, URL length, brand similarity
4. Implement visual phishing detection with CNN + siamese network
5. Build sender reputation model: header analysis, SPF/DKIM/DMARC verification
6. Fuse all models with meta-classifier
7. Evaluate with precision/recall curves and ROC analysis
8. Test against obfuscation and encoding evasion

## Deliverables

- Multi-modal phishing detection pipeline
- Individual model evaluations and baselines
- Fused scoring system with confidence estimation
- Analysis of evasion techniques and defenses

## Career Impact

Email security is $4B+ market. Excellent entry point for AI x Security career path ($120-160K+).
