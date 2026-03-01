# Project 1: Network Intrusion Detection with Deep Learning

> **Track A:** AI-Powered Security Systems

| | |
|---|---|
| **Convergence** | AI/ML 60% · Cyber 40% |
| **Difficulty** | Intermediate |
| **Duration** | 12-16 hours |

## Overview

Build an intelligent network intrusion detection system (NIDS) that classifies network traffic in real-time using deep learning. Move beyond signature-based detection to catch zero-day attacks by learning the statistical patterns of normal vs malicious traffic.

## Why This Convergence Matters

Traditional IDS relies on known attack signatures and misses novel threats. ML-based IDS learns what "normal" looks like and flags deviations, catching zero-day exploits that signature-based systems cannot. This is the foundational use case where AI transforms cybersecurity.

## Learning Objectives

- Master network packet feature engineering
- Train anomaly detection and classification models on network flow data
- Handle extreme class imbalance
- Evaluate with security-relevant metrics (detection rate, false alarm rate, time-to-detect)

## Implementation Steps

1. Load and explore the CICIDS2017 or NSL-KDD dataset — understand what each network flow feature represents
2. Engineer security-specific features: entropy of packet sizes, connection burst rates, port scan detection features, DNS query anomalies
3. Build baseline classifiers: Random Forest and XGBoost on tabular flow features
4. Implement a 1D-CNN that processes raw packet byte sequences
5. Build an autoencoder trained ONLY on normal traffic for zero-day detection
6. Implement a streaming pipeline: simulate real-time packet capture
7. Build an alert triage dashboard with MITRE ATT&CK mapping
8. Test against adversarial evasion

## Deliverables

- Working NIDS with multiple detection models
- Real-time streaming detection pipeline
- Alert triage dashboard
- Adversarial robustness evaluation report

## Career Impact

Network detection engineering is the backbone of every SOC. AI-powered NIDS roles command $140-180K+.
