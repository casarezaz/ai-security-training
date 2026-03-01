# Scenario 2: Securing a Medical AI Deployment

## Situation

A hospital network is deploying an AI system that reads chest X-rays to flag potential pneumonia cases for radiologist review. The system processes 2,000 images daily and must be HIPAA-compliant. Before go-live, the CISO has requested a security assessment of the entire ML pipeline.

## What Makes This Hard

The system touches PHI (protected health information) at every stage: training data, model weights (which may memorize patient data), inference inputs, and predictions. Adversarial attacks could cause missed diagnoses. The model was fine-tuned from a publicly available pre-trained model (supply chain risk). The system connects to hospital PACS systems (network attack surface).

## Your Mission

Produce a security assessment covering the full ML lifecycle: training data provenance and access controls, model security (adversarial robustness, extraction resistance, memorization risk), inference pipeline hardening, network security of integrations, and HIPAA compliance mapping. Include specific, actionable recommendations prioritized by risk.

## Success Criteria

A security assessment report that a CISO can act on immediately, with findings mapped to HIPAA requirements, NIST AI RMF, and specific remediation steps with estimated effort and timelines.
