# Security-Aware ML System Design

## Key Concepts

- **ML attack surfaces:** Training data, model weights, inference API, feature pipeline, model serving infrastructure, monitoring systems
- **Data security:** Poisoning detection (activation clustering, spectral signatures), data provenance tracking, training data access controls
- **Model security:** Weight encryption at rest and in transit, model watermarking for IP protection, access controls on inference APIs
- **Inference security:** Rate limiting to prevent model extraction, input validation to filter adversarial queries, output perturbation for privacy
- **Pipeline security:** Dependency scanning, code signing for training scripts, immutable training environments, reproducible builds
- **Monitoring:** Drift detection (data drift, concept drift, adversarial drift), performance degradation alerts, anomalous query pattern detection

## Study Questions

1. Design a threat model for an ML-powered fraud detection system. What are the attack vectors, and who are the threat actors?
2. How would you detect if an attacker was slowly poisoning your training data over weeks to shift the decision boundary?
3. What monitoring would you implement to detect model extraction attacks against a production API?
4. How does the NIST AI Risk Management Framework map to practical security controls for ML systems?

## Practice Exercise

Create a complete threat model for an ML-powered medical diagnosis system. Identify at least 10 attack vectors, rate each by likelihood and impact, map each to MITRE ATLAS, and propose specific mitigations. Present this as a one-page risk matrix.
