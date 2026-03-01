# Privacy & AI Ethics in Security Contexts

## Key Concepts

- **Differential privacy:** Epsilon-delta definitions, composition theorems, the privacy-utility tradeoff curve
- **Federated learning:** Client-server architecture, FedAvg, non-IID data challenges, communication efficiency, secure aggregation
- **Membership inference:** Can an attacker determine if a specific record was in training data? Shadow model attack methodology
- **Model inversion:** Reconstructing training data features from model outputs, particularly dangerous for face recognition models
- **AI surveillance ethics:** Facial recognition bias, predictive policing concerns, the balance between security and civil liberties
- **Regulatory landscape:** GDPR Article 22 (automated decision-making), EU AI Act risk classifications, CCPA, HIPAA implications for ML

## Study Questions

1. A hospital wants to train a disease prediction model across 5 hospitals without sharing patient data. Design the architecture and identify the remaining privacy risks.
2. How does differential privacy protect against membership inference? What epsilon value provides meaningful protection?
3. An employer wants to deploy AI-powered camera monitoring for security. What ethical guardrails should be in place?
4. How should a security team handle the discovery that their threat detection model has learned to profile users based on protected characteristics?

## Practice Exercise

Train a simple classifier on a sensitive dataset (e.g., medical). Implement a membership inference attack and measure the success rate. Then apply differential privacy (DP-SGD) at epsilon = 1, 5, and 10. Re-measure membership inference success at each level. Plot the privacy-accuracy-attack tradeoff.
