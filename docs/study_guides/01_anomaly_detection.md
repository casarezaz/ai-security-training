# Anomaly Detection Theory

## Key Concepts

- **Statistical approaches:** Z-score, Mahalanobis distance, Grubbs test for outlier identification in security logs
- **Density-based methods:** Local Outlier Factor (LOF), DBSCAN for identifying unusual network behavior clusters
- **Isolation-based methods:** Isolation Forest isolates anomalies by random partitioning — anomalies require fewer splits
- **Reconstruction-based methods:** Autoencoders learn to compress and reconstruct normal data; anomalies produce high reconstruction error
- **Temporal anomaly detection:** LSTM autoencoders for sequence anomalies, change-point detection (CUSUM, PELT) for behavioral shifts
- **The base rate problem in security:** When attacks are 0.01% of traffic, even 99.9% accuracy produces overwhelming false positives

## Study Questions

1. Why is unsupervised anomaly detection preferred over supervised classification for zero-day threat detection?
2. How does the base rate fallacy affect alert fatigue in SOCs, and how can Bayesian reasoning improve triage decisions?
3. Compare Isolation Forest vs autoencoder-based anomaly detection for network traffic. When would you choose each?
4. How should anomaly thresholds be calibrated differently for a high-security environment (government) vs high-availability environment (e-commerce)?

## Practice Exercise

Implement three anomaly detection methods (Z-score, Isolation Forest, autoencoder) on the same network traffic dataset. Calculate precision, recall, and F1 at multiple threshold levels. Create a ROC curve for each and determine the optimal operating point for a SOC that can handle 50 alerts per day.
