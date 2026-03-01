# Scenario 4: Incident Response — Compromised ML Pipeline

## Situation

Your security monitoring has detected anomalous behavior in the CI/CD pipeline that builds and deploys your company's fraud detection model. Investigation reveals that an attacker compromised a third-party Python package used in the feature engineering stage. The malicious package has been present for 3 weeks and subtly modifies training features to reduce the model's ability to detect a specific fraud pattern.

## What Makes This Hard

This is a data poisoning attack via supply chain compromise — the most difficult AI attack to detect. The model still performs well on standard metrics (accuracy, AUC), but its detection rate for one specific fraud type has dropped from 94% to 67%. The attacker chose a subtle modification that wouldn't trigger performance monitoring alerts.

## Your Mission

Execute the incident response: contain the compromise, determine the blast radius (which model versions are affected, how much fraud went undetected), remediate the poisoned models, and implement controls to prevent recurrence. You need to brief both the security team AND the ML engineering team.

## Success Criteria

A complete incident response report with timeline, root cause analysis, financial impact estimate, remediation steps taken, and a forward-looking prevention plan that addresses both supply chain security and ML pipeline integrity monitoring.
