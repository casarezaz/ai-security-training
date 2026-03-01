# Scenario 1: Nation-State APT Detection Using ML

## Situation

Your organization's threat intelligence team has identified indicators that a sophisticated nation-state actor (APT-level) has been operating inside the network for an estimated 3-6 months. Traditional detection tools found nothing. Leadership wants an AI-powered hunt to find the intrusion, scope the compromise, and establish ongoing detection capabilities.

## What Makes This Hard

APT actors specifically design their TTPs to evade ML-based detection: they mimic normal user behavior, use living-off-the-land binaries, encrypt C2 traffic to look like legitimate HTTPS, and operate slowly to avoid triggering anomaly thresholds.

## Your Mission

Design an ML-powered threat hunting methodology. Specify which data sources you'd collect (authentication logs, DNS, proxy, endpoint telemetry, email). Detail which models you'd train and on what features. Explain how you'd handle the adversary's evasion of your models. Define detection coverage in terms of MITRE ATT&CK techniques.

## Success Criteria

A comprehensive hunt plan that identifies the TTPs most likely used by the threat actor, maps detection models to each TTP, accounts for adversarial evasion, and includes a 90-day continuous monitoring plan with ML-powered alerting.
