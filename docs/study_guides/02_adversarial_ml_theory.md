# Adversarial Machine Learning Theory

## Key Concepts

- **Threat model taxonomy:** Evasion (test-time attacks), poisoning (training-time), model extraction (stealing), inference (privacy attacks)
- **Gradient-based attacks:** FGSM uses the sign of the loss gradient; PGD iterates with projection back to epsilon-ball; C&W optimizes for minimal perturbation
- **Robustness-accuracy tradeoff:** Adversarial training improves robustness but reduces clean accuracy (Tsipras et al. 2019 proved this is inherent)
- **Certified defenses:** Randomized smoothing provides provable robustness guarantees within a certified radius — but the radius is often too small for practical use
- **Real-world adversarial examples:** Physical-world attacks on autonomous vehicles, adversarial patches, audio adversarial examples
- **Defenses in depth:** No single defense is sufficient. Layer input preprocessing, adversarial training, detection networks, and certified methods

## Study Questions

1. Why is Lp-norm bounded perturbation the standard threat model, and what are its limitations for real-world attacks?
2. Explain why adversarial training with PGD is considered the strongest empirical defense. What is its computational cost?
3. How do transfer attacks work, and why is this problematic for black-box deployed models?
4. The robustness-accuracy tradeoff suggests we can't have both. How should a security practitioner balance this for a malware classifier?

## Practice Exercise

Take a pre-trained ImageNet classifier. Implement FGSM at epsilon values of 0.01, 0.03, 0.05, 0.1, and 0.3. Plot clean accuracy vs robust accuracy. Then implement adversarial training at each epsilon level and re-measure. Graph the results and identify the optimal epsilon for adversarial training.
