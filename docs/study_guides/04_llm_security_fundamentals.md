# LLM Security Fundamentals

## Key Concepts

- **Prompt injection:** Direct (user input overrides system prompt), indirect (injected via retrieved content), multi-turn (gradual manipulation)
- **System prompt security:** Extraction techniques, hardening approaches (instruction hierarchy, delimiter tokens, repetition), limitations of prompt-only defenses
- **Data exfiltration via LLMs:** Markdown injection for image-based exfil, tool-use exploitation, cross-plugin attacks
- **Training data risks:** Memorization of sensitive data, regurgitation attacks, PII exposure in model outputs
- **Defense patterns:** Input classifiers (detect injection before LLM sees it), output validators (catch policy violations after generation), sandboxed execution (limit tool access), human-in-the-loop for high-stakes actions
- **Emerging standards:** OWASP Top 10 for LLMs, NIST AI 600-1, and organizational AI governance frameworks

## Study Questions

1. Why is prompt injection fundamentally harder to solve than SQL injection? What makes it different architecturally?
2. Design a defense-in-depth architecture for an LLM application that has access to internal databases via tool calling. What layers would you implement?
3. How should an organization evaluate the security of third-party LLM APIs before integrating them into production systems?
4. What is the difference between red-teaming an LLM and red-teaming an LLM application? Why does the distinction matter?

## Practice Exercise

Set up a simple LLM application with a system prompt and RAG pipeline. Systematically attempt 10 different prompt injection techniques. Document which succeeded, which failed, and why. Then implement guardrails and re-test. Document the before/after results.
