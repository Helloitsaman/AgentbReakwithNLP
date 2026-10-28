"""
AgentBreak NLP package.

Adds natural-language-processing intelligence on top of the deterministic
security engine. Every module works offline with scikit-learn and the Python
standard library; heavier models (transformers, spaCy) are optional and are
only used when installed. The deterministic oracle stays the source of
*confirmed* findings — NLP results are always surfaced as *suspected* findings
with a confidence score, so the platform's zero-false-positive guarantee holds.

Pipeline coverage:
  preprocess        - normalisation, tokenisation, sentence split, decoding
  injection_clf     - TF-IDF + Logistic Regression prompt-injection classifier
  instruction_detect- imperative-instruction-in-data detector (POS-style rules)
  leakage           - fuzzy canary + PII NER + semantic similarity leak checks
  refusal           - refusal / compliance classifier (lexicon + optional NLI)
  mutator           - adversarial paraphrase / obfuscation / back-translation
  drift             - goal-drift detection via embedding cosine similarity
  quality           - benign task quality (ROUGE-style) + false-positive logic
  insights          - OWASP classification, clustering, keywords, analytics
"""

from __future__ import annotations

__all__ = [
    "preprocess",
    "injection_clf",
    "instruction_detect",
    "leakage",
    "refusal",
    "mutator",
    "drift",
    "quality",
    "insights",
]

__version__ = "1.0.0"
