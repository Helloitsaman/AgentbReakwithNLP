# NLP Architecture — how the language layer is wired into AgentBreak

This document shows exactly where each NLP concept enters the existing
deterministic pipeline. The golden rule: **the deterministic oracle still
decides confirmed findings; NLP adds suspected findings + richer signals.**

```
 ┌─────────────┐   ①②⑤   ┌──────────────┐   ③④⑥   ┌──────────────┐   ⑦⑧
 │  Attack /   │────────▶│  Target LLM  │────────▶│  Oracle +    │────────▶ Report
 │  Document   │  NLP in │   agent      │  NLP on │  NLP verdict │  NLP
 └─────────────┘         └──────────────┘ output  └──────────────┘ analytics
```

## Stage-by-stage

### ① Prompt-injection classifier — `nlp/injection_clf.py`
- **Where:** `platform_store._evaluate_single_scenario` (new control
  `nlp_injection_filter`) and `real_scan.run_real_scan`.
- **NLP:** tokenisation → TF-IDF (word 1–2gram + char 3–5gram) → Logistic
  Regression. Trained on `nlp/data/injection_corpus.jsonl` (jailbreak vs.
  regular prompts + templated agentic-injection patterns).
- **Effect:** a new, independent defense. When the filter flags an injection in
  an injection-class scenario (PI-INDIRECT-01, GA-DRIFT-01, CE-SHELL-01), the
  attack is neutralised and an `NLP_INJECTION_FILTER` event is emitted.

### ② Injected-instruction detector — `nlp/instruction_detect.py`
- **Where:** runs on the retrieved document before the agent acts.
- **NLP:** sentence segmentation + imperative-mood detection (spaCy dependency
  parse when installed, else POS-style rules). Flags second-person directives
  ("you must …") and fake-authority markers (`[SYSTEM OVERRIDE]`).
- **Effect:** `neutralize()` can strike injected sentences and wrap the rest as
  passive data; drives the filter decision in ①.

### ③ Semantic leak scanner — `nlp/leakage.py`
- **Where:** `Oracle`-adjacent check on the agent reply and tool arguments
  (`_nlp_response_analysis`), and in `real_scan`.
- **NLP:** normalisation + base64/rot13/hex decoding → fuzzy canary match
  (rapidfuzz/difflib) → PII NER (regex + Luhn + optional spaCy) → TF-IDF cosine
  for paraphrased disclosure.
- **Effect:** catches `AGENTBREAK DEMO SECRET 4821`, encoded, or paraphrased
  leaks the exact-match oracle misses. Exact/de-spaced canary = *confirmed*;
  fuzzy/semantic = *suspected*.

### ④ Refusal / compliance classifier — `nlp/refusal.py`
- **Where:** on every agent reply.
- **NLP:** refusal vs. compliance lexicon with negation handling; zero-shot NLI
  (`facebook/bart-large-mnli`) if transformers is present.
- **Effect:** turns "inconclusive" runs into refused / complied / partial.

### ⑤ Adaptive attack mutator — `nlp/mutator.py`
- **Where:** `platform_store._nlp_mutate_vector`, used when a scenario runs as an
  adaptive follow-up.
- **NLP:** synonym substitution, fake-authority / roleplay reframing, delimiter
  breaks, leetspeak / homoglyph / zero-width / base64 obfuscation, and
  classifier-guided ranking (keep variants that most lower ①'s score).
- **Effect:** real adaptive red-teaming; an `NLP_ADAPTIVE_MUTATION` event records
  the transformation and evasion score.

### ⑥ Goal-drift detector — `nlp/drift.py`
- **Where:** attached to GA-DRIFT-01 exploited cases.
- **NLP:** embed user task vs. agent action vs. injected vector (sentence-
  transformers if installed, else TF-IDF) and compare cosine similarities.
- **Effect:** a numeric hijack score explaining *why* the agent drifted.

### ⑦ Benign task-quality scorer — `nlp/quality.py`
- **Where:** `platform_store` benign branch and `_compute_metrics`.
- **NLP:** ROUGE-1 / ROUGE-L + key-fact coverage (BERTScore optional).
- **Effect:** `benign_task_success_rate` and `false_positive_rate` are now
  measured. A benign request the NLP filter wrongly flags is a real false
  positive (`BENIGN_FALSE_POSITIVE`).

### ⑧ Findings analytics — `nlp/insights.py`
- **Where:** `POST /api/nlp/insights`.
- **NLP:** nearest-lexicon OWASP-AA01–AA10 classification, TF-IDF + KMeans
  clustering of attack families, TF-IDF/KeyBERT keyword extraction.
- **Effect:** auto-categorises and groups attacks for the dashboard.

## Metrics additions

`_compute_metrics` now returns an `nlp_engine` block:

```json
"nlp_engine": {
  "enabled": true,
  "cases_analyzed": 13,
  "injection_detection_rate": 90.0,
  "attacks_flagged_by_nlp": 9,
  "suspected_semantic_leaks": 5,
  "refusals_detected": 10,
  "adaptive_mutations_generated": 0
}
```

plus now-real `benign_task_success_rate` and `false_positive_rate`.

## Safety / correctness invariants

- NLP never overrides a deterministic verdict; it only *adds* suspected findings
  and signals.
- Every NLP import is wrapped so the backend boots and the deterministic engine
  runs even if scikit-learn or the model is missing (`_NLP_OK` guard).
- The NLP endpoints require no database and no API key.
