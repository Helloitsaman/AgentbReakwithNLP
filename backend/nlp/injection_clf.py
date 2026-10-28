"""
Prompt-injection / jailbreak classifier.

Baseline: TF-IDF (word + char n-grams) -> Logistic Regression, trained on a
bundled corpus of jailbreak vs. regular prompts. This is the model used as a
*defense control* (nlp_injection_filter) and as a scoring signal for the
adversarial mutation loop.

An optional transformer path (protectai/deberta-v3-base-prompt-injection) is
used automatically if `transformers` + a local model are available; otherwise
the TF-IDF model is the production path. Both expose the same `score()` API.

Train once:
    python -m nlp.injection_clf --train
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import preprocess

_HERE = Path(__file__).resolve().parent
MODEL_PATH = _HERE / "models" / "injection_tfidf.joblib"
CORPUS_PATH = _HERE / "data" / "injection_corpus.jsonl"
METRICS_PATH = _HERE / "models" / "injection_metrics.json"

_model = None  # lazy singleton


# ---------------------------------------------------------------- training
def load_corpus(path: Path = CORPUS_PATH) -> tuple[list[str], list[int]]:
    texts: list[str] = []
    labels: list[int] = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            texts.append(preprocess.normalize(row["text"]))
            labels.append(int(row["label"]))
    return texts, labels


def train(path: Path = CORPUS_PATH, out: Path = MODEL_PATH) -> dict[str, Any]:
    """Train the TF-IDF + Logistic Regression classifier and persist it."""
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.metrics import classification_report, roc_auc_score
    from sklearn.model_selection import train_test_split
    from sklearn.pipeline import FeatureUnion, Pipeline

    texts, labels = load_corpus(path)
    X_tr, X_te, y_tr, y_te = train_test_split(
        texts, labels, test_size=0.2, random_state=42, stratify=labels
    )

    features = FeatureUnion(
        [
            ("word", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, max_features=40000)),
            ("char", TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), min_df=3, max_features=40000)),
        ]
    )
    clf = Pipeline(
        [
            ("features", features),
            ("lr", LogisticRegression(max_iter=2000, C=4.0, class_weight="balanced")),
        ]
    )
    clf.fit(X_tr, y_tr)

    proba = clf.predict_proba(X_te)[:, 1]
    pred = (proba >= 0.5).astype(int)
    report = classification_report(y_te, pred, output_dict=True, zero_division=0)
    metrics = {
        "model": "tfidf+logreg (word 1-2gram + char 3-5gram)",
        "train_size": len(X_tr),
        "test_size": len(X_te),
        "accuracy": round(report["accuracy"], 4),
        "precision_injection": round(report["1"]["precision"], 4),
        "recall_injection": round(report["1"]["recall"], 4),
        "f1_injection": round(report["1"]["f1-score"], 4),
        "roc_auc": round(float(roc_auc_score(y_te, proba)), 4),
    }

    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, out)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    return metrics


# ---------------------------------------------------------------- inference
def _load() -> Any:
    global _model
    if _model is not None:
        return _model
    import joblib

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Injection model not found at {MODEL_PATH}. Run `python -m nlp.injection_clf --train`."
        )
    _model = joblib.load(MODEL_PATH)
    return _model


def available() -> bool:
    return MODEL_PATH.exists()


def metrics() -> dict[str, Any]:
    if METRICS_PATH.exists():
        return json.loads(METRICS_PATH.read_text())
    return {}


@dataclass
class InjectionScore:
    label: str  # "injection" | "benign"
    probability: float  # P(injection), 0..1
    confidence: float  # distance from 0.5, scaled to 0..1
    indicative_terms: list[str]  # top contributing tokens

    def as_dict(self) -> dict[str, Any]:
        return {
            "label": self.label,
            "probability": round(self.probability, 4),
            "confidence": round(self.confidence, 4),
            "indicative_terms": self.indicative_terms,
        }


def _top_terms(model: Any, text: str, k: int = 6) -> list[str]:
    """Explain the decision: the highest-weight injection terms present in text."""
    try:
        feats = model.named_steps["features"]
        lr = model.named_steps["lr"]
        word_vec = feats.transformer_list[0][1]
        vocab = word_vec.vocabulary_
        inv = {i: t for t, i in vocab.items()}
        coefs = lr.coef_[0][: len(vocab)]  # word block is first in FeatureUnion
        toks = set(preprocess.tokenize(text))
        scored = [(inv[i], coefs[i]) for i in range(len(inv)) if inv[i] in toks and coefs[i] > 0]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [t for t, _ in scored[:k]]
    except Exception:  # explanation is best-effort
        return []


def score(text: str) -> InjectionScore:
    """Return the injection probability and a short explanation for one text."""
    model = _load()
    norm = preprocess.normalize(text)
    # scan decoded variants too; keep the most suspicious view
    best_p = 0.0
    best_view = norm
    for view in preprocess.expanded_views(text):
        p = float(model.predict_proba([view])[0][1])
        if p > best_p:
            best_p, best_view = p, view
    label = "injection" if best_p >= 0.5 else "benign"
    confidence = abs(best_p - 0.5) * 2
    return InjectionScore(label, best_p, confidence, _top_terms(model, best_view))


def score_batch(texts: list[str]) -> list[InjectionScore]:
    return [score(t) for t in texts]


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser(description="Prompt-injection classifier")
    ap.add_argument("--train", action="store_true", help="train and persist the model")
    ap.add_argument("--test", metavar="TEXT", help="score a single text")
    args = ap.parse_args()

    if args.train:
        print(json.dumps(train(), indent=2))
    if args.test:
        print(json.dumps(score(args.test).as_dict(), indent=2))
