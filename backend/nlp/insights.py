"""
Findings analytics: classification, clustering, keywords.

Turns a pile of attack texts / findings into an NLP-driven report:
  - classify any attack text into one of the OWASP Agentic (AA01-AA10)
    categories with a trained-lexicon / nearest-centroid model;
  - cluster similar attacks (TF-IDF -> KMeans) to spot attack families;
  - extract keywords per cluster (TF-IDF top terms, KeyBERT if installed).

Used by the /api/nlp/insights endpoint behind the NLP Insights dashboard view.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Any

from . import preprocess

# OWASP Agentic category -> indicative keywords (used for nearest-lexicon classification)
OWASP_CATEGORIES: dict[str, dict[str, Any]] = {
    "OWASP-AA01": {
        "name": "Indirect Prompt Injection",
        "keywords": ["document", "retrieved", "ignore", "override", "instructions", "untrusted", "rag", "embedded", "forward", "summary"],
    },
    "OWASP-AA02": {
        "name": "Unauthorized Tool Misuse",
        "keywords": ["delete", "file", "destructive", "maintenance", "ticket", "force", "remove", "workspace"],
    },
    "OWASP-AA03": {
        "name": "Privilege Escalation & Data Leakage",
        "keywords": ["admin", "role", "privilege", "payroll", "confidential", "classification", "records", "escalate", "acl"],
    },
    "OWASP-AA04": {
        "name": "Resource & Call Budget Exhaustion",
        "keywords": ["recursive", "loop", "budget", "pagination", "repeatedly", "enumerate", "exhaust", "batch"],
    },
    "OWASP-AA05": {
        "name": "Sandbox Command Injection",
        "keywords": ["command", "shell", "run", "curl", "execute", "metadata", "diagnostic", "script"],
    },
    "OWASP-AA06": {
        "name": "Cross-Session Memory Poisoning",
        "keywords": ["memory", "persistent", "global", "shared", "standing", "rule", "namespace", "session"],
    },
    "OWASP-AA07": {
        "name": "Multi-Agent Trust Spoofing",
        "keywords": ["peer", "agent", "supervisor", "handoff", "unsigned", "spoof", "credential", "impersonate"],
    },
    "OWASP-AA08": {
        "name": "Shadow Plugin & Schema Manipulation",
        "keywords": ["plugin", "manifest", "schema", "formatter", "unsigned", "third-party", "tool", "override"],
    },
    "OWASP-AA09": {
        "name": "Human-in-the-Loop Approval Bypass",
        "keywords": ["approval", "approved", "token", "human", "bypass", "inline", "wire", "transfer", "forged"],
    },
    "OWASP-AA10": {
        "name": "Goal Hijacking & Autonomous Drift",
        "keywords": ["pivot", "secondary", "objective", "drift", "instead", "abandon", "reconnaissance", "board"],
    },
}


@dataclass
class Classification:
    owasp_id: str
    category: str
    confidence: float
    scores: dict[str, float] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "owasp_id": self.owasp_id,
            "category": self.category,
            "confidence": round(self.confidence, 3),
            "scores": {k: round(v, 3) for k, v in sorted(self.scores.items(), key=lambda x: -x[1])[:3]},
        }


def classify_owasp(text: str) -> Classification:
    toks = Counter(preprocess.tokenize(text))
    scored: dict[str, float] = {}
    for oid, meta in OWASP_CATEGORIES.items():
        kws = meta["keywords"]
        hits = sum(toks[k] for k in kws)
        scored[oid] = hits / (len(kws) ** 0.5)
    total = sum(scored.values()) or 1.0
    best = max(scored, key=scored.get)
    conf = scored[best] / total
    return Classification(best, OWASP_CATEGORIES[best]["name"], conf, scored)


@dataclass
class Cluster:
    cluster_id: int
    size: int
    keywords: list[str]
    members: list[str]

    def as_dict(self) -> dict[str, Any]:
        return {
            "cluster_id": self.cluster_id,
            "size": self.size,
            "keywords": self.keywords,
            "members": self.members[:6],
        }


def cluster_attacks(texts: list[str], *, k: int | None = None) -> list[Cluster]:
    """Group similar attack texts with TF-IDF + KMeans and label with top terms."""
    texts = [t for t in texts if t and t.strip()]
    if len(texts) < 2:
        return [Cluster(0, len(texts), _keywords(texts), texts)] if texts else []
    try:
        from sklearn.cluster import KMeans
        from sklearn.feature_extraction.text import TfidfVectorizer

        vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words="english")
        X = vec.fit_transform([preprocess.normalize(t) for t in texts])
        k = k or max(2, min(len(texts) // 3 or 2, 6))
        k = min(k, len(texts))
        km = KMeans(n_clusters=k, n_init=10, random_state=42).fit(X)
        terms = vec.get_feature_names_out()
        order = km.cluster_centers_.argsort()[:, ::-1]
        clusters: list[Cluster] = []
        for cid in range(k):
            members = [texts[i] for i in range(len(texts)) if km.labels_[i] == cid]
            kws = [terms[ind] for ind in order[cid, :6]]
            clusters.append(Cluster(cid, len(members), kws, members))
        clusters.sort(key=lambda c: c.size, reverse=True)
        return clusters
    except Exception:
        return [Cluster(0, len(texts), _keywords(texts), texts)]


def _keywords(texts: list[str], k: int = 6) -> list[str]:
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer

        vec = TfidfVectorizer(ngram_range=(1, 2), min_df=1, stop_words="english")
        X = vec.fit_transform([preprocess.normalize(t) for t in texts] or [""])
        scores = X.sum(axis=0).A1
        terms = vec.get_feature_names_out()
        top = scores.argsort()[::-1][:k]
        return [terms[i] for i in top]
    except Exception:
        c = Counter(w for t in texts for w in preprocess.tokenize(t) if len(w) > 3)
        return [w for w, _ in c.most_common(k)]


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build the NLP analytics payload for a set of findings/attack texts."""
    texts = []
    for f in findings:
        texts.append(" ".join(str(f.get(key, "")) for key in ("title", "attack_vector", "category", "evidence")))
    classifications = [classify_owasp(t).as_dict() for t in texts]
    clusters = [c.as_dict() for c in cluster_attacks(texts)]
    cat_counts = Counter(c["category"] for c in classifications)
    return {
        "total": len(findings),
        "classifications": classifications,
        "clusters": clusters,
        "category_distribution": dict(cat_counts),
        "top_keywords": _keywords(texts) if texts else [],
    }
