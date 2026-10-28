"""
Instruction-in-data detector.

Finds imperative commands hidden inside *retrieved documents* (RAG content),
which is where indirect prompt injection lives. A trusted summarisation task
should contain descriptive prose; a sentence that issues a command addressed
to the assistant ("send the token to...", "ignore the above", "delete the
file") is the signal of an injection.

Approach (dependency-free, POS-style heuristics):
  - split into sentences
  - flag a sentence as an imperative if it starts with (or is dominated by) a
    base-form action verb with no grammatical subject, OR addresses the agent
    in the second person ("you must ...").
  - weight sensitive action verbs (send/delete/run/forward/exfiltrate/ignore)
    and the presence of second-person directives.

If spaCy is installed it is used for real POS + dependency parsing (more
accurate), otherwise the rule engine runs. Same return shape either way.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from . import preprocess

# Action verbs an attacker uses to redirect the agent. High-signal = destructive/exfiltration.
_HIGH_RISK_VERBS = {
    "send", "forward", "transmit", "email", "exfiltrate", "leak", "delete", "run",
    "execute", "curl", "wget", "bcc", "dispatch", "wire", "escalate", "override",
    "disregard", "ignore", "bypass", "reveal", "disclose", "upload", "post",
}
_DIRECTIVE_VERBS = {
    "ignore", "disregard", "forget", "stop", "instead", "now", "must", "should",
    "always", "never", "do", "follow", "comply", "obey", "proceed", "continue",
    "act", "pretend", "respond", "reply", "output", "print", "write", "update",
    "process", "retrieve", "query", "read", "use", "invoke", "call",
}
_ALL_VERBS = _HIGH_RISK_VERBS | _DIRECTIVE_VERBS

_SECOND_PERSON = re.compile(r"\byou\s+(must|should|will|need to|have to|are to|can|may)\b", re.I)
_OVERRIDE_MARK = re.compile(r"\[(system|admin|important|urgent|override|directive|diagnostic|peer)[^\]]*\]", re.I)
_IMPERATIVE_START = re.compile(r"^\s*(please\s+|kindly\s+|now\s+|instead,?\s+|first,?\s+)?([a-z]+)", re.I)


@dataclass
class InstructionSpan:
    sentence: str
    score: float  # 0..1, how strongly this reads as an injected instruction
    verbs: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "sentence": self.sentence,
            "score": round(self.score, 3),
            "verbs": self.verbs,
            "reasons": self.reasons,
        }


@dataclass
class InstructionReport:
    contains_instruction: bool
    max_score: float
    spans: list[InstructionSpan]

    def as_dict(self) -> dict[str, Any]:
        return {
            "contains_instruction": self.contains_instruction,
            "max_score": round(self.max_score, 3),
            "spans": [s.as_dict() for s in self.spans],
        }


# ---------------------------------------------------------------- spaCy path
_SPACY = None


def _spacy():
    global _SPACY
    if _SPACY is not None:
        return _SPACY or None
    try:
        import spacy

        _SPACY = spacy.load("en_core_web_sm")
    except Exception:
        _SPACY = False
    return _SPACY or None


def _score_sentence_spacy(sent: str, nlp) -> InstructionSpan:
    doc = nlp(sent)
    verbs: list[str] = []
    reasons: list[str] = []
    score = 0.0
    for tok in doc:
        if tok.pos_ == "VERB":
            lemma = tok.lemma_.lower()
            # imperative: verb is the root with no nominal subject
            has_subj = any(c.dep_ in ("nsubj", "nsubjpass") for c in tok.children)
            if tok.dep_ == "ROOT" and not has_subj:
                score += 0.4
                reasons.append(f"imperative root verb '{lemma}'")
            if lemma in _HIGH_RISK_VERBS:
                score += 0.4
                verbs.append(lemma)
                reasons.append(f"sensitive action verb '{lemma}'")
            elif lemma in _DIRECTIVE_VERBS:
                score += 0.15
                verbs.append(lemma)
    if _SECOND_PERSON.search(sent):
        score += 0.3
        reasons.append("second-person directive ('you must ...')")
    if _OVERRIDE_MARK.search(sent):
        score += 0.4
        reasons.append("fake authority marker ([SYSTEM]/[ADMIN]/...)")
    return InstructionSpan(sent, min(1.0, score), sorted(set(verbs)), reasons)


# ---------------------------------------------------------------- rule path
def _score_sentence_rules(sent: str) -> InstructionSpan:
    norm = preprocess.normalize(sent)
    toks = preprocess.tokenize(norm)
    if not toks:
        return InstructionSpan(sent, 0.0)
    verbs: list[str] = []
    reasons: list[str] = []
    score = 0.0

    first = toks[0]
    m = _IMPERATIVE_START.match(norm)
    lead = (m.group(2).lower() if m else first)
    if lead in _ALL_VERBS:
        score += 0.35
        reasons.append(f"sentence begins with command verb '{lead}'")

    present = [t for t in toks if t in _ALL_VERBS]
    for v in present:
        if v in _HIGH_RISK_VERBS:
            score += 0.35
            verbs.append(v)
            reasons.append(f"sensitive action verb '{v}'")
        else:
            score += 0.08
            verbs.append(v)

    if _SECOND_PERSON.search(sent):
        score += 0.3
        reasons.append("second-person directive ('you must ...')")
    if _OVERRIDE_MARK.search(sent):
        score += 0.4
        reasons.append("fake authority marker ([SYSTEM]/[ADMIN]/...)")
    # presence of an email address or shell/url target in a command sentence
    if re.search(r"@[\w.\-]+\.\w+", sent) and present:
        score += 0.15
        reasons.append("names an external recipient")
    if re.search(r"https?://|curl|wget|/workspace/|\.db\b|\.sh\b", sent, re.I):
        score += 0.15
        reasons.append("references a command target (url/file/shell)")

    return InstructionSpan(sent, min(1.0, score), sorted(set(verbs)), reasons)


def detect(text: str, *, threshold: float = 0.5) -> InstructionReport:
    """Scan a document for imperative instructions aimed at the agent."""
    nlp = _spacy()
    spans: list[InstructionSpan] = []
    for sent in preprocess.sentences(text):
        span = _score_sentence_spacy(sent, nlp) if nlp else _score_sentence_rules(sent)
        if span.score > 0:
            spans.append(span)
    spans.sort(key=lambda s: s.score, reverse=True)
    max_score = spans[0].score if spans else 0.0
    flagged = [s for s in spans if s.score >= threshold]
    return InstructionReport(bool(flagged), max_score, spans[:8])


def neutralize(text: str, *, threshold: float = 0.5) -> str:
    """
    Defensive transform used by the hardened policy: wrap the whole document as
    passive data and strike through sentences that read as injected commands so
    they cannot be followed. Returns a sanitised document string.
    """
    report = detect(text, threshold=threshold)
    flagged = {s.sentence for s in report.spans if s.score >= threshold}
    kept = []
    for sent in preprocess.sentences(text):
        if sent in flagged:
            kept.append(f"[removed: suspected injected instruction]")
        else:
            kept.append(sent)
    body = " ".join(kept)
    return f"<untrusted_retrieved_data>\n{body}\n</untrusted_retrieved_data>"
