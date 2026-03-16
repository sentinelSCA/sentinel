import json
import re
from pathlib import Path

FAQ_PATH = Path("knowledge/faq.json")
ALIASES_PATH = Path("knowledge/faq_aliases.json")

FALLBACK = "I don’t have information about that in Sentinel’s published FAQ. Please use the contact page for further questions."

BLOCK_PATTERNS = [
    r"\bcompare\b",
    r"\bcompetitor\b",
    r"\bcompetitors\b",
    r"\bversus\b",
    r"\bvs\b",
    r"\broadmap\b",
    r"\bfuture\b",
    r"\bnext year\b",
    r"\blegal\b",
    r"\blawsuit\b",
    r"\bguarantee\b",
    r"\bcustomers\b",
    r"\bwho uses\b",
]

SYNONYMS = {
    "security": ["secure", "protection"],
    "architecture": ["layers", "pipeline", "structure"],
    "authenticate": ["identity", "sign", "signature", "verified", "verify"],
    "cost": ["price", "pricing"],
    "agent": ["ai", "bot", "automation"],
}

def normalize(text: str) -> str:
    text = text.lower().strip()
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text

def load_faq():
    if not FAQ_PATH.exists():
        return []
    return json.loads(FAQ_PATH.read_text(encoding="utf-8"))

def load_aliases():
    if not ALIASES_PATH.exists():
        return {}
    return json.loads(ALIASES_PATH.read_text(encoding="utf-8"))

def tokenize(text):
    tokens = re.findall(r"[a-zA-Z0-9_]+", text.lower())
    expanded = []
    for t in tokens:
        expanded.append(t)
        for k, syns in SYNONYMS.items():
            if t == k or t in syns:
                expanded.append(k)
    return expanded

def blocked_question(question):
    q = question.lower()
    for pattern in BLOCK_PATTERNS:
        if re.search(pattern, q):
            return True
    return False

def alias_match(question, faq):
    aliases = load_aliases()
    qn = normalize(question)
    if qn not in aliases:
        return None
    target_q = aliases[qn]
    for item in faq:
        if item.get("question") == target_q:
            return item
    return None

def score(question, faq_q, faq_a):
    q_tokens = tokenize(question)
    faq_text = (faq_q + " " + faq_a).lower()
    score_value = 0
    for token in q_tokens:
        score_value += faq_text.count(token)
    return score_value

def answer_from_faq(question):
    if blocked_question(question):
        return FALLBACK

    faq = load_faq()
    if not faq:
        return FALLBACK

    aliased = alias_match(question, faq)
    if aliased:
        return aliased["answer"]

    best = None
    best_score = 0

    for item in faq:
        s = score(question, item["question"], item["answer"])
        if s > best_score:
            best_score = s
            best = item

    if not best or best_score < 3:
        return FALLBACK

    return best["answer"]

if __name__ == "__main__":
    tests = [
        "What is Sentinel?",
        "What does Sentinel do?",
        "How does Sentinel work?",
        "How are agents verified?",
        "What is Sentinel pricing?",
        "Compare Sentinel to CrowdStrike"
    ]

    for t in tests:
        print("\\nQ:", t)
        print("A:", answer_from_faq(t))
