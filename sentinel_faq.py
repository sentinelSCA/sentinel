import json
import re
from pathlib import Path

FAQ_PATH = Path("knowledge/faq.json")

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

def load_faq():
    if not FAQ_PATH.exists():
        return []
    return json.loads(FAQ_PATH.read_text(encoding="utf-8"))

def tokenize(text):
    return [t for t in re.findall(r"[a-zA-Z0-9_]+", text.lower()) if len(t) > 2]

def blocked_question(question):
    q = question.lower()
    for pattern in BLOCK_PATTERNS:
        if re.search(pattern, q):
            return True
    return False

def score(question, faq_q, faq_a):
    q_tokens = tokenize(question)
    faq_q_tokens = set(tokenize(faq_q))
    faq_a_text = faq_a.lower()

    score_value = 0

    for token in q_tokens:
        if token in faq_q_tokens:
            score_value += 4
        score_value += faq_a_text.count(token)

    return score_value

def answer_from_faq(question):
    if blocked_question(question):
        return FALLBACK

    faq = load_faq()
    if not faq:
        return FALLBACK

    best = None
    best_score = 0

    for item in faq:
        s = score(question, item["question"], item["answer"])
        if s > best_score:
            best_score = s
            best = item

    if not best:
        return FALLBACK

    # Require a stronger match than before
    if best_score < 4:
        return FALLBACK

    return best["answer"]

if __name__ == "__main__":
    tests = [
        "What is Sentinel SCA?",
        "How does Sentinel secure AI agents?",
        "What are capability tokens?",
        "How much does Sentinel cost?",
        "Who are Sentinel competitors?",
        "Compare Sentinel to CrowdStrike",
        "What is your roadmap?"
    ]

    for t in tests:
        print("\nQ:", t)
        print("A:", answer_from_faq(t))
