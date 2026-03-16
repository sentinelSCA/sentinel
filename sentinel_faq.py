import json
import re
from pathlib import Path

FAQ_PATH = Path("knowledge/faq.json")

FALLBACK = "I don’t have information about that in Sentinel’s published FAQ. Please use the contact page for further questions."

def load_faq():
    if not FAQ_PATH.exists():
        return []
    return json.loads(FAQ_PATH.read_text())

def tokenize(text):
    return re.findall(r"[a-zA-Z0-9_]+", text.lower())

def score(question, faq_q, faq_a):
    tokens = tokenize(question)
    hay = (faq_q + " " + faq_a).lower()
    s = 0
    for t in tokens:
        s += hay.count(t)
    return s

def answer_from_faq(question):
    faq = load_faq()

    best = None
    best_score = 0

    for item in faq:
        s = score(question, item["question"], item["answer"])
        if s > best_score:
            best_score = s
            best = item

    if not best or best_score < 2:
        return FALLBACK

    return best["answer"]

if __name__ == "__main__":
    tests = [
        "What is Sentinel SCA?",
        "How does Sentinel secure AI agents?",
        "What are capability tokens?",
        "How much does Sentinel cost?",
        "Who are Sentinel competitors?"
    ]

    for t in tests:
        print("\nQ:", t)
        print("A:", answer_from_faq(t))
