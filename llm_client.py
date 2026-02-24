import os
import requests

def llm_generate(prompt: str) -> str:
    """
    If OPENAI_API_KEY is set, call OpenAI (via HTTP) later.
    For now: return a deterministic placeholder so system stays stable.
    """
    # Phase 0: placeholder (no external dependency)
    return f"[DRAFT]\n{prompt}\n\n(LLM not wired yet)"
