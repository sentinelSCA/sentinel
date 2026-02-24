import os
import requests

OLLAMA_HOST = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")

def ollama_generate(prompt: str, model: str | None = None, timeout: int = 120) -> str:
    model = model or os.getenv("OLLAMA_MODEL", "llama3")

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
    }

    r = requests.post(f"{OLLAMA_HOST}/api/generate", json=payload, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    return (data.get("response") or "").strip()
