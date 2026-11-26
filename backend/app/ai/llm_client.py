from __future__ import annotations

import httpx

from app.config import get_settings


def generate_grounded_completion(system_prompt: str, user_prompt: str) -> str | None:
    """Invoke configured LLM provider (OpenAI or Gemini) if credentials exist; otherwise return None for deterministic fallback."""
    settings = get_settings()
    provider = (settings.LLM_PROVIDER or "none").lower()

    if provider == "openai" and settings.OPENAI_API_KEY:
        try:
            with httpx.Client(timeout=20.0) as client:
                resp = client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {settings.OPENAI_API_KEY}"},
                    json={
                        "model": settings.OPENAI_MODEL,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "temperature": 0.1,
                    },
                )
                resp.raise_for_status()
                return resp.json()["choices"][0]["message"]["content"]
        except Exception:
            return None

    if provider == "gemini" and settings.GEMINI_API_KEY:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{settings.GEMINI_MODEL}:generateContent"
            with httpx.Client(timeout=20.0) as client:
                resp = client.post(
                    url,
                    params={"key": settings.GEMINI_API_KEY},
                    json={
                        "system_instruction": {"parts": [{"text": system_prompt}]},
                        "contents": [{"parts": [{"text": user_prompt}]}],
                        "generationConfig": {"temperature": 0.1},
                    },
                )
                resp.raise_for_status()
                candidates = resp.json().get("candidates", [])
                if candidates:
                    return candidates[0]["content"]["parts"][0]["text"]
        except Exception:
            return None

    return None
