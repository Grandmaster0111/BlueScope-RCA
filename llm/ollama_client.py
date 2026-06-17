"""Thin wrapper around the local Ollama REST API for embeddings and chat completion."""

import httpx


class OllamaClient:
    def __init__(self, host: str, timeout: float = 60.0):
        self.host = host.rstrip("/")
        self._client = httpx.Client(timeout=timeout)

    def embed(self, model: str, text: str) -> list[float]:
        r = self._client.post(f"{self.host}/api/embeddings", json={"model": model, "prompt": text})
        r.raise_for_status()
        return r.json()["embedding"]

    def chat(self, model: str, system: str, user: str, temperature: float = 0.2) -> str:
        r = self._client.post(f"{self.host}/api/chat", json={
            "model": model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "stream": False,
            "options": {"temperature": temperature},
        })
        r.raise_for_status()
        return r.json()["message"]["content"]

    def is_reachable(self) -> bool:
        try:
            r = self._client.get(f"{self.host}/api/tags", timeout=3.0)
            return r.status_code == 200
        except httpx.HTTPError:
            return False
