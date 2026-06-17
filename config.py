import os
from dataclasses import dataclass


@dataclass
class Config:
    ollama_host: str = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    llm_model: str = os.environ.get("RCA_LLM_MODEL", "llama3.2:latest")
    embed_model: str = os.environ.get("RCA_EMBED_MODEL", "nomic-embed-text")

    corpus_dir: str = os.path.join(os.path.dirname(__file__), "rag", "corpus")
    embed_cache_path: str = os.path.join(os.path.dirname(__file__), "data", "embed_cache.json")

    retrieval_top_k: int = 4
    max_failures_per_capture: int = 25  # safety cap on LLM calls per request

    host: str = os.environ.get("RCA_HOST", "0.0.0.0")
    port: int = int(os.environ.get("RCA_PORT", "8800"))
