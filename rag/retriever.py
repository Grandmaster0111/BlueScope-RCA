"""
Embedding-based retriever over the curated knowledge base.

Chunk embeddings are computed once via Ollama's embedding model and cached
to disk (data/embed_cache.json), keyed by a hash of the corpus content so
edits to the knowledge base automatically invalidate the cache.
"""

import hashlib
import json
from pathlib import Path

import numpy as np

from llm.ollama_client import OllamaClient
from rag.corpus_loader import Chunk, load_corpus


def _corpus_hash(chunks: list[Chunk]) -> str:
    h = hashlib.sha256()
    for c in chunks:
        h.update(c.id.encode())
        h.update(c.text.encode())
    return h.hexdigest()


class Retriever:
    def __init__(self, corpus_dir: str, cache_path: str, embed_model: str, client: OllamaClient):
        self.embed_model = embed_model
        self.client = client
        self.chunks: list[Chunk] = load_corpus(corpus_dir)
        self._by_id: dict[str, Chunk] = {c.id: c for c in self.chunks}
        self._vectors: np.ndarray = self._load_or_build(cache_path)

    def _load_or_build(self, cache_path: str) -> np.ndarray:
        chash = _corpus_hash(self.chunks)
        path = Path(cache_path)

        if path.exists():
            cached = json.loads(path.read_text())
            if cached.get("hash") == chash and cached.get("model") == self.embed_model:
                vecs = cached["embeddings"]
                if len(vecs) == len(self.chunks):
                    return np.array(vecs, dtype=np.float32)

        vectors = [self.client.embed(self.embed_model, c.text) for c in self.chunks]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"hash": chash, "model": self.embed_model, "embeddings": vectors}))
        return np.array(vectors, dtype=np.float32)

    def get_by_id(self, chunk_id: str) -> Chunk | None:
        return self._by_id.get(chunk_id)

    def retrieve(self, query: str, top_k: int = 4, exclude_ids: set[str] | None = None) -> list[Chunk]:
        q = np.array(self.client.embed(self.embed_model, query), dtype=np.float32)
        sims = self._vectors @ q / (np.linalg.norm(self._vectors, axis=1) * np.linalg.norm(q) + 1e-8)
        if exclude_ids:
            for i, c in enumerate(self.chunks):
                if c.id in exclude_ids:
                    sims[i] = -np.inf
        top_idx = np.argsort(-sims)[:top_k]
        return [self.chunks[i] for i in top_idx]
