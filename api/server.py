import logging

from fastapi import FastAPI

from api.routes import router
from config import Config
from llm.ollama_client import OllamaClient
from rag.retriever import Retriever

logger = logging.getLogger(__name__)


def create_app(config: Config | None = None) -> FastAPI:
    config = config or Config()
    app = FastAPI(title="BlueScope-RCA")
    app.state.config = config

    @app.on_event("startup")
    def _init_state():
        app.state.ollama = OllamaClient(config.ollama_host)
        app.state.retriever = None
        if not app.state.ollama.is_reachable():
            logger.warning("Ollama not reachable at %s -- retriever not initialized", config.ollama_host)
            return
        try:
            app.state.retriever = Retriever(
                corpus_dir=config.corpus_dir,
                cache_path=config.embed_cache_path,
                embed_model=config.embed_model,
                client=app.state.ollama,
            )
        except Exception:
            logger.exception("Failed to build retriever (embedding model '%s' missing?)", config.embed_model)

    app.include_router(router, prefix="/api")
    return app
