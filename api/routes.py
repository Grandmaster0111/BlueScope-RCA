import tempfile
from pathlib import Path

from fastapi import APIRouter, File, HTTPException, Request, UploadFile
from pydantic import BaseModel

from rca.pipeline import analyze_capture

router = APIRouter()


class AnalyzePathRequest(BaseModel):
    path: str


@router.post("/rca/analyze")
async def analyze_upload(request: Request, file: UploadFile = File(...)):
    """Analyze an uploaded .btsnoop capture file."""
    cfg = request.app.state.config
    data = await file.read()
    with tempfile.NamedTemporaryFile(suffix=".btsnoop", delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        return _run_analysis(request, tmp_path, cfg)
    finally:
        Path(tmp_path).unlink(missing_ok=True)


@router.post("/rca/analyze-path")
async def analyze_path(request: Request, body: AnalyzePathRequest):
    """Analyze a .btsnoop capture file already present on the server filesystem."""
    cfg = request.app.state.config
    if not Path(body.path).exists():
        raise HTTPException(status_code=404, detail=f"No such file: {body.path}")
    return _run_analysis(request, body.path, cfg)


def _run_analysis(request: Request, path: str, cfg):
    if request.app.state.retriever is None:
        raise HTTPException(status_code=503, detail=(
            "RAG retriever not ready -- Ollama unreachable or the embedding "
            f"model '{cfg.embed_model}' isn't pulled yet. Check /api/status."
        ))
    try:
        return analyze_capture(
            path=path,
            retriever=request.app.state.retriever,
            client=request.app.state.ollama,
            llm_model=cfg.llm_model,
            top_k=cfg.retrieval_top_k,
            max_failures=cfg.max_failures_per_capture,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/status")
async def status(request: Request):
    cfg = request.app.state.config
    reachable = request.app.state.ollama.is_reachable()
    return {
        "server": "ok",
        "ollama_reachable": reachable,
        "llm_model": cfg.llm_model,
        "embed_model": cfg.embed_model,
        "corpus_chunks": len(request.app.state.retriever.chunks) if request.app.state.retriever else 0,
    }
