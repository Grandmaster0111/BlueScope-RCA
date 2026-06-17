"""
Loads the curated knowledge base in rag/corpus/ into flat text chunks
suitable for embedding and retrieval. JSON code tables become one chunk
per code; the markdown file is split into one chunk per section.
"""

import json
from dataclasses import dataclass
from pathlib import Path


@dataclass
class Chunk:
    id: str
    text: str
    source: str


def _load_json_codes(path: Path) -> list[Chunk]:
    data = json.loads(path.read_text())
    layer = data.get("layer", path.stem)
    source = data.get("source", path.name)
    chunks = []

    for table_name, table in data.items():
        if not isinstance(table, dict) or table_name in ("layer", "source"):
            continue
        for code, info in table.items():
            if not isinstance(info, dict):
                continue
            causes = info.get("common_causes") or []
            causes_str = "; ".join(causes) if causes else "none listed"
            text = (
                f"{layer} {table_name.replace('_', ' ')} {code} -- {info.get('name', '')}\n"
                f"Description: {info.get('description', '')}\n"
                f"Common causes: {causes_str}"
            )
            chunks.append(Chunk(id=f"{path.stem}:{table_name}:{code}", text=text, source=source))

    return chunks


def _load_markdown(path: Path) -> list[Chunk]:
    text = path.read_text()
    sections = text.split("\n## ")
    chunks = []
    for i, section in enumerate(sections):
        section = section.strip()
        if not section:
            continue
        if not section.startswith("#"):
            section = "## " + section
        title = section.splitlines()[0].lstrip("# ").strip()
        chunks.append(Chunk(id=f"{path.stem}:{i}:{title}", text=section, source=path.name))
    return chunks


def load_corpus(corpus_dir: str) -> list[Chunk]:
    chunks: list[Chunk] = []
    for path in sorted(Path(corpus_dir).glob("*.json")):
        chunks.extend(_load_json_codes(path))
    for path in sorted(Path(corpus_dir).glob("*.md")):
        chunks.extend(_load_markdown(path))
    return chunks
