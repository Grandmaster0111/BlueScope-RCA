"""
Benchmark harness: scores BlueScope-RCA's two pipeline stages independently
against the labeled synthetic dataset in benchmark/dataset.py.

  1. Detection accuracy -- did rca/rules.py find the right failure (layer,
     kind, code) for each injected case, in the right order, with none
     missed and none spurious?
  2. Explanation accuracy -- for each correctly-detected failure, does the
     LLM's plain-English explanation mention at least one of the expected
     root-cause keywords for that code (a case-insensitive substring
     check against terms drawn from the curated knowledge base)?

Writes benchmark/report.json (machine-readable) and benchmark/report.md
(human-readable) with per-case results and overall accuracy.
"""

import json
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from benchmark.dataset import CASES, build_capture
from config import Config
from ingest.btsnoop import parse_btsnoop
from llm.ollama_client import OllamaClient
from rag.retriever import Retriever
from rca.pipeline import explain_failure
from rca.rules import find_failures


def _detection_results():
    tmp = Path(tempfile.mktemp(suffix=".btsnoop"))
    tmp.write_bytes(build_capture())
    try:
        packets = parse_btsnoop(str(tmp))
        failures = find_failures(packets)
    finally:
        tmp.unlink(missing_ok=True)

    results = []
    for i, case in enumerate(CASES):
        f = failures[i] if i < len(failures) else None
        detected_ok = f is not None and f.layer == case.layer and f.kind == case.kind and f.code_hex == case.code_hex
        results.append({"case": case, "failure": f, "detected_ok": detected_ok})
    return results, len(failures)


def _keyword_match(explanation: str, keywords: list[str]) -> str | None:
    text = explanation.lower()
    for kw in keywords:
        if kw.lower() in text:
            return kw
    return None


def run() -> dict:
    config = Config()
    client = OllamaClient(config.ollama_host)
    if not client.is_reachable():
        raise SystemExit(f"Ollama not reachable at {config.ollama_host}")
    retriever = Retriever(config.corpus_dir, config.embed_cache_path, config.embed_model, client)

    detection, total_detected = _detection_results()
    detection_pass = sum(1 for r in detection if r["detected_ok"])

    case_reports = []
    explanation_pass = 0
    t0 = time.time()
    for r in detection:
        case, f = r["case"], r["failure"]
        entry = {
            "name": case.name,
            "expected": {"layer": case.layer, "kind": case.kind, "code": case.code_hex},
            "detected_ok": r["detected_ok"],
        }
        if r["detected_ok"]:
            result = explain_failure(f, retriever, client, config.llm_model, config.retrieval_top_k)
            matched_kw = _keyword_match(result["explanation"], case.keywords)
            entry["explanation"] = result["explanation"]
            entry["citations"] = result["citations"]
            entry["expected_keywords"] = case.keywords
            entry["matched_keyword"] = matched_kw
            entry["explanation_ok"] = matched_kw is not None
            if matched_kw is not None:
                explanation_pass += 1
        else:
            entry["explanation_ok"] = False
            entry["note"] = "skipped explanation scoring -- detection failed for this case"
        case_reports.append(entry)
    elapsed = time.time() - t0

    n = len(CASES)
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "llm_model": config.llm_model,
        "embed_model": config.embed_model,
        "total_cases": n,
        "total_failures_detected": total_detected,
        "detection_accuracy": round(detection_pass / n, 4),
        "explanation_accuracy": round(explanation_pass / n, 4),
        "elapsed_seconds": round(elapsed, 1),
        "cases": case_reports,
    }
    return report


def _write_markdown(report: dict, path: Path) -> None:
    lines = [
        "# BlueScope-RCA Benchmark Report",
        "",
        f"Run at: {report['timestamp']}",
        f"LLM model: `{report['llm_model']}`  |  Embedding model: `{report['embed_model']}`",
        f"Elapsed: {report['elapsed_seconds']}s for {report['total_cases']} cases",
        "",
        f"**Detection accuracy: {report['detection_accuracy'] * 100:.1f}%** "
        f"({int(report['detection_accuracy'] * report['total_cases'])}/{report['total_cases']})",
        f"**Explanation accuracy: {report['explanation_accuracy'] * 100:.1f}%** "
        f"({int(report['explanation_accuracy'] * report['total_cases'])}/{report['total_cases']})",
        "",
        "Detection accuracy = the rule engine identified the correct layer/kind/code "
        "for the injected failure. Explanation accuracy = the LLM's explanation, for "
        "correctly-detected failures, mentioned at least one expected root-cause keyword.",
        "",
        "## Per-case results",
        "",
        "| Case | Layer | Code | Detected | Explained | Matched keyword |",
        "|---|---|---|---|---|---|",
    ]
    for c in report["cases"]:
        det = "✅" if c["detected_ok"] else "❌"
        exp = "✅" if c.get("explanation_ok") else "❌"
        kw = c.get("matched_keyword") or "-"
        lines.append(f"| {c['name']} | {c['expected']['layer']} | {c['expected']['code']} | {det} | {exp} | {kw} |")

    lines.append("")
    lines.append("## Explanations")
    for c in report["cases"]:
        lines.append(f"\n### {c['name']} ({c['expected']['layer']} {c['expected']['code']})")
        if c["detected_ok"]:
            lines.append(f"\n{c['explanation']}\n")
            lines.append(f"*Citations: {', '.join(c['citations'])}*")
        else:
            lines.append(f"\n_{c.get('note', 'not detected')}_")

    path.write_text("\n".join(lines))


if __name__ == "__main__":
    report = run()
    out_dir = Path(__file__).parent
    (out_dir / "report.json").write_text(json.dumps(report, indent=2))
    _write_markdown(report, out_dir / "report.md")

    print(f"Detection accuracy:   {report['detection_accuracy'] * 100:.1f}%")
    print(f"Explanation accuracy: {report['explanation_accuracy'] * 100:.1f}%")
    print(f"Elapsed: {report['elapsed_seconds']}s")
    print(f"Reports written to {out_dir}/report.json and {out_dir}/report.md")
