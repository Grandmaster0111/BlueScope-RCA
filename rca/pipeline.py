"""Orchestrates the full RCA flow: ingest -> detect -> retrieve -> explain."""

from ingest.btsnoop import parse_btsnoop
from llm.ollama_client import OllamaClient
from rag.retriever import Retriever
from rca.rules import FailureEvent, find_failures

_SYSTEM_PROMPT = (
    "You are a Bluetooth protocol root-cause-analysis assistant embedded in a packet "
    "analyzer. You explain HCI/L2CAP/SMP failures to a firmware/connectivity engineer "
    "in plain English, grounded strictly in the provided specification context.\n\n"
    "The 'Code' and 'Code name' facts below name the ONE failure you must explain. The "
    "context entry tagged [PRIMARY] describes that exact code -- your root cause must "
    "come from it. Every other context entry describes a DIFFERENT code, included only "
    "for background; never state one of them as the cause, and never substitute a "
    "different code's name or description for the one named in 'Code name'. If you "
    "are about to write a root cause that doesn't match 'Code name', stop and rebase it "
    "on the [PRIMARY] entry instead.\n\n"
    "Respond in 2-4 sentences: state the likely root cause(s) for 'Code name' "
    "specifically, then one concrete next debugging step. Do not invent details that "
    "aren't supported by the given context or the packet facts."
)

# Maps a FailureEvent's (layer, kind) to the exact corpus chunk id holding
# that failure's own code, so the LLM is always grounded in the right entry
# instead of relying solely on embedding-similarity ranking (which can rank
# a different code/table above the correct one when codes share a value).
_EXACT_LOOKUP_TABLE = {
    ("L2CAP", "Connect Rejected"): "connect_result_codes",
    ("L2CAP", "Configure Rejected"): "configure_result_codes",
    ("L2CAP", "Command Reject"): "command_reject_reason_codes",
}


def _exact_chunk_id(f: FailureEvent) -> str | None:
    if f.layer == "HCI":
        return f"hci_error_codes:codes:{f.code_hex}"
    if f.layer == "SMP":
        return f"smp_reason_codes:pairing_failed_reason_codes:{f.code_hex}"
    if f.layer == "L2CAP":
        table = _EXACT_LOOKUP_TABLE.get((f.layer, f.kind))
        if table:
            return f"l2cap_result_codes:{table}:{f.code_hex}"
    return None


def _build_query(f: FailureEvent) -> str:
    return f"{f.layer} {f.kind} error code {f.code_hex}"


def _code_name(chunk) -> str | None:
    """Extracts the code's human name from a corpus chunk's first line ('... -- Name')."""
    first_line = chunk.text.splitlines()[0]
    if " -- " in first_line:
        return first_line.split(" -- ", 1)[1].strip()
    return None


def _build_user_prompt(f: FailureEvent, primary, supplementary) -> str:
    parts = []
    if primary is not None:
        parts.append(f"[PRIMARY] [{primary.id}]\n{primary.text}")
    parts.extend(f"[{c.id}]\n{c.text}" for c in supplementary)
    context = "\n\n".join(parts)
    name = _code_name(primary) if primary is not None else None
    facts = [
        f"Layer: {f.layer}",
        f"Event: {f.kind}",
        f"Code: {f.code_hex}",
        f"Code name: {name}" if name else None,
        f"Connection handle: {f.handle}" if f.handle is not None else None,
        f"Additional context: {f.context}" if f.context else None,
        f"Packet #{f.seq} at t={f.ts_us / 1e6:.3f}s in the capture",
    ]
    facts_str = "\n".join(x for x in facts if x)
    reminder = f" Remember: you are explaining {f.code_hex} ({name}) specifically, not any other code." if name else ""
    return (
        f"A Bluetooth packet capture shows the following failure:\n{facts_str}\n\n"
        f"Relevant specification context:\n{context}\n\n"
        f"Explain the likely root cause and suggest one next debugging step.{reminder}"
    )


def explain_failure(f: FailureEvent, retriever: Retriever, client: OllamaClient,
                     llm_model: str, top_k: int) -> dict:
    exact_id = _exact_chunk_id(f)
    primary = retriever.get_by_id(exact_id) if exact_id else None
    exclude = {primary.id} if primary else None
    supplementary = retriever.retrieve(_build_query(f), top_k=top_k, exclude_ids=exclude)

    explanation = client.chat(llm_model, _SYSTEM_PROMPT, _build_user_prompt(f, primary, supplementary))
    citations = ([primary.id] if primary else []) + [c.id for c in supplementary]
    return {
        "layer": f.layer,
        "kind": f.kind,
        "code": f.code_hex,
        "handle": f.handle,
        "context": f.context,
        "packet_seq": f.seq,
        "timestamp_s": round(f.ts_us / 1e6, 6),
        "summary": f.summary,
        "explanation": explanation.strip(),
        "citations": citations,
    }


def analyze_capture(path: str, retriever: Retriever, client: OllamaClient,
                     llm_model: str, top_k: int, max_failures: int) -> dict:
    packets = parse_btsnoop(path)
    all_failures = find_failures(packets)
    failures = all_failures[:max_failures]

    results = [explain_failure(f, retriever, client, llm_model, top_k) for f in failures]

    return {
        "total_packets": len(packets),
        "failure_count": len(all_failures),
        "analyzed_count": len(results),
        "failures": results,
    }
