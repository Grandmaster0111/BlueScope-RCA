# BlueScope-RCA

An on-device LLM layer for [BlueScope](../bluescope) that performs automated
root cause analysis on Bluetooth connection failures and anomalies. It reads
a raw `.btsnoop` capture, decodes the HCI/L2CAP/SMP layers itself, detects
known failure signatures (non-zero status/result codes), grounds each one in
a curated Bluetooth Core Specification knowledge base via RAG, and asks a
local quantized LLM to produce a plain-English explanation -- no cloud
dependency, so capture traces never leave the machine.

## How it works

```
.btsnoop file
     │
     ▼
ingest/btsnoop.py     -- decode HCI packet stream (CMD/EVT/ACL/SCO/ISO)
     │
     ▼
rca/rules.py           -- detect failure signatures across HCI / L2CAP / SMP
     │
     ▼
rag/retriever.py       -- embed the failure + retrieve relevant spec context
     │  (Ollama: nomic-embed-text, cosine similarity over rag/corpus/)
     ▼
rca/pipeline.py         -- prompt a local LLM with facts + retrieved context
     │  (Ollama: llama3.2)
     ▼
structured RCA report (JSON)
```

Failure detection covers:
- **HCI**: Connection Complete / Disconnection Complete / Command
  Complete / Command Status / Encryption Change / LE Connection Complete
  (and Enhanced) with non-zero status, plus non-benign disconnect reasons.
- **L2CAP**: Connection Response rejections (PSM not supported, security
  block, etc.), Configuration Response rejections, Connection Parameter
  Update rejections, Command Reject.
- **SMP**: Pairing Failed PDUs (passkey failure, auth requirements,
  confirm value mismatch, etc.).

The knowledge base (`rag/corpus/`) is a curated set of HCI controller error
codes, L2CAP result codes, and SMP pairing failure reasons (Bluetooth Core
Spec Vol 1 Part F, Vol 3 Part A, Vol 3 Part H), plus a markdown file of
common multi-layer failure narratives (connection parameter negotiation,
L2CAP rejections, pairing failures, page vs. connection timeout, MIC
failures, LE establishment failures).

## Requirements

- Python 3.10+
- [Ollama](https://ollama.com) running locally, with:
  ```bash
  ollama pull llama3.2        # or any other instruct model
  ollama pull nomic-embed-text
  ```

## Installation

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

## Usage

```bash
.venv/bin/python serve.py
```

Then either upload a capture file:

```bash
curl -F file=@/path/to/capture.btsnoop http://localhost:8800/api/rca/analyze
```

or analyze a file already on disk (e.g. one downloaded from bluescope):

```bash
curl -X POST http://localhost:8800/api/rca/analyze-path \
  -H 'Content-Type: application/json' \
  -d '{"path": "/home/you/Desktop/projects/bluescope/captures/run_16_hci.btsnoop"}'
```

### No hardware needed -- synthetic test capture

```bash
.venv/bin/python samples/make_synthetic_capture.py
curl -F file=@samples/synthetic_failures.btsnoop http://localhost:8800/api/rca/analyze
```

This generates a capture with four deliberate failures (BR/EDR page
timeout, LE connection timeout disconnect, L2CAP PSM-not-supported
rejection, SMP pairing failure) to exercise the full pipeline.

### Response shape

```json
{
  "total_packets": 9,
  "failure_count": 4,
  "analyzed_count": 4,
  "failures": [
    {
      "layer": "HCI",
      "kind": "Connection Complete Failed",
      "code": "0x04",
      "handle": 0,
      "packet_seq": 3,
      "timestamp_s": 0.004,
      "explanation": "...",
      "citations": ["hci_error_codes:codes:0x04"]
    }
  ]
}
```

## Configuration

Environment variables (see `config.py`):

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_HOST` | `http://localhost:11434` | Ollama server URL |
| `RCA_LLM_MODEL` | `llama3.2:latest` | Model used for explanations |
| `RCA_EMBED_MODEL` | `nomic-embed-text` | Model used for RAG retrieval |
| `RCA_HOST` / `RCA_PORT` | `0.0.0.0` / `8800` | Server bind address |

## Project layout

```
BlueScope-RCA/
├── serve.py              # Entry point
├── config.py              # Runtime configuration
├── ingest/
│   └── btsnoop.py          # Standalone .btsnoop decoder
├── rca/
│   ├── rules.py             # Failure signature detection
│   └── pipeline.py           # Detect -> retrieve -> explain orchestration
├── rag/
│   ├── corpus/                # Curated HCI/L2CAP/SMP knowledge base
│   ├── corpus_loader.py        # Chunking
│   └── retriever.py             # Embedding + cosine-similarity retrieval
├── llm/
│   └── ollama_client.py          # Ollama REST API wrapper
├── api/
│   ├── server.py                  # FastAPI app
│   └── routes.py                   # /api/rca/analyze, /api/status
└── samples/
    └── make_synthetic_capture.py    # Generates a test capture, no HW needed
```

## API endpoints

| Method | Path | Description |
|---|---|---|
| `POST` | `/api/rca/analyze` | Upload a `.btsnoop` file, get back an RCA report |
| `POST` | `/api/rca/analyze-path` | Analyze a capture already on the server filesystem |
| `GET` | `/api/status` | Server health, Ollama reachability, corpus size |
