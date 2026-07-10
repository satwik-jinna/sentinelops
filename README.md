# SentinelOps

Autonomous security operations agent platform. A LangGraph multi-agent
pipeline that ingests security alerts, investigates them, and decides
whether to auto-remediate, escalate, or close them — with a full audit
trail for compliance.

Matches the architecture: `client -> gateway -> agents -> datastore`,
with external calls to a SIEM feed and threat-intel APIs.

```
security dashboard -> API gateway -> ingestion -> triage -> enrichment
    -> investigation -> decision -> audit -> incident DB
```

## Structure

```
sentinelops/
  agents/
    state.py     # shared graph state (TypedDict passed between nodes)
    nodes.py     # one function per agent (ingestion, triage, ...)
    graph.py     # LangGraph StateGraph wiring the nodes together
  tools/
    mcp_tools.py # mock MCP-style tools: IP reputation, CVE lookup, asset DB
    rag.py       # mock vector store retrieval over past incidents
  api/
    main.py      # FastAPI app exposing POST /alerts
  tests/
    test_graph.py
  requirements.txt
  Dockerfile
  .env.example
```

## Running it

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # add OPENAI_API_KEY if you want real LLM calls
uvicorn api.main:app --reload
```

Then:

```bash
curl -X POST http://localhost:8000/alerts -H "Content-Type: application/json" \
  -d '{"source": "siem", "raw_alert": "Multiple failed logins from 203.0.113.5 followed by successful login"}'
```

Without an `OPENAI_API_KEY` set, the pipeline falls back to a rule-based
stub classifier so the whole graph is runnable and testable with zero
external dependencies — useful for local dev and CI.

## Design notes for interviews

- **Agents are independently testable.** Each node in `agents/nodes.py`
  is a plain function `(state) -> state_updates`, so you can unit test
  triage logic without spinning up the whole graph.
- **Tool calls are isolated in `tools/`.** This is the MCP integration
  seam — swap the mock functions for real MCP server calls without
  touching agent logic.
- **The audit agent is not optional.** Every run produces a reasoning
  trace (`state["trace"]`) regardless of the final decision — this is
  what makes the demo credible for a regulated/security context, not
  just a chatbot with extra steps.
- **Next steps to extend:** add a real vector DB (Pinecone/Chroma) in
  `tools/rag.py`, add prompt-injection detection on `raw_alert` before
  it reaches the LLM (agents ingest untrusted log data), wire real MCP
  servers in `tools/mcp_tools.py`, containerize with the included
  Dockerfile, deploy behind the FastAPI app on Kubernetes.
