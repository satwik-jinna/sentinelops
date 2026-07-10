# Contributing to SentinelOps

Thanks for your interest in this project. It's primarily a portfolio/demo
project, but contributions, issues, and suggestions are welcome.

## Local setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
```

## Running tests

```bash
pytest tests/ -v
```

## Code style

- Keep agent nodes in `agents/nodes.py` as plain functions: `(state) -> dict`.
- Keep tool integrations isolated in `tools/` so they can be swapped for
  real MCP servers or vector stores without touching agent logic.
- Add a test in `tests/` for any new agent behavior.

## Opening a pull request

1. Fork the repo and create a branch off `main`.
2. Make your change with a clear, focused commit.
3. Make sure `pytest tests/ -v` passes locally.
4. Open a PR describing what changed and why.
