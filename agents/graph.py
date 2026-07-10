"""Wires the six agents into a LangGraph StateGraph.

Linear for now (ingestion -> triage -> enrichment -> investigation ->
decision -> audit), matching the architecture diagram. Conditional
routing is the natural next step — e.g. skip enrichment/investigation
for very-low-severity alerts to save latency and cost — added via
`add_conditional_edges` on the `triage` node.
"""

from __future__ import annotations

from langgraph.graph import END, StateGraph

from agents.nodes import (
    audit_agent,
    decision_agent,
    enrichment_agent,
    ingestion_agent,
    investigation_agent,
    triage_agent,
)
from agents.state import AlertState


def build_graph():
    graph = StateGraph(AlertState)

    graph.add_node("ingestion", ingestion_agent)
    graph.add_node("triage", triage_agent)
    graph.add_node("enrichment", enrichment_agent)
    graph.add_node("investigation", investigation_agent)
    graph.add_node("decision", decision_agent)
    graph.add_node("audit", audit_agent)

    graph.set_entry_point("ingestion")
    graph.add_edge("ingestion", "triage")
    graph.add_edge("triage", "enrichment")
    graph.add_edge("enrichment", "investigation")
    graph.add_edge("investigation", "decision")
    graph.add_edge("decision", "audit")
    graph.add_edge("audit", END)

    return graph.compile()


# Compiled once at import time so the FastAPI app doesn't rebuild the
# graph on every request.
sentinelops_graph = build_graph()
