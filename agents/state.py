"""Shared state passed between every node in the SentinelOps graph.

Keeping this as a single TypedDict (LangGraph's recommended pattern)
means each agent only reads the keys it needs and writes the keys it
owns — nobody needs the full picture to be tested in isolation.
"""

from __future__ import annotations

from typing import Literal, TypedDict


Severity = Literal["low", "medium", "high", "critical"]
Action = Literal["auto_remediate", "escalate", "close_false_positive"]

"""
AlertState is the single source of truth passed between every agent
in the graph. Each agent reads only the keys it needs and writes only
the keys it owns, which is what makes every node in agents/nodes.py
independently unit-testable.
"""

class AlertState(TypedDict, total=False):
    # --- input ---
    source: str  # e.g. "siem", "edr", "manual"
    raw_alert: str  # unstructured text as received

    # --- ingestion agent ---
    alert_id: str
    normalized_alert: dict

    # --- triage agent ---
    severity: Severity
    alert_type: str  # e.g. "phishing", "anomalous_login", "malware"

    # --- enrichment agent ---
    ip_reputation: dict
    cve_matches: list
    asset_context: dict

    # --- investigation agent ---
    similar_incidents: list
    recommended_playbook: str

    # --- decision agent ---
    action: Action
    confidence: float
    rationale: str

    # --- audit agent ---
    trace: list[str]  # append-only reasoning log, one entry per agent
