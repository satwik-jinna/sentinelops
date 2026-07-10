"""Mock retrieval over past incidents and playbooks.

Swap `_INCIDENT_LIBRARY` + `search_incidents` for a real vector store
(Pinecone, Chroma, FAISS) once you have real historical incident data
and an embedding model wired up. Keeping the interface the same means
`agents/nodes.py` never needs to change.
"""

from __future__ import annotations


_INCIDENT_LIBRARY = [
    {
        "id": "INC-1042",
        "alert_type": "anomalous_login",
        "summary": "Impossible-travel login flagged, later confirmed as VPN use.",
        "playbook": "Verify VPN egress IP against corporate VPN pool before escalating.",
        "outcome": "false_positive",
    },
    {
        "id": "INC-1087",
        "alert_type": "anomalous_login",
        "summary": "Brute-force login attempts followed by a successful login from a known-bad IP.",
        "playbook": "Force password reset, revoke active sessions, isolate the account.",
        "outcome": "confirmed_compromise",
    },
    {
        "id": "INC-1115",
        "alert_type": "phishing",
        "summary": "Credential-harvesting link clicked, no follow-on login detected.",
        "playbook": "Reset credentials proactively, block sender domain, notify user.",
        "outcome": "contained",
    },
]


def search_incidents(alert_type: str, top_k: int = 2) -> list[dict]:
    """Naive keyword match standing in for a real vector similarity search."""
    matches = [inc for inc in _INCIDENT_LIBRARY if inc["alert_type"] == alert_type]
    return matches[:top_k]


def recommend_playbook(similar_incidents: list[dict]) -> str:
    if not similar_incidents:
        return "No matching playbook found — default to manual analyst review."
    return similar_incidents[0]["playbook"]
