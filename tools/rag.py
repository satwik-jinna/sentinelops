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
    """Rank past incidents by relevance to the given alert type.

    This is a stand-in for real semantic search. Swap this function's
    body for an embedding lookup (Pinecone/Chroma) once real incident
    data and an embedding model are available — the return shape stays
    the same, so agents/nodes.py doesn't need to change.
    """
    scored = [
        (inc, 1.0 if inc["alert_type"] == alert_type else 0.0)
        for inc in _INCIDENT_LIBRARY
    ]
    scored.sort(key=lambda pair: pair[1], reverse=True)
    return [inc for inc, score in scored if score > 0][:top_k]


def recommend_playbook(similar_incidents: list[dict]) -> str:
    if not similar_incidents:
        return "No matching playbook found — default to manual analyst review."
    return similar_incidents[0]["playbook"]
