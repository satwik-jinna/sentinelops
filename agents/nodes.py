"""One function per agent. Each node takes the current AlertState and
returns a dict of the keys it updates — LangGraph merges that back into
state. Keeping nodes as plain functions makes them trivially unit
testable (see tests/test_graph.py).
"""

from __future__ import annotations

import os
import uuid

from agents.state import AlertState
from tools.mcp_tools import asset_lookup, cve_lookup, extract_ips, ip_reputation_lookup
from tools.rag import recommend_playbook, search_incidents


_USE_LLM = bool(os.getenv("OPENAI_API_KEY"))


def _llm():
    """Lazily construct a chat model only if an API key is configured.

    Keeps the whole graph runnable with zero external dependencies —
    useful for local dev, CI, and interviews where you don't want to
    depend on a live API key.
    """
    from langchain_openai import ChatOpenAI

    model = os.getenv("SENTINELOPS_MODEL", "gpt-4o-mini")
    return ChatOpenAI(model=model, temperature=0)


# --- 1. Ingestion agent -----------------------------------------------

def ingestion_agent(state: AlertState) -> dict:
    normalized = {
        "source": state.get("source", "unknown"),
        "text": state["raw_alert"].strip(),
        "ips": extract_ips(state["raw_alert"]),
    }
    alert_id = str(uuid.uuid4())[:8]
    trace = state.get("trace", [])
    trace.append(f"[ingestion] normalized alert {alert_id} from {normalized['source']}")
    return {"alert_id": alert_id, "normalized_alert": normalized, "trace": trace}


# --- 2. Triage agent ----------------------------------------------------

_KEYWORD_SEVERITY = {
    "successful login": "high",
    "malware": "critical",
    "exfil": "critical",
    "phishing": "medium",
    "failed login": "low",
}


def triage_agent(state: AlertState) -> dict:
    text = state["normalized_alert"]["text"].lower()

    if _USE_LLM:
        llm = _llm()
        prompt = (
            "Classify this security alert. Respond with exactly two lines:\n"
            "severity: <low|medium|high|critical>\n"
            "type: <short alert type, e.g. anomalous_login, phishing, malware>\n\n"
            f"Alert: {text}"
        )
        reply = llm.invoke(prompt).content
        severity, alert_type = _parse_triage_reply(reply)
    else:
        severity = next(
            (v for k, v in _KEYWORD_SEVERITY.items() if k in text), "low"
        )
        alert_type = "anomalous_login" if "login" in text else "phishing" if "phish" in text else "unclassified"

    trace = state.get("trace", [])
    trace.append(f"[triage] classified as {alert_type} (severity={severity})")
    return {"severity": severity, "alert_type": alert_type, "trace": trace}


def _parse_triage_reply(reply: str) -> tuple[str, str]:
    severity, alert_type = "medium", "unclassified"
    for line in reply.splitlines():
        if line.lower().startswith("severity:"):
            severity = line.split(":", 1)[1].strip().lower()
        if line.lower().startswith("type:"):
            alert_type = line.split(":", 1)[1].strip().lower()
    return severity, alert_type


# --- 3. Enrichment agent -------------------------------------------------

def enrichment_agent(state: AlertState) -> dict:
    ips = state["normalized_alert"].get("ips", [])
    ip_rep = ip_reputation_lookup(ips[0]) if ips else {}
    cves = cve_lookup(product="openssh") if "login" in state["alert_type"] else []
    asset = asset_lookup(hostname_or_user=state.get("source", "unknown"))

    trace = state.get("trace", [])
    trace.append(
        f"[enrichment] ip_reputation={ip_rep.get('malicious', 'n/a')} "
        f"cves_found={len(cves)}"
    )
    return {
        "ip_reputation": ip_rep,
        "cve_matches": cves,
        "asset_context": asset,
        "trace": trace,
    }


# --- 4. Investigation agent ----------------------------------------------

def investigation_agent(state: AlertState) -> dict:
    matches = search_incidents(state["alert_type"])
    playbook = recommend_playbook(matches)

    trace = state.get("trace", [])
    trace.append(f"[investigation] found {len(matches)} similar past incidents")
    return {"similar_incidents": matches, "recommended_playbook": playbook, "trace": trace}


# --- 5. Decision agent -----------------------------------------------------

def decision_agent(state: AlertState) -> dict:
    ip_malicious = state.get("ip_reputation", {}).get("malicious", False)
    severity = state["severity"]

    if ip_malicious and severity in ("high", "critical"):
        action, confidence = "auto_remediate", 0.9
        rationale = "Known-bad IP combined with high/critical severity."
    elif severity == "low":
        action, confidence = "close_false_positive", 0.7
        rationale = "Low severity with no corroborating threat intel."
    else:
        action, confidence = "escalate", 0.6
        rationale = "Ambiguous signal — needs analyst review."

    trace = state.get("trace", [])
    trace.append(f"[decision] action={action} confidence={confidence} — {rationale}")
    return {"action": action, "confidence": confidence, "rationale": rationale, "trace": trace}


# --- 6. Audit / governance agent -------------------------------------------

def audit_agent(state: AlertState) -> dict:
    trace = state.get("trace", [])
    trace.append(
        f"[audit] final record — alert_id={state.get('alert_id')} "
        f"action={state.get('action')} rationale={state.get('rationale')}"
    )
    # In production: persist this trace to the incident DB (Postgres)
    # for compliance and auditability, not just return it in-memory.
    return {"trace": trace}
