from agents.graph import sentinelops_graph


def test_high_severity_known_bad_ip_auto_remediates():
    result = sentinelops_graph.invoke(
        {
            "source": "siem",
            "raw_alert": "Multiple failed login attempts from 203.0.113.5 "
            "followed by a successful login",
        }
    )
    assert result["severity"] in ("high", "critical")
    assert result["action"] == "auto_remediate"
    assert result["ip_reputation"]["malicious"] is True
    assert len(result["trace"]) == 6  # one entry per agent


def test_low_severity_closes_as_false_positive():
    result = sentinelops_graph.invoke(
        {"source": "siem", "raw_alert": "Single failed login from 10.0.0.4"}
    )
    assert result["severity"] == "low"
    assert result["action"] == "close_false_positive"


def test_trace_records_every_agent_in_order():
    result = sentinelops_graph.invoke(
        {"source": "manual", "raw_alert": "Suspicious phishing email reported by user"}
    )
    stages = [line.split("]")[0][1:] for line in result["trace"]]
    assert stages == [
        "ingestion",
        "triage",
        "enrichment",
        "investigation",
        "decision",
        "audit",
    ]
