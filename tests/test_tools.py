from tools.mcp_tools import extract_ips, ip_reputation_lookup
from tools.rag import recommend_playbook, search_incidents


def test_ip_reputation_flags_known_bad_ip():
    result = ip_reputation_lookup("203.0.113.5")
    assert result["malicious"] is True
    assert result["valid"] is True


def test_ip_reputation_clean_ip():
    result = ip_reputation_lookup("10.0.0.4")
    assert result["malicious"] is False


def test_extract_ips_finds_addresses_in_text():
    text = "Failed login from 203.0.113.5 and 10.0.0.4"
    ips = extract_ips(text)
    assert "203.0.113.5" in ips
    assert "10.0.0.4" in ips


def test_search_incidents_matches_alert_type():
    matches = search_incidents("anomalous_login")
    assert len(matches) > 0
    assert all(m["alert_type"] == "anomalous_login" for m in matches)


def test_recommend_playbook_handles_no_matches():
    result = recommend_playbook([])
    assert "no matching playbook" in result.lower()
