"""Mock MCP-style tools.

Each function stands in for an MCP server call. Swap the body of each
function for a real MCP client call (e.g. via `mcp_servers` in the
Anthropic API, or a LangChain MCP adapter) without touching agent code
in agents/nodes.py — that's the whole point of isolating tools here.
"""

from __future__ import annotations

import ipaddress
import re


_KNOWN_BAD_IPS = {"203.0.113.5", "198.51.100.23"}


def ip_reputation_lookup(ip: str) -> dict:
    """Mock threat-intel IP reputation check."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return {"ip": ip, "valid": False}

    is_known_bad = ip in _KNOWN_BAD_IPS
    return {
        "ip": ip,
        "valid": True,
        "malicious": is_known_bad,
        "score": 92 if is_known_bad else 5,
        "source": "mock-threat-intel",
    }


def cve_lookup(product: str, version: str | None = None) -> list[dict]:
    """Mock CVE database lookup for a product/version."""
    # In production: call the NVD API or an internal CVE feed via MCP.
    return [
        {
            "cve_id": "CVE-2024-MOCK-0001",
            "product": product,
            "version": version or "unknown",
            "severity": "high",
            "description": f"Mock vulnerability entry for {product}.",
        }
    ]


def asset_lookup(hostname_or_user: str) -> dict:
    """Mock internal asset/user directory lookup."""
    return {
        "identifier": hostname_or_user,
        "owner": "unknown",
        "criticality": "medium",
        "environment": "production",
    }


def extract_ips(text: str) -> list[str]:
    """Small helper: pull IPv4 addresses out of free text alerts."""
    return re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text)
