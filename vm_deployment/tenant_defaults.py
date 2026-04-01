from __future__ import annotations

import json
import os
from typing import Any, Dict, List


def _env_first(*names: str, default: str = "") -> str:
    for name in names:
        value = (os.getenv(name) or "").strip()
        if value:
            return value
    return default


def _split_csv(value: str) -> List[str]:
    return [item.strip() for item in (value or "").split(",") if item.strip()]


def _csv_env(*names: str, default: List[str] | None = None) -> List[str]:
    for name in names:
        value = (os.getenv(name) or "").strip()
        if value:
            return _split_csv(value)
    return list(default or [])


def _json_env(*names: str) -> Any:
    for name in names:
        raw = (os.getenv(name) or "").strip()
        if not raw:
            continue
        try:
            return json.loads(raw)
        except Exception:
            continue
    return None


def _legacy_bng_peers() -> Dict[str, str]:
    peers = {
        "NE": _env_first("BNG_PEER_NE"),
        "IL": _env_first("BNG_PEER_IL"),
        "IA": _env_first("BNG_PEER_IA"),
        "KS": _env_first("BNG_PEER_KS"),
        "IN": _env_first("BNG_PEER_IN"),
    }
    return {key: value for key, value in peers.items() if value}


def _route_reflector_peers() -> List[Dict[str, str]]:
    parsed = _json_env("NEXUS_ROUTE_REFLECTOR_PEERS_JSON", "NEXTLINK_ROUTE_REFLECTOR_PEERS_JSON")
    if isinstance(parsed, list):
        peers: List[Dict[str, str]] = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            name = str(item.get("name") or "").strip()
            remote = str(item.get("remote") or item.get("ip") or "").strip()
            if remote:
                peers.append({"name": name or f"peer-{len(peers) + 1}", "remote": remote})
        if peers:
            return peers

    peers = []
    peer1 = _env_first("NEXUS_BGP_PEER_1", "NEXTLINK_BGP_PEER_1")
    peer2 = _env_first("NEXUS_BGP_PEER_2", "NEXTLINK_BGP_PEER_2")
    if peer1:
        peers.append({"name": "PEER1", "remote": peer1})
    if peer2:
        peers.append({"name": "PEER2", "remote": peer2})
    return peers


def load_tenant_defaults(include_sensitive: bool = True) -> Dict[str, Any]:
    bng_peers_json = _json_env("NEXUS_BNG_PEERS_JSON")
    if isinstance(bng_peers_json, dict):
        bng_peers = {str(key): str(value) for key, value in bng_peers_json.items() if str(value).strip()}
    else:
        bng_peers = _legacy_bng_peers()

    dns_servers = _csv_env("NEXUS_DNS_SERVERS")
    if not dns_servers:
        legacy_primary = _env_first("NEXTLINK_DNS_PRIMARY")
        legacy_secondary = _env_first("NEXTLINK_DNS_SECONDARY")
        dns_servers = [value for value in [legacy_primary, legacy_secondary] if value] or ["1.1.1.1", "8.8.8.8"]

    ntp_servers = _csv_env("NEXUS_NTP_SERVERS", "NEXTLINK_NTP_SERVERS", default=["pool.ntp.org", "time.google.com"])
    radius_secret = _env_first("NEXUS_RADIUS_SECRET", "NEXTLINK_RADIUS_SECRET")

    defaults: Dict[str, Any] = {
        "tenant": {
            "code": _env_first("NEXUS_TENANT_CODE", "TENANT_CODE", default="default"),
            "name": _env_first("NEXUS_TENANT_NAME", "TENANT_NAME", default="Default Tenant"),
            "allowed_email_domain": _env_first("NEXUS_ALLOWED_EMAIL_DOMAIN", "ALLOWED_EMAIL_DOMAIN"),
        },
        "routing": {
            "asn": _env_first("NEXUS_DEFAULT_ASN", "NEXTLINK_DEFAULT_ASN", default="65000"),
            "route_reflector_peers": _route_reflector_peers(),
            "bng_peers": bng_peers,
            "default_bng_peer": _env_first("NEXUS_BNG_PEER_DEFAULT", "BNG_PEER_DEFAULT", default=next(iter(bng_peers.values()), "")),
        },
        "services": {
            "dns_servers": dns_servers,
            "ntp_servers": ntp_servers,
            "syslog_server": _env_first("NEXUS_SYSLOG_SERVER", "NEXTLINK_SYSLOG_SERVER"),
        },
        "snmp": {
            "contact": _env_first("NEXUS_SNMP_CONTACT", "NEXTLINK_SNMP_CONTACT", default="noc@example.com"),
            "community": _env_first("NEXUS_SNMP_COMMUNITY", "NEXTLINK_SNMP_COMMUNITY"),
        },
        "radius": {
            "dhcp_servers": _csv_env("NEXUS_RADIUS_DHCP_SERVERS", "NEXTLINK_RADIUS_DHCP_SERVERS"),
            "login_servers": _csv_env("NEXUS_RADIUS_LOGIN_SERVERS", "NEXTLINK_RADIUS_LOGIN_SERVERS"),
        },
        "security": {
            "shared_key": _env_first("NEXUS_SHARED_KEY", "NEXTLINK_SHARED_KEY"),
        },
        "policy": {
            "compliance_profile": _env_first("NEXUS_COMPLIANCE_PROFILE", "NEXTLINK_COMPLIANCE_PROFILE", default="default"),
            "reference_doc": _env_first("NEXUS_POLICY_REFERENCE_DOC", "NEXTLINK_POLICY_REFERENCE_DOC"),
        },
        "audit": {
            "uses_legacy_nextlink_env": any(
                bool((os.getenv(name) or "").strip())
                for name in (
                    "NEXTLINK_DNS_PRIMARY",
                    "NEXTLINK_DNS_SECONDARY",
                    "NEXTLINK_SYSLOG_SERVER",
                    "NEXTLINK_RADIUS_SECRET",
                    "NEXTLINK_SNMP_CONTACT",
                    "NEXTLINK_BGP_PEER_1",
                    "NEXTLINK_BGP_PEER_2",
                )
            ),
        },
    }
    if include_sensitive:
        defaults["radius"]["secret"] = radius_secret
    return defaults


def load_runtime_app_config() -> Dict[str, Any]:
    defaults = load_tenant_defaults(include_sensitive=False)
    return {
        "tenant": defaults["tenant"],
        "routing_defaults": {
            "asn": defaults["routing"]["asn"],
            "route_reflector_peers": defaults["routing"]["route_reflector_peers"],
        },
        "bng_peers": defaults["routing"]["bng_peers"],
        "default_bng_peer": defaults["routing"]["default_bng_peer"],
    }


def load_infrastructure_defaults() -> Dict[str, Any]:
    defaults = load_tenant_defaults(include_sensitive=True)
    return {
        "tenant": defaults["tenant"],
        "dns_servers": {
            "primary": defaults["services"]["dns_servers"][0] if defaults["services"]["dns_servers"] else "",
            "secondary": defaults["services"]["dns_servers"][1] if len(defaults["services"]["dns_servers"]) > 1 else "",
            "all": defaults["services"]["dns_servers"],
        },
        "shared_key": defaults["security"]["shared_key"] or None,
        "snmp": defaults["snmp"],
        "radius": defaults["radius"],
        "services": {
            "syslog_server": defaults["services"]["syslog_server"],
            "ntp_servers": defaults["services"]["ntp_servers"],
        },
        "routing": defaults["routing"],
        "policy": defaults["policy"],
        "audit": defaults["audit"],
    }


def load_nokia_defaults() -> Dict[str, Any]:
    defaults = load_tenant_defaults(include_sensitive=False)
    return {
        "snmp_community": _env_first("NOKIA7250_SNMP_COMMUNITY", "NEXUS_NOKIA_SNMP_COMMUNITY", default=defaults["snmp"]["community"]),
        "nlroot_pw": _env_first("NOKIA7250_NLROOT_PW", "NEXUS_NOKIA_NLROOT_PW"),
        "admin_pw": _env_first("NOKIA7250_ADMIN_PW", "NEXUS_NOKIA_ADMIN_PW"),
        "bgp_auth_key": _env_first("NOKIA7250_BGP_AUTH_KEY", "NEXUS_NOKIA_BGP_AUTH_KEY"),
        "ospf_auth_key": _env_first("NOKIA7250_OSPF_AUTH_KEY", "NEXUS_NOKIA_OSPF_AUTH_KEY", default=_env_first("NOKIA7250_BGP_AUTH_KEY", "NEXUS_NOKIA_BGP_AUTH_KEY")),
        "routing_defaults": {
            "asn": defaults["routing"]["asn"],
            "route_reflector_peers": defaults["routing"]["route_reflector_peers"],
        },
        "tenant": defaults["tenant"],
        "policy": defaults["policy"],
    }
