#!/usr/bin/env python3

from __future__ import annotations

import sys
from pathlib import Path


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))

from tenant_defaults import load_infrastructure_defaults, load_nokia_defaults, load_runtime_app_config, load_tenant_defaults  # noqa: E402


def test_tenant_defaults_prefer_nexus_env_and_remain_neutral(monkeypatch):
    monkeypatch.setenv("NEXUS_TENANT_CODE", "tenant-a")
    monkeypatch.setenv("NEXUS_TENANT_NAME", "Acme Telecom")
    monkeypatch.setenv("NEXUS_DEFAULT_ASN", "64512")
    monkeypatch.setenv("NEXUS_DNS_SERVERS", "1.1.1.1,8.8.8.8")
    monkeypatch.setenv("NEXUS_BNG_PEERS_JSON", '{"TX":"10.20.30.40"}')
    monkeypatch.delenv("NEXTLINK_DNS_PRIMARY", raising=False)
    monkeypatch.delenv("NEXTLINK_DNS_SECONDARY", raising=False)

    defaults = load_tenant_defaults(include_sensitive=False)
    assert defaults["tenant"]["code"] == "tenant-a"
    assert defaults["tenant"]["name"] == "Acme Telecom"
    assert defaults["routing"]["asn"] == "64512"
    assert defaults["services"]["dns_servers"] == ["1.1.1.1", "8.8.8.8"]
    assert defaults["routing"]["bng_peers"] == {"TX": "10.20.30.40"}


def test_tenant_defaults_fall_back_to_legacy_envs_when_present(monkeypatch):
    monkeypatch.delenv("NEXUS_DNS_SERVERS", raising=False)
    monkeypatch.setenv("NEXTLINK_DNS_PRIMARY", "142.147.112.3")
    monkeypatch.setenv("NEXTLINK_DNS_SECONDARY", "142.147.112.19")
    monkeypatch.setenv("NEXTLINK_SNMP_CONTACT", "netops@team.nxlink.com")

    defaults = load_infrastructure_defaults()
    assert defaults["dns_servers"]["primary"] == "142.147.112.3"
    assert defaults["dns_servers"]["secondary"] == "142.147.112.19"
    assert defaults["snmp"]["contact"] == "netops@team.nxlink.com"
    assert defaults["audit"]["uses_legacy_nextlink_env"] is True


def test_runtime_and_nokia_defaults_expose_shared_routing_metadata(monkeypatch):
    monkeypatch.setenv("NEXUS_DEFAULT_ASN", "64513")
    monkeypatch.setenv("NEXUS_ROUTE_REFLECTOR_PEERS_JSON", '[{"name":"RR1","remote":"10.10.10.10"}]')
    monkeypatch.setenv("NOKIA7250_BGP_AUTH_KEY", "secret")

    runtime = load_runtime_app_config()
    nokia = load_nokia_defaults()
    assert runtime["routing_defaults"]["asn"] == "64513"
    assert runtime["routing_defaults"]["route_reflector_peers"][0]["remote"] == "10.10.10.10"
    assert nokia["routing_defaults"]["asn"] == "64513"
    assert nokia["bgp_auth_key"] == "secret"
