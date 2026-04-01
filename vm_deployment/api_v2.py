#!/usr/bin/env python3
"""
API v2 (contract-first layer) for NEXUS.

This module adds:
- API key + scope auth for /api/v2
- Async job model (submit/status/events/cancel)
- Stable action registry so external UIs can drive backend safely
- Explicit NEXUS catalog metadata for Swagger/OpenAPI consumers
"""

from __future__ import annotations

import json
import os
import hashlib
import hmac
import secrets
import sqlite3
import threading
import uuid
import difflib
import ipaddress
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Literal, Optional, Set, Tuple, Union
from urllib.parse import urljoin

import requests
from fastapi import APIRouter, Body, Depends, Header, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

try:
    from mt_config_gen.mt_tower import MTTowerConfig
    from mt_config_gen.mt_bng2 import MTBNG2Config
except Exception:
    from vm_deployment.mt_config_gen.mt_tower import MTTowerConfig
    from vm_deployment.mt_config_gen.mt_bng2 import MTBNG2Config

from ido_adapter import apply_compliance as ido_apply_compliance
from ido_adapter import merge_defaults as ido_merge_defaults


router = APIRouter(prefix="/api/v2", tags=["NEXUS API v2"])


class ErrorResponse(BaseModel):
    detail: str = Field(
        ...,
        description="Human-readable error detail.",
        examples=["Authentication required - missing or incorrect API key or Bearer token"],
    )


class EventItem(BaseModel):
    ts: str = Field(..., description="RFC3339 UTC timestamp")
    level: str = Field(..., description="Event level", examples=["info"])
    message: str = Field(..., description="Event message")


class JobSummary(BaseModel):
    job_id: str = Field(..., description="Unique async job id")
    request_id: str = Field(..., description="Request correlation id")
    action: str = Field(..., description="Stable action id")
    submitted_by: str = Field(..., description="Submitting API key id")
    status: str = Field(..., description="Job lifecycle status")
    created_at: str = Field(..., description="RFC3339 UTC timestamp")
    started_at: Optional[str] = Field(default=None, description="RFC3339 UTC timestamp")
    finished_at: Optional[str] = Field(default=None, description="RFC3339 UTC timestamp")
    cancel_requested: bool = Field(..., description="Whether cancellation has been requested")
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class JobDetail(JobSummary):
    payload: Dict[str, Any]


class HealthData(BaseModel):
    legacy_api_base: str
    legacy_health: Dict[str, Any]
    ido_caps: Dict[str, Any]


class HealthEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: HealthData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "de34edce-f608-4f1c-a4d6-c76c113cd4e4",
                "status": "degraded",
                "message": "v2 health",
                "data": {
                    "legacy_api_base": "http://127.0.0.1:5000",
                    "legacy_health": {"ok": False, "error": "Legacy API unreachable"},
                    "ido_caps": {"ok": True, "status_code": 200},
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class ActionsData(BaseModel):
    actions: List[str]
    notes: Dict[str, str]


class ActionsEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: ActionsData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "b5f8c93f-0c66-4764-a651-c3a4302fcad8",
                "status": "ok",
                "message": "",
                "data": {
                    "actions": ["health.get", "ftth.generate_bng", "aviat.run"],
                    "notes": {
                        "mt.*": "Native renderer actions",
                        "legacy.proxy": "Whitelisted generic proxy to legacy /api/* endpoint",
                    },
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class WhoAmIData(BaseModel):
    api_key: str
    scopes: List[str]


class WhoAmIEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: WhoAmIData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "8ddf1092-21e5-4edf-a5f4-f4f53f8f0ec0",
                "status": "ok",
                "message": "",
                "data": {"api_key": "omni-prod-key", "scopes": ["admin"]},
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class ResourceLink(BaseModel):
    method: str
    path: str


class BootstrapData(BaseModel):
    api_version: str
    service: str
    base_url_hint: str
    methods_supported: List[str]
    resources: Dict[str, ResourceLink]
    notes: Dict[str, str]


class BootstrapEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: BootstrapData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "f913489f-97c8-4d5e-9ec7-4c6f5a4f1de5",
                "status": "ok",
                "message": "OMNI bootstrap contract",
                "data": {
                    "api_version": "v2",
                    "service": "noc-configmaker",
                    "base_url_hint": "/api/v2",
                    "methods_supported": ["GET", "POST", "PUT", "PATCH"],
                    "resources": {
                        "health": {"method": "GET", "path": "/api/v2/omni/health"},
                        "job_submit": {"method": "POST", "path": "/api/v2/omni/jobs"},
                    },
                    "notes": {
                        "read_method": "READ maps to GET in HTTP semantics",
                        "auth": "X-API-Key or Authorization: Bearer <key>",
                        "idempotency": "Mutating endpoints require Idempotency-Key",
                    },
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class WorkflowsData(BaseModel):
    workflows: Dict[str, Any]
    parity_doc: str
    actions_count: int


class WorkflowsEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: WorkflowsData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "86d57fe9-a32e-44a3-bf33-eae2e8ff0f26",
                "status": "ok",
                "message": "OMNI workflow/action mappings",
                "data": {
                    "workflows": {"dashboard": {"health": "health.get"}},
                    "parity_doc": "/docs/UI_API_PARITY.md",
                    "actions_count": 90,
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class SubmitJobRequest(BaseModel):
    action: str = Field(..., description="Stable action id from GET /api/v2/omni/actions")
    payload: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Action-specific payload. If omitted, extra top-level fields are folded into payload.",
    )

    model_config = ConfigDict(
        extra="allow",
        json_schema_extra={
            "examples": [
                {
                    "action": "ftth.generate_bng",
                    "payload": {
                        "deployment_type": "outstate",
                        "router_identity": "RTR-MT2216-AR1.NE-WESTERN-WE-1",
                        "loopback_ip": "10.249.7.137/32",
                        "olt_network": "10.249.180.0/29",
                        "olt_name_primary": "NE-WESTERN-MF2-1",
                    },
                },
                {
                    "action": "health.get",
                    "payload": {
                        "path": "/api/health",
                        "method": "GET",
                    },
                },
            ]
        }
    )


class LegacyProxyPayload(BaseModel):
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE"] = Field(
        ..., description="HTTP verb used when calling the whitelisted legacy backend route."
    )
    path: str = Field(..., description="Whitelisted legacy backend path beginning with /api/.")
    params: Optional[Dict[str, Any]] = Field(default=None, description="Optional query parameters.")
    headers: Optional[Dict[str, str]] = Field(default=None, description="Optional request headers.")
    body: Optional[Dict[str, Any]] = Field(default=None, description="Optional JSON request body.")
    timeout: int = Field(default=120, ge=1, le=600, description="Upstream timeout in seconds.")


class HealthGetJobRequest(BaseModel):
    action: Literal["health.get"] = Field(..., description="Run a health check against the published service surface.")
    payload: Dict[str, Any] = Field(
        default_factory=dict,
        description="Health requests do not require a payload.",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "health.get",
                "payload": {},
            }
        }
    )


class LegacyProxyJobRequest(BaseModel):
    action: Literal["legacy.proxy"] = Field(..., description="Generic legacy proxy for approved internal routes.")
    payload: LegacyProxyPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "legacy.proxy",
                "payload": {
                    "method": "GET",
                    "path": "/api/health",
                    "params": {},
                    "timeout": 120,
                },
            }
        }
    )


class FtthGenerateBngPayload(BaseModel):
    deployment_type: str = Field(..., description="Template/deployment profile identifier selected by the tenant.")
    router_identity: str = Field(..., description="Target router identity/hostname.")
    loopback_ip: str = Field(..., description="Loopback address with prefix.")
    olt_network: str = Field(..., description="Assigned OLT network block.")
    olt_name_primary: str = Field(..., description="Primary OLT name.")
    cpe_network: Optional[str] = Field(default=None, description="Subscriber-facing CPE network block.")
    cgnat_private: Optional[str] = Field(default=None, description="Private CGNAT address space.")
    access_policy: Optional[str] = Field(default=None, description="Tenant-defined policy/template reference.")
    tenant_code: Optional[str] = Field(default=None, description="Tenant identifier for downstream automation.")


class FtthGenerateBngJobRequest(BaseModel):
    action: Literal["ftth.generate_bng"] = Field(..., description="Generate FTTH BNG configuration output.")
    payload: FtthGenerateBngPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "ftth.generate_bng",
                "payload": {
                    "deployment_type": "standard-bng",
                    "router_identity": "RTR-EDGE-01",
                    "loopback_ip": "10.249.7.137/32",
                    "olt_network": "10.249.180.0/29",
                    "olt_name_primary": "OLT-WEST-01",
                    "cpe_network": "100.64.32.0/19",
                    "cgnat_private": "100.64.0.0/10",
                    "access_policy": "fiber-default",
                    "tenant_code": "tenant-a",
                },
            }
        }
    )


class FtthPreviewBngPayload(BaseModel):
    loopback_ip: str = Field(..., description="Loopback address with prefix.")
    cpe_cidr: str = Field(..., description="Subscriber/CPE CIDR block.")
    cgnat_cidr: str = Field(..., description="CGNAT CIDR block.")


class FtthPreviewBngJobRequest(BaseModel):
    action: Literal["ftth.preview_bng"] = Field(..., description="Preview FTTH address plan outputs without generating config.")
    payload: FtthPreviewBngPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "ftth.preview_bng",
                "payload": {
                    "loopback_ip": "10.249.7.137/32",
                    "cpe_cidr": "10.249.184.0/21",
                    "cgnat_cidr": "100.64.0.0/10",
                },
            }
        }
    )


class NokiaBackhaulItem(BaseModel):
    name: str = Field(..., description="Backhaul interface or logical service name.")
    peer_ip: Optional[str] = Field(default=None, description="Peer address when applicable.")
    vlan: Optional[int] = Field(default=None, description="VLAN id when applicable.")
    description: Optional[str] = Field(default=None, description="Tenant-facing description.")


class NokiaGenerate7250Payload(BaseModel):
    system_name: str = Field(..., description="Router hostname/system name.")
    system_ip: str = Field(..., description="System loopback address.")
    location: str = Field(..., description="Site or market label.")
    backhauls: List[NokiaBackhaulItem] = Field(..., description="Backhaul definitions for the node.")
    tenant_code: Optional[str] = Field(default=None, description="Tenant identifier for generated artifacts.")


class NokiaGenerate7250JobRequest(BaseModel):
    action: Literal["nokia.generate_7250"] = Field(..., description="Generate Nokia 7250 configuration output.")
    payload: NokiaGenerate7250Payload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "nokia.generate_7250",
                "payload": {
                    "system_name": "PE1-WEST-01",
                    "system_ip": "10.10.10.1",
                    "location": "West Hub",
                    "backhauls": [
                        {"name": "to-core-a", "peer_ip": "10.10.20.1", "vlan": 2100, "description": "Primary uplink"}
                    ],
                    "tenant_code": "tenant-a",
                },
            }
        }
    )


class TaranaGeneratePayload(BaseModel):
    config: str = Field(..., description="Source configuration text or normalized device input.")
    device: str = Field(..., description="Device or sector identifier.")
    routeros_version: str = Field(..., description="Target RouterOS version.")
    tenant_code: Optional[str] = Field(default=None, description="Tenant identifier for downstream automation.")


class TaranaGenerateJobRequest(BaseModel):
    action: Literal["tarana.generate"] = Field(..., description="Generate tenant-neutral Tarana configuration output.")
    payload: TaranaGeneratePayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "tarana.generate",
                "payload": {
                    "config": "set interface ge-1/1/1 description backhaul",
                    "device": "tarana-sector-a",
                    "routeros_version": "7.16.2",
                    "tenant_code": "tenant-a",
                },
            }
        }
    )


class AviatRunPayload(BaseModel):
    ips: List[str] = Field(..., description="Target radio management IP addresses.")
    tasks: List[str] = Field(..., description="Requested maintenance tasks.")
    firmware: Optional[str] = Field(default=None, description="Optional firmware target or package identifier.")
    username: Optional[str] = Field(default=None, description="Device login username when required.")
    password: Optional[str] = Field(default=None, description="Device login password when required.")
    requested_by: Optional[str] = Field(default=None, description="Operator or calling system identity.")


class AviatRunJobRequest(BaseModel):
    action: Literal["aviat.run"] = Field(..., description="Run Aviat radio maintenance workflow.")
    payload: AviatRunPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "aviat.run",
                "payload": {
                    "ips": ["10.247.180.66"],
                    "tasks": ["backup", "upgrade", "verify"],
                    "firmware": "CTR-4.2.0",
                    "requested_by": "omni-automation",
                },
            }
        }
    )


class ConfigsSavePayload(BaseModel):
    config_type: str = Field(..., description="Configuration family or generator type.")
    device_name: str = Field(..., description="Operator-facing device identifier.")
    device_type: str = Field(..., description="Platform/model identifier.")
    loopback_ip: Optional[str] = Field(default=None, description="Loopback or management IP when applicable.")
    config_content: str = Field(..., description="Rendered configuration text.")
    site_name: Optional[str] = Field(default=None, description="Site or market label.")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional tenant-defined metadata.")


class ConfigsSaveJobRequest(BaseModel):
    action: Literal["configs.save"] = Field(..., description="Persist a generated configuration artifact.")
    payload: ConfigsSavePayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "configs.save",
                "payload": {
                    "config_type": "tower-config",
                    "device_name": "RTR-EDGE-01",
                    "device_type": "CCR2004",
                    "loopback_ip": "10.249.7.137/32",
                    "config_content": "/system identity set name=RTR-EDGE-01",
                    "site_name": "West Hub",
                    "metadata": {"tenant_code": "tenant-a", "workflow": "mikrotik.render"},
                },
            }
        }
    )


class ConfigsGetPayload(BaseModel):
    config_id: int = Field(..., ge=1, description="Saved configuration record id.")


class ConfigsGetJobRequest(BaseModel):
    action: Literal["configs.get"] = Field(..., description="Fetch a saved configuration artifact by id.")
    payload: ConfigsGetPayload

    model_config = ConfigDict(
        json_schema_extra={"example": {"action": "configs.get", "payload": {"config_id": 42}}}
    )


class DeviceFetchConfigSshPayload(BaseModel):
    host: str = Field(..., description="Device hostname or management IP.")
    port: int = Field(default=22, ge=1, le=65535, description="SSH port.")
    username: str = Field(..., description="SSH username.")
    password: str = Field(..., description="SSH password.")
    command: str = Field(..., description="Read-only device command used to fetch running/exported config.")


class DeviceFetchConfigSshJobRequest(BaseModel):
    action: Literal["device.fetch_config_ssh"] = Field(..., description="Fetch device configuration over SSH.")
    payload: DeviceFetchConfigSshPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "device.fetch_config_ssh",
                "payload": {
                    "host": "10.249.10.10",
                    "port": 22,
                    "username": "admin",
                    "password": "redacted",
                    "command": "/export terse",
                },
            }
        }
    )


class ComplianceApplyPayload(BaseModel):
    config: str = Field(..., description="Rendered config text to be normalized or validated.")
    loopback_ip: Optional[str] = Field(default=None, description="Loopback or router identifier used for policy matching.")
    policy_name: Optional[str] = Field(default=None, description="Tenant policy/template reference.")


class ComplianceApplyJobRequest(BaseModel):
    action: Literal["compliance.apply"] = Field(..., description="Apply compliance overlays to generated configuration.")
    payload: ComplianceApplyPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "compliance.apply",
                "payload": {
                    "config": "/routing ospf instance set default router-id=10.249.7.137",
                    "loopback_ip": "10.249.7.137/32",
                    "policy_name": "standard-edge",
                },
            }
        }
    )


class CompliancePolicyGetPayload(BaseModel):
    policy_name: str = Field(..., description="Tenant policy/template identifier.")


class CompliancePolicyGetJobRequest(BaseModel):
    action: Literal["compliance.policies.get"] = Field(..., description="Fetch a single named compliance policy.")
    payload: CompliancePolicyGetPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {"action": "compliance.policies.get", "payload": {"policy_name": "standard-edge"}}
        }
    )


class FeedbackSubmitPayload(BaseModel):
    type: str = Field(..., description="Feedback type such as feedback, bug, or feature.")
    rating: Optional[int] = Field(default=None, ge=1, le=5, description="Optional rating score.")
    message: str = Field(..., description="User-facing feedback content.")
    email: Optional[str] = Field(default=None, description="Contact email for follow-up.")
    tab: Optional[str] = Field(default=None, description="UI tab/workflow where the feedback originated.")


class FeedbackSubmitJobRequest(BaseModel):
    action: Literal["feedback.submit"] = Field(..., description="Submit user feedback into the shared review queue.")
    payload: FeedbackSubmitPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "feedback.submit",
                "payload": {
                    "type": "feature",
                    "rating": 5,
                    "message": "Need tenant-specific defaults in the Nokia workflow.",
                    "email": "ops@example.com",
                    "tab": "nokia-configurator",
                },
            }
        }
    )


class IdoPingPayload(BaseModel):
    host: str = Field(..., description="Device management IP or hostname.")


class IdoPingJobRequest(BaseModel):
    action: Literal["ido.ping"] = Field(..., description="Ping a device through the IDO backend.")
    payload: IdoPingPayload

    model_config = ConfigDict(
        json_schema_extra={"example": {"action": "ido.ping", "payload": {"host": "10.249.10.10"}}}
    )


class IdoDeviceInfoPayload(BaseModel):
    host: str = Field(..., description="Device management IP or hostname.")
    username: str = Field(..., description="Device login username.")
    password: str = Field(..., description="Device login password.")


class IdoGenericDeviceInfoJobRequest(BaseModel):
    action: Literal["ido.generic.device_info"] = Field(..., description="Fetch generic device facts through IDO.")
    payload: IdoDeviceInfoPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "ido.generic.device_info",
                "payload": {"host": "10.249.10.10", "username": "admin", "password": "redacted"},
            }
        }
    )


class NokiaConfiguratorPayload(BaseModel):
    model: str = Field(..., description="Target Nokia platform or model.")
    profile: str = Field(..., description="Tenant profile or template name.")
    system_name: str = Field(..., description="Router/system hostname.")
    system_ip: str = Field(..., description="System loopback IP address.")
    tenant_code: Optional[str] = Field(default=None, description="Tenant identifier used for policy/template lookup.")


class NokiaConfiguratorJobRequest(BaseModel):
    action: Literal["nokia.configurator.generate"] = Field(
        ..., description="Generate Nokia configurator output for the unified Nokia workflow."
    )
    payload: NokiaConfiguratorPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "nokia.configurator.generate",
                "payload": {
                    "model": "7750",
                    "profile": "edge-standard",
                    "system_name": "PE1-WEST-01",
                    "system_ip": "10.10.10.1",
                    "tenant_code": "tenant-a",
                },
            }
        }
    )


class ParseMikrotikForNokiaPayload(BaseModel):
    config: str = Field(..., description="Raw MikroTik configuration or export text.")


class ParseMikrotikForNokiaJobRequest(BaseModel):
    action: Literal["migration.parse_mikrotik_for_nokia"] = Field(
        ..., description="Parse MikroTik config into Nokia migration helper output."
    )
    payload: ParseMikrotikForNokiaPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "migration.parse_mikrotik_for_nokia",
                "payload": {"config": "/interface bridge\nadd name=bridge1"},
            }
        }
    )


class FtthFiberCustomerPayload(BaseModel):
    routerboard: str = Field(..., description="Target routerboard model.")
    routeros: str = Field(..., description="Target RouterOS version.")
    provider: str = Field(..., description="Tenant/provider profile name.")
    address: str = Field(..., description="Customer/service IP address.")
    network: str = Field(..., description="Customer/service network block.")
    port: Optional[str] = Field(default=None, description="Access port label.")
    loopback_ip: Optional[str] = Field(default=None, description="Router loopback IP.")
    vlan_mode: Optional[str] = Field(default=None, description="VLAN mode such as none or tagged.")
    vlan_id: Optional[str] = Field(default=None, description="VLAN id when tagged.")
    apply_compliance: bool = Field(default=True, description="Apply compliance overlays before returning output.")


class FtthFiberCustomerJobRequest(BaseModel):
    action: Literal["ftth.fiber_customer"] = Field(..., description="Generate FTTH fiber customer handoff configuration.")
    payload: FtthFiberCustomerPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "ftth.fiber_customer",
                "payload": {
                    "routerboard": "CCR2004",
                    "routeros": "7.19.4",
                    "provider": "tenant-a",
                    "address": "132.147.10.2/30",
                    "network": "132.147.10.0/30",
                    "port": "sfp-sfpplus1",
                    "vlan_mode": "tagged",
                    "vlan_id": "2100",
                    "apply_compliance": True,
                },
            }
        }
    )


class FtthFiberSitePayload(BaseModel):
    tower_name: str = Field(..., description="Site/tower name.")
    loopback_1072: str = Field(..., description="Loopback for the 1072 node.")
    loopback_1036: str = Field(..., description="Loopback for the 1036 node.")
    bh1_subnet: str = Field(..., description="Primary backhaul subnet.")
    link_1072_1036_a: str = Field(..., description="Link A between 1072 and 1036.")
    link_1072_1036_b: str = Field(..., description="Link B between 1072 and 1036.")
    fiber_port_ip: str = Field(..., description="Fiber uplink IP address.")
    backhauls: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional additional backhaul definitions.")
    apply_compliance: bool = Field(default=True, description="Apply compliance overlays before returning output.")


class FtthFiberSiteJobRequest(BaseModel):
    action: Literal["ftth.fiber_site"] = Field(..., description="Generate paired FTTH fiber site configurations.")
    payload: FtthFiberSitePayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "ftth.fiber_site",
                "payload": {
                    "tower_name": "WEST-HUB",
                    "loopback_1072": "10.249.50.1/32",
                    "loopback_1036": "10.249.50.2/32",
                    "bh1_subnet": "10.249.60.0/30",
                    "link_1072_1036_a": "10.249.61.0/31",
                    "link_1072_1036_b": "10.249.61.2/31",
                    "fiber_port_ip": "10.249.62.1/30",
                    "apply_compliance": True,
                },
            }
        }
    )


class FtthIsdFiberPayload(BaseModel):
    router_type: str = Field(..., description="Target router type.")
    tower_name: str = Field(..., description="Site/tower name.")
    loopback_subnet: str = Field(..., description="Loopback subnet or IP.")
    private_ip: str = Field(..., description="Private service IP.")
    public_ip: str = Field(..., description="Public service IP.")
    fiber_port_ip: str = Field(..., description="Fiber port IP.")
    backhauls: Optional[List[Dict[str, Any]]] = Field(default=None, description="Optional backhaul definitions.")
    apply_compliance: bool = Field(default=True, description="Apply compliance overlays before returning output.")


class FtthIsdFiberJobRequest(BaseModel):
    action: Literal["ftth.isd_fiber"] = Field(..., description="Generate ISD fiber configuration and port map.")
    payload: FtthIsdFiberPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "ftth.isd_fiber",
                "payload": {
                    "router_type": "CCR1036",
                    "tower_name": "WEST-HUB",
                    "loopback_subnet": "10.249.70.1/32",
                    "private_ip": "10.249.71.1/30",
                    "public_ip": "132.147.20.1/30",
                    "fiber_port_ip": "10.249.72.1/30",
                    "apply_compliance": True,
                },
            }
        }
    )


class BulkGeneratePayload(BaseModel):
    config_type: str = Field(..., description="Generator/config type to run in bulk.")
    rows: List[Dict[str, Any]] = Field(..., description="Normalized bulk input rows.")
    save_completed: bool = Field(default=True, description="Persist generated configs after successful execution.")


class BulkGenerateJobRequest(BaseModel):
    action: Literal["bulk.generate"] = Field(..., description="Generate multiple configs in a single batch.")
    payload: BulkGeneratePayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "bulk.generate",
                "payload": {
                    "config_type": "tower",
                    "rows": [{"site_name": "WEST-HUB", "loopback_subnet": "10.249.7.137/32"}],
                    "save_completed": True,
                },
            }
        }
    )


class BulkSshFetchPayload(BaseModel):
    rows: List[Dict[str, Any]] = Field(..., description="Bulk SSH fetch targets with host and credential fields.")
    command: Optional[str] = Field(default=None, description="Optional override command used for each target.")


class BulkSshFetchJobRequest(BaseModel):
    action: Literal["bulk.ssh_fetch"] = Field(..., description="Fetch configs from multiple devices over SSH.")
    payload: BulkSshFetchPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "bulk.ssh_fetch",
                "payload": {
                    "rows": [{"host": "10.249.10.10", "username": "admin", "password": "redacted"}],
                    "command": "/export terse",
                },
            }
        }
    )


class BulkMigrationAnalyzePayload(BaseModel):
    rows: List[Dict[str, Any]] = Field(..., description="Bulk migration source rows.")


class BulkMigrationAnalyzeJobRequest(BaseModel):
    action: Literal["bulk.migration_analyze"] = Field(..., description="Analyze multiple migration inputs before execution.")
    payload: BulkMigrationAnalyzePayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "bulk.migration_analyze",
                "payload": {"rows": [{"site_name": "WEST-HUB", "source_config": "/interface bridge add name=bridge1"}]},
            }
        }
    )


class BulkMigrationExecutePayload(BaseModel):
    rows: List[Dict[str, Any]] = Field(..., description="Prepared migration execution rows.")
    save_completed: bool = Field(default=True, description="Persist generated outputs after successful execution.")


class BulkMigrationExecuteJobRequest(BaseModel):
    action: Literal["bulk.migration_execute"] = Field(..., description="Execute a prepared bulk migration batch.")
    payload: BulkMigrationExecutePayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "bulk.migration_execute",
                "payload": {
                    "rows": [{"site_name": "WEST-HUB", "source_config": "/interface bridge add name=bridge1"}],
                    "save_completed": True,
                },
            }
        }
    )


class BulkComplianceScanPayload(BaseModel):
    rows: List[Dict[str, Any]] = Field(..., description="Configs or devices to scan in bulk.")
    mode: Optional[str] = Field(default=None, description="Optional scan mode/profile.")


class BulkComplianceScanJobRequest(BaseModel):
    action: Literal["bulk.compliance_scan"] = Field(..., description="Run bulk compliance scanning workflow.")
    payload: BulkComplianceScanPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "bulk.compliance_scan",
                "payload": {"rows": [{"site_name": "WEST-HUB", "config": "/routing ospf instance set default"}]},
            }
        }
    )


class SshPushConfigPayload(BaseModel):
    rows: List[Dict[str, Any]] = Field(..., description="Target devices plus config content to push.")
    dry_run: bool = Field(default=False, description="Validate connectivity without applying config.")


class SshPushConfigJobRequest(BaseModel):
    action: Literal["device.ssh_push_config"] = Field(..., description="Push prepared configs to multiple devices over SSH.")
    payload: SshPushConfigPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "device.ssh_push_config",
                "payload": {
                    "rows": [{"host": "10.249.10.10", "username": "admin", "password": "redacted", "config": "/system identity set name=RTR-EDGE-01"}],
                    "dry_run": False,
                },
            }
        }
    )


class CambiumRunPayload(BaseModel):
    radios: List[Dict[str, Any]] = Field(..., description="Cambium radios queued for maintenance or upgrade.")
    tasks: List[str] = Field(..., description="Requested task list such as backup, firmware, or verify.")
    firmware_version: Optional[str] = Field(default=None, description="Target firmware version when applicable.")
    firmware_source: Optional[str] = Field(default=None, description="Firmware catalog/source selector.")
    requested_by: Optional[str] = Field(default=None, description="Operator or calling system identity.")


class CambiumRunJobRequest(BaseModel):
    action: Literal["cambium.run"] = Field(..., description="Run Cambium radio workflow for backup, firmware, and verification.")
    payload: CambiumRunPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "cambium.run",
                "payload": {
                    "radios": [{"ip": "10.247.180.66", "username": "admin", "password": "redacted"}],
                    "tasks": ["backup", "firmware", "verify"],
                    "firmware_version": "5.10.4-13433",
                    "firmware_source": "stable",
                    "requested_by": "omni-automation",
                },
            }
        }
    )


class MikrotikToNokiaMigrationPayload(BaseModel):
    source_config: str = Field(..., description="Source MikroTik configuration text.")
    preserve_ips: bool = Field(default=True, description="Preserve source IP addressing during conversion.")
    tenant_code: Optional[str] = Field(default=None, description="Tenant identifier for template/policy lookups.")


class MikrotikToNokiaMigrationJobRequest(BaseModel):
    action: Literal["migration.mikrotik_to_nokia"] = Field(
        ..., description="Convert MikroTik configuration to Nokia SR OS format."
    )
    payload: MikrotikToNokiaMigrationPayload

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "action": "migration.mikrotik_to_nokia",
                "payload": {
                    "source_config": "/interface bridge add name=bridge1",
                    "preserve_ips": True,
                    "tenant_code": "tenant-a",
                },
            }
        }
    )


PublishedSubmitJobRequest = Union[
    HealthGetJobRequest,
    LegacyProxyJobRequest,
    FtthGenerateBngJobRequest,
    FtthPreviewBngJobRequest,
    NokiaGenerate7250JobRequest,
    TaranaGenerateJobRequest,
    AviatRunJobRequest,
    ConfigsSaveJobRequest,
    ConfigsGetJobRequest,
    DeviceFetchConfigSshJobRequest,
    ComplianceApplyJobRequest,
    CompliancePolicyGetJobRequest,
    FeedbackSubmitJobRequest,
    IdoPingJobRequest,
    IdoGenericDeviceInfoJobRequest,
    NokiaConfiguratorJobRequest,
    ParseMikrotikForNokiaJobRequest,
    FtthFiberCustomerJobRequest,
    FtthFiberSiteJobRequest,
    FtthIsdFiberJobRequest,
    BulkGenerateJobRequest,
    BulkSshFetchJobRequest,
    BulkMigrationAnalyzeJobRequest,
    BulkMigrationExecuteJobRequest,
    BulkComplianceScanJobRequest,
    SshPushConfigJobRequest,
    CambiumRunJobRequest,
    MikrotikToNokiaMigrationJobRequest,
    SubmitJobRequest,
]


class JobAcceptedData(BaseModel):
    job_id: str
    request_id: str
    action: str
    status: str


class JobAcceptedEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: JobAcceptedData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
                "status": "accepted",
                "message": "Job accepted",
                "data": {
                    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
                    "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
                    "action": "ftth.generate_bng",
                    "status": "queued",
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class JobsListData(BaseModel):
    jobs: List[JobSummary]
    count: int


class JobsListEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: JobsListData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "f8966fcb-98e2-44f8-8740-9ad2400c4bf7",
                "status": "ok",
                "message": "",
                "data": {
                    "jobs": [
                        {
                            "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
                            "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
                            "action": "health.get",
                            "submitted_by": "omni-prod-key",
                            "status": "success",
                            "created_at": "2026-03-30T02:04:30.164Z",
                            "started_at": "2026-03-30T02:04:31.164Z",
                            "finished_at": "2026-03-30T02:04:32.164Z",
                            "cancel_requested": False,
                            "result": {"http_status": 200, "ok": True},
                            "error": None,
                        }
                    ],
                    "count": 1,
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class JobDetailEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: JobDetail
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "15a4df1c-3f32-483b-ab59-2874521ca2f5",
                "status": "ok",
                "message": "",
                "data": {
                    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
                    "request_id": "9fcb9791-198c-43e3-8e5a-5f6aa7f15a03",
                    "action": "ftth.generate_bng",
                    "submitted_by": "omni-prod-key",
                    "status": "running",
                    "created_at": "2026-03-30T02:04:30.164Z",
                    "started_at": "2026-03-30T02:04:31.164Z",
                    "finished_at": None,
                    "cancel_requested": False,
                    "result": None,
                    "error": None,
                    "payload": {"deployment_type": "outstate"},
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class JobEventsData(BaseModel):
    job_id: str
    status: str
    events: List[EventItem]


class JobEventsEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: JobEventsData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "5a5e5db4-4ed6-4f26-ac87-d48eb7efc9f8",
                "status": "ok",
                "message": "",
                "data": {
                    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
                    "status": "running",
                    "events": [
                        {"ts": "2026-03-30T02:04:30.164Z", "level": "info", "message": "Started action"},
                        {"ts": "2026-03-30T02:04:31.164Z", "level": "success", "message": "Action completed"},
                    ],
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class CancelJobData(BaseModel):
    job_id: str
    status: str
    cancel_requested: bool


class CancelJobEnvelope(BaseModel):
    request_id: str
    status: str
    message: str = ""
    data: CancelJobData
    errors: List[str] = Field(default_factory=list)
    timestamp: str

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "request_id": "7dc6cb40-fc08-4e53-ad4d-8afeb1fdf0e0",
                "status": "ok",
                "message": "Cancel request accepted",
                "data": {
                    "job_id": "089d0977-cec4-4cd8-9961-5c2dc9bbb34f",
                    "status": "running",
                    "cancel_requested": True,
                },
                "errors": [],
                "timestamp": "2026-03-30T02:04:30.164Z",
            }
        }
    )


class PatchJobRequest(BaseModel):
    op: Optional[str] = Field(default=None, description="Use 'cancel' to request cancellation.")
    action: Optional[str] = Field(default=None, description="Legacy alias for op. 'stop' is also accepted.")

    model_config = ConfigDict(
        json_schema_extra={
            "examples": [
                {"op": "cancel"},
                {"action": "stop"},
            ]
        }
    )


COMMON_ERROR_RESPONSES = {
    400: {
        "model": ErrorResponse,
        "description": "Bad request / missing Idempotency-Key",
        "content": {"application/json": {"example": {"detail": "Missing Idempotency-Key"}}},
    },
    401: {
        "model": ErrorResponse,
        "description": "Missing auth or invalid signing headers",
        "content": {"application/json": {"example": {"detail": "Missing API key"}}},
    },
    403: {
        "model": ErrorResponse,
        "description": "Invalid API key or insufficient scope",
        "content": {"application/json": {"example": {"detail": "Insufficient scope; need 'job.submit'"}}},
    },
    404: {
        "model": ErrorResponse,
        "description": "Resource not found",
        "content": {"application/json": {"example": {"detail": "Job not found"}}},
    },
    409: {
        "model": ErrorResponse,
        "description": "Idempotency or replay conflict",
        "content": {"application/json": {"example": {"detail": "Idempotency-Key reused with different payload"}}},
    },
    422: {
        "model": ErrorResponse,
        "description": "Validation failure",
        "content": {"application/json": {"example": {"detail": "Missing 'action'"}}},
    },
    503: {
        "model": ErrorResponse,
        "description": "API key or signing config missing on server",
        "content": {
            "application/json": {
                "example": {
                    "detail": "API keys are not configured for /api/v2 (set NOC_API_KEYS_JSON or NOC_API_KEYS)"
                }
            }
        },
    },
}


PUBLIC_ACTION_NOTES: Dict[str, str] = {
    "health.get": "Tenant-neutral health probe for the published service.",
    "configs.save": "Persist rendered configuration artifacts and associated metadata.",
    "configs.get": "Retrieve one saved configuration artifact by id.",
    "ftth.generate_bng": "Generate FTTH BNG artifacts using tenant-selected templates and policy references.",
    "ftth.preview_bng": "Preview FTTH address planning output before generation.",
    "nokia.generate_7250": "Generate Nokia 7250 artifacts from tenant-neutral structured input.",
    "tarana.generate": "Generate Tarana-related configuration output.",
    "aviat.run": "Run Aviat maintenance workflow for backup, status, verification, and upgrade operations.",
    "device.fetch_config_ssh": "Fetch current device configuration over SSH using operator-supplied credentials.",
    "compliance.apply": "Apply compliance overlays or normalization rules to configuration text.",
    "compliance.policies.get": "Retrieve a named tenant policy/template definition.",
    "feedback.submit": "Submit operator feedback, bug reports, or feature requests.",
    "ido.ping": "Probe device reachability through the IDO backend.",
    "ido.generic.device_info": "Retrieve generic device facts through the IDO backend.",
    "nokia.configurator.generate": "Generate Nokia configurator output for the unified Nokia workflow.",
    "migration.parse_mikrotik_for_nokia": "Parse MikroTik exports into Nokia migration helper structures.",
    "ftth.fiber_customer": "Generate FTTH customer handoff configuration.",
    "ftth.fiber_site": "Generate paired FTTH fiber site configurations.",
    "ftth.isd_fiber": "Generate ISD fiber configuration output.",
    "bulk.generate": "Execute batch config generation workflow.",
    "bulk.ssh_fetch": "Fetch device configs in bulk over SSH.",
    "bulk.migration_analyze": "Analyze bulk migration inputs before execution.",
    "bulk.migration_execute": "Execute bulk migration jobs.",
    "bulk.compliance_scan": "Run compliance scan across a bulk input set.",
    "device.ssh_push_config": "Push prepared configs to devices over SSH.",
    "cambium.run": "Run Cambium backup, firmware, and verify workflow.",
    "migration.mikrotik_to_nokia": "Convert MikroTik configuration into Nokia SR OS format.",
    "legacy.proxy": "Escape hatch for approved internal routes while native contract coverage is completed.",
}


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso_now() -> str:
    return _utc_now().isoformat().replace("+00:00", "Z")


def _request_id() -> str:
    return str(uuid.uuid4())


def _secure_data_dir() -> Path:
    base = (os.getenv("NOC_RUNTIME_DIR") or "").strip()
    if base:
        p = Path(base)
    else:
        p = Path(__file__).resolve().parents[1] / "secure_data"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _db_path() -> Path:
    return _secure_data_dir() / "api_v2.db"


def _db_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(str(_db_path()), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def _json_dumps(value: Any) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False, sort_keys=True)


def _body_hash(body_bytes: bytes) -> str:
    return hashlib.sha256(body_bytes).hexdigest()


def _request_body_bytes(request: Request) -> bytes:
    cached = getattr(request.state, "_cached_body", None)
    if cached is None:
        cached = b""
        setattr(request.state, "_cached_body", cached)
    return cached


def _canonical_signing_message(request: Request, body_bytes: bytes, ts: str, nonce: str) -> str:
    return "\n".join(
        [
            request.method.upper(),
            request.url.path,
            ts,
            nonce,
            _body_hash(body_bytes),
        ]
    )


def _parse_signing_keys() -> Dict[str, str]:
    records: Dict[str, str] = {}
    raw_json = (os.getenv("NOC_API_SIGNING_KEYS_JSON") or "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                for kid, secret in parsed.items():
                    if str(kid).strip() and str(secret).strip():
                        records[str(kid).strip()] = str(secret).strip()
        except Exception:
            pass
    raw_compact = (os.getenv("NOC_API_SIGNING_KEYS") or "").strip()
    if raw_compact:
        for entry in raw_compact.split(";"):
            entry = entry.strip()
            if not entry or ":" not in entry:
                continue
            kid, secret = entry.split(":", 1)
            kid = kid.strip()
            secret = secret.strip()
            if kid and secret:
                records[kid] = secret
    return records


_SIGNING_KEYS = _parse_signing_keys()
_SIGNATURE_REQUIRED = (os.getenv("NOC_API_V2_REQUIRE_SIGNATURE", "true").strip().lower() not in {"0", "false", "no"})
_IDEMPOTENCY_REQUIRED = (os.getenv("NOC_API_V2_REQUIRE_IDEMPOTENCY", "true").strip().lower() not in {"0", "false", "no"})
_SIGNATURE_SKEW_SECONDS = int((os.getenv("NOC_API_V2_SIGNATURE_SKEW_SECONDS") or "300").strip())
_NONCE_TTL_SECONDS = int((os.getenv("NOC_API_V2_NONCE_TTL_SECONDS") or "900").strip())
_IDEMPOTENCY_TTL_SECONDS = int((os.getenv("NOC_API_V2_IDEMPOTENCY_TTL_SECONDS") or "86400").strip())


def _envelope(
    *,
    status: str,
    data: Any = None,
    message: str = "",
    errors: Optional[List[str]] = None,
    request_id: Optional[str] = None,
) -> Dict[str, Any]:
    return {
        "request_id": request_id or _request_id(),
        "status": status,
        "message": message,
        "data": data,
        "errors": errors or [],
        "timestamp": _iso_now(),
    }


def _parse_api_keys() -> Dict[str, Set[str]]:
    """
    Supports:
    - NOC_API_KEYS_JSON='{"key1":["admin"],"key2":["config.read","job.submit"]}'
    - NOC_API_KEYS='key1:admin,config.read;key2:config.read'
    - NOC_API_KEY='single-key' (grants admin)
    """
    records: Dict[str, Set[str]] = {}

    raw_json = (os.getenv("NOC_API_KEYS_JSON") or "").strip()
    if raw_json:
        try:
            parsed = json.loads(raw_json)
            if isinstance(parsed, dict):
                for key, scopes in parsed.items():
                    if not key:
                        continue
                    if isinstance(scopes, (list, tuple)):
                        records[str(key)] = {str(s).strip() for s in scopes if str(s).strip()}
                    elif isinstance(scopes, str):
                        records[str(key)] = {s.strip() for s in scopes.split(",") if s.strip()}
        except Exception:
            pass

    raw_compact = (os.getenv("NOC_API_KEYS") or "").strip()
    if raw_compact:
        for entry in raw_compact.split(";"):
            entry = entry.strip()
            if not entry:
                continue
            if ":" in entry:
                key, scope_csv = entry.split(":", 1)
                scopes = {s.strip() for s in scope_csv.split(",") if s.strip()}
            else:
                key, scopes = entry, {"admin"}
            key = key.strip()
            if key:
                records[key] = scopes or {"admin"}

    single = (os.getenv("NOC_API_KEY") or "").strip()
    if single:
        records.setdefault(single, {"admin"})

    return records


_API_KEYS = _parse_api_keys()


def _init_db() -> None:
    conn = _db_conn()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_jobs (
                job_id TEXT PRIMARY KEY,
                request_id TEXT,
                action TEXT NOT NULL,
                submitted_by TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT,
                error_text TEXT,
                cancel_requested INTEGER NOT NULL DEFAULT 0
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_jobs_created_at ON v2_jobs(created_at DESC)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_job_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                ts TEXT NOT NULL,
                level TEXT NOT NULL,
                message TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_job_events_job_id ON v2_job_events(job_id, id)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_nonces (
                nonce TEXT PRIMARY KEY,
                key_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_nonces_created_at ON v2_nonces(created_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_idempotency (
                idem_key TEXT NOT NULL,
                api_key TEXT NOT NULL,
                method TEXT NOT NULL,
                path TEXT NOT NULL,
                request_hash TEXT NOT NULL,
                response_json TEXT NOT NULL,
                status_code INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                PRIMARY KEY (idem_key, api_key, method, path)
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_idempotency_expires_at ON v2_idempotency(expires_at)")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS v2_maintenance_windows (
                window_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                scheduled_at TEXT NOT NULL,
                duration_minutes INTEGER NOT NULL,
                priority TEXT NOT NULL,
                devices_json TEXT NOT NULL,
                tasks_json TEXT NOT NULL,
                notes TEXT,
                ticket_number TEXT,
                ticket_url TEXT,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                created_by TEXT NOT NULL
            )
            """
        )
        cur.execute("CREATE INDEX IF NOT EXISTS idx_v2_maintenance_scheduled_at ON v2_maintenance_windows(scheduled_at DESC)")
        conn.commit()
    finally:
        conn.close()


def _prune_nonce_store(conn: sqlite3.Connection) -> None:
    cutoff = int(datetime.now(timezone.utc).timestamp()) - _NONCE_TTL_SECONDS
    conn.execute("DELETE FROM v2_nonces WHERE created_at < ?", (cutoff,))


def _reserve_nonce(key_id: str, nonce: str) -> None:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    conn = _db_conn()
    try:
        _prune_nonce_store(conn)
        conn.execute(
            "INSERT INTO v2_nonces(nonce, key_id, created_at) VALUES(?,?,?)",
            (nonce, key_id, now_ts),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=409, detail="Replay detected: nonce already used")
    finally:
        conn.close()


def _load_idempotency(
    *,
    idem_key: str,
    api_key: str,
    method: str,
    path: str,
    request_hash: str,
) -> Optional[Tuple[int, Dict[str, Any]]]:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    conn = _db_conn()
    try:
        conn.execute("DELETE FROM v2_idempotency WHERE expires_at < ?", (now_ts,))
        row = conn.execute(
            """
            SELECT request_hash, response_json, status_code
            FROM v2_idempotency
            WHERE idem_key=? AND api_key=? AND method=? AND path=? AND expires_at>=?
            """,
            (idem_key, api_key, method, path, now_ts),
        ).fetchone()
        conn.commit()
        if not row:
            return None
        if row["request_hash"] != request_hash:
            raise HTTPException(status_code=409, detail="Idempotency-Key reused with different payload")
        return int(row["status_code"]), json.loads(row["response_json"])
    finally:
        conn.close()


def _save_idempotency(
    *,
    idem_key: str,
    api_key: str,
    method: str,
    path: str,
    request_hash: str,
    status_code: int,
    response_json: Dict[str, Any],
) -> None:
    now_ts = int(datetime.now(timezone.utc).timestamp())
    exp_ts = now_ts + _IDEMPOTENCY_TTL_SECONDS
    conn = _db_conn()
    try:
        conn.execute(
            """
            INSERT OR REPLACE INTO v2_idempotency(
                idem_key, api_key, method, path, request_hash, response_json, status_code, created_at, expires_at
            ) VALUES(?,?,?,?,?,?,?,?,?)
            """,
            (
                idem_key,
                api_key,
                method,
                path,
                request_hash,
                _json_dumps(response_json),
                status_code,
                now_ts,
                exp_ts,
            ),
        )
        conn.commit()
    finally:
        conn.close()


_init_db()


def _require_scope(required: str) -> Callable[..., Dict[str, Any]]:
    async def _dep(
        request: Request,
        x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
        authorization: Optional[str] = Header(default=None, alias="Authorization"),
        x_key_id: Optional[str] = Header(default=None, alias="X-Key-Id"),
        x_timestamp: Optional[str] = Header(default=None, alias="X-Timestamp"),
        x_nonce: Optional[str] = Header(default=None, alias="X-Nonce"),
        x_signature: Optional[str] = Header(default=None, alias="X-Signature"),
    ) -> Dict[str, Any]:
        if not _API_KEYS:
            raise HTTPException(
                status_code=503,
                detail="API keys are not configured for /api/v2 (set NOC_API_KEYS_JSON or NOC_API_KEYS)",
            )
        token = (x_api_key or "").strip()
        if not token and authorization and authorization.lower().startswith("bearer "):
            token = authorization.split(" ", 1)[1].strip()
        if not token:
            raise HTTPException(status_code=401, detail="Missing API key")
        scopes = _API_KEYS.get(token)
        if scopes is None:
            raise HTTPException(status_code=403, detail="Invalid API key")
        if "admin" not in scopes and required not in scopes:
            raise HTTPException(status_code=403, detail=f"Insufficient scope; need '{required}'")

        body_bytes = await request.body()
        setattr(request.state, "_cached_body", body_bytes)

        if _SIGNATURE_REQUIRED:
            if not _SIGNING_KEYS:
                raise HTTPException(status_code=503, detail="Request-signing is required but no signing keys are configured")
            key_id = (x_key_id or "").strip()
            ts_raw = (x_timestamp or "").strip()
            nonce = (x_nonce or "").strip()
            signature = (x_signature or "").strip()
            if not key_id or not ts_raw or not nonce or not signature:
                raise HTTPException(status_code=401, detail="Missing signature headers (X-Key-Id, X-Timestamp, X-Nonce, X-Signature)")

            signing_secret = _SIGNING_KEYS.get(key_id)
            if not signing_secret:
                raise HTTPException(status_code=403, detail="Unknown signing key id")

            try:
                ts_val = int(ts_raw)
            except ValueError:
                raise HTTPException(status_code=401, detail="Invalid X-Timestamp")
            now_ts = int(datetime.now(timezone.utc).timestamp())
            if abs(now_ts - ts_val) > _SIGNATURE_SKEW_SECONDS:
                raise HTTPException(status_code=401, detail="Request timestamp out of allowed window")

            canonical = _canonical_signing_message(request, body_bytes, ts_raw, nonce)
            expected = hmac.new(signing_secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature):
                raise HTTPException(status_code=401, detail="Invalid request signature")

            _reserve_nonce(key_id, nonce)

        return {"api_key": token, "scopes": sorted(scopes)}

    return _dep


def _legacy_api_base() -> str:
    return (os.getenv("NOC_LEGACY_API_BASE") or "http://127.0.0.1:5000").rstrip("/")


def _mt_config_class(config_type: str):
    mapping = {
        "tower": MTTowerConfig,
        "bng2": MTBNG2Config,
    }
    cls = mapping.get((config_type or "").strip().lower())
    if not cls:
        raise ValueError(f"Unsupported config_type '{config_type}'")
    return cls


def _render_mt(action: str, payload: Dict[str, Any]) -> Any:
    config_type = (payload.get("config_type") or payload.get("type") or "").strip().lower()
    if not config_type:
        raise ValueError("Missing config_type")
    config_cls = _mt_config_class(config_type)
    local_payload = ido_merge_defaults(config_type, dict(payload.get("payload") or payload.get("data") or payload))
    apply_compliance = bool(local_payload.pop("apply_compliance", True))
    payload_loopback = local_payload.get("loopback_subnet") or local_payload.get("loop_ip")
    cfg = config_cls(**local_payload)
    if action == "mt.portmap":
        return cfg.generate_port_map()
    config_text = cfg.generate_config()
    if apply_compliance:
        config_text = ido_apply_compliance(config_text, payload_loopback)
    if config_type == "bng2":
        # Compliance blocks are shared across profiles; sanitize transport-only BNG2 output after compliance merge.
        config_text = MTBNG2Config._sanitize_transport_only_output(config_text)
    if action == "mt.config":
        return config_text
    return {"config": config_text, "portmap": cfg.generate_port_map(), "config_type": config_type}


def _legacy_call(payload: Dict[str, Any]) -> Any:
    method = str(payload.get("method") or "GET").upper()
    path = str(payload.get("path") or "").strip()
    if not path.startswith("/api/"):
        raise ValueError("legacy path must start with /api/")
    if path.startswith("/api/v2/"):
        raise ValueError("legacy path cannot target /api/v2/")

    timeout = int(payload.get("timeout") or 120)
    url = urljoin(_legacy_api_base() + "/", path.lstrip("/"))
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    headers = payload.get("headers") if isinstance(payload.get("headers"), dict) else {}
    body = payload.get("body")

    if method == "GET":
        resp = requests.get(url, params=params, headers=headers, timeout=timeout)
    elif method == "POST":
        resp = requests.post(url, params=params, headers=headers, json=body, timeout=timeout)
    elif method == "PUT":
        resp = requests.put(url, params=params, headers=headers, json=body, timeout=timeout)
    elif method == "PATCH":
        resp = requests.patch(url, params=params, headers=headers, json=body, timeout=timeout)
    elif method == "DELETE":
        resp = requests.delete(url, params=params, headers=headers, timeout=timeout)
    else:
        raise ValueError(f"Unsupported method '{method}'")

    content_type = (resp.headers.get("content-type") or "").lower()
    data: Any
    if "application/json" in content_type:
        try:
            data = resp.json()
        except Exception:
            data = {"raw": resp.text}
    else:
        data = {"raw": resp.text}

    return {
        "http_status": resp.status_code,
        "ok": 200 <= resp.status_code < 300,
        "path": path,
        "method": method,
        "response": data,
    }


def _legacy_get(path: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(payload: Dict[str, Any]) -> Any:
        params = payload.get("params") if isinstance(payload.get("params"), dict) else payload
        return _legacy_call({"method": "GET", "path": path, "params": params})
    return _handler


def _legacy_post(path: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(payload: Dict[str, Any]) -> Any:
        body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
        return _legacy_call({"method": "POST", "path": path, "body": body})
    return _handler


def _legacy_put(path: str) -> Callable[[Dict[str, Any]], Any]:
    def _handler(payload: Dict[str, Any]) -> Any:
        body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
        return _legacy_call({"method": "PUT", "path": path, "body": body})
    return _handler


def _ido_proxy_call(target_path: str, payload: Dict[str, Any]) -> Any:
    method = str(payload.get("method") or "POST").upper()
    body = payload.get("body") if isinstance(payload.get("body"), dict) else payload
    params = payload.get("params") if isinstance(payload.get("params"), dict) else {}
    proxy_path = f"/api/ido/proxy/{target_path.lstrip('/')}"
    return _legacy_call({"method": method, "path": proxy_path, "params": params, "body": body})


def _require_int(payload: Dict[str, Any], key: str) -> int:
    try:
        return int(payload.get(key))
    except Exception:
        raise ValueError(f"Missing or invalid '{key}'")


def _configs_get(payload: Dict[str, Any]) -> Any:
    config_id = _require_int(payload, "config_id")
    return _legacy_call({"method": "GET", "path": f"/api/get-completed-config/{config_id}"})


def _configs_portmap_download(payload: Dict[str, Any]) -> Any:
    config_id = _require_int(payload, "config_id")
    return _legacy_call({"method": "GET", "path": f"/api/download-port-map/{config_id}"})


def _aviat_abort(payload: Dict[str, Any]) -> Any:
    task_id = str(payload.get("task_id") or "").strip()
    if not task_id:
        raise ValueError("Missing 'task_id'")
    body = payload.get("body") if isinstance(payload.get("body"), dict) else {}
    return _legacy_call({"method": "POST", "path": f"/api/aviat/abort/{task_id}", "body": body})


def _aviat_status(payload: Dict[str, Any]) -> Any:
    task_id = str(payload.get("task_id") or "").strip()
    if not task_id:
        raise ValueError("Missing 'task_id'")
    return _legacy_call({"method": "GET", "path": f"/api/aviat/status/{task_id}"})


def _admin_feedback_update_status(payload: Dict[str, Any]) -> Any:
    feedback_id = _require_int(payload, "feedback_id")
    body = {k: v for k, v in payload.items() if k != "feedback_id"}
    return _legacy_call({"method": "PUT", "path": f"/api/admin/feedback/{feedback_id}/status", "body": body})


def _compliance_policy_get(payload: Dict[str, Any]) -> Any:
    policy_name = str(payload.get("policy_name") or "").strip()
    if not policy_name:
        raise ValueError("Missing 'policy_name'")
    return _legacy_call({"method": "GET", "path": f"/api/get-config-policy/{policy_name}"})


def _require_str(payload: Dict[str, Any], key: str) -> str:
    value = str(payload.get(key) or "").strip()
    if not value:
        raise ValueError(f"Missing '{key}'")
    return value


def _parse_ipv4(value: str) -> str:
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except Exception as exc:
        raise ValueError(f"Invalid IPv4 address '{value}'") from exc


def _parse_network(value: str) -> ipaddress.IPv4Network:
    try:
        return ipaddress.IPv4Network(str(value).strip(), strict=False)
    except Exception as exc:
        raise ValueError(f"Invalid IPv4 network '{value}'") from exc


def _netmask_to_prefix(value: str) -> int:
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{str(value).strip()}").prefixlen
    except Exception as exc:
        raise ValueError(f"Invalid IPv4 netmask '{value}'") from exc


def _mask_cisco_secret(value: str) -> str:
    return (value or "").replace("0456532B5A0B5B580D2028", "***")


def _render_cisco_interface(payload: Dict[str, Any]) -> Dict[str, Any]:
    desc = _require_str(payload, "port_description")
    port_type = str(payload.get("port_type") or "TenGigE").strip() or "TenGigE"
    port_number = _require_str(payload, "port_number")
    interface_ip = _parse_ipv4(_require_str(payload, "interface_ip"))
    subnet_mask = _parse_ipv4(str(payload.get("subnet_mask") or "255.255.255.252").strip())
    ospf_cost = str(payload.get("ospf_cost") or "10").strip() or "10"
    ospf_process = str(payload.get("ospf_process") or "1").strip() or "1"
    ospf_area = str(payload.get("ospf_area") or "0").strip() or "0"
    mtu = str(payload.get("mtu") or "9216").strip() or "9216"
    passive = str(payload.get("passive") or "No").strip().lower() in {"yes", "true", "1"}
    ospf_key = str(payload.get("ospf_key") or "0456532B5A0B5B580D2028").strip()

    passive_line = "passive" if passive else "no passive"
    lines = [
        "configure terminal",
        "",
        f"interface {port_type} {port_number}",
        f"description {desc}",
        f"mtu {mtu}",
        f"ipv4 address {interface_ip} {subnet_mask}",
        "no shutdown",
        "!",
        "",
        f"router ospf {ospf_process} area {ospf_area}",
        f" interface {port_type} {port_number}",
        f"  cost {ospf_cost}",
        "  authentication message-digest",
        f"  message-digest-key 1 md5 encrypted {ospf_key}",
        "  network point-to-point",
        f"  {passive_line}",
        " !",
        "",
        "commit",
        "end",
    ]
    config = "\n".join(lines).strip() + "\n"
    return {
        "success": True,
        "config": config,
        "masked_preview": _mask_cisco_secret(config),
        "metadata": {
            "port_description": desc,
            "port_type": port_type,
            "port_number": port_number,
            "interface_ip": interface_ip,
            "subnet_mask": subnet_mask,
            "ospf_cost": ospf_cost,
            "ospf_process": ospf_process,
            "ospf_area": ospf_area,
            "mtu": mtu,
            "passive": passive,
        },
    }


def _render_enterprise_feeding(payload: Dict[str, Any]) -> Dict[str, Any]:
    label = _require_str(payload, "label")
    port = _require_str(payload, "port")
    speed = str(payload.get("speed") or "auto").strip() or "auto"
    loop = str(payload.get("loopback_ip") or "").strip()
    public_ip = str(payload.get("public_ip") or "").strip()
    uplink = _parse_network(_require_str(payload, "backhaul_cidr"))

    network_int = int(uplink.network_address)
    prefix = uplink.prefixlen
    total_addresses = 2 ** (32 - prefix)
    last_usable = network_int + (total_addresses - 2 if prefix < 31 else total_addresses - 1)
    tower_gateway_int = network_int + 1
    customer_gateway_int = network_int + 4
    if customer_gateway_int > last_usable:
        raise ValueError(f"Subnet {uplink.with_prefixlen} does not have enough usable addresses for enterprise feeding")

    backhaul_ip = str(ipaddress.IPv4Address(tower_gateway_int))
    backhaul_network = str(uplink.network_address)
    gateway_ip = str(ipaddress.IPv4Address(customer_gateway_int))
    backhaul_network_cidr = f"{backhaul_network}/{prefix}"

    config = "# === Enterprise / Commercial Auto-generated ===\n\n"
    config += "/interface ethernet\n"
    ethernet_parts = [f'comment="{label}"']
    if speed == "auto":
        ethernet_parts.append("auto-negotiation=yes")
    else:
        ethernet_parts.append("auto-negotiation=no")
        ethernet_parts.append(speed if "duplex=" in speed else f"speed={speed}")
    config += f"set [ find default-name={port} ] {' '.join(ethernet_parts)}\n\n"
    config += "/ip address\n"
    config += f'add address={backhaul_ip}/{prefix} comment="{label}" interface={port} network={backhaul_network}\n\n'
    config += "/ip firewall address-list\n"
    if loop:
        loop_ip = str(loop).split("/", 1)[0]
        _parse_ipv4(loop_ip)
        config += f'add address={loop_ip} comment="{label}" list=bgp-networks\n'
    if public_ip:
        _parse_ipv4(public_ip)
        config += f'add address={public_ip} comment="{label}" list=bgp-networks\n'
    config += "\n"
    if loop or public_ip:
        config += "/ip route\n"
        if loop:
            config += f'add comment="{label}" disabled=no distance=1 dst-address={loop_ip} gateway={gateway_ip} routing-table=main scope=30 target-scope=10\n'
        if public_ip:
            config += f'add comment="{label}" disabled=no distance=1 dst-address={public_ip} gateway={gateway_ip} routing-table=main scope=30 target-scope=10\n'
        config += "\n"
    config += "/routing ospf interface-template\n"
    config += f'add area=backbone-v2 auth-id=1 comment="{label}" cost=10 disabled=no networks={backhaul_network_cidr} priority=1\n'
    return {
        "success": True,
        "config": config,
        "metadata": {
            "label": label,
            "port": port,
            "tower_gateway_ip": backhaul_ip,
            "customer_gateway_ip": gateway_ip,
            "network": backhaul_network_cidr,
        },
    }


def _render_enterprise_feeding_outstate(payload: Dict[str, Any]) -> Dict[str, Any]:
    state = _require_str(payload, "state").upper()
    loopback = _require_str(payload, "loopback_ip")
    username = _require_str(payload, "username")
    loopback_ip = str(loopback).split("/", 1)[0]
    _parse_ipv4(loopback_ip)
    tunnel_type = "bgp-tunnel" if state == "IL" else "ldp"

    config = "################################\n"
    config += "###       BNG CONFIGS        ###\n"
    config += "################################\n"
    config += "# Copy and Paste these lines into the BNGs removing the leading # sign\n\n"
    config += "# MT BNG\n"
    config += f'#/interface vpls add name=vpls2000-{username} disabled=no advertised-l2mtu=1580 cisco-style=yes cisco-style-id=2245 comment="VPLS2000-{username}"  remote-peer={loopback_ip}\n'
    config += f'#/interface bridge port add bridge=bridge2000 interface=vpls2000-{username} horizon=1\n\n'
    config += "# Nokia BNG\n"
    config += "#show service sdp     ###Shows used SDP IDs###\n"
    config += "#/configure service sdp <Next available SdpId> mpls create\n"
    config += f"#/configure service sdp <Next available SdpId> mpls description {username}     ###Adds tower description###\n"
    config += f"#/configure service sdp <Next available SdpId> mpls far-end {loopback_ip}           ###Tower Loop###\n"
    config += f"#/configure service sdp <Next available SdpId> mpls {tunnel_type}                          ###{'bgp-tunnel for CHICAGO' if state == 'IL' else 'ldp for OMAHA and most regions'}\n"
    config += "#/configure service sdp <Next available SdpId> mpls keep-alive shutdown\n"
    config += "#/configure service sdp <Next available SdpId> mpls no shutdown\n"
    config += "#/configure service vpls 2245 mesh-sdp <next available>:2245 create restrict-protected-src discard-frame\n"
    config += "#/configure service vpls 2245 mesh-sdp <next available>:2245 no shutdown\n"
    return {
        "success": True,
        "config": config,
        "metadata": {"state": state, "loopback_ip": loopback_ip, "username": username, "tunnel_type": tunnel_type},
    }


def _compute_config_diff(payload: Dict[str, Any]) -> Dict[str, Any]:
    config_a = str(payload.get("config_a") or payload.get("left") or "").replace("\r\n", "\n")
    config_b = str(payload.get("config_b") or payload.get("right") or "").replace("\r\n", "\n")
    if not config_a and not config_b:
        raise ValueError("At least one of 'config_a' or 'config_b' is required")

    lines_a = config_a.split("\n")
    lines_b = config_b.split("\n")
    diff_lines = list(difflib.ndiff(lines_a, lines_b))
    added = sum(1 for line in diff_lines if line.startswith("+ "))
    removed = sum(1 for line in diff_lines if line.startswith("- "))
    changed = added + removed
    return {
        "success": True,
        "summary": {
            "left_lines": len(lines_a),
            "right_lines": len(lines_b),
            "added": added,
            "removed": removed,
            "changed": changed,
        },
        "diff": diff_lines,
    }


def _normalize_dns_servers(value: Any) -> str:
    if isinstance(value, list):
        items = [str(v).strip() for v in value if str(v).strip()]
        if not items:
            raise ValueError("dns_servers must not be empty")
        return ",".join(items)
    text = str(value or "").strip()
    if not text:
        raise ValueError("Missing 'dns_servers'")
    return text


def _render_6ghz_switch(payload: Dict[str, Any]) -> Dict[str, Any]:
    switch_type = _require_str(payload, "switch_type")
    routeros_version = _require_str(payload, "routeros_version")
    vlan3000 = _parse_network(_require_str(payload, "vlan3000_subnet"))
    vlan4000 = _parse_network(_require_str(payload, "vlan4000_subnet"))
    pool_offset = int(payload.get("pool_offset") or 0)
    dns_servers = _normalize_dns_servers(payload.get("dns_servers"))
    shared_key = str(payload.get("shared_key") or "CHANGE_ME").strip() or "CHANGE_ME"

    if switch_type == "swt_mt326":
        port1, port2, switch_comment = "sfp-sfpplus8", "sfp-sfpplus9", "SWT-CRS326"
    elif switch_type == "swt_ccr2004":
        port1, port2, switch_comment = "sfp-sfpplus8", "sfp-sfpplus9", "SWT-CCR2004"
    elif switch_type == "swt_mt309":
        port1, port2, switch_comment = "sfp-sfpplus8", "sfp-sfpplus9", "SWT-MT309"
    else:
        raise ValueError(f"Unsupported switch_type '{switch_type}'")

    gateway_3000 = str(next(vlan3000.hosts()))
    gateway_4000 = str(next(vlan4000.hosts()))
    broadcast_4000 = vlan4000.broadcast_address
    last_usable_4000 = str(ipaddress.IPv4Address(int(broadcast_4000) - 1))
    pool_start = str(ipaddress.IPv4Address(int(ipaddress.IPv4Address(gateway_4000)) + pool_offset))

    config = "###################################\n###  6GHz SWITCH PORT CONFIG    ###\n###################################\n\n"
    config += "/interface bridge\n"
    config += "add name=bridge2000 port-cost-mode=short\n"
    config += "add name=bridge3000 port-cost-mode=short\n"
    config += "add name=bridge4000 port-cost-mode=short\n\n"
    config += "/interface ethernet\n"
    config += f'set [ find default-name={port1} ] comment="{switch_comment} Uplink #1 - BONDED" speed=10G-baseSR-LR\n'
    config += f'set [ find default-name={port2} ] comment="{switch_comment} Uplink #2 - BONDED" speed=10G-baseSR-LR\n\n'
    config += "/interface bonding\n"
    config += f"add lacp-user-key=1 mode=802.3ad name=bonding1 slaves={port1},{port2} transmit-hash-policy=layer-2-and-3\n\n"
    config += "/interface vlan\n"
    config += "add interface=bonding1 name=vlan1000-bonding1 vlan-id=1000\n"
    config += "add interface=bonding1 name=vlan2000-bonding1 vlan-id=2000\n"
    config += "add interface=bonding1 name=vlan3000-bonding1 vlan-id=3000\n"
    config += "add interface=bonding1 name=vlan4000-bonding1 vlan-id=4000\n\n"
    config += "/interface bridge port\n"
    config += "add bridge=bridge4000 ingress-filtering=no interface=vlan4000-bonding1 internal-path-cost=10 path-cost=10\n"
    config += "add bridge=bridge3000 ingress-filtering=no interface=vlan3000-bonding1 internal-path-cost=10 path-cost=10\n"
    config += "add bridge=lan-bridge ingress-filtering=no interface=vlan1000-bonding1 internal-path-cost=10 path-cost=10\n"
    config += "add bridge=bridge2000 ingress-filtering=no interface=vlan2000-bonding1 internal-path-cost=10 path-cost=10\n\n"
    config += "/ip address\n"
    config += f"add address={gateway_3000}/{vlan3000.prefixlen} comment=6GHZ interface=bridge3000 network={vlan3000.network_address}\n"
    config += f'add address={gateway_4000}/{vlan4000.prefixlen} comment="6GHZ CPE" interface=bridge4000 network={vlan4000.network_address}\n\n'
    config += "/ip pool\n"
    config += f"add name=vlan4000 ranges={pool_start}-{last_usable_4000}\n\n"
    config += "/ip dhcp-server\n"
    config += "add address-pool=vlan4000 interface=bridge4000 lease-time=1h name=vlan4000\n\n"
    config += "/ip dhcp-server network\n"
    config += f"add address={vlan4000.network_address}/{vlan4000.prefixlen} dns-server={dns_servers} gateway={gateway_4000} netmask={vlan4000.prefixlen}\n\n"
    config += "/ip firewall address-list\n"
    config += f"add address={vlan3000.network_address}/{vlan3000.prefixlen} comment=6ghz list=bgp-networks\n\n"
    config += "/routing ospf interface-template\n"
    config += f'add area=backbone-v2 auth=md5 auth-id=1 auth-key={shared_key} comment="6GHZ CPE" disabled=no interfaces=bridge4000 networks={vlan4000.network_address}/{vlan4000.prefixlen} passive priority=1\n'
    return {
        "success": True,
        "config": config,
        "metadata": {
            "switch_type": switch_type,
            "routeros_version": routeros_version,
            "dns_servers": dns_servers.split(","),
        },
    }


def _render_6ghz_switch_outstate(payload: Dict[str, Any]) -> Dict[str, Any]:
    switch_type = _require_str(payload, "switch_type")
    routeros_version = _require_str(payload, "routeros_version")
    del routeros_version
    if switch_type == "swt_mt309":
        switch_comment = "SWT-CRS309"
        port = _require_str(payload, "port")
        config = "###################################\n###  6GHz SWITCH CONFIG (OUT-OF-STATE)  ###\n###################################\n\n"
        config += "/interface bridge\nadd comment=DYNAMIC name=bridge1000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=STATIC name=bridge2000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=INFRA name=bridge3000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=CPE name=bridge4000 port-cost-mode=short protocol-mode=none\n\n"
        config += f"/interface ethernet\nset [ find default-name={port} ] auto-negotiation=no comment={switch_comment} speed=10G-baseSR-LR\n\n"
        config += "/interface vlan\n"
        config += f"add comment=VLAN1000-DYNAMIC interface={port} name=vlan1000-B vlan-id=1000\n"
        config += f"add comment=VLAN2000-STATIC interface={port} name=vlan2000-B vlan-id=2000\n"
        config += f"add comment=VLAN3000-INFRA interface={port} name=vlan3000-B vlan-id=3000\n"
        config += f"add comment=VLAN4000-CPE interface={port} name=vlan4000-B vlan-id=4000\n\n"
        config += "/interface bridge port\n"
        config += "add bridge=bridge1000 interface=vlan1000-B internal-path-cost=10 path-cost=10\n"
        config += "add bridge=bridge2000 interface=vlan2000-B internal-path-cost=10 path-cost=10\n"
        config += "add bridge=bridge3000 interface=vlan3000-B internal-path-cost=10 path-cost=10\n"
        config += "add bridge=bridge4000 interface=vlan4000-B internal-path-cost=10 path-cost=10\n"
        return {"success": True, "config": config, "metadata": {"switch_type": switch_type, "port": port}}
    if switch_type == "swt_ccr2004":
        switch_comment = "SWT-MT2004"
        port = _require_str(payload, "port")
        config = "###################################\n###  6GHz SWITCH CONFIG (OUT-OF-STATE)  ###\n###################################\n\n"
        config += "/interface bridge\nadd comment=DYNAMIC name=bridge1000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=STATIC name=bridge2000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=INFRA name=bridge3000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=CPE name=bridge4000 port-cost-mode=short protocol-mode=none\n\n"
        config += f"/interface ethernet\nset [ find default-name={port} ] auto-negotiation=no comment={switch_comment} speed=10G-baseSR-LR\n\n"
        config += "/interface vlan\n"
        config += f"add comment=VLAN1000-DYNAMIC interface={port} name=vlan1000-B vlan-id=1000\n"
        config += f"add comment=VLAN2000-STATIC interface={port} name=vlan2000-B vlan-id=2000\n"
        config += f"add comment=VLAN3000-INFRA interface={port} name=vlan3000-B vlan-id=3000\n"
        config += f"add comment=VLAN4000-CPE interface={port} name=vlan4000-B vlan-id=4000\n\n"
        config += "/interface bridge port\n"
        config += "add bridge=bridge1000 interface=vlan1000-B internal-path-cost=10 path-cost=10\n"
        config += "add bridge=bridge2000 interface=vlan2000-B internal-path-cost=10 path-cost=10\n"
        config += "add bridge=bridge3000 interface=vlan3000-B internal-path-cost=10 path-cost=10\n"
        config += "add bridge=bridge4000 interface=vlan4000-B internal-path-cost=10 path-cost=10\n"
        config += f"add bridge=bridge9990 disabled=yes interface={port} internal-path-cost=10 path-cost=10\n"
        return {"success": True, "config": config, "metadata": {"switch_type": switch_type, "port": port}}
    if switch_type == "swt_mt326":
        port1 = _require_str(payload, "port1")
        port2 = _require_str(payload, "port2")
        if port1 == port2:
            raise ValueError("port1 and port2 must be different")
        config = "###################################\n###  6GHz SWITCH CONFIG (OUT-OF-STATE)  ###\n###################################\n\n"
        config += "/interface bridge\nadd comment=DYNAMIC name=bridge1000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=DHCP name=bridge1500 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=STATIC name=bridge2000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=INFRA name=bridge3000 port-cost-mode=short protocol-mode=none\n"
        config += "add comment=CPE name=bridge4000 port-cost-mode=short protocol-mode=none\n\n"
        config += f'/interface ethernet\nset [ find default-name={port1} ] comment="SWT-CRS326 Uplink #1 - BONDED"\n'
        config += f'set [ find default-name={port2} ] comment="SWT-CRS326 Uplink #2 - BONDED"\n\n'
        config += f"/interface bonding\nadd lacp-user-key=1 mode=802.3ad name=bonding1 slaves={port1},{port2} transmit-hash-policy=layer-2-and-3\n\n"
        config += "/interface vlan\nadd interface=bonding1 name=vlan1000-bonding1 vlan-id=1000\nadd interface=bonding1 name=vlan2000-bonding1 vlan-id=2000\nadd interface=bonding1 name=vlan3000-bonding1 vlan-id=3000\nadd interface=bonding1 name=vlan4000-bonding1 vlan-id=4000\n\n"
        config += "/interface bridge port\nadd bridge=bridge4000 ingress-filtering=no interface=vlan4000-bonding1 internal-path-cost=10 path-cost=10\nadd bridge=bridge3000 ingress-filtering=no interface=vlan3000-bonding1 internal-path-cost=10 path-cost=10\nadd bridge=bridge1000 ingress-filtering=no interface=vlan1000-bonding1 internal-path-cost=10 path-cost=10\nadd bridge=bridge2000 ingress-filtering=no interface=vlan2000-bonding1 internal-path-cost=10 path-cost=10\n"
        return {"success": True, "config": config, "metadata": {"switch_type": switch_type, "port1": port1, "port2": port2}}
    raise ValueError(f"Unsupported switch_type '{switch_type}'")


def _render_mpls_enterprise(payload: Dict[str, Any]) -> Dict[str, Any]:
    device = str(payload.get("routerboard_device") or payload.get("device") or "").strip().lower()
    if not device:
        raise ValueError("Missing 'routerboard_device'")
    customer_code = _require_str(payload, "customer_code")
    loopback_ip = _require_str(payload, "loopback_ip").replace("/32", "").strip()
    _parse_ipv4(loopback_ip)
    device_name = str(payload.get("device_name") or customer_code).strip() or customer_code
    customer_handoff = _require_str(payload, "customer_handoff")
    uplinks = payload.get("uplinks") or []
    if not isinstance(uplinks, list) or not uplinks:
        raise ValueError("MPLS enterprise requires a non-empty 'uplinks' list")
    dns_servers = _normalize_dns_servers(payload.get("dns_servers"))
    dns_items = [item.strip() for item in dns_servers.split(",") if item.strip()]
    if len(dns_items) < 2:
        raise ValueError("dns_servers must contain at least two DNS servers")
    syslog_server = str(payload.get("syslog_server") or "").strip()
    shared_key = str(payload.get("shared_key") or "CHANGE_ME").strip() or "CHANGE_ME"
    snmp_community = str(payload.get("snmp_community") or "CHANGE_ME").strip() or "CHANGE_ME"
    snmp_contact = str(payload.get("snmp_contact") or "noc@example.invalid").strip() or "noc@example.invalid"
    vpls_static_id = str(payload.get("vpls_static_id") or "2245").strip() or "2245"
    vpls_peer = str(payload.get("vpls_peer") or "").strip()
    enable_bgp = bool(payload.get("enable_bgp"))
    bgp_as = int(payload.get("bgp_as") or 0) if enable_bgp else 0
    bgp_peers = payload.get("bgp_peers") or []
    if enable_bgp and (not bgp_as or not isinstance(bgp_peers, list) or not bgp_peers):
        raise ValueError("When enable_bgp=true, provide bgp_as and at least one bgp_peers entry")

    config = "################################\n###       BASE CONFIG        ###\n################################\n\n"
    config += f"# PORT MAP SUMMARY\n# Customer handoff: {customer_handoff}\n# Primary uplink: {uplinks[0].get('interface','UNSET')}\n\n"
    config += "# IP SERVICES\n/ip service set telnet disabled=yes port=5023\n/ip service set ftp disabled=yes port=5021\n/ip service set www disabled=yes port=1234\n/ip service set ssh port=5022 address=\"\"\n/ip service set api disabled=yes\n/ip service set api-ssl disabled=yes\n/ip service set www-ssl disabled=no port=443\n/ip service set winbox address=\"\"\n\n"
    config += "# BRIDGES\n/interface bridge\nadd comment=DYNAMIC name=bridge1000 protocol-mode=none\nadd comment=STATIC name=bridge2000 protocol-mode=none\nadd comment=INFRA name=bridge3000 protocol-mode=none\nadd comment=CPE name=bridge4000 protocol-mode=none\nadd comment=LOOPBACK name=loop0\n\n"
    config += "# DNS\n/ip dns\n"
    config += f"set servers={dns_items[0]},{dns_items[1]}\n\n"
    config += "################################\n###       SYSTEM SPECIFIC    ###\n################################\n\n"
    config += f"/system identity\nset name={device_name}\n\n"
    config += "/mpls interface\nadd disabled=no interface=all mpls-mtu=9000\n\n"
    if vpls_peer:
        config += "/interface vpls\n"
        config += f"add arp=enabled bridge=bridge2000 bridge-horizon=1 cisco-static-id={vpls_static_id} disabled=no mtu=1500 name=vpls2000-bng1 peer={vpls_peer} pw-control-word=disabled pw-l2mtu=1500 pw-type=raw-ethernet\n\n"
    config += f"/interface ethernet\nset [ find default-name={customer_handoff} ] comment=\"Customer Uplink #1\"\n\n"
    config += f"/interface bridge port\nadd bridge=bridge2000 interface={customer_handoff}\n\n"

    for uplink in uplinks:
        iface = _require_str(uplink, "interface")
        ip_cidr = _require_str(uplink, "ip")
        network = _parse_network(ip_cidr)
        comment = str(uplink.get("comment") or device_name).replace('"', "")
        config += "/interface ethernet\n"
        config += f"set [ find default-name={iface} ] comment=\"{comment}\" l2mtu=9212 mtu=9198\n"
        config += "/ip address\n"
        config += f"add address={ip_cidr} interface={iface} comment=\"{comment}\" network={network.network_address}/{network.prefixlen}\n\n"
        config += "/mpls ldp interface\n"
        config += f"add interface={iface} comment=\"{comment}\"\n\n"
        config += "/routing ospf interface-template\n"
        config += f"add area=area0 auth=md5 auth-id=1 auth-key={shared_key} comment=\"{comment}\" cost=10 disabled=no interfaces={iface} networks={network.network_address}/{network.prefixlen} priority=1 type=ptp\n\n"

    config += f"/routing ospf instance\nadd disabled=no name=default-v2 router-id={loopback_ip}\n\n"
    config += "/routing ospf area\nadd disabled=no instance=default-v2 name=area0 area-id=0.0.0.0 type=default\n\n"
    config += "/ip address\n"
    config += f"add address={loopback_ip}/32 interface=loop0 network={loopback_ip}\n\n"
    config += "/routing bgp template\nadd as=65000 disabled=no name=default routing-table=main\n\n"
    if enable_bgp:
        config += "/routing bgp connection\n"
        for idx, peer in enumerate(bgp_peers, 1):
            peer_ip = _parse_ipv4(_require_str(peer, "ip"))
            peer_as = int(peer.get("as") or bgp_as)
            config += f"add name=peer-{idx} remote.address={peer_ip} remote.as={peer_as} templates=default tcp-md5-key={shared_key}\n"
        config += "\n"
    config += "/snmp community\nset [ find default=yes ] read-access=no\n"
    config += f"add name={snmp_community} addresses=::/0\n/snmp\nset contact={snmp_contact} enabled=yes location=\"\" trap-community={snmp_community} src-address={loopback_ip}\n\n"
    if syslog_server:
        config += "/system logging action\n"
        config += f"add name=syslog remote={syslog_server} src-address={loopback_ip} target=remote\n"
        config += "/system logging\nadd action=syslog topics=critical\nadd action=syslog topics=error\nadd action=syslog topics=info\nadd action=syslog topics=warning\n\n"
    config += "################################\n###       BNG CONFIGS        ###\n################################\n"
    config += "# Copy and Paste these lines into the BNGs removing the leading # sign\n\n"
    config += "# MT BNG\n"
    config += f"#/interface vpls add name=vpls2000-{device_name} disabled=no advertised-l2mtu=1580 cisco-style=yes cisco-style-id={vpls_static_id} comment=\"VPLS2000-{device_name}\"  remote-peer={loopback_ip}\n"
    config += f"#/interface bridge port add bridge=bridge2000 interface=vpls2000-{device_name} horizon=1\n\n"
    config += "# Nokia BNG\n#show service sdp     ###Shows used SDP IDs###\n"
    config += "#/configure service sdp <Next available SdpId> mpls create\n"
    config += f"#/configure service sdp <Next available SdpId> mpls description {device_name}\n"
    config += f"#/configure service sdp <Next available SdpId> mpls far-end {loopback_ip}\n"
    config += "#/configure service sdp <Next available SdpId> mpls ldp\n"
    config += "#/configure service sdp <Next available SdpId> mpls keep-alive shutdown\n"
    config += "#/configure service sdp <Next available SdpId> mpls no shutdown\n"
    config += f"#/configure service vpls {vpls_static_id} mesh-sdp <next available>:{vpls_static_id} create restrict-protected-src discard-frame\n"
    config += f"#/configure service vpls {vpls_static_id} mesh-sdp <next available>:{vpls_static_id} no shutdown\n"
    return {
        "success": True,
        "config": config,
        "metadata": {
            "routerboard_device": device,
            "customer_code": customer_code,
            "device_name": device_name,
            "loopback_ip": loopback_ip,
            "customer_handoff": customer_handoff,
        },
    }


def _maintenance_row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
    return {
        "window_id": row["window_id"],
        "name": row["name"],
        "scheduled_at": row["scheduled_at"],
        "duration_minutes": int(row["duration_minutes"]),
        "priority": row["priority"],
        "devices": json.loads(row["devices_json"] or "[]"),
        "tasks": json.loads(row["tasks_json"] or "[]"),
        "notes": row["notes"] or "",
        "ticket_number": row["ticket_number"] or "",
        "ticket_url": row["ticket_url"] or "",
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "created_by": row["created_by"],
    }


def _maintenance_list(status: Optional[str] = None, limit: int = 250) -> List[Dict[str, Any]]:
    conn = _db_conn()
    try:
        params: List[Any] = []
        sql = "SELECT * FROM v2_maintenance_windows"
        if status and status != "all":
            sql += " WHERE status=?"
            params.append(status)
        sql += " ORDER BY scheduled_at DESC LIMIT ?"
        params.append(max(1, min(limit, 1000)))
        rows = conn.execute(sql, params).fetchall()
        return [_maintenance_row_to_dict(row) for row in rows]
    finally:
        conn.close()


def _maintenance_create(payload: Dict[str, Any], created_by: str) -> Dict[str, Any]:
    name = _require_str(payload, "name")
    scheduled_at = _require_str(payload, "scheduled_at")
    duration_minutes = int(payload.get("duration_minutes") or payload.get("duration") or 120)
    priority = str(payload.get("priority") or "normal").strip() or "normal"
    devices = payload.get("devices") or []
    tasks = payload.get("tasks") or []
    if not isinstance(devices, list) or not devices:
        raise ValueError("Maintenance window requires a non-empty 'devices' list")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("Maintenance window requires a non-empty 'tasks' list")
    for device in devices:
        _parse_ipv4(str(device).strip())
    window_id = str(uuid.uuid4())
    now = _iso_now()
    row = {
        "window_id": window_id,
        "name": name,
        "scheduled_at": scheduled_at,
        "duration_minutes": duration_minutes,
        "priority": priority,
        "devices_json": _json_dumps(devices),
        "tasks_json": _json_dumps(tasks),
        "notes": str(payload.get("notes") or "").strip(),
        "ticket_number": str(payload.get("ticket_number") or payload.get("ticketNum") or "").strip(),
        "ticket_url": str(payload.get("ticket_url") or payload.get("ticketUrl") or "").strip(),
        "status": str(payload.get("status") or "scheduled").strip() or "scheduled",
        "created_at": now,
        "updated_at": now,
        "created_by": created_by,
    }
    conn = _db_conn()
    try:
        conn.execute(
            """
            INSERT INTO v2_maintenance_windows(
                window_id, name, scheduled_at, duration_minutes, priority, devices_json, tasks_json,
                notes, ticket_number, ticket_url, status, created_at, updated_at, created_by
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                row["window_id"], row["name"], row["scheduled_at"], row["duration_minutes"], row["priority"],
                row["devices_json"], row["tasks_json"], row["notes"], row["ticket_number"], row["ticket_url"],
                row["status"], row["created_at"], row["updated_at"], row["created_by"],
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return _maintenance_get(window_id)


def _maintenance_get(window_id: str) -> Dict[str, Any]:
    conn = _db_conn()
    try:
        row = conn.execute("SELECT * FROM v2_maintenance_windows WHERE window_id=?", (window_id,)).fetchone()
        if not row:
            raise HTTPException(status_code=404, detail="Maintenance window not found")
        return _maintenance_row_to_dict(row)
    finally:
        conn.close()


def _maintenance_update(window_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    current = _maintenance_get(window_id)
    merged = {**current, **payload}
    devices = merged.get("devices") or []
    tasks = merged.get("tasks") or []
    if not isinstance(devices, list) or not devices:
        raise ValueError("Maintenance window requires a non-empty 'devices' list")
    if not isinstance(tasks, list) or not tasks:
        raise ValueError("Maintenance window requires a non-empty 'tasks' list")
    for device in devices:
        _parse_ipv4(str(device).strip())
    updated_at = _iso_now()
    conn = _db_conn()
    try:
        conn.execute(
            """
            UPDATE v2_maintenance_windows
            SET name=?, scheduled_at=?, duration_minutes=?, priority=?, devices_json=?, tasks_json=?,
                notes=?, ticket_number=?, ticket_url=?, status=?, updated_at=?
            WHERE window_id=?
            """,
            (
                str(merged.get("name") or "").strip(),
                str(merged.get("scheduled_at") or "").strip(),
                int(merged.get("duration_minutes") or 120),
                str(merged.get("priority") or "normal").strip(),
                _json_dumps(devices),
                _json_dumps(tasks),
                str(merged.get("notes") or "").strip(),
                str(merged.get("ticket_number") or "").strip(),
                str(merged.get("ticket_url") or "").strip(),
                str(merged.get("status") or "scheduled").strip(),
                updated_at,
                window_id,
            ),
        )
        conn.commit()
    finally:
        conn.close()
    return _maintenance_get(window_id)


def _maintenance_delete(window_id: str) -> None:
    conn = _db_conn()
    try:
        conn.execute("DELETE FROM v2_maintenance_windows WHERE window_id=?", (window_id,))
        conn.commit()
    finally:
        conn.close()


_COMMAND_VAULT_CATALOG: Dict[str, Any] = {
    "families": [
        {
            "key": "nokia",
            "label": "Nokia Command Vault",
            "subsections": [
                {
                    "key": "7750-bng",
                    "label": "Nokia 7750 - BNG Commands Guide",
                    "entries": [
                        {
                            "title": "Show Router BGP Interfaces",
                            "tags": ["show", "router", "interface", "bgp", "7750", "bng"],
                            "command": "show router interface",
                        },
                        {
                            "title": "Show Service SAP Usage",
                            "tags": ["show", "service", "sap", "7750", "bng"],
                            "command": "show service sap-using",
                        },
                    ],
                },
                {
                    "key": "7250-port",
                    "label": "Nokia 7250 - Port Setup",
                    "entries": [
                        {
                            "title": "Configure Access Port",
                            "tags": ["port", "ethernet", "access", "7250"],
                            "command": "/configure port 1/1/1 ethernet mode access",
                        },
                        {
                            "title": "Enable Port",
                            "tags": ["port", "admin", "no shutdown", "7250"],
                            "command": "/configure port 1/1/1 no shutdown",
                        },
                    ],
                },
            ],
        },
        {
            "key": "cisco",
            "label": "Cisco Command Vault",
            "entries": [
                {
                    "title": "Show OSPF Neighbor",
                    "tags": ["ospf", "neighbor", "show", "ios", "xe"],
                    "command": "show ip ospf neighbor",
                },
                {
                    "title": "Show BGP Summary",
                    "tags": ["bgp", "show", "summary", "ios", "xe"],
                    "command": "show ip bgp summary",
                },
            ],
        },
        {
            "key": "mikrotik",
            "label": "MikroTik Command Vault",
            "entries": [
                {
                    "title": "Show BGP Sessions",
                    "tags": ["bgp", "routing", "print", "routeros"],
                    "command": "/routing/bgp/session/print detail",
                },
                {
                    "title": "Show OSPF Neighbors",
                    "tags": ["ospf", "routing", "print", "routeros"],
                    "command": "/routing/ospf/neighbor/print detail",
                },
            ],
        },
    ]
}


def _command_vault_catalog(payload: Dict[str, Any]) -> Dict[str, Any]:
    family_filter = str(payload.get("family") or "").strip().lower()
    subsection_filter = str(payload.get("subsection") or "").strip().lower()
    query = str(payload.get("query") or "").strip().lower()

    results: List[Dict[str, Any]] = []
    for family in _COMMAND_VAULT_CATALOG["families"]:
        if family_filter and family["key"] != family_filter:
            continue
        family_entries = []

        for subsection in family.get("subsections", []):
            if subsection_filter and subsection["key"] != subsection_filter:
                continue
            filtered = [
                entry
                for entry in subsection.get("entries", [])
                if not query
                or query in entry["title"].lower()
                or query in entry["command"].lower()
                or any(query in tag.lower() for tag in entry.get("tags", []))
            ]
            if filtered:
                family_entries.append(
                    {
                        "type": "subsection",
                        "key": subsection["key"],
                        "label": subsection["label"],
                        "entries": filtered,
                    }
                )

        if not subsection_filter:
            filtered = [
                entry
                for entry in family.get("entries", [])
                if not query
                or query in entry["title"].lower()
                or query in entry["command"].lower()
                or any(query in tag.lower() for tag in entry.get("tags", []))
            ]
            if filtered:
                family_entries.append({"type": "family_entries", "entries": filtered})

        if family_entries:
            results.append(
                {
                    "family": family["key"],
                    "label": family["label"],
                    "sections": family_entries,
                }
            )

    return {
        "filters": {
            "family": family_filter or None,
            "subsection": subsection_filter or None,
            "query": query or None,
        },
        "results": results,
        "count": sum(len(section["entries"]) for family in results for section in family["sections"]),
    }


@dataclass
class JobEvent:
    ts: str
    level: str
    message: str


@dataclass
class JobRecord:
    job_id: str
    action: str
    submitted_by: str
    request_id: str
    payload: Dict[str, Any] = field(default_factory=dict)
    status: str = "queued"  # queued|running|success|error|cancelled
    created_at: str = field(default_factory=_iso_now)
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    result: Any = None
    error: Optional[str] = None
    cancel_requested: bool = False
    events: List[JobEvent] = field(default_factory=list)


class JobManager:
    def __init__(self):
        self._jobs: Dict[str, JobRecord] = {}
        self._lock = threading.Lock()
        self._executor = ThreadPoolExecutor(max_workers=int(os.getenv("NOC_API_V2_JOB_WORKERS", "8")))
        self._hydrate_from_db()

    def _hydrate_from_db(self) -> None:
        conn = _db_conn()
        try:
            rows = conn.execute(
                """
                SELECT job_id, request_id, action, submitted_by, payload_json, status, created_at,
                       started_at, finished_at, result_json, error_text, cancel_requested
                FROM v2_jobs
                ORDER BY created_at DESC
                LIMIT 2000
                """
            ).fetchall()
            for row in rows:
                payload = json.loads(row["payload_json"] or "{}")
                result = json.loads(row["result_json"]) if row["result_json"] else None
                job = JobRecord(
                    job_id=row["job_id"],
                    action=row["action"],
                    submitted_by=row["submitted_by"],
                    request_id=row["request_id"] or "",
                    payload=payload,
                    status=row["status"],
                    created_at=row["created_at"],
                    started_at=row["started_at"],
                    finished_at=row["finished_at"],
                    result=result,
                    error=row["error_text"],
                    cancel_requested=bool(row["cancel_requested"]),
                )
                if job.status in {"queued", "running"}:
                    job.status = "error"
                    job.error = "Job interrupted by service restart"
                    if not job.finished_at:
                        job.finished_at = _iso_now()
                    conn.execute(
                        "UPDATE v2_jobs SET status=?, error_text=?, finished_at=? WHERE job_id=?",
                        (job.status, job.error, job.finished_at, job.job_id),
                    )
                ev_rows = conn.execute(
                    "SELECT ts, level, message FROM v2_job_events WHERE job_id=? ORDER BY id ASC",
                    (job.job_id,),
                ).fetchall()
                job.events = [JobEvent(ts=e["ts"], level=e["level"], message=e["message"]) for e in ev_rows]
                self._jobs[job.job_id] = job
            conn.commit()
        finally:
            conn.close()

    def _persist_job(self, job: JobRecord) -> None:
        conn = _db_conn()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO v2_jobs(
                    job_id, request_id, action, submitted_by, payload_json, status, created_at, started_at, finished_at,
                    result_json, error_text, cancel_requested
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    job.job_id,
                    job.request_id,
                    job.action,
                    job.submitted_by,
                    _json_dumps(job.payload),
                    job.status,
                    job.created_at,
                    job.started_at,
                    job.finished_at,
                    _json_dumps(job.result) if job.result is not None else None,
                    job.error,
                    1 if job.cancel_requested else 0,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    def add_event(self, job: JobRecord, level: str, message: str) -> None:
        evt = JobEvent(ts=_iso_now(), level=level, message=message)
        with self._lock:
            job.events.append(evt)
            if len(job.events) > 500:
                job.events = job.events[-500:]
        conn = _db_conn()
        try:
            conn.execute(
                "INSERT INTO v2_job_events(job_id, ts, level, message) VALUES(?,?,?,?)",
                (job.job_id, evt.ts, evt.level, evt.message),
            )
            conn.execute(
                """
                DELETE FROM v2_job_events
                WHERE job_id=?
                  AND id NOT IN (
                      SELECT id FROM v2_job_events
                      WHERE job_id=?
                      ORDER BY id DESC
                      LIMIT 500
                  )
                """,
                (job.job_id, job.job_id),
            )
            conn.commit()
        finally:
            conn.close()

    def submit(self, action: str, payload: Dict[str, Any], submitted_by: str, request_id: str) -> JobRecord:
        job = JobRecord(
            job_id=str(uuid.uuid4()),
            action=action,
            submitted_by=submitted_by,
            request_id=request_id,
            payload=payload or {},
        )
        with self._lock:
            self._jobs[job.job_id] = job
        self._persist_job(job)
        self._executor.submit(self._run, job.job_id)
        return job

    def _run(self, job_id: str) -> None:
        with self._lock:
            job = self._jobs.get(job_id)
        if not job:
            return
        if job.cancel_requested:
            job.status = "cancelled"
            job.finished_at = _iso_now()
            self._persist_job(job)
            return
        job.status = "running"
        job.started_at = _iso_now()
        self._persist_job(job)
        self.add_event(job, "info", f"Started action '{job.action}'")
        try:
            handler = _ACTION_HANDLERS.get(job.action)
            if not handler:
                raise ValueError(f"Unsupported action '{job.action}'")
            if job.cancel_requested:
                job.status = "cancelled"
                job.finished_at = _iso_now()
                return
            job.result = handler(job.payload)
            if job.cancel_requested:
                job.status = "cancelled"
            else:
                job.status = "success"
                self.add_event(job, "success", "Action completed")
        except Exception as exc:
            job.status = "error"
            job.error = str(exc)
            self.add_event(job, "error", str(exc))
        finally:
            job.finished_at = _iso_now()
            self._persist_job(job)

    def get(self, job_id: str) -> Optional[JobRecord]:
        with self._lock:
            return self._jobs.get(job_id)

    def list(self, limit: int = 100) -> List[JobRecord]:
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda j: j.created_at, reverse=True)
        return jobs[: max(1, min(limit, 1000))]

    def cancel(self, job_id: str) -> Optional[JobRecord]:
        with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            job.cancel_requested = True
            if job.status == "queued":
                job.status = "cancelled"
                job.finished_at = _iso_now()
        if job:
            self.add_event(job, "warning", "Cancel requested")
            self._persist_job(job)
        return job


_JOBS = JobManager()


_ACTION_HANDLERS: Dict[str, Callable[[Dict[str, Any]], Any]] = {
    # Native MikroTik generators
    "mt.render": lambda payload: _render_mt("mt.render", payload),
    "mt.config": lambda payload: _render_mt("mt.config", payload),
    "mt.portmap": lambda payload: _render_mt("mt.portmap", payload),

    # Generic legacy proxy (escape hatch, still whitelisted by backend)
    "legacy.proxy": _legacy_call,

    # Dashboard / shared reads
    "health.get": _legacy_get("/api/health"),
    "app.config.get": _legacy_get("/api/app-config"),
    "infrastructure.get": _legacy_get("/api/infrastructure"),
    "routerboards.list": _legacy_get("/api/get-routerboards"),

    # Activity / history
    "activity.list": lambda payload: _legacy_call(
        {
            "method": "GET",
            "path": "/api/get-activity",
            "params": payload.get("params") if isinstance(payload.get("params"), dict) else payload,
        }
    ),
    "activity.log": _legacy_post("/api/log-activity"),

    # Completed config store
    "configs.list": lambda payload: _legacy_call(
        {
            "method": "GET",
            "path": "/api/get-completed-configs",
            "params": payload.get("params") if isinstance(payload.get("params"), dict) else payload,
        }
    ),
    "configs.save": _legacy_post("/api/save-completed-config"),
    "configs.get": _configs_get,
    "configs.portmap.download": _configs_portmap_download,
    "configs.portmap.extract": _legacy_post("/api/extract-port-map"),

    # Migration / translation
    "migration.parse_mikrotik_for_nokia": _legacy_post("/api/parse-mikrotik-for-nokia"),
    "migration.parse_mikrotik": _legacy_post("/api/parse-mikrotik-for-nokia"),
    "migration.mikrotik_to_nokia": _legacy_post("/api/migrate-mikrotik-to-nokia"),
    "migration.config": _legacy_post("/api/migrate-config"),
    "compliance.apply": _legacy_post("/api/apply-compliance"),
    "config.validate": _legacy_post("/api/validate-config"),
    "config.suggest": _legacy_post("/api/suggest-config"),
    "config.explain": _legacy_post("/api/explain-config"),
    "config.translate": _legacy_post("/api/translate-config"),
    "config.autofill_from_export": _legacy_post("/api/autofill-from-export"),

    # FTTH
    "ftth.preview_bng": _legacy_post("/api/preview-ftth-bng"),
    "ftth.generate_bng": _legacy_post("/api/generate-ftth-bng"),
    "ftth.generate_fiber_customer": _legacy_post("/api/generate-ftth-fiber-customer"),
    "ftth.generate_fiber_site": _legacy_post("/api/generate-ftth-fiber-site"),
    "ftth.generate_isd_fiber": _legacy_post("/api/generate-ftth-isd-fiber"),
    "ftth.mf2_package": _legacy_post("/api/ftth-home/mf2-package"),
    "ftth.fiber_customer": _legacy_post("/api/generate-ftth-fiber-customer"),
    "ftth.fiber_site": _legacy_post("/api/generate-ftth-fiber-site"),
    "ftth.isd_fiber": _legacy_post("/api/generate-ftth-isd-fiber"),

    # Nokia
    "nokia.generate_7250": _legacy_post("/api/generate-nokia7250"),
    "nokia.configurator.generate": _legacy_post("/api/generate-nokia-configurator"),
    "nokia.defaults": _legacy_get("/api/nokia7250-defaults"),
    "nokia.configurator.defaults": _legacy_get("/api/nokia-configurator-defaults"),
    "nokia.configurator.generate": _legacy_post("/api/generate-nokia-configurator"),

    # Enterprise
    "enterprise.generate_non_mpls": _legacy_post("/api/gen-enterprise-non-mpls"),

    # Tarana
    "tarana.generate": _legacy_post("/api/gen-tarana-config"),

    # Switch maker / edge switching
    "switch.generate_mikrotik": _legacy_post("/api/generate-mt-switch-config"),
    "switch.generate_6ghz": _render_6ghz_switch,
    "switch.generate_6ghz_outstate": _render_6ghz_switch_outstate,
    "enterprise.feeding.generate": _render_enterprise_feeding,
    "enterprise.feeding.generate_outstate": _render_enterprise_feeding_outstate,
    "cisco.generate_interface": _render_cisco_interface,
    "config.diff": _compute_config_diff,
    "enterprise.generate_mpls": _render_mpls_enterprise,
    "command.vault.catalog": _command_vault_catalog,

    # SSH Config Fetch
    "device.fetch_config_ssh": _legacy_post("/api/fetch-config-ssh"),
    "device.push_config_ssh": _legacy_post("/api/ssh-push-config"),

    # Feedback
    "feedback.submit": _legacy_post("/api/feedback"),
    "feedback.status.mine": _legacy_get("/api/feedback/my-status"),

    # Bulk / orchestration
    "bulk.generate": _legacy_post("/api/bulk-generate"),
    "bulk.ssh_fetch": _legacy_post("/api/bulk-ssh-fetch"),
    "bulk.migration_analyze": _legacy_post("/api/bulk-migration-analyze"),
    "bulk.migration_execute": _legacy_post("/api/bulk-migration-execute"),
    "bulk.compliance_scan": _legacy_post("/api/bulk-compliance-scan"),
    "device.ssh_push_config": _legacy_post("/api/ssh-push-config"),

    # Admin
    "admin.feedback.list": _legacy_get("/api/admin/feedback"),
    "admin.feedback.update_status": _admin_feedback_update_status,
    "admin.feedback.export": _legacy_get("/api/admin/feedback/export"),
    "admin.users.reset_password": _legacy_post("/api/admin/users/reset-password"),

    # Compliance / Config Policies
    "compliance.policies.list": _legacy_get("/api/get-config-policies"),
    "compliance.policies.get": _compliance_policy_get,
    "compliance.policies.bundle": _legacy_get("/api/get-config-policy-bundle"),
    "compliance.policies.reload": _legacy_post("/api/reload-config-policies"),
    "compliance.reload": _legacy_post("/api/reload-compliance"),
    "compliance.status": _legacy_get("/api/compliance-status"),
    "compliance.blocks": _legacy_get("/api/compliance/blocks"),
    "compliance.engineering": _legacy_get("/api/compliance/engineering"),

    # IDO / Field Config Studio capabilities + proxy actions
    "ido.capabilities": _legacy_get("/api/ido/capabilities"),
    "ido.ping": lambda payload: _ido_proxy_call("/api/ping", payload),
    "ido.generic.device_info": lambda payload: _ido_proxy_call("/api/generic/device_info", payload),
    "ido.ap.device_info": lambda payload: _ido_proxy_call("/api/ap/device_info", payload),
    "ido.ap.running_config": lambda payload: _ido_proxy_call("/api/ap/running_config", payload),
    "ido.ap.standard_config": lambda payload: _ido_proxy_call("/api/ap/standard_config", payload),
    "ido.ap.generate": lambda payload: _ido_proxy_call("/api/ap/generate", payload),
    "ido.bh.device_info": lambda payload: _ido_proxy_call("/api/bh/device_info", payload),
    "ido.bh.running_config": lambda payload: _ido_proxy_call("/api/bh/running_config", payload),
    "ido.bh.standard_config": lambda payload: _ido_proxy_call("/api/bh/standard_config", payload),
    "ido.bh.generate": lambda payload: _ido_proxy_call("/api/bh/generate", payload),
    "ido.swt.device_info": lambda payload: _ido_proxy_call("/api/swt/device_info", payload),
    "ido.swt.running_config": lambda payload: _ido_proxy_call("/api/swt/running_config", payload),
    "ido.swt.standard_config": lambda payload: _ido_proxy_call("/api/swt/standard_config", payload),
    "ido.swt.generate": lambda payload: _ido_proxy_call("/api/swt/generate", payload),
    "ido.ups.device_info": lambda payload: _ido_proxy_call("/api/ups/device_info", payload),
    "ido.ups.running_config": lambda payload: _ido_proxy_call("/api/ups/running_config", payload),
    "ido.ups.standard_config": lambda payload: _ido_proxy_call("/api/ups/standard_config", payload),
    "ido.ups.generate": lambda payload: _ido_proxy_call("/api/ups/generate", payload),
    "ido.rpc.device_info": lambda payload: _ido_proxy_call("/api/rpc/device_info", payload),
    "ido.rpc.running_config": lambda payload: _ido_proxy_call("/api/rpc/running_config", payload),
    "ido.rpc.standard_config": lambda payload: _ido_proxy_call("/api/rpc/standard_config", payload),
    "ido.rpc.generate": lambda payload: _ido_proxy_call("/api/rpc/generate", payload),
    "ido.wave.config": lambda payload: _ido_proxy_call("/api/waveconfig/generate", payload),
    "ido.nokia7250.generate": lambda payload: _ido_proxy_call("/api/7250config/generate", payload),

    # Aviat
    "aviat.run": _legacy_post("/api/aviat/run"),
    "aviat.activate_scheduled": lambda payload: _legacy_call(
        {"method": "POST", "path": "/api/aviat/activate-scheduled", "body": payload}
    ),
    "aviat.check_status": lambda payload: _legacy_call(
        {"method": "POST", "path": "/api/aviat/check-status", "body": payload}
    ),
    "aviat.scheduled.get": _legacy_get("/api/aviat/scheduled"),
    "aviat.loading.get": _legacy_get("/api/aviat/loading"),
    "aviat.queue.get": _legacy_get("/api/aviat/queue"),
    "aviat.queue.update": _legacy_post("/api/aviat/queue"),
    "aviat.reboot_required.get": _legacy_get("/api/aviat/reboot-required"),
    "aviat.reboot_required.run": _legacy_post("/api/aviat/reboot-required/run"),
    "aviat.scheduled.sync": _legacy_post("/api/aviat/scheduled/sync"),
    "aviat.fix_stp": _legacy_post("/api/aviat/fix-stp"),
    "aviat.stream.global": _legacy_get("/api/aviat/stream/global"),
    "aviat.abort": _aviat_abort,
    "aviat.status": _aviat_status,
    "aviat.precheck_recheck": _legacy_post("/api/aviat/precheck/recheck"),

    # Bulk / power tools
    "bulk.generate": _legacy_post("/api/bulk-generate"),
    "bulk.fetch_config": _legacy_post("/api/bulk-ssh-fetch"),
    "bulk.migration.analyze": _legacy_post("/api/bulk-migration-analyze"),
    "bulk.migration.execute": _legacy_post("/api/bulk-migration-execute"),
    "bulk.compliance.scan": _legacy_post("/api/bulk-compliance-scan"),

    # Cambium
    "cambium.run": _legacy_post("/api/cambium/run"),
}


_NEXUS_WORKFLOWS: Dict[str, Any] = {
    "dashboard_and_history": {
        "label": "Dashboard, Configs, and Log History",
        "delivery": "api",
        "actions": [
            "health.get",
            "app.config.get",
            "infrastructure.get",
            "routerboards.list",
            "activity.list",
            "activity.log",
            "configs.list",
            "configs.save",
            "configs.get",
            "configs.portmap.download",
            "configs.portmap.extract",
        ],
    },
    "mikrotik_config_generator": {
        "label": "MikroTik Config Generator",
        "tabs": ["tower", "bng2"],
        "delivery": "api",
        "actions": ["mt.render", "mt.config", "mt.portmap"],
    },
    "non_mpls_enterprise": {
        "label": "Non-MPLS Enterprise",
        "delivery": "api",
        "actions": ["enterprise.generate_non_mpls"],
    },
    "nokia_7250": {
        "defaults": "nokia.defaults",
        "generate": "nokia.generate_7250",
        "configurator_generate": "nokia.configurator.generate",
        "generate_ido": "ido.nokia7250.generate",
        "parse_mikrotik": "migration.parse_mikrotik_for_nokia",
        "migrate_from_mikrotik": "migration.mikrotik_to_nokia",
    },
    "mpls_enterprise": {
        "label": "MPLS Enterprise",
        "delivery": "api",
        "actions": ["enterprise.generate_mpls"],
    },
    "tarana_sectors": {
        "label": "Tarana Sectors",
        "delivery": "api",
        "actions": ["tarana.generate"],
    },
    "enterprise_feeding": {
        "label": "Enterprise Feeding",
        "delivery": "api",
        "actions": ["enterprise.feeding.generate", "enterprise.feeding.generate_outstate"],
    },
    "switch_maker": {
        "label": "MikroTik Switch Maker",
        "delivery": "api",
        "actions": ["switch.generate_mikrotik"],
    },
    "six_ghz_switch_port": {
        "label": "6GHz Switch Port",
        "delivery": "api",
        "actions": ["switch.generate_6ghz", "switch.generate_6ghz_outstate"],
    },
    "field_config_studio": {
        "label": "Device Config Studio",
        "delivery": "api",
        "actions": [
            "ido.capabilities",
            "ido.ping",
            "ido.generic.device_info",
            "ido.ap.device_info",
            "ido.ap.running_config",
            "ido.ap.standard_config",
            "ido.ap.generate",
            "ido.bh.device_info",
            "ido.bh.running_config",
            "ido.bh.standard_config",
            "ido.bh.generate",
            "ido.swt.device_info",
            "ido.swt.running_config",
            "ido.swt.standard_config",
            "ido.swt.generate",
            "ido.ups.device_info",
            "ido.ups.running_config",
            "ido.ups.standard_config",
            "ido.ups.generate",
            "ido.rpc.device_info",
            "ido.rpc.running_config",
            "ido.rpc.standard_config",
            "ido.rpc.generate",
            "ido.wave.config",
            "ido.nokia7250.generate",
        ],
    },
    "nokia_configurator": {
        "label": "Nokia Configurator",
        "delivery": "api",
        "actions": [
            "nokia.defaults",
            "nokia.generate_7250",
            "nokia.configurator.defaults",
            "nokia.configurator.generate",
        ],
    },
    "nokia_migration": {
        "label": "Nokia Migration",
        "delivery": "api",
        "actions": [
            "migration.parse_mikrotik",
            "migration.mikrotik_to_nokia",
            "migration.config",
            "config.translate",
            "config.autofill_from_export",
        ],
    },
    "ftth": {
        "preview_bng": "ftth.preview_bng",
        "generate_bng": "ftth.generate_bng",
        "mf2_package": "ftth.mf2_package",
        "fiber_customer": "ftth.fiber_customer",
        "fiber_site": "ftth.fiber_site",
        "isd_fiber": "ftth.isd_fiber",
    },
    "bulk_operations": {
        "generate": "bulk.generate",
        "ssh_fetch": "bulk.ssh_fetch",
        "migration_analyze": "bulk.migration_analyze",
        "migration_execute": "bulk.migration_execute",
        "compliance_scan": "bulk.compliance_scan",
        "ssh_push_config": "device.ssh_push_config",
    },
    "cambium": {
        "run": "cambium.run",
    },
    "tenant_api_direction": {
        "label": "Tenant-neutral contract direction",
        "delivery": "api",
        "notes": "Payloads should use tenant templates, policies, and explicit addressing inputs instead of provider-specific hidden defaults.",
    },
    "aviat_backhaul": {
        "label": "Aviat Backhaul Updater",
        "delivery": "api",
        "actions": [
            "aviat.run",
            "aviat.check_status",
            "aviat.activate_scheduled",
            "aviat.queue.get",
            "aviat.queue.update",
            "aviat.status",
            "aviat.precheck_recheck",
            "aviat.scheduled.get",
            "aviat.loading.get",
            "aviat.reboot_required.get",
            "aviat.reboot_required.run",
            "aviat.scheduled.sync",
            "aviat.fix_stp",
            "aviat.abort",
            "aviat.stream.global",
        ],
    },
    "ftth_configurator": {
        "label": "FTTH Configurator",
        "tabs": ["olt", "bng", "fiber", "fiber_site", "isd_fiber"],
        "delivery": "api",
        "actions": [
            "ftth.preview_bng",
            "ftth.generate_bng",
            "ftth.generate_fiber_customer",
            "ftth.generate_fiber_site",
            "ftth.generate_isd_fiber",
            "ftth.mf2_package",
        ],
    },
    "command_vault": {
        "label": "Command Vault",
        "delivery": "api",
        "actions": ["command.vault.catalog"],
        "notes": "Reference content is exposed as a backend catalog so Omni can render the same families and search/filter flows.",
    },
    "cisco_port_setup": {
        "label": "Cisco Port Setup",
        "delivery": "api",
        "actions": ["cisco.generate_interface"],
    },
    "power_tools": {
        "label": "Power Tools",
        "delivery": "mixed",
        "actions": [
            "config.diff",
            "bulk.generate",
            "bulk.fetch_config",
            "bulk.migration.analyze",
            "bulk.migration.execute",
            "bulk.compliance.scan",
            "device.fetch_config_ssh",
            "device.push_config_ssh",
            "compliance.status",
            "compliance.blocks",
            "compliance.engineering",
            "compliance.apply",
            "compliance.policies.list",
            "compliance.policies.get",
            "compliance.policies.bundle",
            "compliance.policies.reload",
            "compliance.reload",
        ],
        "notes": "Most power-tool operations are API-backed; some UI orchestration remains local in the browser.",
    },
    "feedback_and_admin": {
        "label": "Feedback and Admin",
        "delivery": "api",
        "actions": [
            "feedback.submit",
            "feedback.status.mine",
            "admin.feedback.list",
            "admin.feedback.update_status",
            "admin.feedback.export",
            "admin.users.reset_password",
        ],
    },
    "maintenance": {
        "label": "Scheduled Maintenance",
        "delivery": "api",
        "actions": [
            "maintenance.windows.list",
            "maintenance.windows.create",
            "maintenance.windows.update",
            "maintenance.windows.delete",
        ],
    },
}

_OMNI_WORKFLOWS: Dict[str, Any] = _NEXUS_WORKFLOWS

_NEXUS_ACTION_CATALOG: Dict[str, Dict[str, Any]] = {
    "mt.render": {
        "tab": "MikroTik Config Generator",
        "delivery": "api",
        "summary": "Render MikroTik config and port map from a typed tower or BNG2 payload.",
        "backend_path": "/api/mt/{config_type}/config + /api/mt/{config_type}/portmap",
        "tenant_ready": True,
        "payload_example": {
            "config_type": "tower",
            "payload": {
                "site_name": "ACME-TX-LIPAN-1",
                "routerboard_model": "CCR2004-1G-12S+2XS",
                "routeros_version": "7.19.4",
                "loopback_subnet": "10.42.12.88/32",
                "uplink_interface": "sfp-sfpplus1",
                "apply_compliance": False,
            },
        },
    },
    "enterprise.generate_non_mpls": {
        "tab": "Non-MPLS Enterprise",
        "delivery": "api",
        "summary": "Generate reusable non-MPLS enterprise handoff configs.",
        "backend_path": "/api/gen-enterprise-non-mpls",
        "tenant_ready": True,
        "payload_example": {
            "device": "RB5009",
            "target_version": "7.19.4",
            "public_cidr": "132.147.10.0/29",
            "bh_cidr": "10.10.10.0/30",
            "loopback_ip": "10.42.10.1/32",
            "uplink_interface": "sfp-sfpplus1",
            "public_port": "ether7",
            "nat_port": "ether8",
            "dns1": "1.1.1.1",
            "dns2": "8.8.8.8",
            "snmp_community": "ACME-NOC",
            "identity": "RTR-RB5009.ACME-HQ",
            "uplink_comment": "BH-EAST",
        },
    },
    "tarana.generate": {
        "tab": "Tarana Sectors",
        "delivery": "api",
        "summary": "Validate or normalize Tarana-related MikroTik config blocks.",
        "backend_path": "/api/gen-tarana-config",
        "tenant_ready": True,
        "payload_example": {
            "config": "/interface bridge\nadd name=bridge3000",
            "device": "ccr2004",
            "routeros_version": "7.19.4",
        },
    },
    "switch.generate_mikrotik": {
        "tab": "MikroTik Switch Maker",
        "delivery": "api",
        "summary": "Generate MikroTik switch config from toolbox-backed switch profiles.",
        "backend_path": "/api/generate-mt-switch-config",
        "tenant_ready": True,
        "payload_example": {
            "switch_type": "2004",
            "profile": "no_bng",
            "routeros": "7.19.4",
            "switch_name": "SWT-ACME-1",
            "management_ip": "10.246.48.194/27",
            "gateway": "10.246.48.193",
            "uplink1": "sfp28-1",
            "state_scope": "custom",
            "apply_compliance": False,
            "ports": [{"port": "sfp-sfpplus1", "comment": "AP1 6GHz"}],
        },
    },
    "switch.generate_6ghz": {
        "tab": "6GHz Switch Port",
        "delivery": "api",
        "summary": "Generate in-state 6GHz switch config with DHCP and OSPF.",
        "backend_path": "/api/v2/nexus/tools/6ghz/instate",
        "tenant_ready": True,
        "payload_example": {
            "switch_type": "swt_ccr2004",
            "routeros_version": "7.19.4",
            "vlan3000_subnet": "10.246.22.224/28",
            "vlan4000_subnet": "10.246.22.240/28",
            "pool_offset": 2,
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
            "shared_key": "CHANGE_ME",
        },
    },
    "switch.generate_6ghz_outstate": {
        "tab": "6GHz Switch Port / Out-of-State",
        "delivery": "api",
        "summary": "Generate out-of-state 6GHz switch uplink and bridge config.",
        "backend_path": "/api/v2/nexus/tools/6ghz/outstate",
        "tenant_ready": True,
        "payload_example": {
            "switch_type": "swt_mt326",
            "routeros_version": "7.19.4",
            "port1": "sfp-sfpplus1",
            "port2": "sfp-sfpplus2",
        },
    },
    "enterprise.generate_mpls": {
        "tab": "MPLS Enterprise",
        "delivery": "api",
        "summary": "Generate MPLS enterprise config from explicit tenant-supplied routing and policy inputs.",
        "backend_path": "/api/v2/nexus/tools/enterprise/mpls",
        "tenant_ready": True,
        "payload_example": {
            "routerboard_device": "ccr2004",
            "routeros_version": "7.19.4",
            "customer_code": "ACME-537853",
            "device_name": "RTR-ACME-537853",
            "loopback_ip": "10.247.72.34/32",
            "customer_handoff": "sfp-sfpplus7",
            "uplinks": [
                {"interface": "sfp-sfpplus1", "ip": "10.247.57.4/29", "comment": "IL-CARMI-CN-1"}
            ],
            "dns_servers": ["1.1.1.1", "8.8.8.8"],
            "syslog_server": "10.0.0.50",
            "shared_key": "CHANGE_ME",
            "snmp_community": "ACME-NOC",
            "snmp_contact": "noc@acme.example",
            "vpls_static_id": 2245,
            "vpls_peer": "10.254.247.3",
            "enable_bgp": True,
            "bgp_as": 65000,
            "bgp_peers": [{"ip": "10.4.0.1", "as": 65000}],
        },
    },
    "enterprise.feeding.generate": {
        "tab": "Enterprise Feeding",
        "delivery": "api",
        "summary": "Generate enterprise feeding handoff config for in-state or standard routed uplinks.",
        "backend_path": "/api/v2/nexus/tools/enterprise-feeding/generate",
        "tenant_ready": True,
        "payload_example": {
            "label": "ACME-CUSTOMER-HANDOFF",
            "port": "sfp-sfpplus4",
            "speed": "10G-baseSR-LR",
            "backhaul_cidr": "10.25.26.48/29",
            "loopback_ip": "10.25.100.1/32",
            "public_ip": "132.147.55.8",
        },
    },
    "enterprise.feeding.generate_outstate": {
        "tab": "Enterprise Feeding / Out-of-State",
        "delivery": "api",
        "summary": "Generate out-of-state BNG snippets for enterprise feeding workflows.",
        "backend_path": "/api/v2/nexus/tools/enterprise-feeding/outstate",
        "tenant_ready": True,
        "payload_example": {
            "state": "IL",
            "loopback_ip": "10.247.72.34/32",
            "username": "ACME-537853",
        },
    },
    "cisco.generate_interface": {
        "tab": "Cisco Port Setup",
        "delivery": "api",
        "summary": "Generate Cisco interface and OSPF handoff config from structured inputs.",
        "backend_path": "/api/v2/nexus/tools/cisco/interface",
        "tenant_ready": True,
        "payload_example": {
            "port_description": "BH-TO-SITE-A",
            "port_type": "TenGigE",
            "port_number": "0/0/0/1",
            "interface_ip": "10.42.10.1",
            "subnet_mask": "255.255.255.252",
            "ospf_cost": 10,
            "ospf_process": 1,
            "ospf_area": "0",
            "mtu": 9216,
            "passive": False,
        },
    },
    "config.diff": {
        "tab": "Config Diff Viewer",
        "delivery": "api",
        "summary": "Compute a line-oriented diff between two configs.",
        "backend_path": "/api/v2/nexus/tools/config-diff",
        "tenant_ready": True,
        "payload_example": {
            "config_a": "/interface bridge\nadd name=bridge1",
            "config_b": "/interface bridge\nadd name=bridge2",
        },
    },
    "command.vault.catalog": {
        "tab": "Command Vault",
        "delivery": "api",
        "summary": "Return command-vault families, subsections, and searchable command entries for Omni or other clients.",
        "backend_path": "/api/v2/nexus/tools/command-vault",
        "tenant_ready": True,
        "payload_example": {
            "family": "nokia",
            "subsection": "7750-bng",
            "query": "bgp",
        },
    },
    "nokia.generate_7250": {
        "tab": "Nokia Configurator",
        "delivery": "api",
        "summary": "Generate Nokia 7250 config using the legacy 7250 builder.",
        "backend_path": "/api/generate-nokia7250",
        "tenant_ready": True,
        "payload_example": {
            "system_name": "RTR-7250-ACME-1",
            "system_ip": "10.42.13.4/32",
            "location": "32.7767,-96.7970",
            "port1_desc": "Switch",
            "port2_desc": "Backhaul",
            "enable_ospf": True,
            "enable_bgp": True,
            "backhauls": [{"name": "BH-1", "ip": "10.0.0.1/30"}],
        },
    },
    "nokia.configurator.generate": {
        "tab": "Nokia Configurator",
        "delivery": "api",
        "summary": "Generate Nokia 7210/7750 unified configs.",
        "backend_path": "/api/generate-nokia-configurator",
        "tenant_ready": True,
        "payload_example": {
            "model": "7210",
            "profile": "isd",
            "system_name": "RTR-7210-ACME-EDGE",
            "system_ip": "10.42.13.4/32",
        },
    },
    "migration.mikrotik_to_nokia": {
        "tab": "Nokia Migration",
        "delivery": "api",
        "summary": "Translate MikroTik export into Nokia-oriented output while preserving intent.",
        "backend_path": "/api/migrate-mikrotik-to-nokia",
        "tenant_ready": True,
        "payload_example": {
            "source_config": "/interface bridge\nadd name=bridge1",
            "preserve_ips": True,
        },
    },
    "ftth.generate_bng": {
        "tab": "FTTH Configurator / BNG",
        "delivery": "api",
        "summary": "Generate FTTH BNG config from explicit addressing inputs.",
        "backend_path": "/api/generate-ftth-bng",
        "tenant_ready": True,
        "payload_example": {
            "deployment_type": "outstate",
            "router_identity": "RTR-MT2216-ACME-BNG",
            "loopback_ip": "10.10.10.1/32",
            "cpe_network": "10.10.12.0/22",
            "cgnat_private": "100.64.10.0/22",
            "cgnat_public": "132.147.10.1/32",
            "unauth_network": "10.10.20.0/22",
            "olt_network": "10.10.30.0/29",
            "olt_name_primary": "OLT-GW",
            "routeros_version": "7.19.4",
        },
    },
    "ftth.generate_fiber_customer": {
        "tab": "FTTH Configurator / Fiber Customer",
        "delivery": "api",
        "summary": "Generate fiber customer handoff config.",
        "backend_path": "/api/generate-ftth-fiber-customer",
        "tenant_ready": True,
        "payload_example": {
            "routerboard": "RB5009",
            "routeros": "7.19.4",
            "provider": "ACME Fiber",
            "port": "sfp-sfpplus1",
            "address": "10.0.50.2/30",
            "network": "10.0.50.0/30",
            "loopback_ip": "10.10.10.2/32",
            "vlan_mode": "tagged",
            "vlan_id": "210",
            "apply_compliance": False,
        },
    },
    "ftth.generate_fiber_site": {
        "tab": "FTTH Configurator / 1072-1036 Fiber Site",
        "delivery": "api",
        "summary": "Generate paired 1072 and 1036 fiber site configs.",
        "backend_path": "/api/generate-ftth-fiber-site",
        "tenant_ready": True,
        "payload_example": {
            "tower_name": "ACME-TX-HUB-1",
            "loopback_1072": "10.26.1.107/32",
            "loopback_1036": "10.26.1.103/32",
            "bh1_subnet": "10.26.10.0/30",
            "link_1072_1036_a": "10.26.20.0/30",
            "link_1072_1036_b": "10.26.20.4/30",
            "fiber_port_ip": "10.26.30.1/30",
            "backhauls": [{"name": "BH-EAST", "port": "sfp-sfpplus1", "subnet": "10.26.40.0/30"}],
            "apply_compliance": False,
        },
    },
    "ftth.generate_isd_fiber": {
        "tab": "FTTH Configurator / ISD Fiber",
        "delivery": "api",
        "summary": "Generate ISD fiber config and port map.",
        "backend_path": "/api/generate-ftth-isd-fiber",
        "tenant_ready": True,
        "payload_example": {
            "router_type": "CCR2004-1G-12S+2XS",
            "tower_name": "ACME-ISD-1",
            "loopback_subnet": "10.26.1.108/32",
            "private_ip": "10.26.50.1/24",
            "public_ip": "132.147.50.1/29",
            "fiber_port_ip": "10.26.60.1/30",
            "backhauls": [{"name": "CR7", "ip": "10.2.0.107/32"}],
            "apply_compliance": False,
        },
    },
    "ido.ap.device_info": {
        "tab": "Device Config Studio",
        "delivery": "api",
        "summary": "Fetch AP device info from the embedded IDO backend.",
        "backend_path": "/api/ido/proxy/api/ap/device_info",
        "tenant_ready": True,
        "payload_example": {
            "host": "10.0.0.20",
            "username": "admin",
            "password": "secret",
        },
    },
    "aviat.run": {
        "tab": "Aviat Backhaul Updater",
        "delivery": "api",
        "summary": "Run Aviat maintenance/update tasks for one or more radios.",
        "backend_path": "/api/aviat/run",
        "tenant_ready": True,
        "payload_example": {
            "ips": ["10.248.10.11", "10.248.10.12"],
            "tasks": ["precheck", "upgrade"],
            "maintenance_params": {"activation_mode": "immediate", "firmware_target": "final"},
        },
    },
    "bulk.generate": {
        "tab": "Bulk Operations Center",
        "delivery": "api",
        "summary": "Generate configs in bulk from a batch of sites.",
        "backend_path": "/api/bulk-generate",
        "tenant_ready": True,
        "payload_example": {
            "sites": [
                {"site_name": "ACME-SITE-1", "device": "CCR2004", "loopback_ip": "10.42.1.1/32"},
                {"site_name": "ACME-SITE-2", "device": "CCR2216", "loopback_ip": "10.42.1.2/32"},
            ],
        },
    },
    "bulk.compliance.scan": {
        "tab": "Compliance Scanner",
        "delivery": "api",
        "summary": "Run bulk compliance scan across multiple configs.",
        "backend_path": "/api/bulk-compliance-scan",
        "tenant_ready": True,
        "payload_example": {
            "items": [
                {"site_name": "ACME-SITE-1", "config": "/interface bridge\nadd name=bridge1", "loopback_ip": "10.42.1.1"},
            ],
        },
    },
    "feedback.submit": {
        "tab": "Feedback",
        "delivery": "api",
        "summary": "Submit user feedback, bugs, or feature requests.",
        "backend_path": "/api/feedback",
        "tenant_ready": True,
        "payload_example": {
            "type": "feature",
            "rating": 5,
            "message": "Need tenant-editable policy bundles.",
            "email": "user@example.com",
            "tab": "feedback",
        },
    },
    "maintenance.windows.create": {
        "tab": "Scheduled Maintenance",
        "delivery": "api",
        "summary": "Create a maintenance window that can be managed from NEXUS or Omni.",
        "backend_path": "/api/v2/nexus/maintenance/windows",
        "tenant_ready": True,
        "payload_example": {
            "name": "ACME tower firmware window",
            "scheduled_at": "2026-04-01T02:00:00Z",
            "duration_minutes": 120,
            "priority": "normal",
            "devices": ["10.0.0.1", "10.0.0.2"],
            "tasks": ["firmware", "testing"],
            "notes": "Upgrade and validate backhaul links.",
            "ticket_number": "NOC-1234",
            "ticket_url": "https://example.invalid/NOC-1234",
        },
    },
}

_JOB_SUBMIT_OPENAPI_EXAMPLES: Dict[str, Any] = {
    action.replace(".", "_"): {
        "summary": meta["tab"],
        "description": meta["summary"],
        "value": {"action": action, "payload": meta["payload_example"]},
    }
    for action, meta in _NEXUS_ACTION_CATALOG.items()
    if isinstance(meta.get("payload_example"), dict)
}


def _job_to_dict(job: JobRecord, include_payload: bool = False, include_events: bool = False) -> Dict[str, Any]:
    out = {
        "job_id": job.job_id,
        "request_id": job.request_id,
        "action": job.action,
        "submitted_by": job.submitted_by,
        "status": job.status,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "cancel_requested": job.cancel_requested,
        "result": job.result,
        "error": job.error,
    }
    if include_payload:
        out["payload"] = job.payload
    if include_events:
        out["events"] = [{"ts": e.ts, "level": e.level, "message": e.message} for e in job.events]
    return out


def _request_model_to_action_payload(payload: BaseModel) -> Tuple[str, Dict[str, Any]]:
    payload_dict = payload.model_dump(exclude_none=True)
    action = str(payload_dict.get("action") or "").strip()
    if not action:
        raise HTTPException(status_code=422, detail="Missing 'action'")

    job_payload = payload_dict.get("payload")
    if isinstance(job_payload, BaseModel):
        job_payload = job_payload.model_dump(exclude_none=True)

    if isinstance(job_payload, dict):
        return action, job_payload

    extra_payload: Dict[str, Any] = {}
    model_extra = getattr(payload, "model_extra", None) or {}
    if isinstance(model_extra, dict):
        extra_payload.update({k: v for k, v in model_extra.items() if k != "action"})

    for key, value in payload_dict.items():
        if key != "action":
            extra_payload.setdefault(key, value)
    return action, extra_payload


def _normalize_idempotency_key(value: Optional[str]) -> str:
    return (value or "").strip()


@router.get("/health", include_in_schema=False)
def v2_health(_: Dict[str, Any] = Depends(_require_scope("health.read"))):
    checks: Dict[str, Any] = {"legacy_api_base": _legacy_api_base(), "legacy_health": {"ok": False}, "ido_caps": {"ok": False}}
    try:
        r = requests.get(urljoin(_legacy_api_base() + "/", "api/health"), timeout=5)
        checks["legacy_health"] = {"ok": r.ok, "status_code": r.status_code}
    except Exception as exc:
        checks["legacy_health"] = {"ok": False, "error": str(exc)}

    try:
        r = requests.get(urljoin(_legacy_api_base() + "/", "api/ido/capabilities"), timeout=5)
        checks["ido_caps"] = {"ok": r.ok, "status_code": r.status_code}
    except Exception as exc:
        checks["ido_caps"] = {"ok": False, "error": str(exc)}

    all_ok = bool(checks["legacy_health"].get("ok"))
    status = "ok" if all_ok else "degraded"
    return _envelope(status=status, data=checks, message="v2 health")


@router.get(
    "/omni/health",
    response_model=HealthEnvelope,
    summary="Health check",
    tags=["OMNI Health"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_health(_: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return v2_health(_)


@router.get("/nexus/health")
def v2_nexus_health(_: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return v2_health(_)


@router.get("/actions", include_in_schema=False)
def v2_actions(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return _envelope(
        status="ok",
        data={
            "actions": sorted(_ACTION_HANDLERS.keys()),
            "notes": {
                **PUBLIC_ACTION_NOTES,
                "mt.*": "Native renderer actions for MikroTik-oriented configuration workflows.",
                "activity.list/configs.list": "Convenience wrappers for common list endpoints.",
                "legacy.proxy": "Whitelisted generic proxy to legacy /api/* endpoint",
                "frontend_only_tabs": "See /api/v2/nexus/workflows for tabs that still need backend promotion",
            },
        },
    )


@router.get(
    "/omni/actions",
    response_model=ActionsEnvelope,
    summary="List supported actions",
    tags=["OMNI Discovery"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_actions(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return v2_actions(_)


@router.get("/nexus/actions")
def v2_nexus_actions(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return v2_actions(_)


@router.get("/whoami", include_in_schema=False)
def v2_whoami(auth: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return _envelope(status="ok", data={"api_key": auth["api_key"], "scopes": auth["scopes"]})


@router.get(
    "/omni/whoami",
    response_model=WhoAmIEnvelope,
    summary="Show current API identity",
    tags=["OMNI Discovery"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_whoami(auth: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return v2_whoami(auth)


@router.get("/nexus/whoami")
def v2_nexus_whoami(auth: Dict[str, Any] = Depends(_require_scope("health.read"))):
    return v2_whoami(auth)


@router.get(
    "/omni/bootstrap",
    response_model=BootstrapEnvelope,
    summary="Bootstrap contract metadata",
    tags=["OMNI Discovery"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_bootstrap(auth: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return v2_nexus_bootstrap(auth)


@router.get("/nexus/bootstrap")
def v2_nexus_bootstrap(auth: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    _ = auth
    return _envelope(
        status="ok",
        data={
            "api_version": "v2",
            "service": "nexus",
            "base_url_hint": "/api/v2/nexus",
            "methods_supported": ["GET", "POST", "PUT", "PATCH"],
            "resources": {
                "health": {"method": "GET", "path": "/api/v2/nexus/health"},
                "identity": {"method": "GET", "path": "/api/v2/nexus/whoami"},
                "actions": {"method": "GET", "path": "/api/v2/nexus/actions"},
                "catalog_actions": {"method": "GET", "path": "/api/v2/nexus/catalog/actions"},
                "workflows": {"method": "GET", "path": "/api/v2/nexus/workflows"},
                "job_submit": {"method": "POST", "path": "/api/v2/nexus/jobs"},
                "job_list": {"method": "GET", "path": "/api/v2/nexus/jobs"},
                "job_get": {"method": "GET", "path": "/api/v2/nexus/jobs/{job_id}"},
                "job_events": {"method": "GET", "path": "/api/v2/nexus/jobs/{job_id}/events"},
                "job_cancel_patch": {"method": "PATCH", "path": "/api/v2/nexus/jobs/{job_id}"},
                "job_cancel_put": {"method": "PUT", "path": "/api/v2/nexus/jobs/{job_id}/cancel"},
            },
            "notes": {
                "read_method": "READ maps to GET in HTTP semantics",
                "auth": "Use X-API-Key or Authorization: Bearer <key>; signing headers are optional unless tenant policy requires them.",
                "idempotency": "Mutating endpoints require Idempotency-Key",
                "compatibility_aliases": [
                    "/api/v2/jobs",
                    "/api/v2/omni/jobs",
                ],
                "tenant_model": "Public payloads should reference tenant templates/policies instead of provider-specific hardcoded behavior.",
            },
        },
        message="NEXUS bootstrap contract",
    )


@router.get(
    "/omni/workflows",
    response_model=WorkflowsEnvelope,
    summary="List workflow to action mappings",
    tags=["OMNI Discovery"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_workflows(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return v2_nexus_workflows(_)


@router.get("/nexus/workflows")
def v2_nexus_workflows(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return _envelope(
        status="ok",
        data={
            "workflows": _NEXUS_WORKFLOWS,
            "parity_doc": "/docs/UI_API_PARITY.md",
            "actions_count": len(_ACTION_HANDLERS),
            "frontend_only_tabs": [
                key
                for key, value in _NEXUS_WORKFLOWS.items()
                if value.get("delivery") in {"frontend_only", "mixed"}
            ],
        },
        message="NEXUS workflow/action mappings",
    )


@router.get("/nexus/catalog/actions")
def v2_nexus_catalog_actions(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return _envelope(
        status="ok",
        data={
            "actions": _NEXUS_ACTION_CATALOG,
            "count": len(_NEXUS_ACTION_CATALOG),
            "coverage_note": "Tabs marked frontend_only in /api/v2/nexus/workflows still need backend promotion before Omni-native UI parity.",
        },
        message="NEXUS action catalog",
    )


@router.post("/nexus/tools/cisco/interface")
def v2_nexus_cisco_interface(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "Cisco port setup",
                "value": _NEXUS_ACTION_CATALOG["cisco.generate_interface"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_render_cisco_interface(payload), message="Cisco interface config generated")


@router.post("/nexus/tools/enterprise-feeding/generate")
def v2_nexus_enterprise_feeding(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "Enterprise feeding",
                "value": _NEXUS_ACTION_CATALOG["enterprise.feeding.generate"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_render_enterprise_feeding(payload), message="Enterprise feeding config generated")


@router.post("/nexus/tools/enterprise-feeding/outstate")
def v2_nexus_enterprise_feeding_outstate(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "Enterprise feeding out-of-state",
                "value": _NEXUS_ACTION_CATALOG["enterprise.feeding.generate_outstate"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_render_enterprise_feeding_outstate(payload), message="Out-of-state enterprise feeding config generated")


@router.post("/nexus/tools/config-diff")
def v2_nexus_config_diff(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "Config diff",
                "value": _NEXUS_ACTION_CATALOG["config.diff"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_compute_config_diff(payload), message="Config diff computed")


@router.post("/nexus/tools/command-vault")
def v2_nexus_command_vault_catalog(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "Command Vault catalog filter",
                "value": _NEXUS_ACTION_CATALOG["command.vault.catalog"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_command_vault_catalog(payload), message="Command Vault catalog")


@router.post("/nexus/tools/6ghz/instate")
def v2_nexus_6ghz_instate(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "6GHz in-state",
                "value": _NEXUS_ACTION_CATALOG["switch.generate_6ghz"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_render_6ghz_switch(payload), message="6GHz in-state config generated")


@router.post("/nexus/tools/6ghz/outstate")
def v2_nexus_6ghz_outstate(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "single_port": {
                "summary": "6GHz out-of-state single-port",
                "value": {
                    "switch_type": "swt_ccr2004",
                    "routeros_version": "7.19.4",
                    "port": "sfp-sfpplus8",
                },
            },
            "bonded": {
                "summary": "6GHz out-of-state bonded",
                "value": _NEXUS_ACTION_CATALOG["switch.generate_6ghz_outstate"]["payload_example"],
            },
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_render_6ghz_switch_outstate(payload), message="6GHz out-of-state config generated")


@router.post("/nexus/tools/enterprise/mpls")
def v2_nexus_enterprise_mpls(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "MPLS enterprise",
                "value": _NEXUS_ACTION_CATALOG["enterprise.generate_mpls"]["payload_example"],
            }
        },
    ),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_render_mpls_enterprise(payload), message="MPLS enterprise config generated")


@router.get("/nexus/maintenance/windows")
def v2_nexus_list_maintenance_windows(
    status: str = "all",
    limit: int = 250,
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    windows = _maintenance_list(status=status, limit=limit)
    return _envelope(status="ok", data={"windows": windows, "count": len(windows)}, message="Maintenance windows")


@router.post("/nexus/maintenance/windows")
def v2_nexus_create_maintenance_window(
    payload: Dict[str, Any] = Body(
        default_factory=dict,
        openapi_examples={
            "default": {
                "summary": "Maintenance create",
                "value": _NEXUS_ACTION_CATALOG["maintenance.windows.create"]["payload_example"],
            }
        },
    ),
    auth: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    window = _maintenance_create(payload, created_by=auth["api_key"])
    return JSONResponse(status_code=201, content=_envelope(status="ok", data=window, message="Maintenance window created"))


@router.get("/nexus/maintenance/windows/{window_id}")
def v2_nexus_get_maintenance_window(
    window_id: str,
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_maintenance_get(window_id), message="Maintenance window")


@router.put("/nexus/maintenance/windows/{window_id}")
def v2_nexus_update_maintenance_window(
    window_id: str,
    payload: Dict[str, Any] = Body(default_factory=dict),
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    return _envelope(status="ok", data=_maintenance_update(window_id, payload), message="Maintenance window updated")


@router.delete("/nexus/maintenance/windows/{window_id}")
def v2_nexus_delete_maintenance_window(
    window_id: str,
    _: Dict[str, Any] = Depends(_require_scope("actions.read")),
):
    _maintenance_delete(window_id)
    return _envelope(status="ok", data={"window_id": window_id}, message="Maintenance window deleted")


@router.post("/jobs", include_in_schema=False)
def v2_submit_job(
    request: Request,
    payload: SubmitJobRequest = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.submit")),
):
    idem_key = _normalize_idempotency_key(idempotency_key)
    if _IDEMPOTENCY_REQUIRED and not idem_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key")

    req_hash = _body_hash(_request_body_bytes(request))
    if idem_key:
        existing = _load_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
        )
        if existing:
            status_code, body = existing
            return JSONResponse(status_code=status_code, content=body)

    action, job_payload = _request_model_to_action_payload(payload)
    rid = request.headers.get("X-Request-ID") or _request_id()
    job = _JOBS.submit(action=action, payload=job_payload, submitted_by=auth["api_key"], request_id=rid)
    response_body = _envelope(
        status="accepted",
        data={
            "job_id": job.job_id,
            "request_id": job.request_id,
            "action": action,
            "status": job.status,
        },
        message="Job accepted",
        request_id=rid,
    )
    if idem_key:
        _save_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
            status_code=202,
            response_json=response_body,
        )
    return JSONResponse(status_code=202, content=response_body)


@router.post(
    "/omni/jobs",
    response_model=JobAcceptedEnvelope,
    status_code=202,
    summary="Submit async job",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_submit_job(
    request: Request,
    payload: PublishedSubmitJobRequest = Body(
        ...,
        description=(
            "Curated published job contract. High-value actions use explicit tenant-neutral payload schemas; "
            "the generic action+payload fallback remains available for actions not yet modeled."
        ),
    ),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.submit")),
):
    return v2_submit_job(
        request=request,
        payload=SubmitJobRequest.model_validate(payload.model_dump(exclude_none=True)),
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.post("/nexus/jobs")
def v2_nexus_submit_job(
    request: Request,
    payload: SubmitJobRequest = Body(..., openapi_examples=_JOB_SUBMIT_OPENAPI_EXAMPLES),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.submit")),
):
    return v2_submit_job(
        request=request,
        payload=payload,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.get("/jobs", include_in_schema=False)
def v2_list_jobs(
    limit: int = Query(default=100, ge=1, le=500, description="Maximum number of jobs to return"),
    auth: Dict[str, Any] = Depends(_require_scope("job.read")),
):
    _ = auth
    rows = [_job_to_dict(j, include_payload=False, include_events=False) for j in _JOBS.list(limit=limit)]
    return _envelope(status="ok", data={"jobs": rows, "count": len(rows)})


@router.get(
    "/omni/jobs",
    response_model=JobsListEnvelope,
    summary="List jobs",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_list_jobs(
    limit: int = Query(default=100, ge=1, le=500, description="Maximum number of jobs to return"),
    auth: Dict[str, Any] = Depends(_require_scope("job.read")),
):
    return v2_list_jobs(limit=limit, auth=auth)


@router.get("/nexus/jobs")
def v2_nexus_list_jobs(
    limit: int = 100,
    auth: Dict[str, Any] = Depends(_require_scope("job.read")),
):
    return v2_list_jobs(limit=limit, auth=auth)


@router.get("/jobs/{job_id}", include_in_schema=False)
def v2_get_job(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    _ = auth
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _envelope(status="ok", data=_job_to_dict(job, include_payload=True, include_events=False))


@router.get(
    "/omni/jobs/{job_id}",
    response_model=JobDetailEnvelope,
    summary="Get job detail",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_get_job(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    return v2_get_job(job_id=job_id, auth=auth)


@router.get("/nexus/jobs/{job_id}")
def v2_nexus_get_job(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    return v2_get_job(job_id=job_id, auth=auth)


@router.get("/jobs/{job_id}/events", include_in_schema=False)
def v2_get_job_events(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    _ = auth
    job = _JOBS.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    return _envelope(
        status="ok",
        data={
            "job_id": job.job_id,
            "status": job.status,
            "events": [{"ts": e.ts, "level": e.level, "message": e.message} for e in job.events],
        },
    )


@router.get(
    "/omni/jobs/{job_id}/events",
    response_model=JobEventsEnvelope,
    summary="Get job event stream snapshot",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_get_job_events(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    return v2_get_job_events(job_id=job_id, auth=auth)


@router.get("/nexus/jobs/{job_id}/events")
def v2_nexus_get_job_events(job_id: str, auth: Dict[str, Any] = Depends(_require_scope("job.read"))):
    return v2_get_job_events(job_id=job_id, auth=auth)


@router.post("/jobs/{job_id}/cancel", include_in_schema=False)
def v2_cancel_job(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    idem_key = _normalize_idempotency_key(idempotency_key)
    if _IDEMPOTENCY_REQUIRED and not idem_key:
        raise HTTPException(status_code=400, detail="Missing Idempotency-Key")
    req_hash = _body_hash(_request_body_bytes(request))
    if idem_key:
        existing = _load_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
        )
        if existing:
            status_code, body = existing
            return JSONResponse(status_code=status_code, content=body)

    _ = auth
    job = _JOBS.cancel(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    response_body = _envelope(
        status="ok",
        data={"job_id": job.job_id, "status": job.status, "cancel_requested": job.cancel_requested},
        message="Cancel request accepted",
    )
    if idem_key:
        _save_idempotency(
            idem_key=idem_key,
            api_key=auth["api_key"],
            method=request.method.upper(),
            path=request.url.path,
            request_hash=req_hash,
            status_code=200,
            response_json=response_body,
        )
    return response_body


@router.post(
    "/omni/jobs/{job_id}/cancel",
    response_model=CancelJobEnvelope,
    summary="Cancel job via POST",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_cancel_job(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.post("/nexus/jobs/{job_id}/cancel")
def v2_nexus_cancel_job(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.put("/jobs/{job_id}/cancel", include_in_schema=False)
def v2_cancel_job_put(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.put(
    "/omni/jobs/{job_id}/cancel",
    response_model=CancelJobEnvelope,
    summary="Cancel job via PUT",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_cancel_job_put(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job_put(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.put("/nexus/jobs/{job_id}/cancel")
def v2_nexus_cancel_job_put(
    request: Request,
    job_id: str,
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_cancel_job_put(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.patch("/jobs/{job_id}", include_in_schema=False)
def v2_patch_job(
    request: Request,
    job_id: str,
    payload: PatchJobRequest = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    op = str(payload.op or payload.action or "").strip().lower()
    if op not in {"cancel", "stop"}:
        raise HTTPException(status_code=422, detail="Supported PATCH ops: cancel")
    return v2_cancel_job(
        request=request,
        job_id=job_id,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.patch(
    "/omni/jobs/{job_id}",
    response_model=CancelJobEnvelope,
    summary="Cancel job via PATCH",
    tags=["OMNI Jobs"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_patch_job(
    request: Request,
    job_id: str,
    payload: PatchJobRequest = Body(...),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_patch_job(
        request=request,
        job_id=job_id,
        payload=payload,
        idempotency_key=idempotency_key,
        auth=auth,
    )


@router.patch("/nexus/jobs/{job_id}")
def v2_nexus_patch_job(
    request: Request,
    job_id: str,
    payload: Dict[str, Any] = Body(default_factory=dict),
    idempotency_key: Optional[str] = Header(default=None, alias="Idempotency-Key"),
    auth: Dict[str, Any] = Depends(_require_scope("job.cancel")),
):
    return v2_patch_job(
        request=request,
        job_id=job_id,
        payload=payload,
        idempotency_key=idempotency_key,
        auth=auth,
    )
