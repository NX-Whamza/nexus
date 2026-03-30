#!/usr/bin/env python3
"""
API v2 (contract-first layer) for NOC ConfigMaker.

This module adds:
- API key + scope auth for /api/v2
- Async job model (submit/status/events/cancel)
- Stable action registry so external UIs (OMNI/Mushu/etc.) can drive backend safely
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


router = APIRouter(prefix="/api/v2", tags=["NOC API v2"])


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
    "ftth.mf2_package": _legacy_post("/api/ftth-home/mf2-package"),

    # Nokia
    "nokia.generate_7250": _legacy_post("/api/generate-nokia7250"),
    "nokia.defaults": _legacy_get("/api/nokia7250-defaults"),

    # Enterprise
    "enterprise.generate_non_mpls": _legacy_post("/api/gen-enterprise-non-mpls"),

    # Tarana
    "tarana.generate": _legacy_post("/api/gen-tarana-config"),

    # SSH Config Fetch
    "device.fetch_config_ssh": _legacy_post("/api/fetch-config-ssh"),

    # Feedback
    "feedback.submit": _legacy_post("/api/feedback"),

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
}


_OMNI_WORKFLOWS: Dict[str, Any] = {
    "dashboard": {
        "health": "health.get",
        "activity_list": "activity.list",
        "configs_list": "configs.list",
        "infrastructure": "infrastructure.get",
    },
    "mikrotik": {
        "render": {"action": "mt.render", "required": ["config_type", "payload"]},
        "config_only": {"action": "mt.config", "required": ["config_type", "payload"]},
        "portmap_only": {"action": "mt.portmap", "required": ["config_type", "payload"]},
    },
    "nokia_7250": {
        "defaults": "nokia.defaults",
        "generate": "nokia.generate_7250",
        "generate_ido": "ido.nokia7250.generate",
        "migrate_from_mikrotik": "migration.mikrotik_to_nokia",
    },
    "enterprise": {
        "generate_non_mpls": "enterprise.generate_non_mpls",
    },
    "tarana": {
        "generate": "tarana.generate",
    },
    "field_config_studio": {
        "capabilities": "ido.capabilities",
        "ap": ["ido.ap.device_info", "ido.ap.running_config", "ido.ap.standard_config", "ido.ap.generate"],
        "bh": ["ido.bh.device_info", "ido.bh.running_config", "ido.bh.standard_config", "ido.bh.generate"],
        "switch": ["ido.swt.device_info", "ido.swt.running_config", "ido.swt.standard_config", "ido.swt.generate"],
        "ups": ["ido.ups.device_info", "ido.ups.running_config", "ido.ups.standard_config", "ido.ups.generate"],
        "rpc": ["ido.rpc.device_info", "ido.rpc.running_config", "ido.rpc.standard_config", "ido.rpc.generate"],
        "wave": "ido.wave.config",
    },
    "aviat": {
        "run": "aviat.run",
        "check_status": "aviat.check_status",
        "activate_scheduled": "aviat.activate_scheduled",
        "queue_get": "aviat.queue.get",
        "queue_update": "aviat.queue.update",
        "status": "aviat.status",
        "precheck_recheck": "aviat.precheck_recheck",
        "scheduled_get": "aviat.scheduled.get",
        "loading_get": "aviat.loading.get",
        "reboot_required_get": "aviat.reboot_required.get",
        "reboot_required_run": "aviat.reboot_required.run",
        "scheduled_sync": "aviat.scheduled.sync",
        "fix_stp": "aviat.fix_stp",
        "abort": "aviat.abort",
    },
    "ftth": {
        "preview_bng": "ftth.preview_bng",
        "generate_bng": "ftth.generate_bng",
        "mf2_package": "ftth.mf2_package",
    },
    "compliance": {
        "apply": "compliance.apply",
        "status": "compliance.status",
        "blocks": "compliance.blocks",
        "engineering": "compliance.engineering",
        "policies_list": "compliance.policies.list",
        "policies_get": "compliance.policies.get",
        "policies_bundle": "compliance.policies.bundle",
        "policies_reload": "compliance.policies.reload",
        "reload": "compliance.reload",
    },
    "device_ops": {
        "fetch_config_ssh": "device.fetch_config_ssh",
        "ping": "ido.ping",
        "generic_device_info": "ido.generic.device_info",
    },
    "feedback": {
        "submit": "feedback.submit",
    },
    "admin": {
        "feedback_list": "admin.feedback.list",
        "feedback_update_status": "admin.feedback.update_status",
        "feedback_export": "admin.feedback.export",
        "users_reset_password": "admin.users.reset_password",
    },
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


@router.get(
    "/omni/bootstrap",
    response_model=BootstrapEnvelope,
    summary="Bootstrap contract metadata",
    tags=["OMNI Discovery"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_bootstrap(auth: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    _ = auth
    return _envelope(
        status="ok",
        data={
            "api_version": "v2",
            "service": "noc-configmaker",
            "base_url_hint": "/api/v2",
            "methods_supported": ["GET", "POST", "PUT", "PATCH"],
            "resources": {
                "health": {"method": "GET", "path": "/api/v2/health"},
                "identity": {"method": "GET", "path": "/api/v2/whoami"},
                "actions": {"method": "GET", "path": "/api/v2/actions"},
                "job_submit": {"method": "POST", "path": "/api/v2/jobs"},
                "job_list": {"method": "GET", "path": "/api/v2/jobs"},
                "job_get": {"method": "GET", "path": "/api/v2/jobs/{job_id}"},
                "job_events": {"method": "GET", "path": "/api/v2/jobs/{job_id}/events"},
                "job_cancel_patch": {"method": "PATCH", "path": "/api/v2/jobs/{job_id}"},
                "job_cancel_put": {"method": "PUT", "path": "/api/v2/jobs/{job_id}/cancel"},
            },
            "notes": {
                "read_method": "READ maps to GET in HTTP semantics",
                "auth": "Use X-API-Key or Authorization: Bearer <key>; signing headers are optional unless tenant policy requires them.",
                "idempotency": "Mutating endpoints require Idempotency-Key",
                "tenant_model": "Public payloads should reference tenant templates/policies instead of provider-specific hardcoded behavior.",
            },
        },
        message="OMNI bootstrap contract",
    )


@router.get(
    "/omni/workflows",
    response_model=WorkflowsEnvelope,
    summary="List workflow to action mappings",
    tags=["OMNI Discovery"],
    responses=COMMON_ERROR_RESPONSES,
)
def v2_omni_workflows(_: Dict[str, Any] = Depends(_require_scope("actions.read"))):
    return _envelope(
        status="ok",
        data={
            "workflows": _OMNI_WORKFLOWS,
            "parity_doc": "/docs/UI_API_PARITY.md",
            "actions_count": len(_ACTION_HANDLERS),
        },
        message="OMNI workflow/action mappings",
    )


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
