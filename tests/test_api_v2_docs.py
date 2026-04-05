#!/usr/bin/env python3
"""Swagger/OpenAPI coverage tests for the published NEXUS API v2 contract."""

from __future__ import annotations

import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "vm_deployment"))

from fastapi_server import app  # noqa: E402


client = TestClient(app)
API_V2_MD = repo_root / "docs" / "API_V2.md"


def test_swagger_ui_is_served_from_docs():
    response = client.get("/docs")
    assert response.status_code == 200
    text = response.text.lower()
    assert "swagger" in text
    assert "/docs/openapi.json" in response.text


def test_top_level_openapi_json_is_not_the_published_spec_surface():
    response = client.get("/openapi.json")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")


def test_docs_openapi_contains_nexus_contract_endpoints_only():
    response = client.get("/docs/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    paths = schema["paths"]
    assert schema["openapi"].startswith("3.")

    assert "/api/v2/nexus/health" in paths
    assert "/api/v2/nexus/actions" in paths
    assert "/api/v2/nexus/whoami" in paths
    assert "/api/v2/nexus/bootstrap" in paths
    assert "/api/v2/nexus/workflows" in paths
    assert "/api/v2/nexus/catalog/actions" in paths
    assert "/api/v2/nexus/tenant/defaults" in paths
    assert "/api/v2/nexus/jobs" in paths
    assert "/api/v2/nexus/jobs/{job_id}" in paths
    assert "/api/v2/nexus/jobs/{job_id}/events" in paths
    assert "/api/v2/nexus/jobs/{job_id}/cancel" in paths
    assert "/api/v2/nexus/tools/command-vault" in paths
    assert "/api/v2/nexus/maintenance/windows" in paths

    assert "/api/v2/omni/health" not in paths
    assert "/api/v2/omni/actions" not in paths
    assert "/api/v2/omni/jobs" not in paths
    assert "/api/v2/health" not in paths
    assert "/api/v2/actions" not in paths
    assert "/api/v2/whoami" not in paths
    assert "/api/v2/jobs" not in paths
    assert "/api/ido/capabilities" not in paths


def test_docs_openapi_includes_published_nexus_models():
    response = client.get("/docs/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    components = schema["components"]["schemas"]

    assert "SubmitJobRequest" in components
    assert "ValidationError" in components
    assert "HTTPValidationError" in components

    submit_post = schema["paths"]["/api/v2/nexus/jobs"]["post"]
    request_schema = submit_post["requestBody"]["content"]["application/json"]["schema"]
    assert request_schema.get("type") == "object" or "$ref" in request_schema

    request_examples = submit_post["requestBody"]["content"]["application/json"]["examples"]
    assert "enterprise_generate_mpls" in request_examples
    assert "switch_generate_mikrotik" in request_examples
    assert "command_vault_catalog" in request_examples

    security_schemes = schema["components"]["securitySchemes"]
    assert "ApiKeyAuth" in security_schemes
    assert "BearerAuth" in security_schemes
    assert submit_post["security"] == [{"ApiKeyAuth": []}, {"BearerAuth": []}]

    tag_names = {tag["name"] for tag in schema["tags"]}
    assert {"NEXUS Health", "NEXUS Discovery", "NEXUS Jobs", "NEXUS Tools", "NEXUS Maintenance"}.issubset(tag_names)


def test_docs_openapi_is_nexus_first():
    response = client.get("/docs/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    assert schema["info"]["title"] == "NEXUS API"
    assert "/api/v2/nexus/*" in schema["info"]["description"]
    assert "Compatibility aliases remain mounted for legacy clients" in schema["info"]["description"]
    assert all(path.startswith("/api/v2/nexus/") for path in schema["paths"])
