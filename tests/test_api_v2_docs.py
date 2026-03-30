#!/usr/bin/env python3
"""Swagger/OpenAPI coverage tests for the API v2 OMNI contract."""

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


def test_docs_openapi_contains_omni_contract_endpoints_only():
    response = client.get("/docs/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    paths = schema["paths"]
    assert schema["openapi"].startswith("3.")

    assert "/api/v2/omni/health" in paths
    assert "/api/v2/omni/actions" in paths
    assert "/api/v2/omni/whoami" in paths
    assert "/api/v2/omni/bootstrap" in paths
    assert "/api/v2/omni/workflows" in paths
    assert "/api/v2/omni/jobs" in paths
    assert "/api/v2/omni/jobs/{job_id}" in paths
    assert "/api/v2/omni/jobs/{job_id}/events" in paths
    assert "/api/v2/omni/jobs/{job_id}/cancel" in paths

    assert "/api/v2/health" not in paths
    assert "/api/v2/actions" not in paths
    assert "/api/v2/whoami" not in paths
    assert "/api/v2/jobs" not in paths


def test_docs_openapi_includes_typed_job_models():
    response = client.get("/docs/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    components = schema["components"]["schemas"]

    assert "SubmitJobRequest" in components
    assert "PatchJobRequest" in components
    assert "JobAcceptedEnvelope" in components
    assert "JobsListEnvelope" in components
    assert "JobDetailEnvelope" in components
    assert "JobEventsEnvelope" in components
    assert "CancelJobEnvelope" in components
    assert "FtthGenerateBngJobRequest" in components
    assert "FtthGenerateBngPayload" in components
    assert "AviatRunJobRequest" in components
    assert "NokiaGenerate7250JobRequest" in components
    assert "ConfigsSaveJobRequest" in components
    assert "ConfigsGetJobRequest" in components
    assert "DeviceFetchConfigSshJobRequest" in components
    assert "ComplianceApplyJobRequest" in components
    assert "FeedbackSubmitJobRequest" in components

    submit_post = schema["paths"]["/api/v2/omni/jobs"]["post"]
    request_schema = submit_post["requestBody"]["content"]["application/json"]["schema"]
    assert "anyOf" in request_schema
    request_refs = {
        item["$ref"].rsplit("/", 1)[-1]
        for item in request_schema["anyOf"]
        if "$ref" in item
    }
    assert "FtthGenerateBngJobRequest" in request_refs
    assert "AviatRunJobRequest" in request_refs
    assert "NokiaGenerate7250JobRequest" in request_refs
    assert "ConfigsSaveJobRequest" in request_refs
    assert "DeviceFetchConfigSshJobRequest" in request_refs
    assert "FeedbackSubmitJobRequest" in request_refs
    assert "SubmitJobRequest" in request_refs

    security_schemes = schema["components"]["securitySchemes"]
    assert "ApiKeyAuth" in security_schemes
    assert "BearerAuth" in security_schemes
    assert submit_post["security"] == [{"ApiKeyAuth": []}, {"BearerAuth": []}]

    tag_names = {tag["name"] for tag in schema["tags"]}
    assert {"OMNI Health", "OMNI Discovery", "OMNI Jobs"}.issubset(tag_names)


def test_api_v2_markdown_matches_swagger_endpoint_inventory():
    response = client.get("/docs/openapi.json")
    assert response.status_code == 200
    schema = response.json()
    swagger_pairs = {
        f"{method.upper()} {path}"
        for path, methods in schema["paths"].items()
        for method in methods.keys()
    }

    md_text = API_V2_MD.read_text(encoding="utf-8")
    md_pairs = set(
        re.findall(r"- `(GET|POST|PUT|PATCH) (/api/v2/omni[^`]+)`", md_text)
    )
    normalized_md_pairs = {f"{method} {path}" for method, path in md_pairs}

    assert normalized_md_pairs
    assert normalized_md_pairs.issubset(swagger_pairs)
    assert "https://noc-configmaker.nxlink.com/docs" in md_text
    assert "https://noc-configmaker.nxlink.com/openapi.json" not in md_text
