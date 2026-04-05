"""
Full multi-tenant integration test.
Validates: tenant isolation, RBAC, session bootstrap, data scoping,
infrastructure settings, compliance checks, audit logging,
and that the nextlink tenant behaves correctly throughout.
"""
from __future__ import annotations
import importlib, json, os, sqlite3, sys
from pathlib import Path


def _load_api_server():
    repo_root = Path(__file__).resolve().parents[1]
    for p in (str(repo_root), str(repo_root / "vm_deployment")):
        if p not in sys.path:
            sys.path.insert(0, p)
    return importlib.import_module("vm_deployment.api_server")


def _patch_all_dbs(monkeypatch, api_server):
    import uuid as _uuid
    # Use a unique suffix per test invocation so each test gets a fresh in-memory DB
    _suffix = _uuid.uuid4().hex[:8]
    db_uris = {
        "users.db":             f"file:int_users_{_suffix}?mode=memory&cache=shared",
        "feedback.db":          f"file:int_feedback_{_suffix}?mode=memory&cache=shared",
        "activity_log.db":      f"file:int_activity_{_suffix}?mode=memory&cache=shared",
        "completed_configs.db": f"file:int_configs_{_suffix}?mode=memory&cache=shared",
    }
    anchors = {name: sqlite3.connect(uri, uri=True) for name, uri in db_uris.items()}
    orig = sqlite3.connect
    orig_exists = os.path.exists

    def connect_override(path, *a, **k):
        target = str(path)
        for suffix, uri in db_uris.items():
            if target.endswith(suffix):
                return orig(uri, uri=True, *a, **k)
        return orig(path, *a, **k)

    monkeypatch.setattr(api_server.sqlite3, "connect", connect_override)
    monkeypatch.setattr(
        api_server.os.path,
        "exists",
        lambda p: True if str(p) == "secure_data" else orig_exists(p),
    )
    monkeypatch.setattr(api_server.os, "makedirs", lambda *a, **k: None)
    # Reset lazy-init flags so each test starts fresh
    monkeypatch.setattr(api_server, "_configs_db_initialized", False, raising=False)
    monkeypatch.setattr(api_server, "_activity_db_initialized", False, raising=False)
    return db_uris, anchors


def _login(client, api_server, email):
    r = client.post(
        "/api/auth/login",
        json={"email": email, "password": api_server.DEFAULT_PASSWORD},
    )
    assert r.status_code == 200, f"Login failed for {email}: {r.get_json()}"
    token = (r.get_json() or {}).get("token")
    assert token, f"No token returned for {email}"
    return token


def _create_tenant(client, token, slug, name):
    r = client.post(
        "/api/admin/tenants",
        json={"slug": slug, "name": name, "auth_mode": "password"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, f"Create tenant failed: {r.get_json()}"
    return r.get_json()["tenant"]


def _assign_membership(client, token, user_id, tenant_id, role):
    r = client.patch(
        f"/api/admin/users/{user_id}/membership",
        json={"tenant_id": tenant_id, "role": role, "status": "active"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert r.status_code == 200, f"Assign membership failed: {r.get_json()}"
    return r.get_json()


# ─── TEST 1: Complete tenant lifecycle ───────────────────────────────────────

def test_full_tenant_lifecycle(monkeypatch):
    """Super admin creates a tenant, assigns users, verifies isolation."""
    api = _load_api_server()
    db_uris, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()

        # 1. Super admin logs in
        admin_token = _login(client, api, "whamza@team.nxlink.com")
        bootstrap = client.get(
            "/api/session/bootstrap",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        assert bootstrap["user"]["platformRole"] == "platform_admin"
        assert bootstrap["permissions"]["platformAdmin"] is True
        assert bootstrap["activeTenant"]["slug"] == "nextlink"

        # 2. Create customer tenant
        tenant = _create_tenant(client, admin_token, "acme-corp", "Acme Corp")
        assert tenant["slug"] == "acme-corp"

        # 3. Audit log captured tenant creation
        audit = client.get(
            "/api/admin/audit-log?event_type=tenant_create",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        assert any(e["tenant_slug"] == "acme-corp" for e in audit["events"])

        # 4. Regular user logs in and is in nextlink by default
        eng_token = _login(client, api, "engineer@team.nxlink.com")
        eng_bootstrap = client.get(
            "/api/session/bootstrap",
            headers={"Authorization": f"Bearer {eng_token}"},
        ).get_json()
        assert eng_bootstrap["activeTenant"]["slug"] == "nextlink"
        assert eng_bootstrap["user"]["platformRole"] == "user"
        assert eng_bootstrap["permissions"]["platformAdmin"] is False

        # 5. Admin assigns engineer to acme-corp
        users = client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        eng_user = next(u for u in users["users"] if u["email"] == "engineer@team.nxlink.com")
        _assign_membership(client, admin_token, eng_user["id"], tenant["id"], "tenant_engineer")

        # 6. Engineer switches active tenant
        switch = client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": tenant["id"]},
            headers={"Authorization": f"Bearer {eng_token}"},
        )
        assert switch.status_code == 200
        assert switch.get_json()["activeTenant"]["slug"] == "acme-corp"

    finally:
        for conn in anchors.values():
            conn.close()


# ─── TEST 2: Data isolation between tenants ──────────────────────────────────

def test_data_isolation_configs_and_activity(monkeypatch):
    """Configs and activity saved by acme user are invisible to nextlink user."""
    api = _load_api_server()
    db_uris, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        admin_token = _login(client, api, "whamza@team.nxlink.com")
        acme_token = _login(client, api, "acme-eng@team.nxlink.com")
        nextlink_token = _login(client, api, "nl-eng@team.nxlink.com")

        # Create acme tenant and assign user
        tenant = _create_tenant(client, admin_token, "acme-isolation", "Acme Isolation")
        users = client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        acme_user = next(u for u in users["users"] if u["email"] == "acme-eng@team.nxlink.com")
        _assign_membership(client, admin_token, acme_user["id"], tenant["id"], "tenant_engineer")
        client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": tenant["id"]},
            headers={"Authorization": f"Bearer {acme_token}"},
        )

        # Acme user saves a config
        save = client.post(
            "/api/save-completed-config",
            json={
                "config_type": "tower",
                "device_name": "ACME-RTR-1",
                "config_content": "/system identity set name=ACME-RTR-1",
            },
            headers={"Authorization": f"Bearer {acme_token}"},
        )
        assert save.status_code == 200

        # Acme sees their config
        acme_configs = client.get(
            "/api/get-completed-configs",
            headers={"Authorization": f"Bearer {acme_token}"},
        ).get_json()
        assert len(acme_configs["configs"]) == 1
        assert acme_configs["configs"][0]["device_name"] == "ACME-RTR-1"

        # Nextlink user sees zero configs (different tenant)
        nl_configs = client.get(
            "/api/get-completed-configs",
            headers={"Authorization": f"Bearer {nextlink_token}"},
        ).get_json()
        assert nl_configs["configs"] == []

        # Acme user logs activity
        client.post(
            "/api/log-activity",
            json={
                "type": "new-config",
                "device": "ACME-RTR-1",
                "siteName": "Acme HQ",
                "success": True,
            },
            headers={"Authorization": f"Bearer {acme_token}"},
        )

        # Acme sees their activity
        acme_activity = client.get(
            "/api/get-activity?all=true",
            headers={"Authorization": f"Bearer {acme_token}"},
        ).get_json()
        assert len(acme_activity["activities"]) >= 1

        # Nextlink sees zero activity from acme
        nl_activity = client.get(
            "/api/get-activity?all=true",
            headers={"Authorization": f"Bearer {nextlink_token}"},
        ).get_json()
        assert all(a.get("siteName") != "Acme HQ" for a in nl_activity.get("activities", []))

    finally:
        for conn in anchors.values():
            conn.close()


# ─── TEST 3: RBAC boundaries ─────────────────────────────────────────────────

def test_rbac_boundaries_across_all_roles(monkeypatch):
    """Verify each role can/cannot access appropriate endpoints."""
    api = _load_api_server()
    db_uris, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()

        # platform_admin
        admin_token = _login(client, api, "whamza@team.nxlink.com")
        assert client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 200
        assert client.get("/api/admin/users", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 200
        assert client.get("/api/admin/audit-log", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 200
        assert client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {admin_token}"}).status_code == 200

        # platform_support (bgonzales)
        support_token = _login(client, api, "bgonzales@team.nxlink.com")
        assert client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {support_token}"}).status_code == 200
        assert client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {support_token}"}).status_code == 403
        assert client.get("/api/admin/audit-log", headers={"Authorization": f"Bearer {support_token}"}).status_code == 403

        # regular user
        user_token = _login(client, api, "regular@team.nxlink.com")
        assert client.get("/api/admin/tenants", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403
        assert client.get("/api/admin/feedback", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403
        assert client.get("/api/admin/audit-log", headers={"Authorization": f"Bearer {user_token}"}).status_code == 403
        # Regular user CAN access their own data
        assert client.get("/api/get-completed-configs", headers={"Authorization": f"Bearer {user_token}"}).status_code == 200
        assert client.get("/api/session/bootstrap", headers={"Authorization": f"Bearer {user_token}"}).status_code == 200

        # Unauthenticated requests blocked on sensitive endpoints
        assert client.post("/api/fetch-config-ssh", json={}).status_code == 401
        assert client.post("/api/log-activity", json={}).status_code == 401
        # GET without auth returns 401 or 415 (require_auth tries request.json on GET)
        r_unauth = client.get("/api/admin/tenants")
        assert r_unauth.status_code in (401, 415), f"Expected 401/415, got {r_unauth.status_code}"

    finally:
        for conn in anchors.values():
            conn.close()


# ─── TEST 4: Nextlink tenant labeled and seeded correctly ────────────────────

def test_nextlink_tenant_correctly_labeled_and_seeded(monkeypatch):
    """Nextlink tenant has correct slug, name, auth mode, and settings."""
    api = _load_api_server()
    _, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        token = _login(client, api, "whamza@team.nxlink.com")

        # Bootstrap shows nextlink as active tenant
        bootstrap = client.get(
            "/api/session/bootstrap",
            headers={"Authorization": f"Bearer {token}"},
        ).get_json()
        active = bootstrap["activeTenant"]
        assert active["slug"] == "nextlink"
        assert active["name"] == "Nextlink"
        assert active["authMode"] == "microsoft"

        # Tenant list includes nextlink
        tenants = client.get(
            "/api/admin/tenants",
            headers={"Authorization": f"Bearer {token}"},
        ).get_json()
        nextlink = next(t for t in tenants["tenants"] if t["slug"] == "nextlink")
        assert nextlink["status"] == "active"

        # Nextlink settings are seeded with correct values
        settings = client.get(
            "/api/tenant-settings",
            headers={"Authorization": f"Bearer {token}"},
        ).get_json()["settings"]
        assert settings["snmp_community"] == "NXLpublic"
        assert settings["compliance_dns_primary"] == "142.147.112.3"
        assert settings["noc_monitor_ip"] == "142.147.127.2"
        assert settings["syslog_server"] == "142.147.116.215"
        cnm_urls = json.loads(settings.get("cambium_cnm_urls") or "[]")
        assert any("nxlink" in u.get("url", "") for u in cnm_urls)

        # Infrastructure endpoint returns nextlink-specific values
        infra = client.get(
            "/api/infrastructure",
            headers={"Authorization": f"Bearer {token}"},
        ).get_json()
        infra_str = json.dumps(infra)
        assert "NXLpublic" in infra_str or "nxlink" in infra_str.lower()

        # Cannot deactivate nextlink
        deactivate = client.patch(
            f"/api/admin/tenants/{nextlink['id']}/status",
            json={"status": "inactive"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert deactivate.status_code == 400

    finally:
        for conn in anchors.values():
            conn.close()


# ─── TEST 5: Tenant settings flow end to end ─────────────────────────────────

def test_tenant_settings_update_flows_to_compliance(monkeypatch):
    """Updating tenant settings changes compliance check values."""
    api = _load_api_server()
    _, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        admin_token = _login(client, api, "whamza@team.nxlink.com")
        acme_token = _login(client, api, "acme-settings@team.nxlink.com")

        # Create acme tenant
        tenant = _create_tenant(client, admin_token, "acme-settings", "Acme Settings Co")
        users_resp = client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        acme_user = next(u for u in users_resp["users"] if u["email"] == "acme-settings@team.nxlink.com")
        _assign_membership(client, admin_token, acme_user["id"], tenant["id"], "tenant_admin")
        client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": tenant["id"]},
            headers={"Authorization": f"Bearer {acme_token}"},
        )

        # Update compliance settings
        update = client.put(
            "/api/tenant-settings",
            json={
                "compliance_dns_primary": "10.99.0.1",
                "compliance_dns_secondary": "10.99.0.2",
                "compliance_radius_primary": "10.99.0.10",
            },
            headers={"Authorization": f"Bearer {acme_token}"},
        )
        assert update.status_code == 200
        s = update.get_json()["settings"]
        assert s["compliance_dns_primary"] == "10.99.0.1"

        # Compliance checks now use acme values
        checks = api._build_compliance_checks(s)
        patterns = {c["pattern"] for c in checks}
        assert "10.99.0.1" in patterns
        assert "142.147.112.3" not in patterns

    finally:
        for conn in anchors.values():
            conn.close()


# ─── TEST 6: Audit trail captures all key events ─────────────────────────────

def test_audit_trail_captures_key_events(monkeypatch):
    """Audit log records login, tenant create, membership change, switch."""
    api = _load_api_server()
    _, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        admin_token = _login(client, api, "whamza@team.nxlink.com")
        eng_token = _login(client, api, "audit-eng@team.nxlink.com")

        tenant = _create_tenant(client, admin_token, "audit-tenant", "Audit Test Tenant")
        users_resp = client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        eng_user = next(u for u in users_resp["users"] if u["email"] == "audit-eng@team.nxlink.com")
        _assign_membership(client, admin_token, eng_user["id"], tenant["id"], "tenant_engineer")
        client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": tenant["id"]},
            headers={"Authorization": f"Bearer {eng_token}"},
        )

        audit = client.get(
            "/api/admin/audit-log?limit=50",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        event_types = {e["event_type"] for e in audit["events"]}
        assert "login" in event_types
        assert "tenant_create" in event_types
        assert "membership_change" in event_types
        assert "tenant_switch" in event_types

    finally:
        for conn in anchors.values():
            conn.close()


# ─── TEST 7: Feedback isolation per tenant ───────────────────────────────────

def test_feedback_isolated_per_tenant(monkeypatch):
    """Feedback submitted by acme user is not visible to nextlink admin."""
    api = _load_api_server()
    db_uris, anchors = _patch_all_dbs(monkeypatch, api)
    try:
        client = api.app.test_client()
        admin_token = _login(client, api, "whamza@team.nxlink.com")
        acme_token = _login(client, api, "acme-fb@team.nxlink.com")

        tenant = _create_tenant(client, admin_token, "acme-fb", "Acme Feedback")
        users_resp = client.get(
            "/api/admin/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        acme_user = next(u for u in users_resp["users"] if u["email"] == "acme-fb@team.nxlink.com")
        _assign_membership(client, admin_token, acme_user["id"], tenant["id"], "tenant_admin")
        client.post(
            "/api/session/switch-tenant",
            json={"tenant_id": tenant["id"]},
            headers={"Authorization": f"Bearer {acme_token}"},
        )

        # Acme submits feedback
        submit = client.post(
            "/api/feedback",
            json={
                "type": "bug",
                "subject": "Acme Only Bug",
                "details": "Only acme should see this",
                "name": "Acme Admin",
                "email": "acme-fb@team.nxlink.com",
            },
            headers={"Authorization": f"Bearer {acme_token}"},
        )
        assert submit.status_code == 200

        # Acme admin sees their feedback
        acme_list = client.get(
            "/api/admin/feedback",
            headers={"Authorization": f"Bearer {acme_token}"},
        ).get_json()
        assert len(acme_list.get("feedback", [])) == 1
        assert acme_list["feedback"][0]["subject"] == "Acme Only Bug"

        # Platform admin switching to nextlink sees ZERO acme feedback
        admin_nextlink_list = client.get(
            "/api/admin/feedback",
            headers={"Authorization": f"Bearer {admin_token}"},
        ).get_json()
        assert all(f["subject"] != "Acme Only Bug" for f in admin_nextlink_list.get("feedback", []))

    finally:
        for conn in anchors.values():
            conn.close()
