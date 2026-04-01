from flask import Blueprint, jsonify
try:
    from tenant_defaults import load_runtime_app_config, load_tenant_defaults
except Exception:
    from vm_deployment.tenant_defaults import load_runtime_app_config, load_tenant_defaults


def create_runtime_blueprint() -> Blueprint:
    bp = Blueprint("runtime_routes", __name__)

    @bp.route('/api/app-config', methods=['GET'])
    def app_config():
        """Lightweight runtime configuration consumed by the frontend."""
        return jsonify(load_runtime_app_config())

    @bp.route('/api/tenant/defaults', methods=['GET'])
    def tenant_defaults():
        """Tenant-neutral defaults and audit metadata for UI/API consumers."""
        return jsonify(load_tenant_defaults(include_sensitive=False))

    return bp

