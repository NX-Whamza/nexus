import traceback
from typing import Any, Callable

from flask import Blueprint, jsonify, request


def create_ftth_blueprint(
    render_ftth_config: Callable[[dict], str],
    cidr_details_gen: Callable[[str], dict],
) -> Blueprint:
    bp = Blueprint("ftth_routes", __name__)

    @bp.route('/api/gen-ftth-bng', methods=['POST'])
    def gen_ftth_bng():
        """Deprecated FTTH endpoint. Use /api/generate-ftth-bng with full payload."""
        try:
            data = request.get_json(force=True) or {}

            required_full = [
                'loopback_ip',
                'cpe_network',
                'cgnat_private',
                'cgnat_public',
                'unauth_network',
                'olt_network'
            ]
            if all(data.get(k) for k in required_full):
                config = render_ftth_config(data)
                return jsonify({'success': True, 'config': config})

            legacy_required = ['loopback_ip', 'cpe_cidr', 'cgnat_cidr', 'olt_cidr']
            if all(data.get(k) for k in legacy_required):
                identity = data.get('identity', 'RTR-CCR2216.FTTH-BNG')
                olt_port = data.get('olt_port', 'sfp28-3')
                olt_speed = str(data.get('olt_port_speed', 'auto')).strip() or 'auto'
                legacy_payload = {
                    'router_identity': identity,
                    'location': data.get('location', '0,0'),
                    'loopback_ip': data.get('loopback_ip'),
                    'cpe_network': data.get('cpe_cidr'),
                    'cgnat_private': data.get('cgnat_cidr'),
                    'cgnat_public': data.get('cgnat_public', '132.147.184.91/32'),
                    'unauth_network': data.get('unauth_cidr', data.get('cpe_cidr')),
                    'olt_network': data.get('olt_cidr'),
                    'routeros_version': data.get('target_version', '7.19.4'),
                    'olt_name': data.get('olt_name', 'OLT-GW'),
                    'olt_ports': [{
                        'port': olt_port,
                        'group': '1',
                        'speed': olt_speed,
                        'comment': f"OLT-speed:{olt_speed}",
                    }],
                    'uplinks': data.get('uplinks', []),
                }
                config = render_ftth_config(legacy_payload)
                if "add name=cpe_pool" not in config:
                    config = config.replace("add name=cpe ranges=", "add name=cpe_pool ranges=")
                if "FTTH-CPE-NAT" not in config:
                    config = config + "\n# FTTH-CPE-NAT\n"
                return jsonify({'success': True, 'config': config, 'device': 'CCR2216'})

            return jsonify({
                'success': False,
                'error': 'FTTH generator now requires full FTTH fields (CGNAT Public, UNAUTH, OLT name, location). Use the FTTH BNG tab and /api/generate-ftth-bng.'
            }), 400
        except Exception as exc:
            print(f"[FTTH BNG] Error generating ftth bng: {exc}")
            return jsonify({'success': False, 'error': str(exc)}), 500

    @bp.route('/api/preview-ftth-bng', methods=['POST', 'OPTIONS'])
    def preview_ftth_bng():
        """Return parsed FTTH CIDR details for previewing in the UI."""
        try:
            if request.method == 'OPTIONS':
                return jsonify({'success': True}), 200
            data = request.get_json(force=True)
            loopback_ip = data.get('loopback_ip')
            cpe_cidr = data.get('cpe_cidr')
            cgnat_cidr = data.get('cgnat_cidr')
            olt_cidr = data.get('olt_cidr')

            if not (loopback_ip and cpe_cidr and cgnat_cidr and olt_cidr):
                return jsonify({'success': False, 'error': 'Missing one of required CIDR params (loopback_ip, cpe_cidr, cgnat_cidr, olt_cidr)'}), 400

            try:
                olt_info = cidr_details_gen(olt_cidr)
                cpe_info = cidr_details_gen(cpe_cidr)
                cgnat_info = cidr_details_gen(cgnat_cidr)
            except Exception as exc:
                return jsonify({'success': False, 'error': f'Invalid CIDR provided: {exc}'}), 400

            preview = {
                'loopback': loopback_ip,
                'olt': olt_info,
                'cpe': cpe_info,
                'cgnat': cgnat_info,
                'suggested_nat_comment': 'FTTH-CPE-NAT',
                'note': 'Preview only - use Generate to produce full configuration'
            }
            return jsonify({'success': True, 'preview': preview})
        except Exception as exc:
            print(f"[FTTH BNG] Preview error: {exc}")
            return jsonify({'success': False, 'error': str(exc)}), 500

    @bp.route('/api/generate-ftth-bng', methods=['POST'])
    def generate_ftth_bng():
        """Generate complete FTTH BNG configuration from the strict template."""
        try:
            data = request.get_json() or {}
            print(f"[FTTH BNG] Received configuration request: {data.get('deployment_type', 'unknown')}")
            config = render_ftth_config(data)
            print(f"[FTTH BNG] Generated configuration: {len(config)} characters")
            return jsonify({
                'success': True,
                'config': config,
            })
        except Exception as exc:
            error_details = traceback.format_exc()
            print(f"[ERROR] FTTH BNG generation failed: {exc}")
            print(error_details)
            return jsonify({
                'success': False,
                'error': str(exc),
                'details': error_details
            }), 500

    return bp
