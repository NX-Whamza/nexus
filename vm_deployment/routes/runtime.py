import os

from flask import Blueprint, jsonify


def create_runtime_blueprint() -> Blueprint:
    bp = Blueprint("runtime_routes", __name__)

    @bp.route('/api/app-config', methods=['GET'])
    def app_config():
        """Lightweight runtime configuration consumed by the frontend."""
        bng_peers = {
            'NE': os.getenv('BNG_PEER_NE', '10.254.247.3'),
            'IL': os.getenv('BNG_PEER_IL', '10.247.72.34'),
            'IA': os.getenv('BNG_PEER_IA', '10.254.247.3'),
            'KS': os.getenv('BNG_PEER_KS', '10.249.0.200'),
            'IN': os.getenv('BNG_PEER_IN', '10.254.247.3'),
        }
        default_bng_peer = os.getenv('BNG_PEER_DEFAULT', '10.254.247.3')
        return jsonify({'bng_peers': bng_peers, 'default_bng_peer': default_bng_peer})

    return bp

