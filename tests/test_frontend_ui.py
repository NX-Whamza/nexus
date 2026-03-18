#!/usr/bin/env python3
"""Simple tests to verify presence of FTTH modal UI in the built frontend file."""

from __future__ import annotations

import os
import sys
from pathlib import Path

repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root))

UI_FILE = repo_root / 'vm_deployment' / 'NOC-configMaker.html'


def test_ftth_modal_exists():
    content = UI_FILE.read_text(encoding='utf-8')
    assert 'FTTH BNG CONFIG' in content, 'Missing menu label "FTTH BNG CONFIG" in Mikrotik dropdown in NOC-configMaker.html'
    assert 'data-tab="ftth-home"' in content, 'Missing FTTH HOME navigation entry in NOC-configMaker.html'
    assert 'id="ftth-home-pane"' in content, 'Missing FTTH HOME content pane id="ftth-home-pane" in NOC-configMaker.html'
    assert 'id="ftth-pane"' in content, 'Missing ftth content pane id="ftth-pane" in NOC-configMaker.html'
    assert 'id="ftthPreviewBtn"' in content, 'Missing Preview button id="ftthPreviewBtn" in NOC-configMaker.html'
    assert ('generateFtthBng' in content) or ('ftthGenerate' in content), 'Missing generator hook: generateFtthBng() or element id="ftthGenerate"'
    assert 'id="ftth_instate_btn"' in content, 'Missing FTTH sub-tab button id="ftth_instate_btn" in NOC-configMaker.html'
    assert 'id="ftth_outstate_btn"' in content, 'Missing FTTH sub-tab button id="ftth_outstate_btn" in NOC-configMaker.html'
    assert 'id="ftth-instate-section"' in content and 'id="ftth-outstate-section"' in content, 'Missing FTTH sub-tab sections in NOC-configMaker.html'
    assert 'id="ftth_add_olt_port_btn"' in content, 'Missing OLT add button id="ftth_add_olt_port_btn" in NOC-configMaker.html'
    assert 'id="ftth_add_backhaul_btn"' in content, 'Missing backhaul add button id="ftth_add_backhaul_btn" in NOC-configMaker.html'
    assert 'id="ftth_open_portconfigs_btn"' in content, 'Missing Open Port & Uplink button id="ftth_open_portconfigs_btn" in NOC-configMaker.html'
    assert 'id="ftth_olt_port_in"' in content, 'Missing OLT port select id="ftth_olt_port_in" in NOC-configMaker.html'
    assert 'id="ftth_olt_speed_in"' in content, 'Missing OLT port speed select id="ftth_olt_speed_in" in NOC-configMaker.html'
    assert 'id="ftth_olt_port_out"' in content, 'Missing OLT port select id="ftth_olt_port_out" in NOC-configMaker.html'
    assert 'id="ftth_olt_speed_out"' in content, 'Missing OLT port speed select id="ftth_olt_speed_out" in NOC-configMaker.html'
    assert 'id="ftth_preset_select"' in content, 'Missing preset select id="ftth_preset_select" in NOC-configMaker.html'
    assert 'id="ftth_preset_save"' in content, 'Missing preset save button id="ftth_preset_save" in NOC-configMaker.html'
    assert 'id="ftth_preset_delete"' in content, 'Missing preset delete button id="ftth_preset_delete" in NOC-configMaker.html'
    assert 'id="ftth_preset_name"' in content, 'Missing preset name input id="ftth_preset_name" in NOC-configMaker.html'


def test_ftth_speed_controls_and_backend_payload_hooks_exist():
    content = UI_FILE.read_text(encoding='utf-8')
    assert '25G-baseSR-LR' in content, 'Missing 25G-baseSR-LR FTTH speed option in NOC-configMaker.html'
    assert "auto_negotiation: row.querySelector('.ftth-uplink-autoneg')?.checked || false" in content, \
        'Missing FTTH uplink auto-negotiation payload mapping in NOC-configMaker.html'
    assert "speed: speedSelect.value" in content, 'Missing FTTH OLT speed payload mapping in NOC-configMaker.html'
    assert 'BGP Peer Configuration' in content, 'Missing FTTH BGP peer display section in NOC-configMaker.html'
    assert '10.2.0.107/32' in content, 'Missing FTTH CR7 peer display in NOC-configMaker.html'
    assert '10.2.0.108/32' in content, 'Missing FTTH CR8 peer display in NOC-configMaker.html'
    assert "const targetUrl = `${apiBase.replace(/\\/+$/, '')}/preview-ftth-bng`;" in content, \
        'Missing resolved API base wiring for FTTH preview in NOC-configMaker.html'
    assert "apiBase + '/save-completed-config'" in content, \
        'Missing completed-config endpoint wiring for bulk SSH save in NOC-configMaker.html'
    assert "apiBase + '/save-config'" not in content, \
        'Found stale /save-config endpoint reference in NOC-configMaker.html'



if __name__ == '__main__':
    try:
        test_ftth_modal_exists()
        test_ftth_speed_controls_and_backend_payload_hooks_exist()
        print('[OK] test_ftth_modal_exists')
        raise SystemExit(0)
    except AssertionError as e:
        print('[FAIL] test_ftth_modal_exists:', e)
        raise SystemExit(1)
