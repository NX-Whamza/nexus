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
    assert 'FTTH BNG CONFIG' in content, 'Missing menu label "FTTH BNG CONFIG" in FTTH HOME navigation in NOC-configMaker.html'
    assert 'data-tab="ftth-home"' in content, 'Missing data-tab="ftth-home" attribute for FTTH HOME navigation in NOC-configMaker.html'
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
    assert 'id="ftthValidateBtn"' in content, 'Missing Validate button id="ftthValidateBtn" in NOC-configMaker.html'
    assert 'id="ftthGenerate"' in content, 'Missing Generate button id="ftthGenerate" in NOC-configMaker.html'
    assert 'id="ftthReset"' in content, 'Missing Reset button id="ftthReset" in NOC-configMaker.html'
    assert 'id="ftthPreview"' in content, 'Missing FTTH preview container id="ftthPreview" in NOC-configMaker.html'
    assert '<option value="25G-baseSR-LR">25G-baseSR-LR</option>' in content, 'Missing 25G-baseSR-LR option for FTTH speed selectors in NOC-configMaker.html'



if __name__ == '__main__':
    try:
        test_ftth_modal_exists()
        print('[OK] test_ftth_modal_exists')
        raise SystemExit(0)
    except AssertionError as e:
        print('[FAIL] test_ftth_modal_exists:', e)
        raise SystemExit(1)
