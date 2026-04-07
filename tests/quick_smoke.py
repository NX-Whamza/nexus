#!/usr/bin/env python3
"""Quick smoke test against running VM at localhost:8000."""
import json
import urllib.request

BASE = "http://localhost:8000"

def post_json(path, data):
    body = json.dumps(data).encode()
    req = urllib.request.Request(f"{BASE}{path}", data=body, headers={"Content-Type": "application/json"}, method="POST")
    try:
        resp = urllib.request.urlopen(req)
        return resp.status, resp.read().decode()[:500]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:500]

def get(path):
    try:
        resp = urllib.request.urlopen(f"{BASE}{path}")
        return resp.status, resp.read().decode()[:200]
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()[:200]

results = []

# 1. HTML page
code, _ = get("/nexus.html")
results.append(("HTML Page", code, code == 200))

# 2. Health
code, body = get("/api/health")
results.append(("Health", code, code == 200))

# 3. Tower config
tower_data = {
    "site_name": "TEST",
    "tower_name": "TEST-TOWER",
    "loopback_subnet": "10.0.0.1/32",
    "cpe_subnet": "10.100.0.0/22",
    "unauth_subnet": "10.200.0.0/22",
    "cgn_priv": "100.64.0.0/22",
    "cgn_pub": "198.51.100.1/32",
    "router_type": "MT2004",
    "latitude": "32.7767",
    "longitude": "-96.7970",
    "state_code": "TX",
    "backhauls": [{"name": "BH-1", "subnet": "10.10.0.0/30", "port": "sfp-sfpplus4", "bandwidth": "auto", "master": True}],
    "switches": [{"name": "SWT-1", "port": "sfp-sfpplus1", "speed": "1G-baseT-full"}]
}
code, body = post_json("/api/mt/tower/config", tower_data)
results.append(("Tower Config", code, code == 200))

# 4. BNG2 config
bng2_data = {
    "site_name": "TEST-BNG",
    "tower_name": "TEST-BNG",
    "loopback_subnet": "10.0.0.2/32",
    "loop_ip": "10.0.0.2/32",
    "gateway": "10.10.1.0/30",
    "router_type": "MT2004",
    "state_code": "KS",
    "ospf_area": "248",
    "latitude": "32.7767",
    "longitude": "-96.7970",
    "bng_1_ip": "10.2.0.107",
    "bng_2_ip": "10.2.0.108",
    "vlan_1000_cisco": "1000",
    "vlan_2000_cisco": "2000",
    "vlan_3000_cisco": "3000",
    "vlan_4000_cisco": "4000",
    "mpls_mtu": "1570",
    "vpls_l2_mtu": "1588",
    "switch_ip": "10.10.2.1/30",
    "backhauls": [{"name": "BH-1", "subnet": "10.10.1.0/30", "port": "sfp-sfpplus4", "bandwidth": "auto", "master": True}]
}
code, body = post_json("/api/mt/bng2/config", bng2_data)
results.append(("BNG2 Config", code, code == 200))

# 5. Compliance
code, body = get("/api/ido/compliance")
results.append(("Compliance", code, code == 200))

# Report
print("\n=== SMOKE TEST RESULTS ===")
all_pass = True
for name, code, ok in results:
    status = "PASS" if ok else "FAIL"
    if not ok:
        all_pass = False
    print(f"  [{status}] {name}: HTTP {code}")

# Show error bodies for failures
for name, code, ok in results:
    if not ok:
        # Re-run to get body
        pass

print(f"\n{'ALL TESTS PASSED' if all_pass else 'SOME TESTS FAILED'}")

# Print tower and bng2 error details
print("\n--- Tower response ---")
tc, tbody = post_json("/api/mt/tower/config", tower_data)
print(f"HTTP {tc}: {tbody}")

print("\n--- BNG2 response ---")
bc, bbody = post_json("/api/mt/bng2/config", bng2_data)
print(f"HTTP {bc}: {bbody}")
