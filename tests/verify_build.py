#!/usr/bin/env python3
"""
Verify that api_server.py will be included in the PyInstaller build
"""
import sys
from pathlib import Path

print("=" * 70)
print("Verifying Build Configuration")
print("=" * 70)
print()

# Check if api_server.py exists (root shim + vm_deployment source)
api_server_path = Path('api_server.py')
if api_server_path.exists():
    print(f"[OK] api_server.py found: {api_server_path.absolute()}")
    print(f"  Size: {api_server_path.stat().st_size:,} bytes")
else:
    print(f"[ERROR] api_server.py NOT FOUND!")
    print(f"  Current directory: {Path.cwd()}")
    sys.exit(1)

launcher_path = Path('vm_deployment') / 'launcher.py'
if launcher_path.exists():
    print(f"[OK] vm_deployment/launcher.py found: {launcher_path.absolute()}")

    # Check if launcher imports api_server
    launcher_content = launcher_path.read_text(encoding='utf-8')
    if 'import api_server' in launcher_content:
        print(f"[OK] launcher contains 'import api_server'")
    else:
        print(f"[ERROR] launcher does NOT import api_server!")
        sys.exit(1)
else:
    print(f"[ERROR] vm_deployment/launcher.py NOT FOUND!")
    sys.exit(1)

# Check spec file
spec_path = Path('NEXUS.spec')
if spec_path.exists():
    print(f"[OK] NEXUS.spec found")
    spec_content = spec_path.read_text(encoding='utf-8')
    if "'api_server'" in spec_content or '"api_server"' in spec_content:
        print(f"[OK] spec file mentions api_server")
    else:
        print(f"[WARN] spec file does not explicitly mention api_server")
else:
    print(f"[WARN] NEXUS.spec not found")

print()
print("=" * 70)
print("Build Verification Complete")
print("=" * 70)
print()
print("If all checks passed, PyInstaller should include api_server.py")
print("If issues persist, the module may need to be explicitly added")
