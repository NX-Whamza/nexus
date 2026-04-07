#!/usr/bin/env python3
"""
NEXUS - Setup Checker
Validates that everything is configured correctly before running.

This script is intended to run cleanly on Windows terminals that may not be UTF-8.
"""

from __future__ import annotations

import os
import sys
import importlib.util
from pathlib import Path


def safe_print(text: str) -> None:
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("utf-8", "backslashreplace").decode("utf-8"))


def has_module(module_name: str) -> bool:
    return importlib.util.find_spec(module_name) is not None


def check_python_version() -> bool:
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 8):
        safe_print(f"[ERROR] Python 3.8+ required (you have {version.major}.{version.minor}.{version.micro})")
        return False
    safe_print(f"[OK] Python {version.major}.{version.minor}.{version.micro} - OK")
    if (version.major, version.minor) != (3, 11):
        safe_print("[WARN] Python 3.11 is the validated runtime used by Dockerfile; other versions may work but are not the primary target")
    return True


def check_pip_packages() -> bool:
    required = ["flask", "flask_cors", "fastapi", "uvicorn", "requests"]
    optional = ["jwt"]
    ai_provider = os.getenv("AI_PROVIDER", "openai").strip().lower()
    if ai_provider == "openai":
        required.append("openai")
    else:
        optional.append("openai")

    missing: list[str] = []
    for package in required:
        try:
            if not has_module(package):
                raise ImportError(package)
            safe_print(f"[OK] {package} - installed")
        except ImportError:
            safe_print(f"[ERROR] {package} - NOT installed")
            missing.append(package)

    for package in optional:
        try:
            if not has_module(package):
                raise ImportError(package)
            safe_print(f"[OK] {package} - installed (optional)")
        except ImportError:
            safe_print(f"[WARN] {package} - NOT installed (optional)")

    if missing:
        safe_print(f"\n[ERROR] Missing packages: {', '.join(missing)}")
        safe_print("Run: pip install -r requirements.txt")
        return False
    return True


def check_openai_key() -> bool:
    ai_provider = os.getenv("AI_PROVIDER", "openai").strip().lower()
    if ai_provider != "openai":
        safe_print(f"[OK] AI_PROVIDER={ai_provider} (OpenAI key not required)")
        return True

    api_key = os.getenv("OPENAI_API_KEY", "")
    if api_key:
        safe_print("[OK] OPENAI_API_KEY environment variable set")
        safe_print(f"     Key preview: {api_key[:12]}...{api_key[-4:]}")
        return True

    env_file = Path(".env")
    if env_file.exists():
        try:
            content = env_file.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            content = ""
        if "OPENAI_API_KEY" in content:
            safe_print("[OK] OPENAI_API_KEY found in .env file")
            return True

    safe_print("[ERROR] OPENAI_API_KEY not configured")
    safe_print("Fix:")
    safe_print("  - set OPENAI_API_KEY=your-key-here")
    safe_print("  - or create .env with OPENAI_API_KEY=your-key-here")
    return False


def check_files() -> bool:
    files = [
        Path("api_server.py"),  # root shim for local dev
        Path("requirements.txt"),
        Path("vm_deployment") / "api_server.py",
        Path("vm_deployment") / "nexus.html",
        Path("vm_deployment") / "login.html",
        Path("vm_deployment") / "change-password.html",
    ]

    ok = True
    for path in files:
        if path.exists():
            safe_print(f"[OK] {path.as_posix()} - exists")
        else:
            safe_print(f"[ERROR] {path.as_posix()} - NOT FOUND")
            ok = False
    return ok


def check_backend_source() -> bool:
    target = Path("vm_deployment") / "api_server.py"
    try:
        content = target.read_text(encoding="utf-8", errors="ignore")
    except Exception as e:
        safe_print(f"[ERROR] Unable to read {target.as_posix()}: {e}")
        return False

    if "from flask" not in content.lower() and "flask" not in content.lower():
        safe_print("[ERROR] Backend source does not appear to import Flask")
        return False
    if "/api/health" not in content:
        safe_print("[ERROR] Backend source does not appear to define /api/health")
        return False

    safe_print("[OK] Backend source looks valid")
    return True


def check_dev_test_tools() -> bool:
    if has_module("pytest"):
        safe_print("[OK] pytest - installed")
    else:
        safe_print("[WARN] pytest - NOT installed (recommended for backend validation)")
    return True


def main() -> int:
    safe_print("=" * 60)
    safe_print("NEXUS - Setup Checker")
    safe_print("=" * 60)

    checks = [
        ("Python Version", check_python_version),
        ("Required Packages", check_pip_packages),
        ("OpenAI Key (if needed)", check_openai_key),
        ("Required Files", check_files),
        ("Backend Source Sanity", check_backend_source),
        ("Dev Test Tools", check_dev_test_tools),
    ]

    results: list[bool] = []
    for name, fn in checks:
        safe_print(f"\n[CHECK] {name}")
        safe_print("-" * 60)
        results.append(fn())

    passed = sum(1 for r in results if r)
    total = len(results)

    safe_print("\n" + "=" * 60)
    safe_print("SUMMARY")
    safe_print("=" * 60)

    if passed == total:
        safe_print(f"[OK] All checks passed ({passed}/{total})")
        safe_print("Next:")
        safe_print("  1) python -m uvicorn --app-dir vm_deployment fastapi_server:app --host 0.0.0.0 --port 5000")
        safe_print("  2) python -m http.server 8000 --directory vm_deployment")
        safe_print("  3) Open: http://localhost:8000/nexus.html")
        return 0

    safe_print(f"[ERROR] {total - passed} checks failed ({passed}/{total} passed)")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

