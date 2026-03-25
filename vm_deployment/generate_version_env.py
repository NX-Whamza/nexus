#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path


ROOT_DIR = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT_DIR / "vm_deployment" / "assets" / "app-version.json"
DEFAULT_CONFIG = {
    "product": "NEXUS",
    "version_base": "2.6",
    "build_offset": 0,
    "release_date": datetime.now().strftime("%b %Y"),
}


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return dict(DEFAULT_CONFIG)
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return dict(DEFAULT_CONFIG)
    config = dict(DEFAULT_CONFIG)
    if isinstance(data, dict):
        config.update(data)
    return config


def _git_output(*args: str) -> str:
    completed = subprocess.run(
        ["git", *args],
        cwd=ROOT_DIR,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _git_commit_count() -> int:
    return int(_git_output("rev-list", "--count", "HEAD"))


def _git_sha() -> str:
    return _git_output("rev-parse", "--short", "HEAD")


def _shell_quote(value: str) -> str:
    return "'" + value.replace("'", "'\"'\"'") + "'"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate NEXUS app version env file")
    parser.add_argument(
        "--output",
        default=str(ROOT_DIR / ".version.env"),
        help="Path to the env file to write",
    )
    args = parser.parse_args()

    config = _load_config()
    version_base = str(config.get("version_base", DEFAULT_CONFIG["version_base"])).strip().lstrip("v")
    build_offset = int(config.get("build_offset", 0) or 0)
    commit_count = _git_commit_count()
    patch = max(commit_count - build_offset, 0)
    version = f"v{version_base}.{patch}"
    release_date = str(config.get("release_date") or datetime.now().strftime("%b %Y")).strip()
    git_sha = _git_sha()
    product = str(config.get("product", DEFAULT_CONFIG["product"])).strip() or "NEXUS"

    env_lines = [
        f"NEXUS_APP_PRODUCT={_shell_quote(product)}",
        f"NEXUS_APP_VERSION={_shell_quote(version)}",
        f"NEXUS_APP_VERSION_BASE={_shell_quote(version_base)}",
        f"NEXUS_APP_BUILD_NUMBER={patch}",
        f"NEXUS_APP_RELEASE_DATE={_shell_quote(release_date)}",
        f"NEXUS_APP_GIT_SHA={_shell_quote(git_sha)}",
    ]

    output_path = Path(args.output)
    output_path.write_text("\n".join(env_lines) + "\n", encoding="utf-8")
    print(f"{version} ({git_sha}) -> {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
