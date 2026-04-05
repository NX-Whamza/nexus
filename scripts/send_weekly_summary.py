#!/usr/bin/env python3
"""Build and send a NEXUS weekly summary to a Teams webhook.

Data sources (pick one):
  --server-url https://nexus.yourserver.com   pulls live data from production NEXUS API
  --db-path /path/to/activity_log.db          reads the SQLite DB directly (local/dev)
  git log                                     work done this week (features, fixes, improvements)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib import error, request
from zoneinfo import ZoneInfo


DEFAULT_DB_PATH = Path("secure_data") / "activity_log.db"
DEFAULT_TIMEZONE = "America/Chicago"
DEFAULT_DAYS = 7
DEFAULT_TITLE = "NEXUS Weekly Summary"
DEFAULT_THEME_COLOR = "0078D7"
DEFAULT_TOP_N = 5
DEFAULT_FOOTER = (
    "If there are any issues, feedback, or tabs you want included in the "
    "NEXUS weekly update, please let me know so we can keep improving it."
)

# Human-friendly names for activity types — keyed to the actual tab name in NEXUS
ACTIVITY_LABELS: dict[str, str] = {
    # MikroTik Config Generator tab (two modes)
    "tower":                    "MikroTik Config Generator — Tower",
    "tower-config":             "MikroTik Config Generator — Tower",
    "bng2":                     "MikroTik Config Generator — BNG2",
    # Tarana Sectors tab
    "tarana-config":            "Tarana Sectors",
    "tarana":                   "Tarana Sectors",
    # Nokia Configurator / Migration tabs
    "nokia-7250-config":        "Nokia Configurator",
    "nokia":                    "Nokia Configurator",
    "migration":                "Nokia Migration",
    # FTTH tabs
    "ftth-bng":                 "FTTH BNG Config",
    "ftth-fiber-customer":      "FTTH Fiber Customer",
    "ftth-fiber-site":          "FTTH 1072/1036 Fiber Site",
    "ftth-isd-fiber":           "FTTH ISD Fiber",
    # Switch / enterprise tabs
    "switch-config":            "Switch Maker",
    "6ghz-switch-config":       "6GHz Switch Port",
    "enterprise-non-mpls":      "Non-MPLS Enterprise Config",
    "enterprise-feeding-config":        "Enterprise Feeding Config",
    "enterprise-feeding-outstate-config": "Enterprise Feeding Config (Outstate)",
    # Other
    "cisco-config":             "Cisco Port Setup",
    "field-config-studio":      "Field Config Studio",
    "compliance":               "Compliance Scanner",
    "aviat":                    "Aviat Backhaul",
    "new-config":               "MikroTik Config Generator",
}

# What each tab actually does — shown in the "Configs Generated" section
ACTIVITY_DESCRIPTIONS: dict[str, str] = {
    "tower": (
        "MikroTik Config Generator (Tower mode) — builds a full tower router config "
        "including IP addressing, OSPF/BGP routing, backhaul interfaces, "
        "firewall rules, and compliance settings."
    ),
    "tower-config": (
        "MikroTik Config Generator (Tower mode) — builds a full tower router config "
        "including IP addressing, OSPF/BGP routing, backhaul interfaces, "
        "firewall rules, and compliance settings."
    ),
    "bng2": (
        "MikroTik Config Generator (BNG2 mode) — generates a BNG2 router config "
        "for broadband subscriber management on a MikroTik platform."
    ),
    "tarana-config": (
        "Tarana Sectors tab — configures VLAN assignments and port mappings "
        "for Tarana wireless sector ports on a MikroTik router."
    ),
    "tarana": (
        "Tarana Sectors tab — configures VLAN assignments and port mappings "
        "for Tarana wireless sector ports on a MikroTik router."
    ),
    "migration": (
        "Nokia Migration tab — generates a cutover script to migrate "
        "an existing Nokia router to a MikroTik device."
    ),
    "nokia-7250-config": (
        "Nokia Configurator tab — generates Nokia 7250 IXR router configurations."
    ),
    "ftth-bng": (
        "FTTH BNG Config tab — generates BNG configuration for managing "
        "fiber subscriber authentication and sessions."
    ),
    "ftth-fiber-customer": (
        "FTTH Fiber Customer tab — provisions a fiber internet customer "
        "with service port, VLAN, and subscriber profile."
    ),
    "switch-config":        "Switch Maker tab — generates MikroTik switch configurations.",
    "6ghz-switch-config":   "6GHz Switch Port tab — configures switch ports for 6GHz radio backhaul.",
    "cisco-config":         "Cisco Port Setup tab — generates Cisco interface port configurations.",
    "field-config-studio":  "Field Config Studio — generates configs for field devices using live site data.",
    "compliance":           "Compliance Scanner — scans router configs against Nextlink policy rules.",
    "aviat":                "Aviat Backhaul tab — manages firmware and maintenance for Aviat microwave units.",
}

# Commit scope/keyword → area label used in the Work Done section
AREA_MAP: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"ftth|fiber|bng", re.I),             "FTTH & Fiber"),
    (re.compile(r"mikrotik|routerboard|switch", re.I), "MikroTik & Switching"),
    (re.compile(r"nokia|migration|enterprise", re.I),  "Nokia Migrations"),
    (re.compile(r"device.config.studio|field.config|smartsys|sc501", re.I), "Field Config Studio"),
    (re.compile(r"cisco", re.I),                       "Cisco Configs"),
    (re.compile(r"ui|frontend|theme|login|sidebar|routing|nexus", re.I), "UI & Navigation"),
    (re.compile(r"startup|health|production|docker|deploy", re.I), "Infrastructure"),
    (re.compile(r"compliance|gitlab", re.I),           "Compliance"),
    (re.compile(r"test|spec|coverage", re.I),          "Tests & Coverage"),
]

# Plain-English translations for known commit subjects
COMMIT_TRANSLATIONS: dict[str, str] = {
    "fix(routerboard): normalize mt identity prefixes":
        "Fixed how router identity names are standardized when generating configs",
    "fix(device-config-studio): support live smartsys sc501 flow":
        "Added live support for the Smartsys SC501 device in Field Config Studio",
    "feat(device-config-studio): restore local field config runtime":
        "Restored Field Config Studio to work locally without needing server connectivity",
    "fix(ftth): enforce gitlab compliance and port dropdowns":
        "Fixed compliance rule enforcement and port selection dropdowns on the FTTH tab",
    "fix(ui): remove rollout banners and harden ftth fallback":
        "Removed outdated rollout banners and fixed the FTTH tab fallback behavior",
    "feat: rebuild mikrotik switch configurator":
        "Rebuilt the MikroTik switch configurator from scratch with improved logic",
    "feat(ftth): add full fiber workspace":
        "Added a complete workspace for setting up and managing fiber internet customers",
    "fix(ui): rename cisco port setup":
        "Renamed the Cisco port setup section for better clarity",
    "feat(ftth): backendize fiber customer generation":
        "Moved fiber customer config generation to the server for better validation and reliability",
    "fix(ui): tighten cisco config output":
        "Cleaned up and standardized the Cisco config output format",
    "fix(ui): restore ftth fiber port helper wiring":
        "Restored the fiber port helper tool that had stopped working",
    "fix(ui): expand cisco and fiber customer generators":
        "Expanded the Cisco and fiber config tools with more options and device support",
    "feat: unify nokia configurator and tighten enterprise generation":
        "Unified the Nokia migration configurator into one streamlined tool",
    "fix: accept shorthand migration target models":
        "Fixed migrations that use shorthand device model names (e.g. 'CCR2004' vs full name)",
    "fix: enforce nextlink migration port policy":
        "Enforced Nextlink's port assignment policy rules during Nokia-to-MikroTik migrations",
    "prevent theme flash on refresh":
        "Fixed a visual flicker that appeared briefly when refreshing the app",
    "polish home and login ui layout":
        "Cleaned up and improved the layout of the home page and login screen",
    "fix sidebar refresh state restoration":
        "Fixed the sidebar losing its navigation state when the page reloads",
    "unify nexus routing and automated version metadata":
        "Unified how NEXUS handles internal navigation and automated version tracking",
    "harden production startup and health checks":
        "Strengthened how NEXUS starts up and monitors its own health in production",
}


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class WeeklySummary:
    total: int
    success: int
    failed: int
    top_activity_types: list[tuple[str, int]]
    top_users: list[tuple[str, int]]
    top_sites: list[tuple[str, int]]
    devices_used: list[tuple[str, int]]
    routeros_versions: list[tuple[str, int]]
    # maps username → their raw activity rows (for per-user narrative)
    user_details: dict[str, list[dict[str, Any]]] = field(default_factory=dict)


@dataclass
class GitChanges:
    by_area: dict[str, list[str]] = field(default_factory=dict)
    total_commits: int = 0


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def friendly_label(value: str) -> str:
    raw = str(value or "").strip()
    if not raw:
        return "Unknown"
    if raw in ACTIVITY_LABELS:
        return ACTIVITY_LABELS[raw]
    normalized = raw.replace("_", " ").replace("-", " ")
    return " ".join(part.capitalize() for part in normalized.split())


def short_label(value: str, fallback: str) -> str:
    raw = str(value or "").strip()
    return raw if raw else fallback


def _translate_commit(subject: str) -> str:
    """Return a plain-English description for a commit subject."""
    key = subject.strip().lower()
    if key in COMMIT_TRANSLATIONS:
        return COMMIT_TRANSLATIONS[key]
    # Strip conventional prefix and capitalize
    m = re.match(r"^(?:feat|fix|refactor|chore|test|docs|perf|style)\(([^)]+)\):\s*(.+)$", subject, re.I)
    if m:
        scope, msg = m.group(1).strip(), m.group(2).strip()
        return f"{msg.capitalize()} ({scope})"
    m2 = re.match(r"^(?:feat|fix|refactor|chore|test|docs|perf|style):\s*(.+)$", subject, re.I)
    if m2:
        return m2.group(1).strip().capitalize()
    return subject.strip().capitalize()


def _classify_commit(subject: str) -> str:
    """Return which area a commit belongs to."""
    for pattern, label in AREA_MAP:
        if pattern.search(subject):
            return label
    return "General"


# ---------------------------------------------------------------------------
# Git changes loader
# ---------------------------------------------------------------------------


def load_git_changes(repo_root: Path, since_dt: datetime) -> GitChanges:
    since_iso = since_dt.strftime("%Y-%m-%dT%H:%M:%S")
    try:
        result = subprocess.run(
            ["git", "log", f"--since={since_iso}", "--pretty=format:%s", "--no-merges"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return GitChanges()

    if result.returncode != 0:
        return GitChanges()

    lines = [ln.strip() for ln in result.stdout.splitlines() if ln.strip()]
    gc = GitChanges(total_commits=len(lines))

    area_map: dict[str, list[str]] = defaultdict(list)
    for subject in lines:
        area = _classify_commit(subject)
        plain = _translate_commit(subject)
        area_map[area].append(plain)

    # Sort areas: biggest first, then alphabetical
    gc.by_area = dict(
        sorted(area_map.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    )
    return gc


# ---------------------------------------------------------------------------
# Activity loader
# ---------------------------------------------------------------------------


def load_rows_from_api(
    server_url: str,
    start_utc: datetime,
    end_utc: datetime,
) -> list[dict[str, Any]]:
    """Pull activity rows from a live NEXUS server via /api/get-activity."""
    url = server_url.rstrip("/") + "/api/get-activity?all=true&limit=10000"
    req = request.Request(url, headers={"Accept": "application/json"})
    try:
        with request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except error.HTTPError as exc:
        raise RuntimeError(f"NEXUS API returned HTTP {exc.code}: {exc.read().decode()}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Could not reach NEXUS server at {server_url}: {exc.reason}") from exc

    # The endpoint returns {"activities": [...]} or a bare list depending on the ?all flag
    rows: list[dict[str, Any]] = data if isinstance(data, list) else data.get("activities", [])

    start_ts = int(start_utc.timestamp())
    end_ts   = int(end_utc.timestamp())

    filtered: list[dict[str, Any]] = []
    for row in rows:
        ts = row.get("timestamp_unix") or row.get("timestampUnix")
        if ts is not None:
            if start_ts <= int(ts) < end_ts:
                filtered.append(row)
        else:
            # Fall back to ISO timestamp string
            raw = str(row.get("timestamp", "") or row.get("created_at", ""))
            if raw:
                try:
                    dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
                    if start_utc <= dt < end_utc:
                        filtered.append(row)
                except ValueError:
                    pass

    # Normalize field names from the API response to match the DB column names
    normalized: list[dict[str, Any]] = []
    for row in filtered:
        normalized.append({
            "username":         row.get("username") or row.get("user", ""),
            "activity_type":    row.get("activity_type") or row.get("activityType") or row.get("type", ""),
            "device":           row.get("device", ""),
            "site_name":        row.get("site_name") or row.get("siteName", ""),
            "routeros_version": row.get("routeros_version") or row.get("routeros") or row.get("routerosVersion", ""),
            "success":          row.get("success", 1),
            "timestamp":        row.get("timestamp", ""),
            "timestamp_unix":   row.get("timestamp_unix") or row.get("timestampUnix", 0),
        })
    return normalized


def load_rows(
    db_path: Path,
    start_utc: datetime,
    end_utc: datetime,
    *,
    include_non_metric: bool = False,
) -> list[dict[str, Any]]:
    if not db_path.exists():
        raise FileNotFoundError(f"Activity database not found: {db_path}")

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        table_names = {
            row["name"]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        }
        if "activities" not in table_names:
            raise RuntimeError(f"Table 'activities' not found in {db_path}")

        columns = {row["name"] for row in conn.execute("PRAGMA table_info(activities)")}

        where_clauses: list[str] = []
        params: list[Any] = []

        if "timestamp_unix" in columns:
            where_clauses.append("timestamp_unix >= ? AND timestamp_unix < ?")
            params.extend([int(start_utc.timestamp()), int(end_utc.timestamp())])
        elif "timestamp" in columns:
            where_clauses.append("timestamp >= ? AND timestamp < ?")
            params.extend([start_utc.isoformat(), end_utc.isoformat()])

        if not include_non_metric and "counts_toward_metrics" in columns:
            where_clauses.append("(counts_toward_metrics IS NULL OR counts_toward_metrics != 0)")

        where_sql = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        query = (
            "SELECT username, activity_type, device, site_name, routeros_version, "
            "success, timestamp, timestamp_unix "
            f"FROM activities {where_sql} ORDER BY COALESCE(timestamp_unix, 0) DESC, timestamp DESC"
        )
        return [dict(row) for row in conn.execute(query, params)]
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Summary builder
# ---------------------------------------------------------------------------


def build_summary(rows: list[dict[str, Any]], *, top_n: int) -> WeeklySummary:
    success_count = 0
    failed_count = 0
    type_counts: Counter[str] = Counter()
    user_counts: Counter[str] = Counter()
    site_counts: Counter[str] = Counter()
    device_counts: Counter[str] = Counter()
    ros_counts: Counter[str] = Counter()
    user_details: dict[str, list[dict[str, Any]]] = defaultdict(list)

    for row in rows:
        if bool(row.get("success", 1)):
            success_count += 1
        else:
            failed_count += 1

        type_counts[friendly_label(str(row.get("activity_type", "")))] += 1

        user = short_label(str(row.get("username", "")), "Unknown")
        user_counts[user] += 1
        user_details[user].append(row)

        site = short_label(str(row.get("site_name", "")), "")
        device = short_label(str(row.get("device", "")), "")
        site_key = site or device or "General"
        site_counts[site_key] += 1

        if device:
            device_counts[device.upper()] += 1
        ros = short_label(str(row.get("routeros_version", "")), "")
        if ros:
            ros_counts[ros] += 1

    return WeeklySummary(
        total=len(rows),
        success=success_count,
        failed=failed_count,
        top_activity_types=type_counts.most_common(top_n),
        top_users=user_counts.most_common(top_n),
        top_sites=site_counts.most_common(top_n),
        devices_used=device_counts.most_common(top_n),
        routeros_versions=ros_counts.most_common(top_n),
        user_details=dict(user_details),
    )


def build_period_strings(now_local: datetime, days: int) -> tuple[datetime, datetime, str]:
    if days <= 0:
        raise ValueError("--days must be greater than 0")
    start_local = now_local - timedelta(days=days)
    period_label = f"{start_local.strftime('%b %d, %Y')} to {now_local.strftime('%b %d, %Y')}"
    return start_local, now_local, period_label


# ---------------------------------------------------------------------------
# Card builder helpers
# ---------------------------------------------------------------------------


def _shorten_site(site: str) -> str:
    """Make long site strings concise for the card."""
    raw = site.strip()
    if not raw:
        return ""
    # Old format: "Tarana Sectors: ALPHA, BETA, GAMMA" — sector letters are port
    # descriptions, not a real site name. Show sector count instead.
    m = re.match(r"Tarana Sectors?:\s*(.+)", raw, re.I)
    if m:
        count = len([s for s in m.group(1).split(",") if s.strip()])
        return f"Tarana {count}-sector config"
    # New format from fixed app: "Tarana N-sector config" — already clean
    if re.match(r"Tarana \d+-sector config", raw, re.I):
        return raw
    return raw


# Shorter display names for use inside the team activity line
_TEAM_SHORT: dict[str, str] = {
    "MikroTik Config Generator — Tower": "Tower Config",
    "MikroTik Config Generator — BNG2":  "BNG2 Config",
    "Tarana Sectors":                    "Tarana Sectors",
    "Nokia Migration":                   "Nokia Migration",
    "Nokia Configurator":                "Nokia Config",
    "FTTH BNG Config":                   "FTTH BNG Config",
    "FTTH Fiber Customer":               "FTTH Fiber Customer",
    "Switch Maker":                      "Switch Config",
    "6GHz Switch Port":                  "6GHz Switch Config",
    "Cisco Port Setup":                  "Cisco Port Setup",
    "Field Config Studio":               "Field Config",
    "Aviat Backhaul":                    "Aviat Backhaul",
    "Compliance Scanner":                "Compliance Scan",
    "Non-MPLS Enterprise Config":        "Enterprise Config",
    "Enterprise Feeding Config":         "Enterprise Feeding",
}


def _team_label(full_label: str) -> str:
    return _TEAM_SHORT.get(full_label, full_label)


def _is_descriptor_site(site: str) -> bool:
    """Return True when the site string is a config description, not a real location."""
    return bool(re.match(r"Tarana \d+-sector config", site, re.I))


def _user_activity_line(user_rows: list[dict[str, Any]]) -> str:
    """Build a concise, readable line for what a user did this week."""
    by_type: dict[str, list[str]] = defaultdict(list)
    for row in user_rows:
        label = friendly_label(str(row.get("activity_type", "")))
        site  = _shorten_site(str(row.get("site_name") or row.get("device") or ""))
        by_type[label].append(site)

    parts: list[str] = []
    for label, sites in by_type.items():
        count  = len(sites)
        short  = _team_label(label)
        unique = list(dict.fromkeys(s for s in sites if s))

        # Tarana: sites are sector-count descriptors, not real locations.
        # Show a compact breakdown: "Tarana Sectors ×4 (3-sector ×3, 4-sector ×1)"
        if unique and all(_is_descriptor_site(s) for s in unique):
            sector_counts: Counter[str] = Counter(sites)
            breakdown = ", ".join(
                f"{s.split()[1]} ×{n}" for s, n in sector_counts.most_common()
            )
            parts.append(f"{short} ×{count} ({breakdown})")
            continue

        # Normal case: show "Short Name at Site1, Site2"
        if unique:
            site_str = ", ".join(unique[:2])
            if len(unique) > 2:
                site_str += f" +{len(unique) - 2} more"
            prefix = f"{short} ×{count}" if count > 1 else short
            parts.append(f"{prefix} at {site_str}")
        else:
            parts.append(f"{short} ×{count}" if count > 1 else short)

    return "  ·  ".join(parts)


# ---------------------------------------------------------------------------
# Card builder
# ---------------------------------------------------------------------------


def _success_rate(summary: WeeklySummary) -> str:
    if summary.total == 0:
        return "N/A"
    return f"{round(summary.success / summary.total * 100)}%"


def build_message_card(
    *,
    title: str,
    theme_color: str,
    timezone_name: str,
    period_label: str,
    summary: WeeklySummary,
    git_changes: GitChanges | None = None,
    footer: str,
) -> dict[str, Any]:

    rate = _success_rate(summary)
    sections: list[dict[str, Any]] = []

    # ------------------------------------------------------------------
    # Section 1 — Snapshot: one headline + 4 facts
    # ------------------------------------------------------------------
    if summary.total == 0:
        headline = "No configs generated this week."
    elif summary.total == 1:
        headline = "1 config generated — completed successfully."
    else:
        headline = (
            f"{summary.total} configs generated — "
            f"{summary.success} successful, {summary.failed} failed."
        )

    sections.append({
        "activityTitle": f"Week of {period_label}",
        "text": headline,
        "facts": [
            {"name": "Total",        "value": str(summary.total)},
            {"name": "Successful",   "value": str(summary.success)},
            {"name": "Failed",       "value": str(summary.failed)},
            {"name": "Success Rate", "value": rate},
        ],
    })

    # ------------------------------------------------------------------
    # Section 2 — Configs: type → count, one detail line
    # ------------------------------------------------------------------
    if summary.top_activity_types:
        config_facts = [
            {"name": label, "value": f"{count} config{'s' if count != 1 else ''}"}
            for label, count in summary.top_activity_types
        ]
        detail_parts: list[str] = []
        if summary.devices_used:
            detail_parts.append(
                "Devices: " + ", ".join(f"{d} ×{c}" for d, c in summary.devices_used)
            )
        if summary.routeros_versions:
            detail_parts.append(
                "RouterOS: " + ", ".join(v for v, _ in summary.routeros_versions)
            )
        section: dict[str, Any] = {"title": "Configs Generated", "facts": config_facts}
        if detail_parts:
            section["text"] = "  ·  ".join(detail_parts)
        sections.append(section)

    # ------------------------------------------------------------------
    # Section 3 — Work done: one summary line + area → count facts only
    # ------------------------------------------------------------------
    if git_changes is not None and git_changes.total_commits > 0:
        # Count new vs fix vs improvement across all translated commit messages
        all_items = [item for items in git_changes.by_area.values() for item in items]
        new_kw  = {"added", "add", "built", "rebuild", "restored", "restore",
                   "unified", "unif", "new", "introduce"}
        fix_kw  = {"fixed", "fix", "enforc", "tighten", "renamed", "removed",
                   "cleaned", "correct", "harden", "normaliz", "support"}
        feat_n  = sum(1 for i in all_items if any(k in i.lower() for k in new_kw))
        fix_n   = sum(1 for i in all_items if any(k in i.lower() for k in fix_kw))
        other_n = git_changes.total_commits - feat_n - fix_n

        parts = []
        if feat_n:   parts.append(f"{feat_n} new")
        if fix_n:    parts.append(f"{fix_n} fixes")
        if other_n > 0: parts.append(f"{other_n} improvements")

        summary_line = (
            f"{git_changes.total_commits} changes merged"
            + (f" — {', '.join(parts)}" if parts else "")
        )
        def _area_highlights(items: list[str]) -> str:
            """Return up to 2 highlights from the area's commit list, lowercased and trimmed."""
            picks = items[:2]
            # Lowercase first letter so it reads naturally after the count line
            cleaned = [p[0].lower() + p[1:] if p else p for p in picks]
            joined = "; ".join(cleaned)
            # Truncate gracefully if the combined string is too long
            if len(joined) > 120:
                joined = joined[:117].rsplit(" ", 1)[0] + "…"
            return joined

        area_facts = [
            {
                "name": area,
                "value": (
                    f"{len(items)} change{'s' if len(items) != 1 else ''} — "
                    + _area_highlights(items)
                ),
            }
            for area, items in git_changes.by_area.items()
        ]
        sections.append({
            "title": "Work Done This Week",
            "text":  summary_line,
            "facts": area_facts,
        })
    elif git_changes is not None:
        sections.append({
            "title": "Work Done This Week",
            "text":  "No code changes merged this week.",
        })

    # ------------------------------------------------------------------
    # Section 4 — Team: per-user narrative (what they did + where)
    # ------------------------------------------------------------------
    if summary.top_users:
        user_facts = [
            {
                "name": user,
                "value": _user_activity_line(summary.user_details.get(user, [])),
            }
            for user, _count in summary.top_users
        ]
        sections.append({"title": "Team Activity", "facts": user_facts})

    return {
        "@type":      "MessageCard",
        "@context":   "http://schema.org/extensions",
        "themeColor": theme_color,
        "summary":    title,
        "title":      title,
        "sections":   sections,
        "text":       footer,
    }


# ---------------------------------------------------------------------------
# Plain-text preview (dry-run)
# ---------------------------------------------------------------------------


def build_plaintext_preview(
    *,
    title: str,
    period_label: str,
    timezone_name: str,
    summary: WeeklySummary,
    git_changes: GitChanges | None = None,
    footer: str,
) -> str:
    rate = _success_rate(summary)
    lines = [
        title,
        f"Period : {period_label} ({timezone_name})",
        "",
        f"Configs generated : {summary.total}",
        f"Successful        : {summary.success}",
        f"Failed            : {summary.failed}",
        f"Success rate      : {rate}",
    ]

    if summary.top_activity_types:
        lines += ["", "What was generated:"]
        for label, count in summary.top_activity_types:
            noun = "config" if count == 1 else "configs"
            lines.append(f"  {label}: {count} {noun}")

    if summary.devices_used:
        lines += ["", "Device models:"]
        lines.extend([f"  {d}: {c}" for d, c in summary.devices_used])

    if git_changes is not None:
        lines += ["", f"Work done this week ({git_changes.total_commits} changes):"]
        for area, items in git_changes.by_area.items():
            lines.append(f"  {area} ({len(items)}):")
            for item in items:
                lines.append(f"    - {item}")

    if summary.top_users:
        lines += ["", "Who used NEXUS:"]
        lines.extend([f"  {user}: {count}" for user, count in summary.top_users])

    if summary.top_sites:
        lines += ["", "Sites:"]
        lines.extend([f"  {site}: {count}" for site, count in summary.top_sites])

    lines += ["", footer]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Webhook sender
# ---------------------------------------------------------------------------


def post_to_webhook(webhook_url: str, payload: dict[str, Any]) -> str:
    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with request.urlopen(req, timeout=20) as resp:
            body = resp.read().decode("utf-8", errors="replace").strip()
            return body or f"HTTP {resp.status}"
    except error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"Webhook returned HTTP {exc.code}: {body}") from exc
    except error.URLError as exc:
        raise RuntimeError(f"Failed to reach webhook: {exc.reason}") from exc


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Send a NEXUS weekly activity summary to a Teams webhook."
    )
    parser.add_argument("--server-url",
        default=os.getenv("NEXUS_SERVER_URL", ""),
        help="Base URL of the live NEXUS server (e.g. https://nexus.yourserver.com). "
             "When set, activity is fetched from the API instead of a local DB file.")
    parser.add_argument("--db-path",
        default=os.getenv("WEEKLY_SUMMARY_DB_PATH", str(DEFAULT_DB_PATH)))
    parser.add_argument("--webhook-url",
        default=os.getenv("TEAMS_WEEKLY_SUMMARY_WEBHOOK_URL", ""))
    parser.add_argument("--timezone",
        default=os.getenv("WEEKLY_SUMMARY_TIMEZONE", DEFAULT_TIMEZONE))
    parser.add_argument("--days", type=int,
        default=int(os.getenv("WEEKLY_SUMMARY_DAYS", str(DEFAULT_DAYS))))
    parser.add_argument("--top", type=int,
        default=int(os.getenv("WEEKLY_SUMMARY_TOP_N", str(DEFAULT_TOP_N))))
    parser.add_argument("--title",
        default=os.getenv("WEEKLY_SUMMARY_TITLE", DEFAULT_TITLE))
    parser.add_argument("--theme-color",
        default=os.getenv("WEEKLY_SUMMARY_THEME_COLOR", DEFAULT_THEME_COLOR))
    parser.add_argument("--footer",
        default=os.getenv("WEEKLY_SUMMARY_FOOTER", DEFAULT_FOOTER))
    parser.add_argument("--include-non-metric", action="store_true")
    parser.add_argument("--no-git", action="store_true",
        help="Skip the git log section")
    parser.add_argument("--repo-root",
        default=os.getenv("WEEKLY_SUMMARY_REPO_ROOT",
                          str(Path(__file__).resolve().parents[1])))
    parser.add_argument("--dry-run", action="store_true",
        help="Print the payload instead of posting")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not args.webhook_url and not args.dry_run:
        print("Missing webhook URL. Set --webhook-url or TEAMS_WEEKLY_SUMMARY_WEBHOOK_URL.",
              file=sys.stderr)
        return 2

    tz = ZoneInfo(args.timezone)
    now_local = datetime.now(tz)
    start_local, end_local, period_label = build_period_strings(now_local, args.days)
    start_utc = start_local.astimezone(UTC)
    end_utc = end_local.astimezone(UTC)

    if args.server_url:
        print(f"Fetching activity from NEXUS server: {args.server_url}")
        rows = load_rows_from_api(args.server_url, start_utc, end_utc)
    else:
        rows = load_rows(Path(args.db_path), start_utc, end_utc,
                         include_non_metric=args.include_non_metric)
    summary = build_summary(rows, top_n=max(1, args.top))

    git_changes: GitChanges | None = None
    if not args.no_git:
        git_changes = load_git_changes(Path(args.repo_root), start_utc)

    payload = build_message_card(
        title=args.title,
        theme_color=args.theme_color,
        timezone_name=args.timezone,
        period_label=period_label,
        summary=summary,
        git_changes=git_changes,
        footer=args.footer,
    )

    if args.dry_run:
        print(build_plaintext_preview(
            title=args.title,
            period_label=period_label,
            timezone_name=args.timezone,
            summary=summary,
            git_changes=git_changes,
            footer=args.footer,
        ))
        print("\n--- JSON PAYLOAD ---\n")
        print(json.dumps(payload, indent=2))
        return 0

    result = post_to_webhook(args.webhook_url, payload)
    print(f"NEXUS weekly summary sent: {result}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
