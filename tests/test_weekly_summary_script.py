from __future__ import annotations

import sys
from datetime import datetime
from pathlib import Path
from zoneinfo import ZoneInfo


repo_root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(repo_root / "scripts"))

from send_weekly_summary import (  # noqa: E402
    GitChanges,
    WeeklySummary,
    build_message_card,
    build_period_strings,
    build_plaintext_preview,
    build_summary,
    friendly_label,
    load_git_changes,
)


# ---------------------------------------------------------------------------
# friendly_label
# ---------------------------------------------------------------------------

def test_friendly_label_maps_known_types():
    assert friendly_label("tower-config") == "MikroTik Config Generator — Tower"
    assert friendly_label("tower")        == "MikroTik Config Generator — Tower"
    assert friendly_label("bng2")         == "MikroTik Config Generator — BNG2"
    assert friendly_label("tarana-config") == "Tarana Sectors"
    assert friendly_label("ftth-fiber-customer") == "FTTH Fiber Customer"
    assert friendly_label("migration")    == "Nokia Migration"
    assert friendly_label("switch-config") == "Switch Maker"


def test_friendly_label_falls_back_gracefully():
    assert friendly_label("custom-type") == "Custom Type"
    assert friendly_label("") == "Unknown"


# ---------------------------------------------------------------------------
# build_summary
# ---------------------------------------------------------------------------

def test_build_summary_aggregates_correctly():
    rows = [
        {"success": 1, "activity_type": "tower-config", "username": "whamza",
         "site_name": "HALLETTSVILLE-NW-1", "device": "CCR2004", "routeros_version": "7.19.4"},
        {"success": 1, "activity_type": "tower-config", "username": "whamza",
         "site_name": "HALLETTSVILLE-NW-1", "device": "CCR2004", "routeros_version": "7.19.4"},
        {"success": 0, "activity_type": "migration", "username": "alice",
         "site_name": "", "device": "Nokia SR", "routeros_version": ""},
        {"success": 1, "activity_type": "ftth-fiber-customer", "username": "bob",
         "site_name": "GOLIAD-1", "device": "Fiber", "routeros_version": ""},
    ]
    summary = build_summary(rows, top_n=3)

    assert summary.total == 4
    assert summary.success == 3
    assert summary.failed == 1
    assert summary.top_activity_types[0] == ("MikroTik Config Generator — Tower", 2)
    assert ("Nokia Migration", 1) in summary.top_activity_types
    assert summary.top_users[0] == ("whamza", 2)
    assert summary.top_sites[0] == ("HALLETTSVILLE-NW-1", 2)
    assert ("CCR2004", 2) in summary.devices_used
    assert ("7.19.4", 2) in summary.routeros_versions


def test_build_summary_empty_rows():
    summary = build_summary([], top_n=5)
    assert summary.total == 0
    assert summary.success == 0
    assert summary.failed == 0
    assert summary.top_activity_types == []
    assert summary.devices_used == []
    assert summary.routeros_versions == []


# ---------------------------------------------------------------------------
# build_period_strings
# ---------------------------------------------------------------------------

def test_build_period_strings_correct_range():
    tz = ZoneInfo("America/Chicago")
    now_local = datetime(2026, 3, 25, 12, 0, tzinfo=tz)
    start, end, label = build_period_strings(now_local, 7)

    assert start == datetime(2026, 3, 18, 12, 0, tzinfo=tz)
    assert end == now_local
    assert label == "Mar 18, 2026 to Mar 25, 2026"


def test_build_period_strings_raises_on_zero():
    tz = ZoneInfo("America/Chicago")
    now_local = datetime(2026, 3, 25, 12, 0, tzinfo=tz)
    try:
        build_period_strings(now_local, 0)
        assert False, "Expected ValueError"
    except ValueError:
        pass


# ---------------------------------------------------------------------------
# build_message_card
# ---------------------------------------------------------------------------

def _one_row_summary() -> WeeklySummary:
    return build_summary(
        [{"success": 1, "activity_type": "tower-config", "username": "whamza",
          "site_name": "HALLETTSVILLE-NW-1", "device": "CCR2004", "routeros_version": "7.19.4"}],
        top_n=5,
    )


def test_card_without_git_has_three_sections():
    payload = build_message_card(
        title="NEXUS Weekly Summary",
        theme_color="0078D7",
        timezone_name="America/Chicago",
        period_label="Mar 18, 2026 to Mar 25, 2026",
        summary=_one_row_summary(),
        git_changes=None,
        footer="Feedback welcome.",
    )
    # overview + what was generated + who used it = 3
    assert len(payload["sections"]) == 3
    assert payload["title"] == "NEXUS Weekly Summary"
    assert payload["text"] == "Feedback welcome."


def test_card_with_git_has_four_sections():
    gc = GitChanges(
        by_area={
            "FTTH & Fiber": ["Added a complete workspace for fiber customers"],
            "MikroTik & Switching": ["Fixed how router names are standardized"],
        },
        total_commits=2,
    )
    payload = build_message_card(
        title="NEXUS Weekly Summary",
        theme_color="0078D7",
        timezone_name="America/Chicago",
        period_label="Mar 18, 2026 to Mar 25, 2026",
        summary=_one_row_summary(),
        git_changes=gc,
        footer="Feedback welcome.",
    )
    # overview + configs + work done + team = 4
    assert len(payload["sections"]) == 4
    work_section = payload["sections"][2]
    assert work_section["title"] == "Work Done This Week"
    # summary line shows total commit count
    assert "2 changes" in work_section["text"]
    # area names appear as facts
    area_names = [f["name"] for f in work_section["facts"]]
    assert "FTTH & Fiber" in area_names
    assert "MikroTik & Switching" in area_names


def test_card_overview_headline_reflects_counts():
    payload = build_message_card(
        title="NEXUS Weekly Summary",
        theme_color="0078D7",
        timezone_name="America/Chicago",
        period_label="Mar 18, 2026 to Mar 25, 2026",
        summary=_one_row_summary(),
        git_changes=None,
        footer="",
    )
    overview_text = payload["sections"][0]["text"]
    # Lean headline — just the count and outcome, no paragraph
    assert "1 config" in overview_text
    assert "successfully" in overview_text.lower()


def test_card_usage_section_has_facts_and_device_detail():
    payload = build_message_card(
        title="NEXUS Weekly Summary",
        theme_color="0078D7",
        timezone_name="America/Chicago",
        period_label="Mar 18, 2026 to Mar 25, 2026",
        summary=_one_row_summary(),
        git_changes=None,
        footer="",
    )
    usage_section = payload["sections"][1]
    # Config type appears in facts
    config_names = [f["name"] for f in usage_section["facts"]]
    assert any("MikroTik" in n or "Tower" in n for n in config_names)
    # Device and firmware in one detail text line
    detail = usage_section.get("text", "")
    assert "CCR2004" in detail or "7.19.4" in detail


def test_card_zero_activity_no_usage_section():
    summary = build_summary([], top_n=5)
    payload = build_message_card(
        title="NEXUS Weekly Summary",
        theme_color="0078D7",
        timezone_name="America/Chicago",
        period_label="Mar 18, 2026 to Mar 25, 2026",
        summary=summary,
        git_changes=None,
        footer="",
    )
    # No activity → no usage section, no team section; only overview
    assert len(payload["sections"]) == 1
    assert "No configs" in payload["sections"][0]["text"]


# ---------------------------------------------------------------------------
# build_plaintext_preview
# ---------------------------------------------------------------------------

def test_plaintext_preview_includes_all_areas():
    gc = GitChanges(
        by_area={
            "FTTH & Fiber": ["Added fiber workspace"],
            "MikroTik & Switching": ["Rebuilt switch configurator"],
        },
        total_commits=2,
    )
    text = build_plaintext_preview(
        title="NEXUS Weekly Summary",
        period_label="Mar 18, 2026 to Mar 25, 2026",
        timezone_name="America/Chicago",
        summary=_one_row_summary(),
        git_changes=gc,
        footer="Feedback welcome.",
    )
    assert "NEXUS Weekly Summary" in text
    assert "FTTH & Fiber" in text
    assert "MikroTik & Switching" in text
    assert "Feedback welcome." in text


# ---------------------------------------------------------------------------
# load_git_changes (integration — requires real git repo)
# ---------------------------------------------------------------------------

def test_load_git_changes_real_repo():
    from datetime import UTC, timedelta
    since = datetime.now(UTC) - timedelta(days=7)
    gc = load_git_changes(repo_root, since)

    assert isinstance(gc, GitChanges)
    assert gc.total_commits >= 0
    assert isinstance(gc.by_area, dict)
    # This week had commits — verify they were classified into known areas
    all_areas = set(gc.by_area.keys())
    known = {"FTTH & Fiber", "MikroTik & Switching", "Nokia Migrations",
             "Field Config Studio", "UI & Navigation", "Infrastructure",
             "Cisco Configs", "Compliance", "Tests & Coverage", "General"}
    assert all_areas.issubset(known), f"Unexpected areas: {all_areas - known}"
