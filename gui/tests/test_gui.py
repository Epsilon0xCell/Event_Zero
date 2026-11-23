"""Headless smoke tests for both Event Zero GUIs.

Run with:  QT_QPA_PLATFORM=offscreen python -m pytest gui/tests -q
Covers window construction for both apps, report JSON loading into both
UIs from the examples fixtures, verdict banner text and colour logic, and
ELI5 tab / segment switching.
"""

import json
import os
import sys

import pytest

GUI_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
REPO = os.path.dirname(GUI_DIR)
sys.path.insert(0, GUI_DIR)
sys.path.insert(0, os.path.join(GUI_DIR, "windows"))
sys.path.insert(0, os.path.join(GUI_DIR, "macos"))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import common  # noqa: E402

pytest.importorskip("PySide6")

from PySide6.QtWidgets import QApplication  # noqa: E402

import event_zero_win as win_mod  # noqa: E402
import event_zero_mac as mac_mod  # noqa: E402


@pytest.fixture(scope="session")
def app():
    return QApplication.instance() or QApplication([])


def gold(name):
    path = os.path.join(REPO, "examples", "gold", name)
    return common.load_report_json(path)


def verdict_report(word="YES", reason="PROVEN", headline=None):
    data = {
        "report_type": "verdict",
        "verdict": word,
        "reason_class": reason,
        "headline": headline or (
            "YES: MALWARE FOUND" if word == "YES" else "NO: NO MALWARE"),
        "files": [
            {"name": "crack.exe", "path_in_release": "crack.exe",
             "verdict": "YES: MALWARE (PROVEN)" if word == "YES"
                        else "NO: ACCOUNTED",
             "why": ["scope test failed: network access"],
             "signed": False, "signature_valid": None,
             "sha256": "ab" * 32, "size_bytes": 1234},
            {"name": "game.exe", "path_in_release": "game.exe",
             "verdict": "NO: ACCOUNTED", "why": [],
             "signed": True, "signature_valid": True,
             "sha256": "cd" * 32, "size_bytes": 9999},
        ],
        "eli5": ["This crack has a thief inside it."],
        "plain_english": ["Malware was proven."],
        "unaccounted": [],
    }
    return {"raw": data}


# ------------------------------------------------------------- common logic

def test_banner_yes_proven_is_danger_with_scope():
    banner = common.banner_for(verdict_report("YES", "PROVEN"))
    assert banner.kind == common.DANGER
    assert banner.text.startswith("YES")
    assert "never executed" in banner.scope
    assert "Checked 2 files" in banner.scope


def test_banner_yes_unaccounted_is_warn_and_names_gaps():
    rep = verdict_report("YES", "UNACCOUNTED",
                         headline="YES: UNACCOUNTED")
    rep["raw"]["unaccounted"] = ["inner.zip: password protected layer"]
    banner = common.banner_for(rep)
    assert banner.kind == common.WARN
    assert "inner.zip" in banner.scope


def test_banner_no_is_safe():
    banner = common.banner_for(verdict_report("NO", "ACCOUNTED"))
    assert banner.kind == common.SAFE
    assert banner.text.startswith("NO")


def test_banner_analysis_high_risk_and_eicar():
    banner = common.banner_for(gold("fake_malware.report.json"))
    assert banner.kind == common.DANGER
    assert "HIGH RISK" in banner.text
    eicar = common.banner_for(gold("eicar.report.json"))
    assert eicar.kind in (common.INFO, common.SAFE)


def test_file_rows_problems_first_and_signer():
    rows = common.file_rows(verdict_report("YES", "PROVEN"))
    assert rows[0]["verdict"].startswith("YES")
    assert rows[0]["signer"] == "Not signed"
    assert rows[1]["signer"] == "Signed, valid"


def test_platform_banner_colours_differ_and_match_semantics():
    assert win_mod.banner_color(common.DANGER) == "#C42B1C"
    assert win_mod.banner_color(common.SAFE) == "#107C10"
    assert mac_mod.banner_color(common.DANGER) == "#FF3B30"
    assert mac_mod.banner_color(common.SAFE) == "#34C759"
    assert win_mod.banner_color(common.DANGER) != \
        mac_mod.banner_color(common.DANGER)


def test_partial_verdict_fails_closed():
    rep = common.partial_verdict("/tmp/release", ["/tmp/release/a.exe"],
                                 "scan cancelled by the user")
    banner = common.banner_for(rep)
    assert banner.text.startswith("YES")
    assert "a.exe" in banner.scope


def test_engine_root_found():
    assert common.find_engine_root() == REPO


# ------------------------------------------------------------- windows app

def test_windows_window_constructs(app):
    win = win_mod.MainWindow()
    assert win.windowTitle() == "Event Zero"
    assert win.nav.count() == 4
    assert "Offline" in win.offline_label.text()


def test_windows_loads_gold_report(app):
    win = win_mod.MainWindow()
    win.load_report(gold("fake_malware.report.json"))
    assert "HIGH RISK" in win.banner.text()
    assert win.banner_kind == common.DANGER
    assert "#C42B1C" in win.banner.styleSheet()
    assert "never executed" in win.scope_label.text()
    assert win.eli5_view.toPlainText() != ""
    assert win.files_table.rowCount() == 1
    assert "192.168.1.100" in win.ioc_view.toPlainText()
    assert "EVENT ZERO" in win.report_view.toPlainText() or \
        "HIGH RISK" in win.report_view.toPlainText()


def test_windows_verdict_report_and_tab_switch(app):
    win = win_mod.MainWindow()
    win.load_report(verdict_report("YES", "PROVEN"))
    assert win.banner.text().startswith("YES")
    win.tabs.setCurrentIndex(1)
    assert win.tabs.currentWidget() is win.files_table
    assert win.files_table.rowCount() == 2
    win.tabs.setCurrentIndex(0)
    assert "thief" in win.eli5_view.toPlainText()


def test_windows_nav_switches_to_verdict_mode(app):
    win = win_mod.MainWindow()
    win.nav.setCurrentRow(1)
    assert win.mode == "verdict"
    assert not win.ref_row.isHidden()
    assert win.section_title.text() == "THE VERDICT"


def test_the_verdict_branding(app):
    assert "The Verdict" in common.ABOUT_TEXT
    assert "Event Zero" in common.ABOUT_TEXT
    win = win_mod.MainWindow()
    assert "The Verdict" in win.nav.item(1).text()
    mac = mac_mod.MainWindow()
    assert "The Verdict" in mac.sidebar.item(1).text()
    mac.sidebar.setCurrentRow(1)
    assert mac.mode == "verdict"
    assert mac.section_title.text() == "THE VERDICT"


# ------------------------------------------------------------- macos app

def test_macos_window_constructs(app):
    win = mac_mod.MainWindow()
    assert win.windowTitle() == "Event Zero"
    assert win.sidebar.count() == 4
    assert win.segment_buttons[0].text() == "ELI5"


def test_macos_loads_gold_report(app):
    win = mac_mod.MainWindow()
    win.load_report(gold("fake_malware.report.json"))
    assert "HIGH RISK" in win.pill.text()
    assert win.banner_kind == common.DANGER
    assert "#FF3B30" in win.pill.styleSheet()
    assert "never executed" in win.scope_label.text()
    assert win.eli5_view.toPlainText() != ""
    assert win.files_table.rowCount() == 1
    assert "192.168.1.100" in win.ioc_view.toPlainText()


def test_macos_verdict_no_is_green_pill(app):
    win = mac_mod.MainWindow()
    win.load_report(verdict_report("NO", "ACCOUNTED"))
    assert win.pill.text().startswith("NO")
    assert win.banner_kind == common.SAFE
    assert "#34C759" in win.pill.styleSheet()


def test_macos_segment_switching(app):
    win = mac_mod.MainWindow()
    win.load_report(gold("fake_malware.report.json"))
    assert win.current_segment() == 0
    win.segment_buttons[2].click()
    assert win.current_segment() == 2
    assert win.views.currentWidget() is win.report_view
    win.segment_buttons[1].click()
    assert win.current_segment() == 1
    assert win.views.currentWidget() is win.plain_view
    assert win.plain_view.toPlainText() != ""


def test_apps_are_different_shells(app):
    win = win_mod.MainWindow()
    mac = mac_mod.MainWindow()
    assert type(win).__module__ != type(mac).__module__
    assert hasattr(win, "nav") and hasattr(mac, "sidebar")
    assert hasattr(mac, "segment_buttons") and hasattr(win, "tabs")
