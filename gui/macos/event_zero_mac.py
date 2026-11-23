"""Event Zero for macOS.

A macOS HIG-inspired shell over the Event Zero engine: a source-list
sidebar, a unified toolbar with a segmented ELI5 / Plain / Evidence
control, vibrancy-like translucent sidebar, a verdict pill, and a
sheet-style settings dialog. In the spirit of the Objective-See era Mac
utilities: one job, no account, fully offline. The engine is consumed
only through its CLI and JSON output, run as a subprocess. Samples are
never executed.

Run:  python event_zero_mac.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt, QSettings
from PySide6.QtGui import QAction, QFont
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (
    QApplication, QButtonGroup, QDialog, QFileDialog, QFrame, QHBoxLayout,
    QLabel, QLineEdit, QListWidget, QListWidgetItem, QMainWindow,
    QMessageBox, QProgressBar, QPushButton, QStackedWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QToolBar, QToolButton, QVBoxLayout,
    QWidget,
)

import common

# macOS system colours (light / dark pairs chosen at runtime).
MAC_RED = "#FF3B30"
MAC_GREEN = "#34C759"
MAC_ORANGE = "#FF9500"
MAC_GRAY = "#8E8E93"
AMBER = "#E39A1E"  # evidence amber (brand)

BANNER_COLORS = {
    common.DANGER: MAC_RED,
    common.SAFE: MAC_GREEN,
    common.WARN: MAC_ORANGE,
    common.INFO: MAC_GRAY,
}


def banner_color(kind):
    return BANNER_COLORS.get(kind, BANNER_COLORS[common.INFO])


def is_dark_mode(widget):
    pal = widget.palette()
    return pal.color(widget.backgroundRole()).lightness() < 128


class SettingsSheet(QDialog):
    """Sheet-style settings: window-modal, attached feel."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        self.setWindowModality(Qt.WindowModality.WindowModal)
        try:
            self.setWindowFlag(Qt.WindowType.Sheet, True)
        except Exception:
            pass
        layout = QVBoxLayout(self)
        info = QLabel(
            f"Engine root: {common.find_engine_root() or 'not found'}\n"
            f"Interpreter: {common.engine_python()}\n\n"
            "Override with the EVENT_ZERO_HOME and EVENT_ZERO_PYTHON "
            "environment variables.\n\n"
            "Privacy: no account, no uploads, no usage data. The engine "
            "runs on this Mac and the sample is never executed.")
        info.setWordWrap(True)
        layout.addWidget(info)
        done = QPushButton("Done")
        done.clicked.connect(self.accept)
        layout.addWidget(done)


class AboutDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("About Event Zero")
        layout = QVBoxLayout(self)
        body = QLabel(common.ABOUT_TEXT)
        body.setWordWrap(True)
        layout.addWidget(body)
        ok = QPushButton("OK")
        ok.clicked.connect(self.accept)
        layout.addWidget(ok)


class MainWindow(QMainWindow):
    SEGMENTS = ["ELI5", "Plain", "Evidence"]

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Event Zero")
        self.resize(1120, 720)
        self.setAcceptDrops(True)
        self.settings = QSettings("EventZero", "EventZeroMac")
        self.current_report = None
        self.runner = None
        self.mode = "analyze"
        self._build_ui()
        self._apply_theme()

    # ------------------------------------------------------------ build
    def _build_ui(self):
        # Unified toolbar: actions left, segmented control centre-right.
        toolbar = QToolBar("Main")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        self.act_open = QAction("Open\u2026", self)
        self.act_open.triggered.connect(lambda: self._pick(False))
        toolbar.addAction(self.act_open)
        self.act_open_folder = QAction("Open Folder\u2026", self)
        self.act_open_folder.triggered.connect(lambda: self._pick(True))
        toolbar.addAction(self.act_open_folder)
        self.act_run = QAction("Run", self)
        self.act_run.triggered.connect(self._run)
        toolbar.addAction(self.act_run)
        self.act_cancel = QAction("Cancel", self)
        self.act_cancel.triggered.connect(self._cancel)
        self.act_cancel.setEnabled(False)
        toolbar.addAction(self.act_cancel)
        toolbar.addSeparator()
        self.act_export_text = QAction("Export Text", self)
        self.act_export_text.triggered.connect(lambda: self._export("txt"))
        toolbar.addAction(self.act_export_text)
        self.act_export_json = QAction("Export JSON", self)
        self.act_export_json.triggered.connect(lambda: self._export("json"))
        toolbar.addAction(self.act_export_json)
        self.act_export_pdf = QAction("Export PDF", self)
        self.act_export_pdf.triggered.connect(lambda: self._export("pdf"))
        toolbar.addAction(self.act_export_pdf)
        spacer = QWidget()
        spacer.setSizePolicy(spacer.sizePolicy().Policy.Expanding,
                             spacer.sizePolicy().Policy.Preferred)
        toolbar.addWidget(spacer)
        self.offline_label = QLabel("Offline \u00B7 nothing leaves this Mac")
        toolbar.addWidget(self.offline_label)
        toolbar.addSeparator()
        # Segmented ELI5 / Plain / Evidence control (rewords, never omits).
        seg_widget = QWidget()
        seg_layout = QHBoxLayout(seg_widget)
        seg_layout.setContentsMargins(0, 0, 0, 0)
        seg_layout.setSpacing(0)
        self.segment_group = QButtonGroup(self)
        self.segment_group.setExclusive(True)
        self.segment_buttons = []
        for idx, name in enumerate(self.SEGMENTS):
            btn = QToolButton()
            btn.setText(name)
            btn.setCheckable(True)
            btn.setObjectName("segment")
            btn.clicked.connect(lambda _=False, i=idx: self._segment_changed(i))
            self.segment_group.addButton(btn, idx)
            self.segment_buttons.append(btn)
            seg_layout.addWidget(btn)
        self.segment_buttons[0].setChecked(True)
        toolbar.addWidget(seg_widget)
        self.act_settings = QAction("Settings", self)
        self.act_settings.triggered.connect(
            lambda: SettingsSheet(self).exec())
        toolbar.addAction(self.act_settings)
        self.act_about = QAction("About", self)
        self.act_about.triggered.connect(lambda: AboutDialog(self).exec())
        toolbar.addAction(self.act_about)

        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # Source-list sidebar with SF-style glyphs.
        self.sidebar = QListWidget()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(210)
        for glyph, label, key in [("\u25C9", "Scan", "scan"),
                                  ("\u25A3", "The Verdict", "verdict"),
                                  ("\u29D6", "History", "history"),
                                  ("\u2699", "Settings", "settings")]:
            item = QListWidgetItem(f"{glyph}  {label}")
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.sidebar.addItem(item)
        self.sidebar.setCurrentRow(0)
        self.sidebar.currentItemChanged.connect(self._sidebar_changed)
        outer.addWidget(self.sidebar)

        content = QWidget()
        col = QVBoxLayout(content)
        col.setContentsMargins(14, 10, 14, 10)
        outer.addWidget(content, 1)

        pick_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(
            "Drop a file or folder here, or press \u2318O. It is read, never run.")
        pick_row.addWidget(self.path_edit, 1)
        col.addLayout(pick_row)

        self.ref_row = QWidget()
        ref_layout = QHBoxLayout(self.ref_row)
        ref_layout.setContentsMargins(0, 0, 0, 0)
        ref_layout.addWidget(QLabel("Genuine reference (optional):"))
        self.ref_edit = QLineEdit()
        self.ref_edit.setPlaceholderText(
            "Original file or folder to diff the crack against")
        ref_layout.addWidget(self.ref_edit, 1)
        btn_ref = QPushButton("Choose\u2026")
        btn_ref.clicked.connect(self._pick_reference)
        ref_layout.addWidget(btn_ref)
        self.ref_row.setVisible(False)
        col.addWidget(self.ref_row)

        prog_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress_label = QLabel("Ready.")
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.progress_label)
        col.addLayout(prog_row)

        self.pages = QStackedWidget()
        col.addWidget(self.pages, 1)
        self.pages.addWidget(self._build_results_page())
        self.pages.addWidget(self._build_history_page())

        if common.find_engine_root() is None:
            self.progress_label.setText(
                "Engine not found. Set EVENT_ZERO_HOME, or open the app "
                "from inside the Event Zero repository.")

    def _build_results_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 4, 0, 0)
        self.section_title = QLabel("SCAN")
        self.section_title.setStyleSheet(
            f"color: {AMBER}; font-size: 11px; font-weight: 600; "
            "letter-spacing: 2px;")
        layout.addWidget(self.section_title)
        # Verdict pill + mandatory scope sentence.
        self.pill = QLabel("No report yet")
        self.pill.setObjectName("pill")
        self.pill.setWordWrap(True)
        layout.addWidget(self.pill)
        self.scope_label = QLabel("")
        self.scope_label.setObjectName("scope")
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)

        # Segmented stack: ELI5 / Plain / Evidence(full text).
        self.views = QStackedWidget()
        self.eli5_view = QTextEdit()
        self.eli5_view.setReadOnly(True)
        self.views.addWidget(self.eli5_view)
        self.plain_view = QTextEdit()
        self.plain_view.setReadOnly(True)
        self.views.addWidget(self.plain_view)
        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setFont(QFont("SF Mono", 11))
        self.views.addWidget(self.report_view)
        layout.addWidget(self.views, 1)

        # Files table + connections, below the layer views.
        self.files_table = QTableWidget(0, 6)
        self.files_table.setHorizontalHeaderLabels(
            ["File", "Verdict", "Why", "Signer", "SHA-256", "Size"])
        self.files_table.setSortingEnabled(True)
        layout.addWidget(self.files_table, 1)
        self.ioc_view = QTextEdit()
        self.ioc_view.setReadOnly(True)
        self.ioc_view.setMaximumHeight(110)
        layout.addWidget(self.ioc_view)
        return page

    def _build_history_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("History (stored on this Mac only)"))
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self._history_open)
        layout.addWidget(self.history_list)
        return page

    def _apply_theme(self):
        dark = is_dark_mode(self)
        bg = "#1E1E1E" if dark else "#F5F5F7"
        sidebar_bg = "rgba(60, 60, 64, 0.55)" if dark else \
            "rgba(232, 232, 236, 0.72)"  # vibrancy-like translucency
        text = "#ECEFF0" if dark else "#1D1D1F"
        self.setStyleSheet(f"""
        QMainWindow, QWidget {{ background: {bg}; color: {text};
            font-family: ".AppleSystemUIFont", "SF Pro Text",
            "Helvetica Neue", sans-serif; font-size: 13px; }}
        QListWidget#sidebar {{ background: {sidebar_bg}; border: none;
            border-right: 1px solid rgba(128,128,128,0.35); }}
        QListWidget#sidebar::item {{ padding: 7px 12px; border-radius: 6px; }}
        QListWidget#sidebar::item:selected {{
            background: rgba(227, 154, 30, 0.30); }}
        QToolButton#segment {{ padding: 4px 14px; border: 1px solid
            rgba(128,128,128,0.5); background: transparent; }}
        QToolButton#segment:checked {{ background: {AMBER}; color: white; }}
        QLabel#pill {{ color: white; font-size: 15px; font-weight: 600;
            padding: 9px 14px; border-radius: 14px;
            background: {banner_color(common.INFO)}; }}
        QLabel#scope {{ color: {"#B9BFC2" if dark else "#5A5A5E"};
            padding: 3px 2px; }}
        QProgressBar {{ height: 6px; border: none; border-radius: 3px;
            background: rgba(128,128,128,0.3); }}
        QProgressBar::chunk {{ background: {AMBER}; border-radius: 3px; }}
        """)

    # ------------------------------------------------------------ segments
    def _segment_changed(self, index):
        self.views.setCurrentIndex(index)

    def current_segment(self):
        return self.views.currentIndex()

    # ------------------------------------------------------------ sidebar
    def _sidebar_changed(self, current, _previous):
        if current is None:
            return
        page = current.data(Qt.ItemDataRole.UserRole)
        if page == "scan":
            self.mode = "analyze"
            self.section_title.setText("SCAN")
            self.ref_row.setVisible(False)
            self.pages.setCurrentIndex(0)
        elif page == "verdict":
            self.mode = "verdict"
            self.section_title.setText("THE VERDICT")
            self.ref_row.setVisible(True)
            self.pages.setCurrentIndex(0)
        elif page == "history":
            self.pages.setCurrentIndex(1)
        elif page == "settings":
            SettingsSheet(self).exec()
            self.pages.setCurrentIndex(0)

    # ------------------------------------------------------------ picking
    def _pick(self, folder):
        if folder:
            path = QFileDialog.getExistingDirectory(self, "Open Folder")
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Open File")
        if path:
            self.path_edit.setText(path)
            self._add_recent(path)

    def _pick_reference(self):
        path, _ = QFileDialog.getOpenFileName(self, "Open genuine reference")
        if not path:
            path = QFileDialog.getExistingDirectory(
                self, "Open genuine reference folder")
        if path:
            self.ref_edit.setText(path)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event):
        urls = event.mimeData().urls()
        if urls:
            self.path_edit.setText(urls[0].toLocalFile())
            self._add_recent(urls[0].toLocalFile())
            event.acceptProposedAction()

    # ------------------------------------------------------------ recents
    def _add_recent(self, path):
        recents = self.settings.value("recents", []) or []
        if path in recents:
            recents.remove(path)
        recents.insert(0, path)
        self.settings.setValue("recents", recents[:12])

    def recent_paths(self):
        return list(self.settings.value("recents", []) or [])

    # ------------------------------------------------------------ history
    def _history_entries(self):
        raw = self.settings.value("history", []) or []
        entries = []
        for item in raw:
            try:
                entries.append(json.loads(item))
            except Exception:
                continue
        return entries

    def _refresh_history(self):
        self.history_list.clear()
        for entry in self._history_entries():
            item = QListWidgetItem(entry["label"])
            item.setData(Qt.ItemDataRole.UserRole, entry["json_path"])
            self.history_list.addItem(item)

    def _history_open(self, item):
        path = item.data(Qt.ItemDataRole.UserRole)
        if path and os.path.isfile(path):
            self.load_report(common.load_report_json(path))
            self.pages.setCurrentIndex(0)

    # ------------------------------------------------------------ running
    def _run(self):
        target = self.path_edit.text().strip()
        if not target:
            QMessageBox.information(self, "Event Zero",
                                    "Choose a file or folder first.")
            return
        if common.EngineRunner is None:
            QMessageBox.critical(self, "Event Zero", "PySide6 is missing.")
            return
        reference = self.ref_edit.text().strip() or None
        self.runner = common.EngineRunner(
            self.mode, target,
            reference=reference if self.mode == "verdict" else None,
            parent=self)
        self.runner.progress.connect(self._on_progress)
        self.runner.report_ready.connect(self.load_report)
        self.runner.partial_ready.connect(self.load_report)
        self.runner.failed.connect(self._on_failed)
        self.runner.finished.connect(self._on_finished)
        self.act_run.setEnabled(False)
        self.act_cancel.setEnabled(True)
        self.progress_label.setText("Working. The sample is never executed.")
        self.runner.start()

    def _cancel(self):
        if self.runner is not None:
            self.runner.cancel()
            self.progress_label.setText(
                "Cancelling. A partial, unaccounted result will be shown.")

    def _on_progress(self, done, total, name):
        self.progress.setRange(0, max(total, 1))
        self.progress.setValue(done)
        if name:
            self.progress_label.setText(f"Checked {done} of {total}: {name}")
        else:
            self.progress_label.setText(f"Checked {done} of {total}.")

    def _on_failed(self, message):
        QMessageBox.critical(self, "Event Zero engine", message)
        self.progress_label.setText("Engine error. See the message shown.")

    def _on_finished(self):
        self.act_run.setEnabled(True)
        self.act_cancel.setEnabled(False)

    # ------------------------------------------------------------ display
    def load_report(self, report):
        """Populate every view from a parsed engine report dict."""
        self.current_report = report
        if report.get("raw", {}).get("report_type") == "verdict":
            self.section_title.setText("THE VERDICT")
        banner = common.banner_for(report)
        self.pill.setText(banner.text)
        self.banner_kind = banner.kind
        self.pill.setStyleSheet(
            f"background: {banner_color(banner.kind)}; color: white; "
            "font-size: 15px; font-weight: 600; padding: 9px 14px; "
            "border-radius: 14px;")
        self.scope_label.setText(banner.scope)
        raw = report.get("raw", {})
        eli5 = raw.get("eli5") or []
        self.eli5_view.setPlainText(
            "\n".join(str(x) for x in eli5)
            or "No ELI5 section in this report.")
        plain = raw.get("plain_english") or []
        plain_lines = [str(x) for x in plain]
        for cap in raw.get("capabilities") or []:
            if isinstance(cap, dict):
                plain_lines.append(
                    f"- {cap.get('name', cap.get('id', '?'))}: "
                    f"{cap.get('explanation', '')}")
        self.plain_view.setPlainText(
            "\n".join(plain_lines) or "No plain English section.")
        self.report_view.setPlainText(common.render_text(report))
        rows = common.file_rows(report)
        self.files_table.setSortingEnabled(False)
        self.files_table.setRowCount(len(rows))
        for r, row in enumerate(rows):
            values = [row["name"], row["verdict"], row["why"], row["signer"],
                      row["sha256"][:16], str(row["size"])]
            for c, value in enumerate(values):
                self.files_table.setItem(r, c, QTableWidgetItem(value))
        self.files_table.setSortingEnabled(True)
        self.files_table.resizeColumnsToContents()
        iocs = common.ioc_lists(report)
        ioc_lines = []
        for key, vals in iocs.items():
            ioc_lines.append(key.replace("_", " ").upper())
            ioc_lines.extend(f"  {v}" for v in vals) or ioc_lines.append(
                "  none found")
            ioc_lines.append("")
        self.ioc_view.setPlainText("\n".join(ioc_lines))
        self._save_history(report, banner.text)
        self.progress_label.setText("Report ready.")

    def _save_history(self, report, label):
        try:
            folder = os.path.join(os.path.expanduser("~"),
                                  ".eventzero", "history")
            os.makedirs(folder, exist_ok=True)
            import time
            path = os.path.join(folder, f"report_{int(time.time())}.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(report.get("raw", {}), fh)
            entries = self._history_entries()
            entries.insert(0, {"label": label, "json_path": path})
            self.settings.setValue(
                "history", [json.dumps(e) for e in entries[:25]])
            self._refresh_history()
        except Exception:
            pass

    # ------------------------------------------------------------ export
    def _export(self, kind):
        if self.current_report is None:
            QMessageBox.information(self, "Event Zero",
                                    "Run or open a report first.")
            return
        if kind == "pdf":
            path, _ = QFileDialog.getSaveFileName(
                self, "Export PDF", "event_zero_report.pdf", "PDF (*.pdf)")
            if not path:
                return
            printer = QPrinter(QPrinter.PrinterMode.HighResolution)
            printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
            printer.setOutputFileName(path)
            doc = self.report_view.document().clone()
            doc.print(printer)
            return
        suffix = "json" if kind == "json" else "txt"
        path, _ = QFileDialog.getSaveFileName(
            self, f"Export {suffix.upper()}", f"event_zero_report.{suffix}")
        if not path:
            return
        with open(path, "w", encoding="utf-8") as fh:
            if kind == "json":
                json.dump(self.current_report.get("raw", {}), fh, indent=2)
            else:
                fh.write(common.render_text(self.current_report))


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("Event Zero")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
