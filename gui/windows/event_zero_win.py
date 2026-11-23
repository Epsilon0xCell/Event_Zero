"""Event Zero for Windows.

A Windows 11 Fluent-inspired shell over the Event Zero engine. Dark
Mica-like base, a NavigationView-style left rail, a CommandBar of top
actions, an InfoBar-style verdict band, and an evidence-amber accent taken
from the Event Zero case-file identity. The engine is consumed only
through its CLI and JSON output, run as a subprocess. Samples are never
executed. Works fully offline.

Run:  python event_zero_win.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from PySide6.QtCore import Qt, QSettings
from PySide6.QtGui import QAction, QColor, QFont
from PySide6.QtPrintSupport import QPrinter
from PySide6.QtWidgets import (
    QApplication, QDialog, QFileDialog, QFrame, QHBoxLayout, QLabel,
    QLineEdit, QListWidget, QListWidgetItem, QMainWindow, QMessageBox,
    QProgressBar, QPushButton, QStackedWidget, QTabWidget, QTableWidget,
    QTableWidgetItem, QTextEdit, QVBoxLayout, QWidget,
)

import common

# ---------------------------------------------------------------- palette
MICA_BG = "#202020"
PANEL = "rgba(44, 44, 44, 0.88)"        # Acrylic-like translucent panel
PANEL_SOLID = "#2C2C2C"
BORDER = "#3A3A3A"
TEXT = "#ECEFF0"                          # case-file paper, on dark
MUTED = "#B9BFC2"
ACCENT = "#4CC2FF"                        # Windows blue accent
ACCENT_DARK = "#0078D4"
AMBER = "#E39A1E"                         # evidence amber (brand)

BANNER_COLORS = {
    common.DANGER: "#C42B1C",   # Windows system red
    common.SAFE: "#107C10",     # Windows system green
    common.WARN: "#9D5D00",
    common.INFO: "#2B3A45",
}


def banner_color(kind):
    return BANNER_COLORS.get(kind, BANNER_COLORS[common.INFO])


STYLESHEET = f"""
QMainWindow, QWidget {{ background: {MICA_BG}; color: {TEXT};
    font-family: "Segoe UI Variable Text", "Segoe UI", sans-serif;
    font-size: 14px; }}
QFrame#panel {{ background: {PANEL}; border: 1px solid {BORDER};
    border-radius: 8px; }}
QFrame#rail {{ background: {PANEL_SOLID}; border-right: 1px solid {BORDER}; }}
QPushButton {{ background: #333333; border: 1px solid {BORDER};
    border-radius: 8px; padding: 6px 14px; }}
QPushButton:hover {{ background: #3D3D3D; }}
QPushButton#primary {{ background: {ACCENT_DARK}; color: white;
    border: 1px solid {ACCENT_DARK}; }}
QPushButton#primary:hover {{ background: #1A86D9; }}
QPushButton:disabled {{ color: #7A7A7A; }}
QLineEdit {{ background: #2B2B2B; border: 1px solid {BORDER};
    border-radius: 8px; padding: 6px 10px; }}
QListWidget {{ background: transparent; border: none; outline: none; }}
QListWidget::item {{ padding: 10px 12px; border-radius: 8px; }}
QListWidget::item:selected {{ background: rgba(76, 194, 255, 0.18);
    border-left: 3px solid {ACCENT}; }}
QTabWidget::pane {{ border: 1px solid {BORDER}; border-radius: 8px;
    background: {PANEL_SOLID}; }}
QTabBar::tab {{ padding: 7px 16px; border-radius: 8px; }}
QTabBar::tab:selected {{ background: rgba(76, 194, 255, 0.18);
    color: {ACCENT}; }}
QTableWidget {{ background: {PANEL_SOLID}; gridline-color: {BORDER};
    border: none; }}
QHeaderView::section {{ background: #262626; color: {MUTED};
    padding: 6px; border: none; }}
QTextEdit {{ background: {PANEL_SOLID}; border: none; }}
QProgressBar {{ border: 1px solid {BORDER}; border-radius: 4px;
    background: #2B2B2B; height: 8px; text-align: center; }}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 4px; }}
QLabel#banner {{ color: white; font-size: 20px; font-weight: 600;
    padding: 14px 16px; border-radius: 8px; }}
QLabel#scope {{ color: {MUTED}; padding: 4px 2px; }}
QLabel#dropzone {{ border: 2px dashed {BORDER}; border-radius: 8px;
    color: {MUTED}; padding: 22px; }}
QLabel#offline {{ color: {AMBER}; }}
"""


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
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Event Zero")
        self.resize(1180, 760)
        self.setAcceptDrops(True)
        self.settings = QSettings("EventZero", "EventZeroWin")
        self.current_report = None
        self.runner = None
        self.mode = "analyze"
        self._build_ui()
        self._restore_recents()

    # ------------------------------------------------------------ build
    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        outer = QHBoxLayout(root)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        # NavigationView-style left rail.
        rail = QFrame()
        rail.setObjectName("rail")
        rail.setFixedWidth(216)
        rail_layout = QVBoxLayout(rail)
        title = QLabel("EVENT ZERO")
        title.setFont(QFont("Segoe UI", 15, QFont.Weight.DemiBold))
        title.setStyleSheet(f"color: {AMBER}; letter-spacing: 2px;")
        rail_layout.addWidget(title)
        sub = QLabel("Case file examination")
        sub.setStyleSheet(f"color: {MUTED}; font-size: 12px;")
        rail_layout.addWidget(sub)
        self.nav = QListWidget()
        for glyph, label, key in [("\u2302", "Analyze", "analyze"),
                                  ("\u2713", "The Verdict", "verdict"),
                                  ("\u2630", "History", "history"),
                                  ("\u2699", "Settings", "settings")]:
            item = QListWidgetItem(f"{glyph}   {label}")
            item.setData(Qt.ItemDataRole.UserRole, key)
            self.nav.addItem(item)
        self.nav.setCurrentRow(0)
        self.nav.currentItemChanged.connect(self._nav_changed)
        rail_layout.addWidget(self.nav)
        rail_layout.addStretch()
        self.offline_label = QLabel("\u25CF Offline: engine runs locally")
        self.offline_label.setObjectName("offline")
        self.offline_label.setWordWrap(True)
        rail_layout.addWidget(self.offline_label)
        outer.addWidget(rail)

        # Content column.
        content = QWidget()
        col = QVBoxLayout(content)
        col.setContentsMargins(16, 12, 16, 12)
        outer.addWidget(content, 1)

        # CommandBar-style top actions.
        bar = QFrame()
        bar.setObjectName("panel")
        bar_layout = QHBoxLayout(bar)
        self.btn_open_file = QPushButton("Open File")
        self.btn_open_folder = QPushButton("Open Folder")
        self.btn_run = QPushButton("Run")
        self.btn_run.setObjectName("primary")
        self.btn_cancel = QPushButton("Cancel")
        self.btn_cancel.setEnabled(False)
        self.btn_export_text = QPushButton("Export Text")
        self.btn_export_json = QPushButton("Export JSON")
        self.btn_export_pdf = QPushButton("Export PDF")
        self.btn_about = QPushButton("About")
        for btn in (self.btn_open_file, self.btn_open_folder, self.btn_run,
                    self.btn_cancel, self.btn_export_text,
                    self.btn_export_json, self.btn_export_pdf, self.btn_about):
            bar_layout.addWidget(btn)
        bar_layout.addStretch()
        col.addWidget(bar)

        self.btn_open_file.clicked.connect(lambda: self._pick(False))
        self.btn_open_folder.clicked.connect(lambda: self._pick(True))
        self.btn_run.clicked.connect(self._run)
        self.btn_cancel.clicked.connect(self._cancel)
        self.btn_about.clicked.connect(lambda: AboutDialog(self).exec())
        self.btn_export_text.clicked.connect(lambda: self._export("txt"))
        self.btn_export_json.clicked.connect(lambda: self._export("json"))
        self.btn_export_pdf.clicked.connect(lambda: self._export("pdf"))

        # Target picker + drop zone.
        pick_row = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText(
            "Path to a file or folder. It will be read, never run.")
        pick_row.addWidget(self.path_edit, 1)
        col.addLayout(pick_row)
        self.drop_label = QLabel(
            "Drop a file or folder here. Event Zero reads it, never runs it.")
        self.drop_label.setObjectName("dropzone")
        self.drop_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        col.addWidget(self.drop_label)

        # Reference row, verdict mode only.
        self.ref_row = QWidget()
        ref_layout = QHBoxLayout(self.ref_row)
        ref_layout.setContentsMargins(0, 0, 0, 0)
        ref_layout.addWidget(QLabel("Genuine reference (optional):"))
        self.ref_edit = QLineEdit()
        self.ref_edit.setPlaceholderText(
            "Original file or folder to diff the crack against")
        ref_layout.addWidget(self.ref_edit, 1)
        btn_ref = QPushButton("Browse")
        btn_ref.clicked.connect(self._pick_reference)
        ref_layout.addWidget(btn_ref)
        self.ref_row.setVisible(False)
        col.addWidget(self.ref_row)

        # Progress.
        prog_row = QHBoxLayout()
        self.progress = QProgressBar()
        self.progress.setRange(0, 1)
        self.progress.setValue(0)
        self.progress_label = QLabel("Ready.")
        prog_row.addWidget(self.progress, 1)
        prog_row.addWidget(self.progress_label)
        col.addLayout(prog_row)

        # Pages: main results, history, settings.
        self.pages = QStackedWidget()
        col.addWidget(self.pages, 1)
        self.pages.addWidget(self._build_results_page())
        self.pages.addWidget(self._build_history_page())
        self.pages.addWidget(self._build_settings_page())

        if common.find_engine_root() is None:
            self.progress_label.setText(
                "Engine not found. Set EVENT_ZERO_HOME, or open the app "
                "from inside the Event Zero repository.")

    def _build_results_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(0, 6, 0, 0)
        self.section_title = QLabel("ANALYSIS")
        self.section_title.setStyleSheet(
            f"color: {AMBER}; font-size: 12px; font-weight: 600; "
            "letter-spacing: 2px;")
        layout.addWidget(self.section_title)
        # InfoBar-style verdict band + mandatory scope sentence.
        self.banner = QLabel("No report yet. Open a file or folder and Run.")
        self.banner.setObjectName("banner")
        self.banner.setWordWrap(True)
        self.banner.setStyleSheet(f"background: {banner_color(common.INFO)};")
        layout.addWidget(self.banner)
        self.scope_label = QLabel("")
        self.scope_label.setObjectName("scope")
        self.scope_label.setWordWrap(True)
        layout.addWidget(self.scope_label)

        self.tabs = QTabWidget()
        self.eli5_view = QTextEdit()
        self.eli5_view.setReadOnly(True)
        self.tabs.addTab(self.eli5_view, "ELI5")
        self.files_table = QTableWidget(0, 6)
        self.files_table.setHorizontalHeaderLabels(
            ["File", "Verdict", "Why", "Signer", "SHA-256", "Size"])
        self.files_table.setSortingEnabled(True)
        self.files_table.horizontalHeader().setStretchLastSection(False)
        self.tabs.addTab(self.files_table, "Files")
        self.ioc_view = QTextEdit()
        self.ioc_view.setReadOnly(True)
        self.tabs.addTab(self.ioc_view, "Connections and IOCs")
        self.report_view = QTextEdit()
        self.report_view.setReadOnly(True)
        self.report_view.setFont(QFont("Consolas", 11))
        self.tabs.addTab(self.report_view, "Full Report")
        layout.addWidget(self.tabs, 1)
        return page

    def _build_history_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Recent examinations (stored on this PC only)"))
        self.history_list = QListWidget()
        self.history_list.itemDoubleClicked.connect(self._history_open)
        layout.addWidget(self.history_list)
        return page

    def _build_settings_page(self):
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.addWidget(QLabel("Engine"))
        self.engine_label = QLabel(
            f"Engine root: {common.find_engine_root() or 'not found'}\n"
            f"Interpreter: {common.engine_python()}\n"
            "Override with the EVENT_ZERO_HOME and EVENT_ZERO_PYTHON "
            "environment variables.")
        self.engine_label.setWordWrap(True)
        layout.addWidget(self.engine_label)
        layout.addWidget(QLabel(
            "Privacy: no account, no uploads, no usage data. The engine "
            "runs locally and the sample is never executed."))
        layout.addStretch()
        return page

    # ------------------------------------------------------------ nav
    def _nav_changed(self, current, _previous):
        if current is None:
            return
        page = current.data(Qt.ItemDataRole.UserRole)
        if page == "analyze":
            self.mode = "analyze"
            self.section_title.setText("ANALYSIS")
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
            self.pages.setCurrentIndex(2)

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

    def _restore_recents(self):
        pass  # recents surface in History via _refresh_history below

    def _refresh_history(self):
        self.history_list.clear()
        for entry in self._history_entries():
            item = QListWidgetItem(entry["label"])
            item.setData(Qt.ItemDataRole.UserRole, entry["json_path"])
            self.history_list.addItem(item)

    def _history_entries(self):
        raw = self.settings.value("history", []) or []
        entries = []
        for item in raw:
            try:
                entries.append(json.loads(item))
            except Exception:
                continue
        return entries

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
        self.btn_run.setEnabled(False)
        self.btn_cancel.setEnabled(True)
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
        self.btn_run.setEnabled(True)
        self.btn_cancel.setEnabled(False)

    # ------------------------------------------------------------ display
    def load_report(self, report):
        """Populate every view from a parsed engine report dict."""
        self.current_report = report
        if report.get("raw", {}).get("report_type") == "verdict":
            self.section_title.setText("THE VERDICT")
        banner = common.banner_for(report)
        self.banner.setText(banner.text)
        self.banner.setStyleSheet(f"background: {banner_color(banner.kind)};")
        self.banner_kind = banner.kind
        self.scope_label.setText(banner.scope)
        raw = report.get("raw", {})
        eli5 = raw.get("eli5") or []
        self.eli5_view.setPlainText(
            "\n".join(str(x) for x in eli5)
            or "No ELI5 section in this report.")
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
        self.report_view.setPlainText(common.render_text(report))
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
            pass  # history is a convenience, never a blocker

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
    try:
        app.setStyle("windows11")  # Qt 6.5+ Fluent style where available
    except Exception:
        pass  # stylesheet below carries the Fluent look on older Qt
    app.setStyleSheet(STYLESHEET)
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
