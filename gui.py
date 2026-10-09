"""
PhishScope - gui.py   (v1.1 - modern UI + paste-to-analyze)
PyQt5 presentation layer with a custom flat dark theme (no qdarkstyle needed).
All parsing / network work runs in AnalysisWorker (QThread) so the UI never blocks.
Everything shown in the UI is defanged.
"""
from __future__ import annotations

import html
import os
from pathlib import Path

from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSettings, QRectF, QVariantAnimation, QEasingCurve
from PyQt5.QtGui import QPainter, QColor, QPen, QFont, QTextDocument, QKeySequence, QGuiApplication
from PyQt5.QtPrintSupport import QPrinter
from PyQt5.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, QPushButton, QLabel, QListWidget,
                             QListWidgetItem, QTabWidget, QTableWidget, QTableWidgetItem, QTextBrowser, QPlainTextEdit,
                             QFileDialog, QMessageBox, QCheckBox, QProgressBar, QDialog, QFormLayout, QLineEdit,
                             QDialogButtonBox, QSplitter, QAbstractItemView, QFrame, QStackedWidget, QShortcut,
                             QButtonGroup, QSizePolicy)

import report
from enrichment import Enricher, fmt_vt
from mail_parser import parse_email, parse_raw, defang_text
from scorer import score

GREEN, AMBER, RED, ACCENT, MUTED = "#34d399", "#fbbf24", "#f87171", "#6c8cff", "#8b92a5"
LEVEL_COLOR = {"low": GREEN, "suspicious": AMBER, "malicious": RED}
AUTH_COLOR = {"pass": GREEN, "fail": RED, "softfail": AMBER, "neutral": AMBER, "none": MUTED}

STYLE = """
* { font-family: "Inter","Segoe UI","SF Pro Text","Helvetica Neue",Arial,sans-serif; font-size: 13px; color: #e6e8ee; }
QMainWindow, QDialog, QWidget#root, QWidget#page { background: #0f1117; }
QFrame#sidebar { background: #13151d; border-right: 1px solid #22263a; }
QFrame#card { background: #171a23; border: 1px solid #242838; border-radius: 14px; }
QLabel { background: transparent; }
QLabel#h1 { font-size: 26px; font-weight: 700; }
QLabel#h2 { font-size: 11px; font-weight: 700; color: #6b7390; letter-spacing: 1px; }
QLabel#muted { color: #8b92a5; }
QLabel#logo { font-size: 18px; font-weight: 700; }
QPushButton { background: #1e2230; border: 1px solid #2a2f44; border-radius: 8px; padding: 8px 14px; }
QPushButton:hover { background: #262b40; }
QPushButton:pressed { background: #2d3350; }
QPushButton:disabled { color: #566; background: #171a23; border-color: #1f2333; }
QPushButton#primary { background: #6c8cff; border: none; color: #0b0e17; font-weight: 700; padding: 10px 20px; }
QPushButton#primary:hover { background: #8aa3ff; }
QPushButton#primary:disabled { background: #2b3358; color: #6d7596; }
QPushButton#nav { text-align: left; background: transparent; border: none; padding: 10px 12px; color: #a6adc0; border-radius: 8px; }
QPushButton#nav:hover { background: #1b1f2d; }
QPushButton#nav:checked { background: #232842; color: #ffffff; font-weight: 600; }
QPushButton#nav:disabled { color: #454b60; }
QPlainTextEdit, QTextBrowser, QListWidget, QLineEdit { background: #12141c; border: 1px solid #242838; border-radius: 10px;
    padding: 8px; selection-background-color: #3b4a8f; }
QPlainTextEdit:focus, QLineEdit:focus { border: 1px solid #6c8cff; }
QPlainTextEdit#paste { font-family: "JetBrains Mono","Cascadia Mono",Consolas,"DejaVu Sans Mono",monospace; font-size: 12px; }
QListWidget { padding: 4px; } QListWidget::item { padding: 7px 8px; border-radius: 6px; color: #a6adc0; }
QListWidget::item:hover { background: #1b1f2d; } QListWidget::item:selected { background: #232842; color: #fff; }
QFrame#drop { border: 2px dashed #2f3550; border-radius: 14px; background: #12141c; }
QFrame#drop[active="true"] { border-color: #6c8cff; background: #161a2b; }
QTabWidget::pane { border: none; top: -1px; }
QTabBar::tab { background: transparent; color: #8b92a5; padding: 10px 16px; margin-right: 4px; border-bottom: 2px solid transparent; }
QTabBar::tab:hover { color: #e6e8ee; } QTabBar::tab:selected { color: #ffffff; border-bottom: 2px solid #6c8cff; font-weight: 600; }
QTableWidget { background: #12141c; border: 1px solid #242838; border-radius: 10px; gridline-color: transparent;
    alternate-background-color: #151822; selection-background-color: #27305a; outline: 0; }
QTableWidget::item { padding: 6px 8px; border: none; }
QHeaderView::section { background: #171a23; color: #8b92a5; border: none; border-bottom: 1px solid #242838; padding: 9px 8px; font-weight: 600; }
QScrollBar:vertical { background: transparent; width: 10px; margin: 0; } QScrollBar:horizontal { background: transparent; height: 10px; }
QScrollBar::handle { background: #2b3046; border-radius: 5px; min-height: 30px; min-width: 30px; } QScrollBar::handle:hover { background: #3a4160; }
QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; } QScrollBar::add-page, QScrollBar::sub-page { background: transparent; }
QProgressBar { background: #1e2230; border: none; border-radius: 2px; max-height: 4px; min-height: 4px; }
QProgressBar::chunk { background: #6c8cff; border-radius: 2px; }
QCheckBox { spacing: 8px; } QCheckBox::indicator { width: 16px; height: 16px; border-radius: 4px; border: 1px solid #39405a; background: #12141c; }
QCheckBox::indicator:checked { background: #6c8cff; border-color: #6c8cff; }
QSplitter::handle { background: #0f1117; } QToolTip { background: #1e2230; color: #e6e8ee; border: 1px solid #2a2f44; padding: 4px; }
"""


def rgba(hex_color: str, a: float) -> str:
    c = QColor(hex_color)
    return f"rgba({c.red()},{c.green()},{c.blue()},{a})"


def pill(text: str, color: str) -> QLabel:
    l = QLabel(text)
    l.setStyleSheet(f"background:{rgba(color, .15)};color:{color};border:1px solid {rgba(color, .35)};"
                    f"border-radius:11px;padding:3px 11px;font-weight:600;")
    l.setSizePolicy(QSizePolicy.Maximum, QSizePolicy.Fixed)
    return l


def load_keys(settings: QSettings) -> dict:
    """Keys come from saved settings, falling back to environment variables."""
    def g(name, env):
        return settings.value(name, "") or os.environ.get(env, "")
    return {"vt": g("vt", "PHISHSCOPE_VT_KEY"), "abuseipdb": g("abuseipdb", "PHISHSCOPE_ABUSEIPDB_KEY"),
            "urlscan": g("urlscan", "PHISHSCOPE_URLSCAN_KEY"), "vt_free": settings.value("vt_free", True, type=bool)}


def score_level(v):
    return "low" if v <= 25 else "suspicious" if v <= 60 else "malicious"


# --------------------------------------------------------------------------- #
class AnalysisWorker(QThread):
    progress = pyqtSignal(str)
    done = pyqtSignal(object, object)
    failed = pyqtSignal(str)

    def __init__(self, kind, source, keys, do_enrich):
        super().__init__()
        self.kind, self.source, self.keys, self.do_enrich = kind, source, keys, do_enrich

    def run(self):
        try:
            self.progress.emit("Parsing email…")
            pe = parse_email(self.source) if self.kind == "file" else parse_raw(self.source)
            if self.do_enrich:
                Enricher(self.keys, self.progress.emit).enrich(pe)
            else:
                pe.warnings.append("Threat-intel enrichment disabled (offline / static-only analysis).")
            self.progress.emit("Scoring…")
            self.done.emit(pe, score(pe))
        except Exception as e:                       # surfaced in the UI, never crashes the app
            self.failed.emit(f"{type(e).__name__}: {e}")


class Gauge(QWidget):
    """Animated 270° risk gauge."""
    def __init__(self):
        super().__init__()
        self.setFixedSize(150, 136)
        self.value = self._shown = 0
        self.anim = QVariantAnimation(self, duration=800, easingCurve=QEasingCurve.OutCubic)
        self.anim.valueChanged.connect(lambda v: (setattr(self, "_shown", v), self.update()))

    def set_value(self, v):
        self.value = v
        self.anim.stop()
        self.anim.setStartValue(float(self._shown))
        self.anim.setEndValue(float(v))
        self.anim.start()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        rect = QRectF(14, 10, 122, 122)
        col = QColor(LEVEL_COLOR[score_level(self.value)])
        p.setPen(QPen(QColor("#252a3d"), 11, cap=Qt.RoundCap))
        p.drawArc(rect, 225 * 16, -270 * 16)
        if self._shown > 0.5:
            p.setPen(QPen(col, 11, cap=Qt.RoundCap))
            p.drawArc(rect, 225 * 16, -int(270 * 16 * self._shown / 100))
        p.setPen(col)
        p.setFont(QFont("Segoe UI", 30, QFont.Bold))
        p.drawText(rect.adjusted(0, -8, 0, -8), Qt.AlignCenter, str(int(round(self._shown))))
        p.setPen(QColor(MUTED))
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.drawText(rect.adjusted(0, 38, 0, 38), Qt.AlignCenter, "RISK SCORE")


class KeysDialog(QDialog):
    def __init__(self, settings, parent=None):
        super().__init__(parent)
        self.settings = settings
        self.setWindowTitle("API Keys")
        self.setMinimumWidth(480)
        form = QFormLayout(self)
        form.setContentsMargins(22, 22, 22, 18)
        form.setSpacing(12)
        self.edits = {}
        for name, label in (("vt", "VirusTotal"), ("abuseipdb", "AbuseIPDB"), ("urlscan", "URLScan.io (optional)")):
            e = QLineEdit(settings.value(name, ""))
            e.setEchoMode(QLineEdit.Password)
            e.setPlaceholderText("not set")
            self.edits[name] = e
            form.addRow(label, e)
        self.free = QCheckBox("VirusTotal free tier (throttle to 4 requests/min)")
        self.free.setChecked(settings.value("vt_free", True, type=bool))
        form.addRow(self.free)
        note = QLabel("Keys are stored unencrypted in this user's local Qt settings. Safer: set the env vars "
                      "PHISHSCOPE_VT_KEY / _ABUSEIPDB_KEY / _URLSCAN_KEY.")
        note.setObjectName("muted")
        note.setWordWrap(True)
        form.addRow(note)
        bb = QDialogButtonBox(QDialogButtonBox.Save | QDialogButtonBox.Cancel)
        bb.button(QDialogButtonBox.Save).setObjectName("primary")
        bb.accepted.connect(self.save)
        bb.rejected.connect(self.reject)
        form.addRow(bb)

    def save(self):
        for k, e in self.edits.items():
            self.settings.setValue(k, e.text().strip())
        self.settings.setValue("vt_free", self.free.isChecked())
        self.accept()


class IocTable(QTableWidget):
    """Table with Ctrl+C / double-click copy (copies the defanged cell text)."""
    copied = pyqtSignal(str)

    def __init__(self, cols):
        super().__init__(0, len(cols))
        self.setHorizontalHeaderLabels(cols)
        self.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.setAlternatingRowColors(True)
        self.setShowGrid(False)
        self.setWordWrap(False)
        self.verticalHeader().setVisible(False)
        self.verticalHeader().setDefaultSectionSize(34)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setMaximumSectionSize(440)
        self.horizontalHeader().setHighlightSections(False)
        self.cellDoubleClicked.connect(lambda r, c: self._copy(self.item(r, c).text() if self.item(r, c) else ""))

    def _copy(self, text):
        QGuiApplication.clipboard().setText(text)
        self.copied.emit("Copied to clipboard")

    def keyPressEvent(self, e):
        if e.matches(QKeySequence.Copy):
            rows = sorted({i.row() for i in self.selectedIndexes()})
            self._copy("\n".join("\t".join(self.item(r, c).text() if self.item(r, c) else ""
                                          for c in range(self.columnCount())) for r in rows))
        else:
            super().keyPressEvent(e)

    def fill(self, rows, colors=None):
        self.setRowCount(len(rows))
        for r, row in enumerate(rows):
            for c, val in enumerate(row):
                it = QTableWidgetItem(str(val))
                it.setToolTip(str(val))
                if colors and (r, c) in colors:
                    it.setForeground(QColor(colors[(r, c)]))
                self.setItem(r, c, it)
        self.resizeColumnsToContents()


def label(text, name=None, wrap=False):
    l = QLabel(text)
    if name:
        l.setObjectName(name)
    l.setWordWrap(wrap)
    return l


# --------------------------------------------------------------------------- #
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PhishScope — Email Phishing Analyzer")
        self.resize(1440, 900)
        self.setMinimumSize(1100, 700)
        self.setAcceptDrops(True)
        self.setStyleSheet(STYLE)
        self.settings = QSettings("PhishScope", "PhishScope")
        self.path = self.pe = self.result = self.worker = None
        self._build()
        self._load_recent()
        QShortcut(QKeySequence("Ctrl+Return"), self, activated=self.run_analysis)
        QShortcut(QKeySequence("Ctrl+O"), self, activated=self.pick_file)
        QShortcut(QKeySequence("Ctrl+N"), self, activated=self.new_analysis)

    # -- layout ------------------------------------------------------------- #
    def _build(self):
        root = QWidget(objectName="root")
        self.setCentralWidget(root)
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        h.addWidget(self._sidebar())
        self.stack = QStackedWidget()
        self.stack.addWidget(self._input_page())
        self.stack.addWidget(self._results_page())
        h.addWidget(self.stack, 1)

    def _sidebar(self):
        side = QFrame(objectName="sidebar")
        side.setFixedWidth(232)
        v = QVBoxLayout(side)
        v.setContentsMargins(14, 18, 14, 14)
        v.setSpacing(6)
        v.addWidget(label("🎣  PhishScope", "logo"))
        v.addWidget(label("Email threat analyzer", "muted"))
        v.addSpacing(14)
        self.nav_new = QPushButton("✉   New analysis", objectName="nav", checkable=True, checked=True)
        self.nav_res = QPushButton("◎   Results", objectName="nav", checkable=True, enabled=False)
        grp = QButtonGroup(self)
        grp.setExclusive(True)
        for b in (self.nav_new, self.nav_res):
            grp.addButton(b)
            v.addWidget(b)
        self.nav_new.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        self.nav_res.clicked.connect(lambda: self.stack.setCurrentIndex(1))
        v.addSpacing(10)
        v.addWidget(label("RECENT FILES", "h2"))
        self.recent = QListWidget()
        self.recent.itemDoubleClicked.connect(lambda it: self.load_file(it.data(Qt.UserRole)))
        v.addWidget(self.recent, 1)
        self.chk = QCheckBox("Online threat-intel lookups")
        self.chk.setChecked(True)
        v.addWidget(self.chk)
        b_keys = QPushButton("⚙  API keys")
        b_keys.clicked.connect(lambda: KeysDialog(self.settings, self).exec_())
        v.addWidget(b_keys)
        v.addSpacing(6)
        v.addWidget(label("EXPORT", "h2"))
        row = QHBoxLayout()
        row.setSpacing(6)
        self.export_btns = []
        for text, fn in (("JSON", self.export_json), ("HTML", self.export_html), ("PDF", self.export_pdf)):
            b = QPushButton(text, enabled=False)
            b.clicked.connect(fn)
            row.addWidget(b)
            self.export_btns.append(b)
        v.addLayout(row)
        self.bar = QProgressBar(textVisible=False)
        self.bar.setRange(0, 1)
        v.addWidget(self.bar)
        self.status = label("Ready", "muted", True)
        v.addWidget(self.status)
        return side

    def _input_page(self):
        page = QWidget(objectName="page")
        v = QVBoxLayout(page)
        v.setContentsMargins(36, 32, 36, 28)
        v.setSpacing(14)
        v.addWidget(label("Analyze an email", "h1"))
        v.addWidget(label("Paste the raw email source, or load / drop an .eml or .msg file. "
                          "Nothing is executed and attachments never touch the disk.", "muted", True))
        self.drop = QFrame(objectName="drop")
        dv = QHBoxLayout(self.drop)
        dv.setContentsMargins(20, 14, 20, 14)
        self.drop_lbl = label("⬇  Drop an .eml / .msg file anywhere in this window")
        dv.addWidget(self.drop_lbl, 1)
        b_browse = QPushButton("Browse file…  (Ctrl+O)")
        b_browse.clicked.connect(self.pick_file)
        b_paste = QPushButton("📋  Paste from clipboard")
        b_paste.clicked.connect(self.paste_clipboard)
        dv.addWidget(b_browse)
        dv.addWidget(b_paste)
        v.addWidget(self.drop)
        v.addWidget(label("RAW EMAIL SOURCE", "h2"))
        self.paste = QPlainTextEdit(objectName="paste")
        self.paste.setLineWrapMode(QPlainTextEdit.NoWrap)
        self.paste.setPlaceholderText(
            "Paste the full message source here (headers + body)…\n\n"
            "  Gmail     ⋮ menu → Show original → Copy to clipboard\n"
            "  Outlook   File → Properties → Internet headers (headers-only works too)\n"
            "  Thunderbird   View → Message Source\n\n"
            "Tip: include the complete headers so hops and SPF/DKIM/DMARC can be analyzed.")
        self.paste.textChanged.connect(self._on_paste_changed)
        v.addWidget(self.paste, 1)
        row = QHBoxLayout()
        self.paste_info = label("", "muted")
        row.addWidget(self.paste_info, 1)
        b_clear = QPushButton("Clear")
        b_clear.clicked.connect(self.new_analysis)
        self.run_btn = QPushButton("Analyze  ▶   (Ctrl+Enter)", objectName="primary")
        self.run_btn.clicked.connect(self.run_analysis)
        row.addWidget(b_clear)
        row.addWidget(self.run_btn)
        v.addLayout(row)
        return page

    def _results_page(self):
        page = QWidget(objectName="page")
        v = QVBoxLayout(page)
        v.setContentsMargins(28, 24, 28, 20)
        v.setSpacing(14)

        card = QFrame(objectName="card")
        ch = QHBoxLayout(card)
        ch.setContentsMargins(20, 14, 24, 14)
        ch.setSpacing(20)
        self.gauge = Gauge()
        ch.addWidget(self.gauge)
        col = QVBoxLayout()
        col.setSpacing(4)
        col.addStretch()
        self.verdict = label("—")
        self.verdict.setStyleSheet("font-size:26px;font-weight:700;")
        self.subject = label("", wrap=True)
        self.sender = label("", "muted", True)
        self.pills = QHBoxLayout()
        self.pills.setSpacing(8)
        col.addWidget(self.verdict)
        col.addWidget(self.subject)
        col.addWidget(self.sender)
        col.addSpacing(6)
        col.addLayout(self.pills)
        col.addStretch()
        ch.addLayout(col, 1)
        v.addWidget(card)

        self.tabs = QTabWidget()
        self.overview = QTextBrowser()
        self.f_table = IocTable(["Field", "Value"])
        self.a_table = IocTable(["Mechanism", "Result"])
        self.h_table = IocTable(["#", "From host", "IP", "By", "Timestamp", "Delay (s)"])
        split = QSplitter(Qt.Vertical)
        for w in (self.f_table, self.a_table, self.h_table):
            split.addWidget(w)
        split.setSizes([280, 130, 280])
        self.u_table = IocTable(["Defanged URL", "Source", "Domain", "Flags", "VirusTotal", "URLScan", "Domain age"])
        att = QSplitter(Qt.Vertical)
        self.t_table = IocTable(["File name", "Size", "Declared", "Detected (magic bytes)", "SHA-256", "Flags", "VirusTotal"])
        self.t_table.itemSelectionChanged.connect(self._att_detail)
        self.t_detail = QPlainTextEdit(objectName="paste")
        self.t_detail.setReadOnly(True)
        att.addWidget(self.t_table)
        att.addWidget(self.t_detail)
        att.setSizes([420, 200])
        self.raw = QPlainTextEdit(objectName="paste")
        self.raw.setReadOnly(True)
        self.raw.setLineWrapMode(QPlainTextEdit.NoWrap)
        for w, name in ((self.overview, "Overview"), (split, "Headers && Hops"), (self.u_table, "URLs && Domains"),
                        (att, "Attachments"), (self.raw, "Raw / MIME")):
            self.tabs.addTab(w, name)
        for t in (self.f_table, self.a_table, self.h_table, self.u_table, self.t_table):
            t.copied.connect(self.status.setText)
        v.addWidget(self.tabs, 1)
        return page

    # -- input handling ----------------------------------------------------- #
    def dragEnterEvent(self, e):
        if e.mimeData().hasUrls():
            e.acceptProposedAction()
            self._drop_active(True)

    def dragLeaveEvent(self, _):
        self._drop_active(False)

    def _drop_active(self, on):
        self.drop.setProperty("active", on)
        self.drop.style().unpolish(self.drop)
        self.drop.style().polish(self.drop)

    def dropEvent(self, e):
        self._drop_active(False)
        for u in e.mimeData().urls():
            if u.toLocalFile().lower().endswith((".eml", ".msg")):
                self.load_file(u.toLocalFile())
                return
        self.status.setText("⚠ Only .eml / .msg files are supported.")

    def pick_file(self):
        p, _ = QFileDialog.getOpenFileName(self, "Open email", "", "Email (*.eml *.msg);;All files (*)")
        if p:
            self.load_file(p)

    def paste_clipboard(self):
        txt = QGuiApplication.clipboard().text()
        if not txt.strip():
            self.status.setText("⚠ Clipboard is empty.")
            return
        self.paste.setPlainText(txt)
        self.status.setText("Pasted from clipboard — press Analyze.")

    def _on_paste_changed(self):
        n = len(self.paste.toPlainText())
        if n:
            self.path = None                                  # pasted text takes over from any loaded file
            self.drop_lbl.setText("⬇  Drop an .eml / .msg file anywhere in this window")
        self.paste_info.setText(f"{n:,} characters · {self.paste.document().blockCount():,} lines" if n else "")

    def new_analysis(self):
        self.paste.clear()
        self.path = None
        self.drop_lbl.setText("⬇  Drop an .eml / .msg file anywhere in this window")
        self.stack.setCurrentIndex(0)
        self.nav_new.setChecked(True)
        self.paste.setFocus()

    def load_file(self, path):
        self.paste.blockSignals(True)
        self.paste.clear()
        self.paste.blockSignals(False)
        self.paste_info.setText("")
        self.path = path
        self.drop_lbl.setText(f"📄  <b>{html.escape(Path(path).name)}</b> loaded — ready to analyze")
        rec = [p for p in self.settings.value("recent", [], type=list) if p != path]
        self.settings.setValue("recent", ([path] + rec)[:10])
        self._load_recent()
        self.stack.setCurrentIndex(0)
        self.nav_new.setChecked(True)
        self.status.setText("File loaded. Press Analyze.")

    def _load_recent(self):
        self.recent.clear()
        for p in self.settings.value("recent", [], type=list):
            it = QListWidgetItem(Path(p).name)
            it.setData(Qt.UserRole, p)
            it.setToolTip(p)
            self.recent.addItem(it)

    # -- analysis ----------------------------------------------------------- #
    def run_analysis(self):
        if self.worker and self.worker.isRunning():
            return
        text = self.paste.toPlainText()
        if text.strip():
            kind, src = "text", text
        elif self.path:
            kind, src = "file", self.path
        else:
            QMessageBox.information(self, "PhishScope", "Paste the email source or open an .eml / .msg file first.")
            return
        keys, online = load_keys(self.settings), self.chk.isChecked()
        if online and not (keys["vt"] or keys["abuseipdb"]):
            self.status.setText("⚠ No VirusTotal/AbuseIPDB keys set — only WHOIS/URLScan will run.")
        self.run_btn.setEnabled(False)
        self.bar.setRange(0, 0)
        self.worker = AnalysisWorker(kind, src, keys, online)
        self.worker.progress.connect(self.status.setText)
        self.worker.done.connect(self.on_done)
        self.worker.failed.connect(self.on_failed)
        self.worker.start()

    def on_failed(self, msg):
        self._idle()
        self.status.setText("Analysis failed")
        QMessageBox.critical(self, "PhishScope", f"Could not analyze input:\n{msg}")

    def _idle(self):
        self.run_btn.setEnabled(True)
        self.bar.setRange(0, 1)

    def on_done(self, pe, res):
        self._idle()
        self.pe, self.result = pe, res
        col = LEVEL_COLOR[res.level]
        self.gauge.set_value(res.total)
        self.verdict.setText(res.verdict)
        self.verdict.setStyleSheet(f"font-size:26px;font-weight:700;color:{col};")
        self.subject.setText(html.escape(defang_text(pe.headers.get("Subject", "")) or "(no subject)"))
        self.sender.setText(html.escape(defang_text(f"From: {pe.headers.get('From', '—')}    ·    Source: {Path(pe.path).name}")))
        while self.pills.count():
            w = self.pills.takeAt(0).widget()
            if w:
                w.deleteLater()
        for m in ("spf", "dkim", "dmarc"):
            self.pills.addWidget(pill(f"{m.upper()} {pe.auth[m]}", AUTH_COLOR.get(pe.auth[m], AMBER)))
        self.pills.addWidget(pill(f"{len(pe.hops)} hops", MUTED))
        self.pills.addWidget(pill(f"{len(pe.urls)} URLs", MUTED))
        self.pills.addWidget(pill(f"{len(pe.attachments)} attachments", MUTED))
        if pe.warnings:
            self.pills.addWidget(pill(f"⚠ {len(pe.warnings)} warning(s)", AMBER))
        self.pills.addStretch()
        self.status.setText("Done" + (f" — {len(pe.warnings)} warning(s)" if pe.warnings else ""))
        for b in self.export_btns:
            b.setEnabled(True)
        self._fill_overview()
        self._fill_headers()
        self._fill_urls()
        self._fill_attachments()
        self.raw.setPlainText(pe.raw_text)
        self.nav_res.setEnabled(True)
        self.nav_res.setChecked(True)
        self.stack.setCurrentIndex(1)

    def _fill_overview(self):
        pe, res = self.pe, self.result
        e, col = html.escape, LEVEL_COLOR[self.result.level]
        rows = "".join(
            f"<tr><td width='54' align='center' valign='middle' bgcolor='#1e2230'><b style='color:{col}'>+{r.points}</b></td>"
            f"<td style='padding:6px 10px'><b>{e(r.title)}</b><br><span style='color:#8b92a5'>{e(r.evidence)}</span></td></tr>"
            for r in res.rules) or "<tr><td style='color:#8b92a5'>No rules triggered.</td></tr>"
        warn = "".join(f"<li>{e(w)}</li>" for w in pe.warnings)
        kw = " &nbsp; ".join(f"<span style='color:#fbbf24'>{e(c)}</span>: “{e(p)}”" for c, p in pe.keyword_hits) or "none detected"
        self.overview.setHtml(
            f"<h3 style='color:#8b92a5'>WHY THIS SCORE</h3><table cellspacing='6' width='100%'>{rows}</table>"
            f"<h3 style='color:#8b92a5'>SOCIAL-ENGINEERING LANGUAGE</h3><p>{kw}</p>"
            f"<h3 style='color:#8b92a5'>ORIGIN</h3><p>Origin IP: <b>{e(pe.origin_ip.replace('.', '[.]') or 'unknown')}</b></p>"
            + (f"<h3 style='color:#fbbf24'>⚠ WARNINGS</h3><ul>{warn}</ul>" if warn else ""))

    def _fill_headers(self):
        pe = self.pe
        self.f_table.fill(list(pe.headers.items()) + [(c, d) for c, d in pe.header_flags],
                          {(len(pe.headers) + i, 0): AMBER for i in range(len(pe.header_flags))})
        rows = [(m.upper(), r) for m, r in pe.auth.items()]
        self.a_table.fill(rows, {(i, 1): AUTH_COLOR.get(r[1], AMBER) for i, r in enumerate(rows)})
        self.h_table.fill([(h.index, h.from_host, h.ip.replace(".", "[.]"), h.by_host, h.timestamp,
                            "" if h.delay_s is None else h.delay_s) for h in pe.hops])

    def _fill_urls(self):
        rows, colors = [], {}
        for i, u in enumerate(self.pe.urls):
            di = self.pe.domain_intel.get(u.domain, {})
            us, w = di.get("urlscan") or {}, di.get("whois") or {}
            vt = u.intel.get("vt")
            rows.append((u.defanged, u.source, u.domain.replace(".", "[.]"), ", ".join(c for c, _ in u.flags), fmt_vt(vt),
                         ("MALICIOUS" if us.get("malicious") else f"{us.get('scans', 0)} scans") if us else "—",
                         f"{w['age_days']} d" if w.get("age_days") is not None else "—"))
            if vt and vt.get("malicious"):
                colors[(i, 4)] = RED
            if w.get("age_days") is not None and w["age_days"] < 30:
                colors[(i, 6)] = RED
            if u.flags:
                colors[(i, 3)] = AMBER
        self.u_table.fill(rows, colors)

    def _fill_attachments(self):
        rows, colors = [], {}
        for i, a in enumerate(self.pe.attachments):
            rows.append((a.filename, a.size, a.declared_type, a.detected_type, a.sha256,
                         ", ".join(c for c, _ in a.flags), fmt_vt(a.intel.get("vt"))))
            if a.flags:
                colors[(i, 5)] = RED
        self.t_table.fill(rows, colors)
        self.t_detail.setPlainText("Select an attachment for details.\nAttachments are analyzed in memory only — never written to disk or executed.")

    def _att_detail(self):
        r = self.t_table.currentRow()
        if self.pe and 0 <= r < len(self.pe.attachments):
            a = self.pe.attachments[r]
            lines = [f"File:     {a.filename}", f"MD5:      {a.md5}", f"SHA-1:    {a.sha1}", f"SHA-256:  {a.sha256}",
                     f"libmagic: {a.magic_desc or 'n/a'}", ""] + [f"[{c}] {d}" for c, d in a.flags]
            if a.archive_members:
                lines += ["", "Archive members (names only):"] + [f"  {m}" for m in a.archive_members[:40]]
            self.t_detail.setPlainText("\n".join(lines))

    # -- export ------------------------------------------------------------- #
    def _save(self, caption, filt, suffix):
        stem = Path(self.pe.path).stem if self.pe else "report"
        p, _ = QFileDialog.getSaveFileName(self, caption, f"phishscope_{stem.replace(' ', '_')}{suffix}", filt)
        return p

    def export_json(self):
        p = self._save("Export JSON", "JSON (*.json)", ".json")
        if p:
            Path(p).write_text(report.to_json(self.pe, self.result), encoding="utf-8")
            self.status.setText(f"Saved {Path(p).name}")

    def export_html(self):
        p = self._save("Export HTML", "HTML (*.html)", ".html")
        if p:
            Path(p).write_text(report.to_html(self.pe, self.result), encoding="utf-8")
            self.status.setText(f"Saved {Path(p).name}")

    def export_pdf(self):
        p = self._save("Export PDF", "PDF (*.pdf)", ".pdf")
        if not p:
            return
        doc = QTextDocument()
        doc.setHtml(report.to_html(self.pe, self.result))
        pr = QPrinter(QPrinter.HighResolution)
        pr.setOutputFormat(QPrinter.PdfFormat)
        pr.setOutputFileName(p)
        doc.print_(pr)
        self.status.setText(f"Saved {Path(p).name}")
