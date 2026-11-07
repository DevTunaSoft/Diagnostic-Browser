"""Diagnostic Browser desktop shell — development preview.

The embedded browser is NOT attached to the existing CDP recorder. Never
display invented health or monitoring results.
"""
import sys
from PySide6.QtCore import QUrl
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QHBoxLayout,
 QVBoxLayout, QLineEdit, QPushButton, QLabel, QTabWidget, QTextEdit, QSplitter)
from PySide6.QtWebEngineWidgets import QWebEngineView

STYLE = """
QWidget {background:#071628;color:#e8f4ff;font:13px 'Segoe UI';}
QPushButton {background:#143454;border:1px solid #315b80;border-radius:7px;padding:10px;}
QPushButton:hover {background:#1b5184;}
QLineEdit {background:#102a43;border:1px solid #3976a6;border-radius:7px;padding:9px;}
QTabWidget::pane {border:1px solid #294b6b;}
QTabBar::tab {background:#12304c;padding:10px 18px;margin-right:3px;}
QTabBar::tab:selected {background:#1556a0;}
"""
HOME = """<html><body style="background:#071628;color:#eef7ff;font-family:Segoe UI;text-align:center;padding-top:12vh">
<div style="font-size:60px;color:#58b8ff">◎</div><h1>Diagnostic Browser</h1>
<p>Secure Browse · Diagnose · Record · Analyze · Report</p>
<p style="color:#a8c3da">Enter a URL in the address bar to browse.</p>
<p style="color:#ffcf8c">Diagnostic capture for this embedded tab is not yet connected.</p></body></html>"""

class Window(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Diagnostic Browser V5.0 — Desktop Preview")
        self.resize(1540, 940)
        self.setStyleSheet(STYLE)
        root = QWidget()
        self.setCentralWidget(root)
        layout = QHBoxLayout(root)
        side = QVBoxLayout()
        side.addWidget(QLabel("◉  Diagnostic Browser V5"))
        for name in ("Browser", "Dashboard", "Diagnostics", "Flight Recorder", "Event Logs", "Reports", "Settings"):
            button = QPushButton(name)
            button.clicked.connect(lambda _, n=name: self.show_section(n))
            side.addWidget(button)
        side.addStretch()
        side.addWidget(QLabel("Recorder: NOT CONNECTED"))
        layout.addLayout(side, 1)
        center = QVBoxLayout()
        layout.addLayout(center, 7)
        toolbar = QHBoxLayout()
        for label, method in (("←",self.back),("→",self.forward),("↻",self.reload),("⌂",self.home)):
            b=QPushButton(label); b.clicked.connect(method); toolbar.addWidget(b)
        self.address = QLineEdit()
        self.address.setPlaceholderText("Search or enter a web address")
        self.address.returnPressed.connect(self.navigate)
        toolbar.addWidget(self.address, 1)
        plus = QPushButton("+ Tab")
        plus.clicked.connect(self.add_tab)
        toolbar.addWidget(plus)
        center.addLayout(toolbar)
        self.tabs = QTabWidget()
        self.tabs.setTabsClosable(True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self.tab_changed)
        center.addWidget(self.tabs, 6)
        self.status = QLabel("Embedded Chromium active · Diagnostic capture not connected")
        center.addWidget(self.status)
        panel = QVBoxLayout()
        panel.addWidget(QLabel("LIVE DIAGNOSTICS"))
        self.diag = QTextEdit()
        self.diag.setReadOnly(True)
        self.diag.setPlainText("Browser: embedded Chromium\n\nHTTP: not instrumented\nJavaScript: not instrumented\nWebSocket: not instrumented\nFrames: not instrumented\n\nFlight recorder: not connected\n\nNo diagnostic claims are made for this tab.")
        panel.addWidget(self.diag)
        panel.addWidget(QLabel("FLIGHT RECORDER"))
        panel.addWidget(QLabel("Not recording this browser session"))
        layout.addLayout(panel, 2)
        self.add_tab()

    def browser(self):
        return self.tabs.currentWidget()

    def add_tab(self):
        view = QWebEngineView()
        view.setHtml(HOME, QUrl("about:blank"))
        idx = self.tabs.addTab(view, "New Tab")
        view.titleChanged.connect(lambda title, v=view: self.rename_tab(v, title))
        view.urlChanged.connect(lambda url, v=view: self.sync_url(v, url))
        self.tabs.setCurrentIndex(idx)

    def rename_tab(self, view, title):
        index=self.tabs.indexOf(view)
        if index >= 0: self.tabs.setTabText(index, title[:24] or "New Tab")

    def sync_url(self, view, url):
        if view is self.browser(): self.address.setText(url.toString() if url.scheme() in ("http","https") else "")

    def navigate(self):
        raw=self.address.text().strip()
        if not raw: return
        if "://" not in raw: raw="https://"+raw
        url=QUrl(raw)
        if url.scheme() not in ("http","https") or not url.host():
            self.status.setText("Blocked: only valid HTTP/HTTPS destinations are supported")
            return
        self.browser().setUrl(url)

    def back(self): self.browser().back()
    def forward(self): self.browser().forward()
    def reload(self): self.browser().reload()
    def home(self): self.browser().setHtml(HOME,QUrl("about:blank"))
    def tab_changed(self, _):
        view=self.browser()
        if view: self.sync_url(view,view.url())
    def close_tab(self, index):
        if self.tabs.count() == 1: return
        view=self.tabs.widget(index)
        self.tabs.removeTab(index)
        view.deleteLater()
    def show_section(self, name):
        self.status.setText(name + " · full integration pending; no telemetry is simulated")

def main():
    app=QApplication(sys.argv)
    window=Window()
    window.show()
    return app.exec()

if __name__=="__main__":
    sys.exit(main())
