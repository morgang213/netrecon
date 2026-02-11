"""Main window and entry point for the NetRecon GUI."""

import sys

from PySide6.QtCore import Qt
from PySide6.QtGui import QFont
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QListWidget,
    QListWidgetItem,
    QMainWindow,
    QSplitter,
    QStackedWidget,
    QWidget,
)

from netrecon.gui.panels import ALL_PANELS


class NetReconWindow(QMainWindow):
    """Main application window with sidebar + tool panels."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle(
            "NetRecon v0.2.0 — Network Security & Penetration Testing Suite"
        )
        self.resize(1100, 700)
        self._build_ui()

    def _build_ui(self):
        # Central widget with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Sidebar ──────────────────────────────────────────
        sidebar_widget = QWidget()
        sidebar_layout = QHBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        self._sidebar = QListWidget()
        self._sidebar.setFixedWidth(220)
        self._sidebar.setFont(QFont("", 11))
        self._sidebar.setStyleSheet(
            "QListWidget { "
            "background: qlineargradient(x1:0, y1:0, x2:0, y2:1, "
            "stop:0 #1e3a5f, stop:1 #2c3e50); "
            "color: white; "
            "border: none; "
            "padding-top: 12px; "
            "} "
            "QListWidget::item { "
            "padding: 12px 16px; "
            "border-left: 3px solid transparent; "
            "} "
            "QListWidget::item:selected { "
            "background: qlineargradient(x1:0, y1:0, x2:1, y2:0, "
            "stop:0 #3498db, stop:1 #2980b9); "
            "color: white; "
            "border-left: 3px solid #e74c3c; "
            "font-weight: bold; "
            "} "
            "QListWidget::item:hover:!selected { "
            "background: rgba(52, 152, 219, 0.3); "
            "border-left: 3px solid #3498db; "
            "}"
        )
        sidebar_layout.addWidget(self._sidebar)
        splitter.addWidget(sidebar_widget)

        # ── Stacked tool panels ──────────────────────────────
        self._stack = QStackedWidget()
        splitter.addWidget(self._stack)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)

        self.setCentralWidget(splitter)

        # Status bar
        self._status = self.statusBar()
        self._status.setStyleSheet(
            "QStatusBar { "
            "background: #ecf0f1; "
            "color: #2c3e50; "
            "font-size: 11px; "
            "padding: 4px; "
            "}"
        )
        self._status.showMessage("Ready — Select a tool to begin")

        # ── Register panels ──────────────────────────────────
        for panel_cls in ALL_PANELS:
            label = panel_cls.tool_label
            if panel_cls.is_active:
                label += "  ⚡"

            item = QListWidgetItem(label)
            self._sidebar.addItem(item)

            panel = panel_cls(status_bar=self._status)
            self._stack.addWidget(panel)

        self._sidebar.currentRowChanged.connect(self._stack.setCurrentIndex)
        self._sidebar.setCurrentRow(0)


def main():
    """Entry point for netrecon-gui."""
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    window = NetReconWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
