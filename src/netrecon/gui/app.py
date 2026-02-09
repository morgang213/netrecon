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
        self.setWindowTitle("NetRecon — Network Security Tools Suite")
        self.resize(960, 640)
        self._build_ui()

    def _build_ui(self):
        # Central widget with splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ── Sidebar ──────────────────────────────────────────
        sidebar_widget = QWidget()
        sidebar_layout = QHBoxLayout(sidebar_widget)
        sidebar_layout.setContentsMargins(0, 0, 0, 0)

        self._sidebar = QListWidget()
        self._sidebar.setFixedWidth(180)
        self._sidebar.setFont(QFont("", 12))
        self._sidebar.setStyleSheet(
            "QListWidget { background: #2c3e50; color: white;"
            "border: none; padding-top: 8px; }"
            "QListWidget::item { padding: 10px 14px; }"
            "QListWidget::item:selected {"
            "background: #3498db; color: white; }"
            "QListWidget::item:hover:!selected {"
            "background: #34495e; }"
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
        self._status.showMessage("Ready")

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
