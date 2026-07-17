"""CipherLab application entry point."""

from __future__ import annotations

import sys
from pathlib import Path

from PyQt6.QtWidgets import QApplication

from main_window import MainWindow


def _load_stylesheet(app: QApplication) -> None:
    stylesheet_path = Path(__file__).with_name("resources").joinpath("styles.qss")
    if stylesheet_path.exists():
        app.setStyleSheet(stylesheet_path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    app = QApplication(sys.argv)
    _load_stylesheet(app)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
