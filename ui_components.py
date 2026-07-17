"""Reusable PyQt6 widgets for CipherLab."""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure

from config import THREAT_COLORS


class ThreatPanel(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.level_value = QLabel("-")
        self.key_space_value = QLabel("-")
        self.brute_force_value = QLabel("-")
        self.cracking_method_value = QLabel("-")
        self.vulnerabilities_value = QLabel("-")
        self.historical_status_value = QLabel("-")
        self.recommendation_value = QLabel("-")

        for label in (
            self.level_value,
            self.key_space_value,
            self.brute_force_value,
            self.cracking_method_value,
            self.vulnerabilities_value,
            self.historical_status_value,
            self.recommendation_value,
        ):
            label.setWordWrap(True)
            label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

        self.container = QFrame()
        self.container.setObjectName("threatContainer")
        self.container.setFrameShape(QFrame.Shape.StyledPanel)

        form_layout = QFormLayout(self.container)
        form_layout.setLabelAlignment(Qt.AlignmentFlag.AlignTop)

        self.level_heading = QLabel("Threat Level")
        self.level_heading.setObjectName("threatHeading")
        self.level_heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.level_heading.setMinimumHeight(48)

        form_layout.addRow(self.level_heading)
        form_layout.addRow("Level", self.level_value)
        form_layout.addRow("Key Space", self.key_space_value)
        form_layout.addRow("Brute Force Time", self.brute_force_value)
        form_layout.addRow("Cracking Method", self.cracking_method_value)
        form_layout.addRow("Vulnerabilities", self.vulnerabilities_value)
        form_layout.addRow("Historical Status", self.historical_status_value)
        form_layout.addRow("Recommendation", self.recommendation_value)

        layout = QVBoxLayout(self)
        layout.addWidget(self.container)

    def update_threat_data(self, threat_dict: dict) -> None:
        threat_level = threat_dict.get("threat_level", "-")
        self.level_heading.setText(threat_level)
        self.level_value.setText(threat_level)
        self.key_space_value.setText(str(threat_dict.get("key_space", "-")))
        self.brute_force_value.setText(str(threat_dict.get("brute_force_time", "-")))
        self.cracking_method_value.setText(str(threat_dict.get("cracking_method", "-")))

        vulnerabilities = threat_dict.get("vulnerabilities", [])
        if isinstance(vulnerabilities, (list, tuple)):
            vulnerabilities_text = "\n".join(f"• {item}" for item in vulnerabilities)
        else:
            vulnerabilities_text = str(vulnerabilities)
        self.vulnerabilities_value.setText(vulnerabilities_text)

        self.historical_status_value.setText(str(threat_dict.get("historical_status", "-")))
        self.recommendation_value.setText(str(threat_dict.get("recommendation", "-")))

        color = THREAT_COLORS.get(threat_level, THREAT_COLORS["TRIVIAL"])
        self.container.setStyleSheet(
            f"#threatContainer {{ background-color: {color}; border-radius: 14px; padding: 12px; }}"
            "#threatContainer QLabel { color: #111111; font-size: 14px; }"
            "#threatHeading { color: #111111; font-size: 22px; font-weight: 700; }"
        )


class FrequencyChart(QWidget):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.figure = Figure(figsize=(8, 4), dpi=100)
        self.figure.patch.set_facecolor("#12151c")
        self.canvas = FigureCanvas(self.figure)
        self.canvas.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

        self.axes = self.figure.add_subplot(111)
        self.axes.set_facecolor("#12151c")

        layout = QHBoxLayout(self)
        layout.addWidget(self.canvas)

        self.update_chart({letter: 0.0 for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"})

    def update_chart(self, freq_dict: dict) -> None:
        letters = [chr(code) for code in range(ord("A"), ord("Z") + 1)]
        values = [float(freq_dict.get(letter, 0.0)) for letter in letters]

        self.axes.clear()
        self.axes.set_facecolor("#12151c")
        self.axes.bar(letters, values, color="#5bbcff", edgecolor="#d7e8ff", linewidth=0.5)
        self.axes.set_ylim(0, max(10.0, max(values, default=0.0) + 5.0))
        self.axes.set_ylabel("Frequency (%)", color="#edf2f7")
        self.axes.set_xlabel("Letters", color="#edf2f7")
        self.axes.tick_params(axis="x", colors="#edf2f7")
        self.axes.tick_params(axis="y", colors="#edf2f7")
        self.axes.grid(axis="y", alpha=0.2, color="#edf2f7")
        self.figure.tight_layout()
        self.canvas.draw_idle()
