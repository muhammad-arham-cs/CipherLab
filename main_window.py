"""Main application window for CipherLab."""

from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QSplitter,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from cipher_engine import AtbashCipher, CaesarCipher, ROT13Cipher, SubstitutionCipher, VigenereCipher, XORCipher
from config import CIPHER_NAMES, THREAT_DATA
from frequency_analyzer import analyze_frequency
from ui_components import FrequencyChart, ThreatPanel


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._updating = False
        self.setWindowTitle("CipherLab - Multi-Cipher Encryption Suite")
        self.setGeometry(100, 100, 1200, 800)
        self._build_ui()
        self.on_cipher_changed()

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)

        root_layout = QVBoxLayout(central)
        root_layout.setContentsMargins(16, 16, 16, 16)
        root_layout.setSpacing(12)

        self.toolbar = QToolBar()
        self.toolbar.setMovable(False)
        self.toolbar.setFloatable(False)
        self.addToolBar(Qt.ToolBarArea.TopToolBarArea, self.toolbar)

        cipher_label = QLabel("Cipher")
        self.cipher_combo = QComboBox()
        self.cipher_combo.addItems(CIPHER_NAMES)
        self.cipher_combo.currentTextChanged.connect(self.on_cipher_changed)

        key_label = QLabel("Key")
        self.key_input = QLineEdit()
        self.key_input.setPlaceholderText("Shift, keyword, seed, or XOR key")
        self.key_input.textChanged.connect(self.on_key_changed)

        self.toolbar.addWidget(cipher_label)
        self.toolbar.addWidget(self.cipher_combo)
        self.toolbar.addSeparator()
        self.toolbar.addWidget(key_label)
        self.toolbar.addWidget(self.key_input)

        self.splitter = QSplitter(Qt.Orientation.Horizontal)

        self.plaintext_edit = QTextEdit()
        self.plaintext_edit.setPlaceholderText("Enter plaintext here")
        self.plaintext_edit.textChanged.connect(self.on_plaintext_changed)

        self.ciphertext_edit = QTextEdit()
        self.ciphertext_edit.setReadOnly(True)
        self.ciphertext_edit.setPlaceholderText("Ciphertext appears here")

        left_panel = self._panel_with_title("PLAINTEXT", self.plaintext_edit)
        right_panel = self._panel_with_title("CIPHERTEXT", self.ciphertext_edit)

        self.splitter.addWidget(left_panel)
        self.splitter.addWidget(right_panel)
        self.splitter.setSizes([600, 600])
        root_layout.addWidget(self.splitter, stretch=3)

        button_row = QHBoxLayout()
        self.encrypt_button = QPushButton("Encrypt")
        self.decrypt_button = QPushButton("Decrypt")
        self.clear_button = QPushButton("Clear")
        self.copy_button = QPushButton("Copy Ciphertext")

        self.encrypt_button.clicked.connect(self.encrypt)
        self.decrypt_button.clicked.connect(self.decrypt)
        self.clear_button.clicked.connect(self.clear_all)
        self.copy_button.clicked.connect(self.copy_ciphertext)

        for button in (self.encrypt_button, self.decrypt_button, self.clear_button, self.copy_button):
            button_row.addWidget(button)
        button_row.addStretch(1)
        root_layout.addLayout(button_row)

        self.tabs = QTabWidget()
        self.threat_panel = ThreatPanel()
        self.frequency_chart = FrequencyChart()
        self.tabs.addTab(self.threat_panel, "Threat Analysis")
        self.tabs.addTab(self.frequency_chart, "Frequency Analysis")
        root_layout.addWidget(self.tabs, stretch=2)

    def _panel_with_title(self, title: str, widget: QWidget) -> QWidget:
        frame = QFrame()
        frame.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(frame)
        heading = QLabel(title)
        heading.setObjectName("panelHeading")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(heading)
        layout.addWidget(widget)
        return frame

    def get_cipher_instance(self, cipher_name: str, key: str):
        normalized = cipher_name.strip().lower()
        if normalized == "caesar":
            try:
                return CaesarCipher(int(key) if key else 3)
            except ValueError:
                return CaesarCipher(3)
        if normalized == "vigenere":
            return VigenereCipher(key or "KEY")
        if normalized == "rot13":
            return ROT13Cipher()
        if normalized == "atbash":
            return AtbashCipher()
        if normalized == "substitution":
            try:
                return SubstitutionCipher(int(key) if key else 42)
            except ValueError:
                return SubstitutionCipher(42)
        if normalized == "xor":
            return XORCipher(key or "CipherLab")
        return CaesarCipher(3)

    def _current_cipher(self):
        return self.get_cipher_instance(self.cipher_combo.currentText(), self.key_input.text())

    def _refresh_views(self) -> None:
        plaintext = self.plaintext_edit.toPlainText()
        cipher = self._current_cipher()
        ciphertext = cipher.encrypt(plaintext)
        self._updating = True
        self.ciphertext_edit.setPlainText(ciphertext)
        self._updating = False
        self.frequency_chart.update_chart(analyze_frequency(ciphertext))

    def on_cipher_changed(self, *_args) -> None:
        cipher_name = self.cipher_combo.currentText()
        threat_data = THREAT_DATA[cipher_name]
        self.threat_panel.update_threat_data(threat_data)

        keyless = cipher_name in {"ROT13", "Atbash"}
        self.key_input.setEnabled(not keyless)
        if keyless:
            self.key_input.setPlaceholderText("No key required")
        elif cipher_name == "Caesar":
            self.key_input.setPlaceholderText("Shift value")
        elif cipher_name == "Vigenère":
            self.key_input.setPlaceholderText("Alphabetic key")
        elif cipher_name == "Substitution":
            self.key_input.setPlaceholderText("Seed value")
        else:
            self.key_input.setPlaceholderText("XOR key")
        self._refresh_views()

    def on_key_changed(self, *_args) -> None:
        if not self._updating:
            self._refresh_views()

    def on_plaintext_changed(self, *_args) -> None:
        if not self._updating:
            self._refresh_views()

    def encrypt(self) -> None:
        self._refresh_views()

    def decrypt(self) -> None:
        cipher = self._current_cipher()
        ciphertext = self.ciphertext_edit.toPlainText()
        plaintext = cipher.decrypt(ciphertext)
        self._updating = True
        self.plaintext_edit.setPlainText(plaintext)
        self._updating = False
        self._refresh_views()

    def clear_all(self) -> None:
        self._updating = True
        self.plaintext_edit.clear()
        self.ciphertext_edit.clear()
        self._updating = False
        self.frequency_chart.update_chart({letter: 0.0 for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ"})

    def copy_ciphertext(self) -> None:
        QApplication.clipboard().setText(self.ciphertext_edit.toPlainText())
