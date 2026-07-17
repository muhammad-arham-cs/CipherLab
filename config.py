"""Shared configuration for CipherLab."""

from __future__ import annotations

from threat_analyzer import get_threat_data


THREAT_COLORS = {
    "CRITICAL": "#FF4444",
    "MODERATE": "#FFAA00",
    "LOW": "#44FF44",
    "TRIVIAL": "#888888",
}


CIPHER_NAMES = ["Caesar", "Vigenère", "ROT13", "Atbash", "Substitution", "XOR"]


THREAT_DATA = {cipher_name: get_threat_data(cipher_name) for cipher_name in CIPHER_NAMES}
