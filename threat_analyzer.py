"""Threat metadata for CipherLab ciphers."""

from __future__ import annotations

from copy import deepcopy


_THREAT_MAP = {
    "caesar": {
        "threat_level": "CRITICAL",
        "key_space": "25",
        "brute_force_time": "<1 second",
        "cracking_method": "Brute force",
        "vulnerabilities": ["Frequency analysis", "Pattern preservation"],
        "historical_status": "Broken 1st century AD",
        "recommendation": "DO NOT USE",
    },
    "vigenere": {
        "threat_level": "MODERATE",
        "key_space": "26^n",
        "brute_force_time": "2-24 hours",
        "cracking_method": "Kasiski examination",
        "vulnerabilities": ["Frequency analysis", "Pattern preservation"],
        "historical_status": "Broken 1863",
        "recommendation": "Historical only",
    },
    "rot13": {
        "threat_level": "TRIVIAL",
        "key_space": "1",
        "brute_force_time": "instant",
        "cracking_method": "Brute force",
        "vulnerabilities": ["Deterministic"],
        "historical_status": "Single solution",
        "recommendation": "Forum spoiler only",
    },
    "atbash": {
        "threat_level": "CRITICAL",
        "key_space": "1",
        "brute_force_time": "instant",
        "cracking_method": "Brute force",
        "vulnerabilities": ["Deterministic"],
        "historical_status": "Deterministic",
        "recommendation": "DO NOT USE",
    },
    "substitution": {
        "threat_level": "MODERATE",
        "key_space": "26!",
        "brute_force_time": "centuries",
        "cracking_method": "Frequency analysis",
        "vulnerabilities": ["Frequency analysis", "Pattern preservation"],
        "historical_status": "Still vulnerable",
        "recommendation": "Educational",
    },
    "xor": {
        "threat_level": "MODERATE",
        "key_space": "2^256",
        "brute_force_time": "10^56 years",
        "cracking_method": "Known-plaintext attack",
        "vulnerabilities": ["Deterministic"],
        "historical_status": "Foundation of stream ciphers",
        "recommendation": "Use in stream ciphers only",
    },
}


_ALIASES = {
    "caesar": "caesar",
    "vigenere": "vigenere",
    "vigenère": "vigenere",
    "rot13": "rot13",
    "atbash": "atbash",
    "substitution": "substitution",
    "xor": "xor",
}


def _normalize_name(cipher_name: str) -> str:
    normalized = cipher_name.strip().lower()
    return _ALIASES.get(normalized, normalized)


def get_threat_data(cipher_name: str):
    canonical_name = _normalize_name(cipher_name)
    threat_data = _THREAT_MAP.get(canonical_name)
    if threat_data is None:
        raise KeyError(f"Unknown cipher: {cipher_name}")
    return deepcopy(threat_data)
