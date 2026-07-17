"""Cipher implementations for CipherLab.

All ciphers preserve the user-facing rules in the project brief:
- classical ciphers only transform letters
- case is preserved
- punctuation, whitespace, and digits are left unchanged
- substitution is reproducible from a seed
- XOR is symmetric and operates across byte values
"""

from __future__ import annotations

import random
import string


_ALPHABET = string.ascii_uppercase


def _shift_character(character: str, shift: int) -> str:
    if character.isalpha() and len(character) == 1:
        base = ord("A") if character.isupper() else ord("a")
        return chr((ord(character) - base + shift) % 26 + base)
    return character


def _coerce_key_bytes(key: object) -> bytes:
    if isinstance(key, bytes):
        return key or b"\x00"
    if isinstance(key, int):
        return bytes([key & 0xFF])
    key_text = str(key)
    return key_text.encode("utf-8") or b"\x00"


class CaesarCipher:
    def __init__(self, shift_key: int = 3) -> None:
        self.shift_key = shift_key % 26

    def encrypt(self, plaintext: str) -> str:
        return "".join(_shift_character(character, self.shift_key) for character in plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return "".join(_shift_character(character, -self.shift_key) for character in ciphertext)


class VigenereCipher:
    def __init__(self, key: str) -> None:
        cleaned_key = [character for character in str(key) if character.isalpha()]
        self.key = "".join(cleaned_key).upper() or "A"

    def _key_shifts(self):
        while True:
            for character in self.key:
                yield ord(character) - ord("A")

    def encrypt(self, plaintext: str) -> str:
        result = []
        key_shifts = self._key_shifts()
        for character in plaintext:
            if character.isalpha():
                shift = next(key_shifts)
                result.append(_shift_character(character, shift))
            else:
                result.append(character)
        return "".join(result)

    def decrypt(self, ciphertext: str) -> str:
        result = []
        key_shifts = self._key_shifts()
        for character in ciphertext:
            if character.isalpha():
                shift = next(key_shifts)
                result.append(_shift_character(character, -shift))
            else:
                result.append(character)
        return "".join(result)


class ROT13Cipher:
    def __init__(self) -> None:
        self.shift_key = 13

    def encrypt(self, plaintext: str) -> str:
        return "".join(_shift_character(character, self.shift_key) for character in plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self.encrypt(ciphertext)


class AtbashCipher:
    def __init__(self) -> None:
        self.mapping = {character: _ALPHABET[::-1][index] for index, character in enumerate(_ALPHABET)}

    def _transform(self, text: str) -> str:
        transformed = []
        for character in text:
            if character.isalpha() and len(character) == 1:
                mapped = self.mapping[character.upper()]
                transformed.append(mapped if character.isupper() else mapped.lower())
            else:
                transformed.append(character)
        return "".join(transformed)

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext)


class SubstitutionCipher:
    def __init__(self, seed: int = 42) -> None:
        self.seed = seed
        rng = random.Random(seed)
        shuffled = list(_ALPHABET)
        rng.shuffle(shuffled)
        self.mapping = {plain: cipher for plain, cipher in zip(_ALPHABET, shuffled)}
        self.reverse_mapping = {cipher: plain for plain, cipher in self.mapping.items()}

    def _substitute(self, text: str, mapping: dict[str, str]) -> str:
        transformed = []
        for character in text:
            if character.isalpha() and len(character) == 1:
                mapped = mapping[character.upper()]
                transformed.append(mapped if character.isupper() else mapped.lower())
            else:
                transformed.append(character)
        return "".join(transformed)

    def encrypt(self, plaintext: str) -> str:
        return self._substitute(plaintext, self.mapping)

    def decrypt(self, ciphertext: str) -> str:
        return self._substitute(ciphertext, self.reverse_mapping)


class XORCipher:
    def __init__(self, key: object) -> None:
        self.key_bytes = _coerce_key_bytes(key)

    def _transform(self, text: str) -> str:
        data = text.encode("latin1", errors="strict")
        transformed = bytearray()
        for index, byte in enumerate(data):
            transformed.append(byte ^ self.key_bytes[index % len(self.key_bytes)])
        return transformed.decode("latin1")

    def encrypt(self, plaintext: str) -> str:
        return self._transform(plaintext)

    def decrypt(self, ciphertext: str) -> str:
        return self._transform(ciphertext)
