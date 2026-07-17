"""Command line interface for CipherLab."""

from __future__ import annotations

import sys

from cipher_engine import AtbashCipher, CaesarCipher, ROT13Cipher, SubstitutionCipher, VigenereCipher, XORCipher


def _build_cipher(cipher_name: str, key: str | None):
    normalized = cipher_name.strip().lower()
    if normalized == "caesar":
        return CaesarCipher(int(key) if key is not None else 3)
    if normalized == "vigenere":
        return VigenereCipher(key or "KEY")
    if normalized == "rot13":
        return ROT13Cipher()
    if normalized == "atbash":
        return AtbashCipher()
    if normalized == "substitution":
        return SubstitutionCipher(int(key) if key is not None else 42)
    if normalized == "xor":
        return XORCipher(key or "CipherLab")
    raise ValueError(f"Unsupported cipher: {cipher_name}")


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if len(args) < 2:
        print("Usage: python cli.py <cipher> <text> [key]")
        print("Ciphers: caesar, vigenere, rot13, atbash, substitution, xor")
        return 1

    cipher_name = args[0]
    text = args[1]
    key = args[2] if len(args) > 2 else None

    try:
        cipher = _build_cipher(cipher_name, key)
    except ValueError as error:
        print(error)
        return 1

    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)

    print(f"Cipher: {cipher_name}")
    print(f"Plaintext: {text}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
