from __future__ import annotations

from cipher_engine import AtbashCipher, CaesarCipher, ROT13Cipher, SubstitutionCipher, VigenereCipher, XORCipher


def _run_cipher_roundtrip(cipher, text: str):
    encrypted = cipher.encrypt(text)
    decrypted = cipher.decrypt(encrypted)
    return encrypted, decrypted


class TestCaesarCipher:
    def setup_method(self):
        self.cipher = CaesarCipher(3)

    def test_basic(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello")
        assert decrypted == "hello"

    def test_spaces(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello world")
        assert decrypted == "hello world"

    def test_case(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "HeLLo")
        assert decrypted == "HeLLo"

    def test_punctuation(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello!")
        assert decrypted == "hello!"

    def test_empty(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "")
        assert decrypted == ""

    def test_single(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "a")
        assert decrypted == "a"

    def test_numbers(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "test123")
        assert decrypted == "test123"


class TestVigenereCipher:
    def setup_method(self):
        self.cipher = VigenereCipher("KEY")

    def test_basic(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello")
        assert decrypted == "hello"

    def test_spaces(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello world")
        assert decrypted == "hello world"

    def test_case(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "HeLLo")
        assert decrypted == "HeLLo"

    def test_punctuation(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello!")
        assert decrypted == "hello!"

    def test_empty(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "")
        assert decrypted == ""

    def test_single(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "a")
        assert decrypted == "a"

    def test_numbers(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "test123")
        assert decrypted == "test123"


class TestROT13Cipher:
    def setup_method(self):
        self.cipher = ROT13Cipher()

    def test_basic(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello")
        assert decrypted == "hello"

    def test_spaces(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello world")
        assert decrypted == "hello world"

    def test_case(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "HeLLo")
        assert decrypted == "HeLLo"

    def test_punctuation(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello!")
        assert decrypted == "hello!"

    def test_empty(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "")
        assert decrypted == ""

    def test_single(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "a")
        assert decrypted == "a"

    def test_numbers(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "test123")
        assert decrypted == "test123"


class TestAtbashCipher:
    def setup_method(self):
        self.cipher = AtbashCipher()

    def test_basic(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello")
        assert decrypted == "hello"

    def test_spaces(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello world")
        assert decrypted == "hello world"

    def test_case(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "HeLLo")
        assert decrypted == "HeLLo"

    def test_punctuation(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello!")
        assert decrypted == "hello!"

    def test_empty(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "")
        assert decrypted == ""

    def test_single(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "a")
        assert decrypted == "a"

    def test_numbers(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "test123")
        assert decrypted == "test123"


class TestSubstitutionCipher:
    def setup_method(self):
        self.cipher = SubstitutionCipher(seed=42)

    def test_basic(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello")
        assert decrypted == "hello"

    def test_spaces(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello world")
        assert decrypted == "hello world"

    def test_case(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "HeLLo")
        assert decrypted == "HeLLo"

    def test_punctuation(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello!")
        assert decrypted == "hello!"

    def test_empty(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "")
        assert decrypted == ""

    def test_single(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "a")
        assert decrypted == "a"

    def test_numbers(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "test123")
        assert decrypted == "test123"


class TestXORCipher:
    def setup_method(self):
        self.cipher = XORCipher("CipherLab")

    def test_basic(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello")
        assert decrypted == "hello"

    def test_spaces(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello world")
        assert decrypted == "hello world"

    def test_case(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "HeLLo")
        assert decrypted == "HeLLo"

    def test_punctuation(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "hello!")
        assert decrypted == "hello!"

    def test_empty(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "")
        assert decrypted == ""

    def test_single(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "a")
        assert decrypted == "a"

    def test_numbers(self):
        _, decrypted = _run_cipher_roundtrip(self.cipher, "test123")
        assert decrypted == "test123"
