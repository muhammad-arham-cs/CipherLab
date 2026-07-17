# CipherLab - Multi-Cipher Encryption Suite

CipherLab is a Windows desktop encryption suite for DecodeLabs Project 2. It combines six classic and modern teaching ciphers with live threat analysis and frequency visualization.

## Features

- 6 ciphers: Caesar, Vigenère, ROT13, Atbash, Substitution, and XOR
- Real-time encryption and decryption in a PyQt6 desktop GUI
- Threat analysis panel with color-coded risk information
- Frequency analysis bar chart for letter distribution
- Command-line interface for quick testing
- Pytest suite covering round-trip behavior for every cipher

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### GUI

```bash
python app.py
```

### CLI

```bash
python cli.py <cipher> <text> [key]
```

Examples:

```bash
python cli.py caesar "hello" 3
python cli.py vigenere "attackatdawn" KEY
python cli.py rot13 "hello world"
python cli.py substitution "hello" 42
```

## Running Tests

```bash
pytest test_ciphers.py -v
```

## Cipher Comparison

| Cipher | Key Space | Status | Recommendation |
| --- | --- | --- | --- |
| Caesar | 25 | Broken | Do not use |
| Vigenère | 26^n | Broken | Historical only |
| ROT13 | 1 | Trivial | Forum spoiler only |
| Atbash | 1 | Deterministic | Do not use |
| Substitution | 26! | Vulnerable | Educational only |
| XOR | 2^256 | Strong in stream-cipher contexts | Use only in proper stream ciphers |

## Security Notice

CipherLab is intended for education, demonstration, and analysis only. It is not a production encryption system.


