"""Frequency analysis helpers."""

from __future__ import annotations

import string


def analyze_frequency(text: str):
    counts = {character: 0 for character in string.ascii_uppercase}
    total_letters = 0

    for character in text:
        if character.isalpha() and len(character) == 1:
            counts[character.upper()] += 1
            total_letters += 1

    if total_letters == 0:
        return {character: 0.0 for character in string.ascii_uppercase}

    return {
        character: round((count / total_letters) * 100, 1)
        for character, count in counts.items()
    }
