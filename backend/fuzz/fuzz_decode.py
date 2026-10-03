#!/usr/bin/env python3
"""Fuzz the layered decoder (``app.analysis.decode.decode_layers``).

The decoder unwraps base64/hex/compressed payloads found inside packages, so it runs on bytes an
attacker chose. Its contract (``fuzz/contracts.py``) is that it never raises, never exceeds its
output bound - a decompression bomb must be cut, not allocated - and never puts a raw payload into
evidence.

    PYTHONPATH=. python fuzz/fuzz_decode.py -max_total_time=60 fuzz/corpus/decode
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from fuzz.contracts import check_decode


def test_one_input(data: bytes) -> None:
    check_decode(data)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
