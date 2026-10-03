#!/usr/bin/env python3
"""Fuzz the ``poetry.lock`` parser (``app.sbom.parsers.poetry_lock.parse_poetry_lock``).

The parser reads TOML from a scanned repository. Malformed TOML, a recursive structure or wrong
types must become warnings, not exceptions, and whatever survives must be well-formed enough for the
SBOM writers downstream (contract in ``fuzz/contracts.py``).

    PYTHONPATH=. python fuzz/fuzz_poetry_lock.py -max_total_time=60 fuzz/corpus/poetry_lock
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from fuzz.contracts import check_poetry_lock


def test_one_input(data: bytes) -> None:
    check_poetry_lock(data)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
