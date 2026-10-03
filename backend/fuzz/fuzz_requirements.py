#!/usr/bin/env python3
"""Fuzz the requirements parser (``app.sbom.parsers.requirements.parse_requirements``).

Warden parses manifests from repositories it does not control, including the ``-r`` / ``-c``
includes they chain to. The parser must report problems as warnings and never raise, never exceed
the dependency limit, and never store a credential it read (contract in ``fuzz/contracts.py``).

    PYTHONPATH=. python fuzz/fuzz_requirements.py -max_total_time=60 fuzz/corpus/requirements
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from fuzz.contracts import check_requirements


def test_one_input(data: bytes) -> None:
    provider = atheris.FuzzedDataProvider(data)
    root = provider.ConsumeBytes(provider.ConsumeIntInRange(0, 8192))
    included = provider.ConsumeBytes(provider.remaining_bytes())
    check_requirements(root, included)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
