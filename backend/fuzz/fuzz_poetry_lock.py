#!/usr/bin/env python3
"""Fuzz the ``poetry.lock`` parser (``app.sbom.parsers.poetry_lock.parse_poetry_lock``).

The parser reads TOML from a scanned repository. Malformed TOML, a recursive structure or wrong
types must become warnings, not exceptions, and whatever survives must be well-formed enough for the
SBOM writers downstream.

    python fuzz/fuzz_poetry_lock.py -max_total_time=60 fuzz/corpus/poetry_lock
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from packaging.utils import canonicalize_name

    from app.sbom.parsers.poetry_lock import parse_poetry_lock

PATH = "poetry.lock"


def test_one_input(data: bytes) -> None:
    result = parse_poetry_lock(PATH, data)

    for package in result.packages:
        assert package.normalized_name == canonicalize_name(package.normalized_name), (
            f"name {package.normalized_name!r} is not canonical"
        )
        assert package.scope in {"required", "optional", "dev"}, f"unexpected scope {package.scope!r}"
        for digest in package.hashes:
            prefix, _, hexdigest = digest.partition(":")
            assert prefix == "sha256" and len(hexdigest) == 64, f"malformed hash {digest!r}"
        for child, specifier in package.dependencies:
            assert child == canonicalize_name(child), f"edge name {child!r} is not canonical"
            assert isinstance(specifier, str)
        assert package.source_url is None or "\x00" not in package.source_url
    for warning in result.warnings:
        assert "\x00" not in warning, "NUL byte survived into a warning"
    for manifest in result.manifests:
        assert manifest.get("status") in {"parsed", "too_large", "error"}, f"unexpected status {manifest!r}"


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
