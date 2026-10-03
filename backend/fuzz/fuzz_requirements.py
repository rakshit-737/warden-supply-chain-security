#!/usr/bin/env python3
"""Fuzz the requirements parser (``app.sbom.parsers.requirements.parse_requirements``).

Warden parses manifests from repositories it does not control, including the ``-r`` / ``-c``
includes they chain to. The parser must report problems as warnings and never raise, never exceed
the dependency limit, and never emit a credential it read.

    python fuzz/fuzz_requirements.py -max_total_time=60 fuzz/corpus/requirements
"""

from __future__ import annotations

import sys

import atheris

with atheris.instrument_imports():
    from packaging.utils import canonicalize_name

    from app.sbom.parsers.requirements import parse_requirements

MAX_DEPENDENCIES = 256
ROOT = "requirements.txt"
# A second file so include handling (`-r`, `-c`) and include cycles get exercised.
INCLUDED = "constraints.txt"


def test_one_input(data: bytes) -> None:
    provider = atheris.FuzzedDataProvider(data)
    root_bytes = provider.ConsumeBytes(provider.ConsumeIntInRange(0, 8192))
    included_bytes = provider.ConsumeBytes(provider.remaining_bytes())
    files = {ROOT: root_bytes, INCLUDED: included_bytes}

    result = parse_requirements(ROOT, files, max_dependencies=MAX_DEPENDENCIES)

    assert len(result.dependencies) <= MAX_DEPENDENCIES, f"{len(result.dependencies)} dependencies past the limit"
    for dep in result.dependencies:
        assert dep.normalized_name == canonicalize_name(dep.normalized_name), (
            f"name {dep.normalized_name!r} is not canonical"
        )
        assert dep.kind in {"requirement", "constraint", "lock"}, f"unexpected kind {dep.kind!r}"
        assert dep.scope in {"required", "optional", "dev"}, f"unexpected scope {dep.scope!r}"
        for digest in dep.hashes:
            assert digest.startswith("sha256:"), f"malformed hash {digest!r}"
        # Whatever sits before the first "@" of the authority is userinfo, and a credential may hide
        # in it. Only an empty userinfo or the conventional "git" user may survive redaction.
        authority = (dep.url or "").split("//", 1)[-1].split("/", 1)[0]
        userinfo = authority.split("@", 1)[0] if "@" in authority else ""
        assert userinfo in {"", "git", "[REDACTED]"}, f"URL userinfo not redacted: {dep.url!r}"
    for warning in result.warnings:
        assert isinstance(warning, str)
        assert "\x00" not in warning, "NUL byte survived into a warning"
    for source in result.index_sources:
        assert isinstance(source, dict)


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
