"""The contracts the fuzz harnesses assert, in one place.

Each ``check_*`` takes the bytes a fuzzer produced, calls its target and asserts what that target
promises. They are plain functions with no Atheris import, so the same contracts run under libFuzzer
(``fuzz_*.py``) and under the dependency-free runner (``run_local.py``) on a machine with no Atheris
wheel. Keeping one definition is the point: a second copy drifts from the implementation and starts
reporting failures that are not bugs.
"""

from __future__ import annotations

import json
import re

from packaging.utils import canonicalize_name

from app.analysis.decode import decode_layers
from app.sbom.parsers.poetry_lock import parse_poetry_lock
from app.sbom.parsers.requirements import parse_requirements

MAX_DEPTH = 4
MAX_OUTPUT = 64 * 1024
MAX_DEPENDENCIES = 256
ROOT = "requirements.txt"
# A second file so include handling (`-r`, `-c`) and include cycles get exercised.
INCLUDED = "constraints.txt"
LOCK_PATH = "poetry.lock"

# "<userinfo>@<host>" at the start of a reference or after "//": the only shape in which a stored
# reference hands a credential to a server. The host part is required, so "token@/path" (no host)
# and "path#a@b" (not an authority, the authority ends at the first "/", "?" or "#") do not match.
AUTHORITY_USERINFO_RE = re.compile(r"(?:\A|//)(?P<userinfo>[^\s/?#]{1,256})@(?P<host>[^\s/?#:@]+)")


def assert_no_credential(url: str | None) -> None:
    """A stored URL may keep the ``git`` SSH user; anything else must carry the redaction marker."""
    match = AUTHORITY_USERINFO_RE.search(url or "")
    userinfo = match.group("userinfo") if match else ""
    assert not userinfo or userinfo == "git" or "[REDACTED]" in userinfo, (
        f"URL userinfo not redacted: {url!r}"
    )


def check_decode(data: bytes) -> None:
    """``decode_layers`` never raises, stays inside its bounds and emits display-safe evidence."""
    result = decode_layers(data, max_depth=MAX_DEPTH, max_output=MAX_OUTPUT)

    assert result.depth <= MAX_DEPTH, f"depth {result.depth} exceeds max_depth {MAX_DEPTH}"
    assert len(result.output) <= MAX_OUTPUT, f"output {len(result.output)} exceeds max_output {MAX_OUTPUT}"
    for layer in result.layers:
        assert layer.output_size <= MAX_OUTPUT, f"layer {layer.encoding} produced {layer.output_size} bytes"
    assert result.bytes_produced >= 0

    evidence = result.to_evidence()
    json.dumps(evidence)
    preview = evidence["decoded_preview"]
    assert isinstance(preview, str)
    assert "\x00" not in preview, "NUL byte survived into the preview"


def check_requirements(root: bytes, included: bytes) -> None:
    """``parse_requirements`` never raises, respects its limit and stores no credential."""
    files = {ROOT: root, INCLUDED: included}
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
        assert_no_credential(dep.url)
        assert_no_credential(dep.index_url)
    for warning in result.warnings:
        assert isinstance(warning, str)
        assert "\x00" not in warning, "NUL byte survived into a warning"
    for source in result.index_sources:
        assert isinstance(source, dict)
        assert_no_credential(source.get("url"))


def check_poetry_lock(data: bytes) -> None:
    """``parse_poetry_lock`` never raises on arbitrary TOML and keeps its output well-formed."""
    result = parse_poetry_lock(LOCK_PATH, data)

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
        assert_no_credential(package.source_url)
        assert_no_credential(package.index_url)
    for warning in result.warnings:
        assert "\x00" not in warning, "NUL byte survived into a warning"
    for manifest in result.manifests:
        assert manifest.get("status") in {"parsed", "too_large", "error"}, f"unexpected status {manifest!r}"
