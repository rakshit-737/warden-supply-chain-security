#!/usr/bin/env python3
"""Fuzz the layered decoder (``app.analysis.decode.decode_layers``).

The decoder unwraps base64/hex/compressed payloads found inside packages, so it runs on bytes an
attacker chose. Its contract is that it never raises, never exceeds its output bound (a
decompression bomb must be cut, not allocated) and never puts a raw payload into evidence.

    python fuzz/fuzz_decode.py -max_total_time=60 fuzz/corpus/decode
"""

from __future__ import annotations

import json
import sys

import atheris

with atheris.instrument_imports():
    from app.analysis.decode import decode_layers

MAX_DEPTH = 4
MAX_OUTPUT = 64 * 1024


def test_one_input(data: bytes) -> None:
    result = decode_layers(data, max_depth=MAX_DEPTH, max_output=MAX_OUTPUT)

    assert result.depth <= MAX_DEPTH, f"depth {result.depth} exceeds max_depth {MAX_DEPTH}"
    assert len(result.output) <= MAX_OUTPUT, f"output {len(result.output)} exceeds max_output {MAX_OUTPUT}"
    for layer in result.layers:
        assert layer.output_size <= MAX_OUTPUT, f"layer {layer.encoding} produced {layer.output_size} bytes"
    assert result.bytes_produced >= 0

    # Evidence must be a bounded, display-safe summary that a report can serialise.
    evidence = result.to_evidence()
    json.dumps(evidence)
    preview = evidence["decoded_preview"]
    assert isinstance(preview, str)
    assert "\x00" not in preview, "NUL byte survived into the preview"


def main() -> None:
    atheris.Setup(sys.argv, test_one_input)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
