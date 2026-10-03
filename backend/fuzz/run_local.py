#!/usr/bin/env python3
"""Run the fuzz contracts without Atheris, for machines with no Atheris wheel (Windows, macOS).

This is not coverage-guided: it mutates the corpus and splices URL- and manifest-shaped fragments,
which is enough to catch a contract that disagrees with the implementation before CI does. The real
campaign is the Atheris job in .github/workflows/security.yml; use this while writing a harness or
reproducing a report.

    PYTHONPATH=. python fuzz/run_local.py                    # every target, 20k inputs each
    PYTHONPATH=. python fuzz/run_local.py requirements 200000
    PYTHONPATH=. python fuzz/run_local.py decode 50000 --seed 7
"""

from __future__ import annotations

import argparse
import random
import sys
from pathlib import Path

from fuzz.contracts import check_decode, check_poetry_lock, check_requirements

CORPUS = Path(__file__).parent / "corpus"

ALPHABET = b"@:/#?[]\\.-_=<>;,%+ \t\n\x00\x0e\xff0ab" + b"https" + b"git"

FRAGMENTS = [
    b"pkg @ ", b"https://", b"//", b"git+ssh://", b"user:s3cret@", b"token@", b"git@",
    b"[REDACTED]@", b"example.com", b"/x.whl", b"?q=1", b"#frag", b"[::1]:8443", b"\x0e",
    b"-r constraints.txt\n", b"--index-url ", b"--hash=sha256:" + b"a" * 64, b"\n", b" ; ",
    b"python_version<'3.9'", b"Foo_Bar[Extra]>=1,<2", b"-e .", b"--find-links ", b"\xff\xfe",
    b"[[package]]\n", b'name = "x"\n', b'version = "1"\n', b"[package.source]\n", b'type = "git"\n',
    b"aGVsbG8=", b"eJzLSM3JyQcABiwCFQ==", b"4e6f74", b"\x1f\x8b\x08", b"\x80\x04\x95",
]

TARGETS = {
    "decode": lambda a, _b: check_decode(a),
    "requirements": check_requirements,
    "poetry_lock": lambda a, _b: check_poetry_lock(a),
}


def _mutate(rng: random.Random, seed: bytes) -> bytes:
    data = bytearray(seed)
    for _ in range(rng.randrange(1, 6)):
        if not data:
            break
        position = rng.randrange(len(data))
        action = rng.randrange(3)
        if action == 0:
            data[position] = rng.choice(ALPHABET)
        elif action == 1:
            del data[position]
        else:
            data[position:position] = bytes([rng.choice(ALPHABET)])
    return bytes(data)


def _generate(rng: random.Random, corpus: list[bytes]) -> bytes:
    style = rng.randrange(3)
    if style == 0:
        return bytes(rng.choice(ALPHABET) for _ in range(rng.randrange(0, 160)))
    if style == 1 or not corpus:
        return b"".join(rng.choice(FRAGMENTS) for _ in range(rng.randrange(1, 10)))
    return _mutate(rng, rng.choice(corpus))


def run(target: str, iterations: int, seed: int) -> int:
    check = TARGETS[target]
    corpus_dir = CORPUS / target
    corpus = [p.read_bytes() for p in sorted(corpus_dir.glob("*")) if p.is_file()] if corpus_dir.is_dir() else []
    rng = random.Random(seed)

    failures = 0
    for index in range(iterations):
        first, second = _generate(rng, corpus), _generate(rng, corpus)
        try:
            check(first, second)
        except AssertionError as exc:
            failures += 1
            print(ascii(f"[{target} {index}] CONTRACT {exc} a={first!r} b={second!r}"))
        except Exception as exc:  # noqa: BLE001 - any raise from a parser is itself a finding
            failures += 1
            print(ascii(f"[{target} {index}] RAISED {type(exc).__name__}: {exc} a={first!r} b={second!r}"))
        if failures >= 5:
            break
    print(f"{target}: iterations={index + 1} failures={failures}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", nargs="?", choices=sorted(TARGETS), help="default: every target")
    parser.add_argument("iterations", nargs="?", type=int, default=20000)
    parser.add_argument("--seed", type=int, default=1337)
    args = parser.parse_args()

    targets = [args.target] if args.target else sorted(TARGETS)
    return 1 if sum(run(t, args.iterations, args.seed) for t in targets) else 0


if __name__ == "__main__":
    sys.exit(main())
