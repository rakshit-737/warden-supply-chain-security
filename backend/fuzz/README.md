# Fuzz harnesses

Coverage-guided fuzzing of the code paths that read **attacker-controlled input**: the layered
decoder that unwraps obfuscated payloads, and the manifest and lock-file parsers. These run on
untrusted bytes from a package or a scanned repository, so a crash in one of them is a denial of
service against a scan — and a silently swallowed `MemoryError` is worse.

Harnesses use [Atheris](https://github.com/google/atheris) (libFuzzer for CPython). Each one asserts
the contract its target promises, not merely "does not crash":

| Harness | Target | Contract asserted |
|---|---|---|
| `fuzz_decode.py` | `app.analysis.decode.decode_layers` | never raises; depth, per-layer output and total output stay inside the configured bounds; the evidence summary is JSON-serialisable and holds no raw payload |
| `fuzz_requirements.py` | `app.sbom.parsers.requirements.parse_requirements` | never raises; dependency count respects the limit; every name is canonical; warnings and index sources are display-safe strings |
| `fuzz_poetry_lock.py` | `app.sbom.parsers.poetry_lock.parse_poetry_lock` | never raises on arbitrary TOML; every locked package has a canonical name and well-formed `sha256:` hashes |

## Run one locally

```bash
cd backend
pip install -r requirements.txt
pip install atheris==3.1.0                 # manylinux x86_64 wheel; see the pin in security.yml
PYTHONPATH=. python fuzz/fuzz_decode.py -max_total_time=60 fuzz/corpus/decode
```

Any libFuzzer flag works (`-runs=N`, `-max_len=N`, `-jobs=N`). A crash is written to the working
directory as `crash-<sha1>`; replay it with
`PYTHONPATH=. python fuzz/fuzz_decode.py crash-<sha1>`.

Atheris 3.x publishes manylinux x86_64 wheels only; on Windows or macOS use WSL, a Linux VM or the container.

## In CI

The `fuzz` job in `.github/workflows/security.yml` runs every harness for a bounded time on pull
requests and on a schedule, seeded from `fuzz/corpus/`. It is a smoke test for the harnesses and a
short regression fuzz — not a long campaign. Add any input that ever caused a crash to the matching
corpus directory so every later run replays it.
